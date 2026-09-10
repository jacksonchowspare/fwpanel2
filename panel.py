#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fwpanel2 — 简易VPS管理面板2.0（适配 Debian 13 / nftables）
================================================================
零第三方依赖：仅使用 Python 标准库 + 系统 nft 命令。

功能：
  * Web 管理界面（浏览器访问）
  * 端口放行/拒绝、IP 白名单/黑名单
  * 服务模板快捷开关（SSH/HTTP/HTTPS/DNS/Mail）
  * 宽松/严格两种模式（严格模式默认拒绝，需显式放行）
  * 防锁死：SSH 放行规则永远存在且不可删除
  * 登录认证：pbkdf2 密码哈希 + session token + 失败锁定
  * nftables 规则原子应用，失败自动回滚

目录结构：
  /etc/fwpanel/config.json     配置（含密码哈希，权限 600）
  /etc/fwpanel/rules.json      规则清单
  /etc/fwpanel/firewall.nft    生成的 nftables 规则文件
  /etc/fwpanel/firewall.nft.bak 上次成功应用的备份

用法：
  fwpanel serve [--port N] [--bind IP]    启动面板（默认）
  fwpanel reset-password                  重置面板密码（交互式）
  fwpanel apply                           仅应用规则（供 systemd 启动时调用）
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ------------------------------- 常量与路径 -------------------------------
CURRENT_VERSION = "3.0.4"
# 测试时用环境变量覆盖配置目录（单测/冒烟测试）
BASE_DIR = os.environ.get("FW_TEST_DIR", "/etc/fwpanel")
APP_DIR = os.environ.get("FW_APP_DIR", "/usr/local/lib/fwpanel")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
NFT_FILE = os.path.join(BASE_DIR, "firewall.nft")
NFT_BACKUP = os.path.join(BASE_DIR, "firewall.nft.bak")
# v1.25.9：规则文件读写锁（watch 清理线程 / 防爆破线程 / API 并发写 rules.json 防竞态）
_RULES_LOCK = threading.Lock()
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

DRY_RUN = "--dry-run" in sys.argv or os.environ.get("FW_DRY_RUN") == "1"

DEFAULT_PORT = 17890
SSH_PORT_DEFAULT = 22
TOKEN_TTL = 24 * 3600          # token 有效期 24 小时
LOCK_MAX_FAIL = 5              # 连续失败次数
LOCK_SECONDS = 300             # 锁定 5 分钟

# ------------------------------- 长任务后台执行（v2.1.18） -------------------------------
# 动机：nginx 网关 proxy_read_timeout 默认 60s，安装/拉取/证书等长任务经反代访问会 504
# （用户实测主控机装 Docker 报 HTTP 504，刷新后发现已装好——任务实际在跑，只是网关先断）。
# 方案：长任务接口立即返回 task_id，后端起线程执行，前端轮询 /api/tasks/<id>。
# 任务状态落盘 BASE_DIR/tasks.json——面板重启不丢结果（用户要求持久化）。
TASKS_FILE = os.path.join(BASE_DIR, "tasks.json")
_TASKS_LOCK = threading.Lock()
_tasks = {}          # task_id -> {action, status, ok, msg, started, finished, done}
_tasks_loaded = False
MAX_TASKS_KEEP = 200  # 磁盘最多保留条数（滚动清理最旧已完成）


def _tasks_load():
    """面板启动时从磁盘加载任务记录；running 状态（上次进程中断）标记为 error"""
    global _tasks, _tasks_loaded
    with _TASKS_LOCK:
        if _tasks_loaded:
            return
        _tasks = {}
        try:
            if os.path.exists(TASKS_FILE):
                with open(TASKS_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    _tasks = data.get("tasks", {}) or {}
        except (OSError, ValueError):
            _tasks = {}
        # 上次进程遗留的 running → error（线程已随进程消失，任务实际中断）
        for t in _tasks.values():
            if t.get("status") == "running" and not t.get("done"):
                t["status"] = "error"
                t["ok"] = False
                t["msg"] = "面板重启导致任务中断，请重新执行"
                t["finished"] = time.time()
        _tasks_loaded = True


def _tasks_save():
    """任务表落盘（原子写）。仅保留最近 MAX_TASKS_KEEP 条已完成/失败的记录"""
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        kept = {}
        # 保留全部 running（不能丢），已完成只留最近 MAX_TASKS_KEEP 条
        running = {k: v for k, v in _tasks.items() if v.get("status") == "running"}
        done_items = [(k, v) for k, v in _tasks.items() if v.get("status") != "running"]
        done_items.sort(key=lambda kv: kv[1].get("finished") or 0, reverse=True)
        for k, v in done_items[:MAX_TASKS_KEEP]:
            kept[k] = v
        kept.update(running)
        tmp = TASKS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"tasks": kept}, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, TASKS_FILE)
    except Exception:
        pass


def start_task(action, fn, *args):
    """启动后台长任务：记录 running 并落盘 → 线程执行 → 更新结果。
    返回 task_id（前端轮询 /api/tasks/<id>）"""
    _tasks_load()
    tid = secrets.token_hex(8)
    with _TASKS_LOCK:
        _tasks[tid] = {
            "action": action, "status": "running", "ok": False,
            "msg": "执行中...", "started": time.time(),
            "finished": None, "done": False,
        }
        _tasks_save()

    def _worker():
        try:
            ok, msg = fn(*args)
        except Exception as e:
            ok, msg = False, f"任务异常: {e}"
        with _TASKS_LOCK:
            t = _tasks.get(tid)
            if t is not None:
                t["status"] = "ok" if ok else "error"
                t["ok"] = ok
                t["msg"] = msg
                t["finished"] = time.time()
                t["done"] = True
                _tasks_save()

    threading.Thread(target=_worker, daemon=True).start()
    return tid


def get_task(tid):
    """查询任务：磁盘已加载则查内存；未加载先加载（重启后内存空，从磁盘恢复）"""
    _tasks_load()
    with _TASKS_LOCK:
        t = _tasks.get(tid)
        if t is None:
            return None
        return dict(t)

# 升级源（国内友好优先）：jsDelivr → GitHub raw → ghproxy.net → ghfast.top → gh-proxy.com
# ⚠ ghproxy.com 已废弃（返回 200 但内容为 HTML 错误页），不可用；后三个镜像 2026-08 实测返回真实文件
UPGRADE_SOURCES = [
    "https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel2@{tag}/{path}",
    "https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/{tag}/{path}",
    "https://ghproxy.net/https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/{tag}/{path}",
    "https://ghfast.top/https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/{tag}/{path}",
    "https://gh-proxy.com/https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/{tag}/{path}",
]

# 服务模板：名称 -> (协议, 端口)
SERVICES = {
    "ssh":   ("tcp", 22),
    "http":  ("tcp", 80),
    "https": ("tcp", 443),
    "dns":   ("udp", 53),
}

VALID_PROTOS = ("tcp", "udp", "both")

# SSH 端口切换时的临时放行规则注释（确认新端口可用后手动删除）
SSH_OLD_PORT_COMMENT = "旧SSH端口-切换保护"

# 严格模式下面板端口自动放行规则的注释（防止面板自身被锁死）
PANEL_PORT_COMMENT = "面板端口-严格模式"

# ------------------------------- 基础工具 -------------------------------

def log(msg):
    print(f"[fwpanel] {time.strftime('%F %T')} {msg}", flush=True)


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def hash_password(password, salt=None):
    """pbkdf2 哈希；返回 salt$hash 字符串"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000)
    return f"{salt}${dk.hex()}"


def verify_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def is_ipv6(ip):
    return ":" in ip


def detect_distro():
    """自动识别系统发行版（读 /etc/os-release），如 'Debian 13'、'Ubuntu 26.04'、'Arch Linux'"""
    try:
        info = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v.strip('"')
        name = info.get("NAME", "").split()[0] if info.get("NAME") else info.get("ID", "Linux")
        ver = info.get("VERSION_ID", "").strip()
        return f"{name} {ver}".strip() if ver else name
    except Exception:
        return "Linux"


def is_valid_ip_or_net(s):
    """校验 IP 目标：单个 IP / CIDR 网段 / 范围，如 1.2.3.4、1.2.3.0/24、
    1.2.3.1-1.2.3.50、2001:db8::/32（IPv4/IPv6 均可）"""
    s = str(s).strip()
    # 范围格式：start-end（两端同版本且 start <= end）
    if "-" in s:
        if s.count("-") != 1:
            return False
        a, b = (x.strip() for x in s.split("-", 1))
        try:
            ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
        except ValueError:
            return False
        return ia.version == ib.version and int(ia) <= int(ib)
    # 单个 IP 或 CIDR
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


# ------------------------------- 配置管理 -------------------------------

class Config:
    def __init__(self):
        self.data = self._load()

    def _load(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                return json.load(f)
        return {}

    def save(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_FILE)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()


# ------------------------------- 规则存储与渲染 -------------------------------

class RuleStore:
    """规则清单持久化 + nftables 规则渲染"""

    RULE_TYPES = ("port_allow", "port_deny", "ip_allow", "ip_deny")

    def __init__(self):
        self.rules = self._load()

    def _load(self):
        with _RULES_LOCK:
            if os.path.exists(RULES_FILE):
                try:
                    with open(RULES_FILE) as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError):
                    return []
            return []

    def save(self):
        # v1.25.9：加锁防并发写文件交错（watch 清理线程与防爆破线程并发 save 实测竞态）
        with _RULES_LOCK:
            os.makedirs(BASE_DIR, exist_ok=True)
            tmp = RULES_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.rules, f, indent=2, ensure_ascii=False)
            os.replace(tmp, RULES_FILE)

    def add(self, rule):
        rule = dict(rule)
        rule["id"] = secrets.token_hex(6)
        rule.setdefault("comment", "")
        self.rules.append(rule)
        self.save()
        return rule

    def remove(self, rule_id):
        for r in self.rules:
            if r["id"] == rule_id:
                if r.get("protected"):
                    return False, "SSH 保护规则不可删除（可在配置中修改 ssh_port 后重建）"
                self.rules.remove(r)
                self.save()
                return True, "ok"
        return False, "规则不存在"

    def get(self, rule_id):
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

    def render(self, config):
        """生成 nftables 规则文本。config 提供模式与 ssh_port"""
        mode = config.get("mode", "permissive")   # permissive 宽松 / strict 严格
        ssh_port = int(config.get("ssh_port", SSH_PORT_DEFAULT))
        lines = []
        lines.append("#!/usr/sbin/nft -f")
        lines.append("table inet fwpanel {")
        lines.append("    chain input {")
        if mode == "strict":
            lines.append("        type filter hook input priority filter; policy drop;")
        else:
            lines.append("        type filter hook input priority filter; policy accept;")
        # 基础放行：已建立连接 + 本机回环 + ICMP
        lines.append("        ct state established,related accept")
        lines.append('        iifname "lo" accept')
        lines.append("        ip protocol icmp accept")
        lines.append("        ip6 nexthdr icmpv6 accept")
        # ⚠ 黑名单规则优先：拒绝类规则（ip_deny/port_deny）必须放在所有 accept 之前，
        #   否则 SSH 保护等 accept 规则会先命中，封禁对 SSH 端口失效
        for r in self.rules:
            if r.get("type") in ("ip_deny", "port_deny"):
                for line in self._render_one(r):
                    lines.append(line)
        # SSH 保护规则（永远存在，防锁死；支持白名单模式：仅允许列表 IP 访问）
        allow_ips = config.get("ssh_allow_ips") or []
        if allow_ips:
            v4 = [ip for ip in allow_ips if ":" not in ip]
            v6 = [ip for ip in allow_ips if ":" in ip]
            if v4:
                lines.append(f"        ip saddr {{{', '.join(v4)}}} tcp dport {ssh_port} accept   # SSH 白名单")
            if v6:
                lines.append(f"        ip6 saddr {{{', '.join(v6)}}} tcp dport {ssh_port} accept   # SSH 白名单")
            lines.append(f"        tcp dport {ssh_port} drop   # SSH 保护(仅白名单 IP 可访问)")
        else:
            lines.append(f"        tcp dport {ssh_port} accept   # SSH 保护(不可删除)")
        # 用户规则（放行/拒绝之外的部分）
        for r in self.rules:
            if r.get("type") not in ("ip_deny", "port_deny"):
                for line in self._render_one(r):
                    lines.append(line)
        lines.append("    }")
        # ⚠ v1.24.27：PREROUTING 拦截链（priority -200，在 Docker DNAT 之前）——
        #   Docker 端口映射（-p 8807:8080）的流量在 PREROUTING 被 DNAT 后走 FORWARD 链进容器，
        #   永远不会经过 input 链，input 链的 port_deny drop 对 Docker 端口完全无效。
        #   这里用 filter hook prerouting priority -200（早于 Docker 的 dstnat -100），
        #   公网直连目标端口在 DNAT 前直接 drop；iifname != "lo" 保证 nginx 本机反代不受影响。
        deny_ports = [r for r in self.rules if r.get("type") == "port_deny"]
        if deny_ports:
            lines.append("    chain prerouting_drop {")
            lines.append("        type filter hook prerouting priority -200; policy accept;")
            for r in deny_ports:
                if r.get("proto") == "both":
                    lines.append(f'        iifname != "lo" tcp dport {r["port"]} drop   # 禁止公网直连(Docker端口)')
                    lines.append(f'        iifname != "lo" udp dport {r["port"]} drop   # 禁止公网直连(Docker端口)')
                else:
                    proto = r.get("proto", "tcp")
                    lines.append(f'        iifname != "lo" {proto} dport {r["port"]} drop   # 禁止公网直连(Docker端口)')
            lines.append("    }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_one(r):
        """单条规则 → nft 规则行列表（proto=both 生成 TCP+UDP 两行）"""
        t = r.get("type")
        comment = r.get("comment", "")
        tag = f"  # {comment}" if comment else ""
        if t in ("port_allow", "port_deny"):
            action = "accept" if t == "port_allow" else "drop"
            # 拒绝类规则排除本机回环：只挡外部流量，不挡 nginx 本机转发（反代目标端口场景）
            prefix = 'iifname != "lo" ' if t == "port_deny" else ""
            if r.get("proto") == "both":
                return [f"        {prefix}tcp dport {r['port']} {action}{tag}",
                        f"        {prefix}udp dport {r['port']} {action}{tag}"]
            proto = r.get("proto", "tcp")
            return [f"        {proto} dport {r['port']} {action}{tag}"]
        if t in ("ip_allow", "ip_deny"):
            action = "accept" if t == "ip_allow" else "drop"
            ip = r["ip"]
            key = "ip6 saddr" if is_ipv6(ip) else "ip saddr"
            return [f"        {key} {ip} {action}{tag}"]
        return []


# ------------------------------- nftables 执行 -------------------------------

class NFTManager:
    """应用规则：备份 -> 原子加载 -> 失败回滚"""

    def __init__(self, store, config):
        self.store = store
        self.config = config

    def apply(self):
        text = self.store.render(self.config)
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(NFT_FILE, "w") as f:
            f.write(text)
        if DRY_RUN:
            log("[dry-run] 生成规则文件，跳过 nft -f 执行")
            log("---- 规则内容 ----")
            for line in text.splitlines():
                print("  " + line)
            log("---- 规则内容结束 ----")
            return True, "dry-run"

        # 备份当前生效规则
        try:
            subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, check=True)
            with open(NFT_BACKUP, "w") as f:
                subprocess.run(["nft", "list", "ruleset"], stdout=f, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            log("无法读取当前规则集（可能为空），跳过备份")

        # 幂等重建：先删除旧表再加载。
        # ⚠ nft -f 对已存在的 chain 是追加语义（规则累积），不删表会导致规则爆炸 + 旧端口残留
        subprocess.run(["nft", "delete", "table", "inet", "fwpanel"],
                       capture_output=True, text=True)

        # 加载
        try:
            result = subprocess.run(
                ["nft", "-f", NFT_FILE], capture_output=True, text=True, timeout=15
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            return False, f"nft 执行失败: {e}"
        if result.returncode != 0:
            # 回滚
            if os.path.exists(NFT_BACKUP):
                subprocess.run(["nft", "-f", NFT_BACKUP], capture_output=True, text=True)
                log("规则加载失败，已回滚备份")
            return False, f"nft 报错: {result.stderr.strip()[:300]}"
        log(f"规则已应用（{len(self.store.rules)} 条用户规则，模式 {self.config.get('mode', 'permissive')}）")
        return True, "ok"

    def disable(self):
        """关闭防火墙：删除 fwpanel 表（rules.json 保留，重新开启时恢复）"""
        if DRY_RUN:
            log("[dry-run] 删除 fwpanel 表（跳过 nft 执行）")
            return True, "dry-run"
        try:
            r = subprocess.run(["nft", "delete", "table", "inet", "fwpanel"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                return False, r.stderr.strip()[:200]
            return True, "ok"
        except FileNotFoundError:
            return False, "nft 不可用"

    def status(self):
        """返回面板管理的规则是否已加载"""
        try:
            r = subprocess.run(["nft", "list", "table", "inet", "fwpanel"],
                               capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except FileNotFoundError:
            return False


# ------------------------------- 认证管理 -------------------------------

class Auth:
    def __init__(self, config):
        self.config = config
        self.tokens = {}            # token -> expiry
        self.lock = threading.Lock()
        self.fail_count = 0
        self.lock_until = 0

    def check_locked(self):
        if time.time() < self.lock_until:
            return True
        return False

    def login(self, username, password):
        with self.lock:
            if self.check_locked():
                return None, "尝试过于频繁，请稍后再试"
            stored_user = self.config.get("username")
            stored_pass = self.config.get("password_hash")
            if not stored_user or not stored_pass:
                return None, "面板未初始化，请运行安装脚本"
            if hmac.compare_digest(username, stored_user) and verify_password(password, stored_pass):
                self.fail_count = 0
                token = secrets.token_urlsafe(32)
                self.tokens[token] = time.time() + TOKEN_TTL
                return token, "ok"
            self.fail_count += 1
            if self.fail_count >= LOCK_MAX_FAIL:
                self.lock_until = time.time() + LOCK_SECONDS
                self.fail_count = 0
                log(f"登录失败次数过多，IP 已锁定 {LOCK_SECONDS}s")
            return None, "用户名或密码错误"

    def check(self, token):
        expiry = self.tokens.get(token, 0)
        if expiry > time.time():
            return True
        self.tokens.pop(token, None)
        return False

    def logout(self, token):
        self.tokens.pop(token, None)

    # ---------- 联邦令牌（2.0 多机管理：节点接受 X-Fwpanel-Token） ----------
    def fed_enabled(self):
        return bool(self.config.get("fed_hash"))

    def check_fed(self, fed_token):
        stored = self.config.get("fed_hash")
        if not stored or not fed_token:
            return False
        return hmac.compare_digest(sha256_hex(fed_token), stored)

    def set_fed_token(self, raw_token):
        """开启/更新联邦令牌（存哈希，明文仅生成时返回一次）"""
        self.config.set("fed_hash", sha256_hex(raw_token))

    def clear_fed_token(self):
        self.config.set("fed_hash", "")


# ------------------------------- 联邦存储（主面板侧节点配置） -------------------------------

FED_NODES_FILE = os.path.join(BASE_DIR, "fed_nodes.json")
FED_HEADER = "X-Fwpanel-Token"

# 联邦代理转发超时分档：长任务端点放宽（节点端安装/拉取/续期等可能数分钟，
# 25s 会误报"节点不可达"——用户实测远程装 Docker 报 TimeoutError 但实际装完）。
# 前缀匹配 rest 路径（节点侧 API），命中即用长超时（600s > 节点端任何 subprocess 上限）
FED_LONG_TASK_PREFIXES = (
    "/api/docker/install", "/api/docker/uninstall",
    "/api/docker/pull", "/api/docker/create", "/api/docker/rmi",
    "/api/docker/compose/up", "/api/docker/compose/upgrade",
    "/api/docker/data-root",
    "/api/proxy/install", "/api/proxy/",
    "/api/cert/", "/api/upgrade",
    "/api/sites/",                       # v3.0.0：网站文件上传/解压可能较慢
)


def fed_proxy_timeout(rest):
    """按节点侧目标路径分档：长任务 600s，其余 25s"""
    if any(rest.startswith(p) for p in FED_LONG_TASK_PREFIXES):
        return 600
    return 25


def _load_fed_nodes():
    try:
        with open(FED_NODES_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_fed_nodes(nodes):
    os.makedirs(BASE_DIR, exist_ok=True)
    tmp = FED_NODES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(nodes, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, FED_NODES_FILE)


def _gen_fed_token():
    return secrets.token_urlsafe(24)


def _http_fed_probe(url, tok):
    """主面板 → 节点探活：请求节点 /api/fed，令牌有效返回节点信息 dict，否则 None"""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/fed", method="GET")
        req.add_header(FED_HEADER, tok)
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except Exception:
        return None


# ------------------------------- 升级功能 -------------------------------

def restart_service():
    """重启 fwpanel 服务（由修改端口/升级等操作延迟调用）"""
    subprocess.run(["systemctl", "restart", "fwpanel"], capture_output=True)


def port_in_use_py(port):
    """Python 侧端口占用检测（bind 测试）

    ⚠ v3.0.1：必须设 SO_REUSEADDR。端口上存在 TIME_WAIT 残留连接（默认存活 60 秒）时，
    不设该选项 bind 会报 EADDRINUSE → 误判「端口已被占用」——实测现象：把面板端口从 A 改成 B 后
    想改回 A 会被拒（明明没人监听），另一个只是"最近有过连接"的端口也会被误判。
    SO_REUSEADDR 只忽略 TIME_WAIT，不会放过真正在 LISTEN 的端口。"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def http_get_json(url, timeout=8):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def http_download(url, dest, timeout=15, expect=None):
    """下载文件到 dest；expect 为 bytes 前缀（如 b"#!" / b'<!DOCTYPE html>\\n<html lang="zh-CN">'），
    内容不匹配视为失败——防止镜像源返回 HTTP 200 的 HTML 错误页被当成真实文件"""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = r.read()
        if not data:
            return False
        if expect is not None and not data.startswith(expect):
            return False
        with open(dest, "wb") as f:
            f.write(data)
        return True
    except Exception:
        return False


def version_tuple(v):
    return tuple(int(x) for x in str(v).split("."))


def version_gt(a, b):
    """a > b（语义化版本比较，处理 1.10.0 > 1.9.0）"""
    return version_tuple(a) > version_tuple(b)


def get_latest_version():
    """查询 GitHub 最新正式版（prerelease=false）。仓库无正式版时返回 None。

    releases/latest 只含正式版但可能 404；改走 releases 列表实时过滤，
    避免把测试版误报为正式版；jsDelivr / gh-proxy 仅作 GitHub 网络不可达时的兜底。
    """
    # 1) GitHub 最新正式版
    d = http_get_json("https://api.github.com/repos/jacksonchowspare/fwpanel2/releases/latest", timeout=15)
    if d and d.get("tag_name"):
        return d["tag_name"].lstrip("v")
    # 2) releases 列表实时过滤(prerelease=false 的最新;全 beta 仓库 → None)
    d = http_get_json("https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=10", timeout=15)
    if isinstance(d, list):
        for x in d:
            if x.get("tag_name") and not x.get("prerelease"):
                return str(x["tag_name"]).lstrip("v")
        return None   # 列表已拿到且无正式版,不继续尝试其它源
    # 3) 网络兜底:jsDelivr data API → gh-proxy 列表
    d = http_get_json("https://data.jsdelivr.com/v1/package/gh/jacksonchowspare/fwpanel2", timeout=15)
    if d and d.get("versions"):
        return d["versions"][0]
    d = http_get_json("https://gh-proxy.com/https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=10", timeout=15)
    if isinstance(d, list):
        for x in d:
            if x.get("tag_name") and not x.get("prerelease"):
                return str(x["tag_name"]).lstrip("v")
    return None


def get_latest_prerelease():
    """查询最新测试版（GitHub prerelease）版本号。

    ⚠ jsDelivr data API 不含 prerelease 信息，只能走 GitHub API 列表
    （主源重试 3 次 → gh-proxy.com 代理兜底）。无测试版返回 None。"""
    def _pick(entries):
        if not isinstance(entries, list):
            return None
        tags = [str(x["tag_name"]).lstrip("v") for x in entries
                if x.get("prerelease") and x.get("tag_name")]
        if not tags:
            return None
        return max(tags, key=lambda v: tuple(int(p) for p in v.split(".") if p.isdigit()))
    for attempt in (1, 2, 3):
        d = http_get_json("https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=10", timeout=20)
        if isinstance(d, list):
            return _pick(d)   # 列表已拿到，无 prerelease 就是确实没有
        if attempt < 3:
            time.sleep(2)
    d = http_get_json("https://gh-proxy.com/https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=10", timeout=20)
    return _pick(d)


def download_panel_files(tag, tmpdir):
    """按版本号下载 panel.py / index.html / github-logo.png / favicon.ico 到临时目录；
    带内容头校验（expect 前缀），镜像返回错误页时跳过该源；
    返回 (py_path, html_path, logo_path 或 None, ico_path 或 None) 或 None"""
    ok, py_path = False, os.path.join(tmpdir, "panel.py")
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="panel.py"), py_path, expect=b"#!"):
            ok = True
            break
    if not ok:
        return None
    ok, html_path = False, os.path.join(tmpdir, "index.html")
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/index.html"), html_path,
                         expect=b'<!DOCTYPE html>\n<html lang="zh-CN">'):
            ok = True
            break
    if not ok:
        return None
    logo_path = os.path.join(tmpdir, "github-logo.png")
    ok = False
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/github-logo.png"), logo_path,
                         expect=b"\x89PNG"):
            ok = True
            break
    ico_path = os.path.join(tmpdir, "favicon.ico")
    ok2 = False
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/favicon.ico"), ico_path,
                         expect=b"\x00\x00\x01\x00"):
            ok2 = True
            break
    # 子资源（v2.1.20）：Web 终端 vendor + 字体。面板内升级此前从不部署 static 子资源，
    # 导致 xterm.js 404 → 终端白屏。单个失败仅 warn 不阻断升级（保留前端缺组件防御提示）
    _sub = os.path.join(tmpdir, "static")
    for rel, expect in (
        ("vendor/xterm.js", b"!function"),
        ("vendor/xterm.css", b"/*"),
        ("vendor/xterm-addon-fit.js", b"!function"),
        ("fonts/fw-sans-sc-regular.woff2", b"wOF2"),
        ("fonts/fw-sans-sc-bold.woff2", b"wOF2"),
        ("fonts/0xProto-Regular.woff2", b"wOF2"),
        ("fonts/0xProto-Bold.woff2", b"wOF2"),
    ):
        dest = os.path.join(_sub, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        for tpl in UPGRADE_SOURCES:
            if http_download(tpl.format(tag=tag, path="static/" + rel), dest, expect=expect):
                break
    return py_path, html_path, (logo_path if ok else None), (ico_path if ok2 else None)


def perform_upgrade(tag=None):
    """一键升级：检查版本（tag=None 用最新正式版）→ 下载 → 校验 → 备份 → 替换 → 延迟重启。返回 (ok, msg)"""
    latest = tag or get_latest_version()
    if not latest:
        return False, "无法获取最新版本（网络问题），请稍后再试"
    if not version_gt(latest, CURRENT_VERSION):
        return False, f"已是最新版本 v{CURRENT_VERSION}"

    tmpdir = tempfile.mkdtemp(prefix="fwpanel-upgrade-")
    backup_py = os.path.join(APP_DIR, "panel.py.bak")
    backup_html = os.path.join(APP_DIR, "static", "index.html.bak")
    backup_ico = os.path.join(APP_DIR, "static", "favicon.ico.bak")
    backup_logo = os.path.join(APP_DIR, "static", "github-logo.png.bak")
    panel_py = os.path.join(APP_DIR, "panel.py")
    panel_html = os.path.join(APP_DIR, "static", "index.html")
    panel_ico = os.path.join(APP_DIR, "static", "favicon.ico")
    panel_logo = os.path.join(APP_DIR, "static", "github-logo.png")
    try:
        files = download_panel_files(latest, tmpdir)
        if not files:
            return False, "下载新版文件失败，请检查网络"
        new_py, new_html, new_logo, new_ico = files
        # 校验：新版 panel.py 必须语法通过，且版本号确实更新
        try:
            import py_compile
            py_compile.compile(new_py, doraise=True)
        except Exception as e:
            return False, f"新版文件校验失败，已中止: {e}"
        try:
            with open(new_py, encoding="utf-8") as f:
                src = f.read()
            m = __import__("re").search(r'CURRENT_VERSION\s*=\s*"([\d.]+)"', src)
            if m and m.group(1) == CURRENT_VERSION:
                return False, "下载到的版本与当前相同，请稍后重试"
        except Exception:
            pass
        # 备份当前文件
        shutil.copy2(panel_py, backup_py)
        shutil.copy2(panel_html, backup_html)
        if os.path.exists(panel_ico):
            shutil.copy2(panel_ico, backup_ico)
        if os.path.exists(panel_logo):
            shutil.copy2(panel_logo, backup_logo)
        # 替换
        os.chmod(new_py, 0o755)
        shutil.copy2(new_py, panel_py)
        shutil.copy2(new_html, panel_html)
        if new_logo and os.path.exists(new_logo):
            shutil.copy2(new_logo, panel_logo)
        if new_ico and os.path.exists(new_ico):
            shutil.copy2(new_ico, panel_ico)
        # 子资源部署（v2.1.20）：vendor / fonts 整目录复制到 static/（缺失跳过）
        for sub in ("vendor", "fonts"):
            src_dir = os.path.join(tmpdir, "static", sub)
            dst_dir = os.path.join(os.path.dirname(panel_html), sub)
            if os.path.isdir(src_dir):
                os.makedirs(dst_dir, exist_ok=True)
                for fn in os.listdir(src_dir):
                    try:
                        shutil.copy2(os.path.join(src_dir, fn), os.path.join(dst_dir, fn))
                    except Exception:
                        pass
    except Exception as e:
        # 失败回滚
        try:
            if os.path.exists(backup_py):
                shutil.copy2(backup_py, panel_py)
            if os.path.exists(backup_html):
                shutil.copy2(backup_html, panel_html)
            if os.path.exists(backup_logo):
                shutil.copy2(backup_logo, panel_logo)
            if os.path.exists(backup_ico):
                shutil.copy2(backup_ico, panel_ico)
        except Exception:
            pass
        return False, f"升级失败，已自动回滚: {e}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # 延迟重启，确保响应先送达浏览器
    threading.Timer(1.5, restart_service).start()
    return True, f"已升级到 v{latest}，服务重启中，请稍候重新登录"


# ------------------------------- SSH 端口管理 -------------------------------

# ------------------------------- 服务器 IP（顶部状态卡显示） -------------------------------

SRV_IP_CACHE = {"ip": None, "ts": 0.0}
SRV_IP_TTL = 300.0
PUBLIC_IP_SOURCES = ("https://api.ipify.org", "https://icanhazip.com",
                     "https://ip.sb", "https://ifconfig.me/ip")


def local_ipv4_pairs():
    """本机 IPv4 地址 [(iface, ip)]，排除回环（ip -4 -o addr show 解析）"""
    pairs = []
    try:
        r = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            # 形如: 2: eth0    inet 1.2.3.4/24 brd ... scope global eth0
            if len(parts) >= 4 and parts[2] == "inet":
                ip = parts[3].split("/")[0]
                if not ip.startswith("127."):
                    pairs.append((parts[1], ip))
    except Exception:
        pass
    return pairs


def _fetch_public_ip():
    """外网回显查询公网 IPv4（多源轮询，任一成功即返回）。DRY_RUN/全部失败 → None"""
    if DRY_RUN:
        return None
    for src in PUBLIC_IP_SOURCES:
        try:
            with urllib.request.urlopen(src, timeout=4) as resp:
                ip = resp.read().decode("utf-8", "replace").strip()
            addr = ipaddress.ip_address(ip)
            if not isinstance(addr, ipaddress.IPv4Address):
                continue
            return ip
        except Exception:
            continue
    return None


def get_server_ip():
    """服务器地址：公网回显优先（结果缓存 5 分钟，避免状态卡频繁出网），
    外网不可达回退主网卡 IPv4；都没有返回 None"""
    now = time.time()
    if SRV_IP_CACHE["ip"] and now - SRV_IP_CACHE["ts"] < SRV_IP_TTL:
        return SRV_IP_CACHE["ip"]
    pub = _fetch_public_ip()
    if pub:
        SRV_IP_CACHE.update(ip=pub, ts=now)
        return pub
    pairs = local_ipv4_pairs()
    ip = None
    if pairs:
        try:
            primary = primary_iface()
            ip = next((p[1] for p in pairs if p[0] == primary), pairs[0][1])
        except Exception:
            ip = pairs[0][1]
    SRV_IP_CACHE.update(ip=ip, ts=now)
    return ip


def warm_server_ip():
    """面板启动后台预热公网 IP（避免首个页面请求等外网查询）"""
    try:
        get_server_ip()
    except Exception:
        pass


SSHD_CONFIG_D = os.environ.get("FW_SSHD_DIR", "/etc/ssh/sshd_config.d")


def get_sshd_port():
    """检测系统 SSH 服务实际监听端口（sshd -T 优先，root 下可用）"""
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.startswith("port "):
                return int(line.split()[1])
    except Exception:
        pass
    return SSH_PORT_DEFAULT


def sync_ssh_port(config):
    """自动同步 SSH 保护端口到系统实际端口（仅当处于自动模式，手动设置后不再覆盖）"""
    if not config.get("ssh_port_auto", True):
        return False
    try:
        detected = get_sshd_port()
        current = int(config.get("ssh_port", SSH_PORT_DEFAULT))
        if detected != current:
            config.set("ssh_port", detected)
            log(f"SSH 保护端口已自动同步为系统实际端口 {detected}")
            return True
    except Exception:
        pass
    return False


def has_established_on_port(port):
    """检测端口上是否存在已建立的 TCP 连接（SSH 连接会保持 ESTABLISHED）"""
    try:
        r = subprocess.run(["ss", "-tn", "state", "established", f"( sport = :{port} )"],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def cleanup_old_ssh_rules(old_port, store):
    """删除指向旧 SSH 端口的全部放行规则（切换保护/服务开关/手动开放等），
    仅保留面板端口规则（避免面板自身被锁死）。
    ⚠ v1.25.9：改用调用方传入的共享 store 实例——此前自建 RuleStore() 只改了磁盘，
    面板主 store 内存仍是旧数据，防爆破线程后续 save() 会把已删规则覆盖回来（伦敦机实测竞态）"""
    before = len(store.rules)
    store.rules = [r for r in store.rules
                   if not (r.get("type") == "port_allow" and r.get("port") == old_port
                           and r.get("comment") != PANEL_PORT_COMMENT)]
    if len(store.rules) != before:
        store.save()
        nft = NFTManager(store, Config())
        nft.apply()
        return True
    return False


def watch_ssh_switch(old_port, new_port, store, confirm_delay=600, wait_timeout=3600):
    """后台监控：检测到新 SSH 端口连接后，延迟 confirm_delay 秒（10 分钟倒计时）再删除旧端口规则。
    等待连接上限 wait_timeout=3600：期间新端口始终无连接则放弃，保留旧规则保住 SSH 通道
    ⚠ v1.25.9：store 必须传面板共享实例（self.server.store / main 的 store），保证清理结果
    与防爆破/API 等其它写者内存一致，否则会被旧内存 save() 覆盖（伦敦机实测）"""
    deadline = time.time() + wait_timeout
    while time.time() < deadline:
        if has_established_on_port(new_port):
            log(f"检测到新 SSH 端口 {new_port} 已有连接，开始 10 分钟倒计时，倒计时结束自动删除旧端口 {old_port} 放行规则")
            time.sleep(confirm_delay)
            if cleanup_old_ssh_rules(old_port, store):
                log(f"已自动删除旧端口 {old_port} 放行规则")
            else:
                log(f"无旧端口规则需清理")
            return
        time.sleep(30)
    log(f"等待新 SSH 端口 {new_port} 连接超时（{wait_timeout}s），保留旧端口 {old_port} 规则，保住 SSH 通道")


def ssh_service_name():
    """检测系统 SSH 服务名：Debian/Ubuntu 是 ssh，Arch/Fedora 等是 sshd"""
    try:
        r = subprocess.run(["systemctl", "list-unit-files"],
                           capture_output=True, text=True, timeout=5)
        if re.search(r"^ssh\.service\s", r.stdout, re.M):
            return "ssh"
    except Exception:
        pass
    return "sshd"


def apply_sshd_port(port):
    """修改系统 SSH 服务端口：写入 sshd_config.d 并重启 ssh。返回 (ok, msg)"""
    if not (1 <= port <= 65535):
        return False, "端口范围 1-65535"
    try:
        os.makedirs(SSHD_CONFIG_D, exist_ok=True)
        conf = os.path.join(SSHD_CONFIG_D, "99-fwpanel-port.conf")
        with open(conf, "w") as f:
            f.write(f"# Managed by fwpanel — SSH port\nPort {port}\n")
        svc = ssh_service_name()
        r = subprocess.run(["systemctl", "restart", svc],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, f"重启 {svc} 服务失败: {r.stderr.strip()[:200]}"
        if get_sshd_port() != port:
            return False, "sshd 未监听新端口，请检查配置"
        return True, f"系统 SSH 端口已切换为 {port}"
    except Exception as e:
        return False, f"修改失败: {e}"


# ------------------------------- SSH 登录策略（认证方式/root 登录） -------------------------------

SSHD_AUTH_CONF = os.path.join(SSHD_CONFIG_D, "99-fwpanel-auth.conf")


def _norm_root_login(v):
    """PermitRootLogin 归一：yes / prohibit-password / no（兼容 without-password 老写法）"""
    v = (v or "").strip().lower()
    if v in ("prohibit-password", "without-password"):
        return "prohibit-password"
    if v in ("yes", "true"):
        return "yes"
    if v in ("no", "false"):
        return "no"
    return None


def sshd_policy_current():
    """读取 sshd 实际生效配置（sshd -T 输出）。失败（非 root/异常）返回 {}"""
    out = {}
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return {}
        for line in r.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                out[parts[0].lower()] = parts[1].strip().lower()
    except Exception:
        pass
    return out


def sshd_policy_managed():
    """读取面板管理的 drop-in 目标值（文件不存在/无内容返回 {}）"""
    data = {}
    try:
        with open(SSHD_AUTH_CONF, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    data[parts[0].lower()] = parts[1].strip().lower()
    except Exception:
        pass
    return data


def other_login_users():
    """系统内除 root 外可登录的普通用户（UID>=1000 且登录 shell 非 nologin/false）。
    用于防锁死校验：禁止 root 登录前确认还有其它通道"""
    users = []
    try:
        p = os.environ.get("FW_PASSWD_FILE", "/etc/passwd")
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if len(parts) < 7:
                    continue
                name, uid, shell = parts[0], parts[2], parts[6]
                if name in ("root", "nobody") or uid == "0":
                    continue
                try:
                    if int(uid) < 1000:
                        continue
                except ValueError:
                    continue
                if shell.strip() in ("", "/usr/sbin/nologin", "/sbin/nologin",
                                     "/bin/false", "/usr/bin/false", "/bin/nologin"):
                    continue
                users.append(name)
    except Exception:
        pass
    return users


def sshd_validate_changes(changes):
    """防锁死组合校验。changes 键：password_auth(bool) / pubkey_auth(bool) / permit_root(str)。
    未提供的项以当前生效值参与合并判断。返回 (ok, error)"""
    cur = sshd_policy_current()
    pa = changes.get("password_auth")
    if pa is None:
        pa = cur.get("passwordauthentication", "yes") == "yes"
    ka = changes.get("pubkey_auth")
    if ka is None:
        ka = cur.get("pubkeyauthentication", "yes") == "yes"
    if not pa and not ka:
        return False, "密码登录和密钥登录不能同时关闭——否则没有任何方式可以登录 SSH"
    if changes.get("permit_root") == "no" and not other_login_users():
        return False, "系统内除 root 外没有其他可登录账号，禁止 root 登录后会把所有 SSH 通道锁死"
    return True, ""


def _restore_auth_conf(backup):
    """还原 drop-in 到 backup 内容（None=删除该文件），并重启 ssh 服务"""
    try:
        if backup is None:
            if os.path.exists(SSHD_AUTH_CONF):
                os.remove(SSHD_AUTH_CONF)
        else:
            with open(SSHD_AUTH_CONF, "w", encoding="utf-8") as f:
                f.write(backup)
    except Exception:
        pass
    try:
        subprocess.run(["systemctl", "restart", ssh_service_name()],
                       capture_output=True, text=True, timeout=30)
    except Exception:
        pass


def apply_sshd_policy(changes):
    """写入面板 drop-in 并重启 sshd，回读验证。返回 (ok, msg, current)"""
    ok, err = sshd_validate_changes(changes)
    if not ok:
        return False, err, None
    target = sshd_policy_managed()   # 幂等：保留此前面板管理的其它项
    if "password_auth" in changes:
        target["passwordauthentication"] = "yes" if changes["password_auth"] else "no"
    if "pubkey_auth" in changes:
        target["pubkeyauthentication"] = "yes" if changes["pubkey_auth"] else "no"
    if "permit_root" in changes:
        target["permitrootlogin"] = _norm_root_login(changes["permit_root"])
    order = ("passwordauthentication", "pubkeyauthentication", "permitrootlogin")
    content = "# Managed by fwpanel — SSH 登录策略\n" + \
              "\n".join("%s %s" % (k, target[k]) for k in order if k in target) + "\n"
    backup = None
    try:
        os.makedirs(SSHD_CONFIG_D, exist_ok=True)
        if os.path.exists(SSHD_AUTH_CONF):
            with open(SSHD_AUTH_CONF, encoding="utf-8", errors="replace") as f:
                backup = f.read()
        with open(SSHD_AUTH_CONF, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        return False, "写入配置失败: %s" % e, None
    try:
        r = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            _restore_auth_conf(backup)
            return False, "sshd 语法检查失败（已自动还原）: %s" % r.stderr.strip()[:200], None
    except Exception as e:
        _restore_auth_conf(backup)
        return False, "sshd -t 执行异常（已自动还原）: %s" % e, None
    svc = ssh_service_name()
    try:
        r = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _restore_auth_conf(backup)
            return False, "重启 %s 服务失败（已自动还原）: %s" % (svc, r.stderr.strip()[:200]), None
    except Exception as e:
        _restore_auth_conf(backup)
        return False, "重启 %s 服务异常（已自动还原）: %s" % (svc, e), None
    after = sshd_policy_current()
    for k, want in (("passwordauthentication", target.get("passwordauthentication")),
                    ("pubkeyauthentication", target.get("pubkeyauthentication")),
                    ("permitrootlogin", target.get("permitrootlogin"))):
        if want is None:
            continue
        got = after.get(k)
        if k == "permitrootlogin":
            got, want = _norm_root_login(got), _norm_root_login(want)
        if got != want:
            _restore_auth_conf(backup)
            return False, ("重启后 %s=%s，未达到目标 %s（已自动还原；主配置文件可能在 "
                           "Include 之前写死了该参数，需在服务器上手动处理）"
                           % (k, got or "未生效", want)), None
    return True, "SSH 登录策略已保存并生效", after


def reset_sshd_policy():
    """删除面板接管配置，恢复系统默认认证。返回 (ok, msg)"""
    backup = None
    try:
        if os.path.exists(SSHD_AUTH_CONF):
            with open(SSHD_AUTH_CONF, encoding="utf-8", errors="replace") as f:
                backup = f.read()
            os.remove(SSHD_AUTH_CONF)
    except Exception as e:
        return False, "删除配置失败: %s" % e
    try:
        r = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            _restore_auth_conf(backup)
            return False, "sshd 语法检查失败（已还原）: %s" % r.stderr.strip()[:200]
    except Exception as e:
        _restore_auth_conf(backup)
        return False, "sshd -t 执行异常（已还原）: %s" % e
    svc = ssh_service_name()
    try:
        r = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            _restore_auth_conf(backup)
            return False, "重启 %s 服务失败（已还原）: %s" % (svc, r.stderr.strip()[:200])
    except Exception as e:
        _restore_auth_conf(backup)
        return False, "重启 %s 服务异常（已还原）: %s" % (svc, e)
    return True, "已移除面板接管配置，SSH 认证方式恢复为系统默认"


# ------------------------------- SSH 密钥对管理（生成/安装/列出/删除） -------------------------------

KEY_TYPES = ("ssh-", "ecdsa-", "sk-")


def user_home(user):
    """查询用户 home 目录（pwd；root 兜底 /root）"""
    try:
        import pwd
        return pwd.getpwnam(user).pw_dir
    except Exception:
        if user == "root":
            return "/root"
        raise ValueError("用户不存在: %s" % user)


def ssh_auth_keys_file(user, home=None):
    return os.path.join(home or user_home(user), ".ssh", "authorized_keys")


def _parse_auth_line(line):
    """解析 authorized_keys 一行 → (key_type, comment)；容忍 options 前缀与行尾 # 注释"""
    body = line.split("#", 1)[0]
    fields = body.split()
    for i, fld in enumerate(fields):
        if fld.startswith(KEY_TYPES):
            comment = fields[i + 2] if len(fields) > i + 2 else ""
            return fld, comment
    return None


def ssh_list_keys(user, home=None):
    """列出用户 authorized_keys：每行 {type, fp, comment, line}。指纹 ssh-keygen -lf 批量计算"""
    path = ssh_auth_keys_file(user, home)
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = [ln.rstrip("\n") for ln in f]
    except Exception:
        return []
    keys = []
    for ln in raw:
        parsed = _parse_auth_line(ln)
        if parsed is None:
            continue
        keys.append({"type": parsed[0], "comment": parsed[1], "fp": "", "line": ln})
    if not keys:
        return keys
    try:
        r = subprocess.run(["ssh-keygen", "-lf", path], capture_output=True, text=True, timeout=10)
        for i, row in enumerate(r.stdout.splitlines()):
            parts = row.split()
            if i < len(keys) and len(parts) >= 2 and parts[1].startswith("SHA256:"):
                keys[i]["fp"] = parts[1]
    except Exception:
        pass
    return keys


def ssh_install_pubkey(user, pubkey_line, home=None):
    """公钥追加到用户 authorized_keys（幂等查重；.ssh 700 / 文件 600）。
    以 root 运行时把目录与文件属主改为目标用户。返回 (ok, msg)"""
    home = home or user_home(user)
    ssh_dir = os.path.join(home, ".ssh")
    path = os.path.join(ssh_dir, "authorized_keys")
    try:
        os.makedirs(ssh_dir, exist_ok=True)
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root:
            try:
                import pwd
                pw = pwd.getpwnam(user)
                os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)
            except Exception:
                pass
        os.chmod(ssh_dir, 0o700)
        content = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
            if pubkey_line.strip() in content.splitlines():
                return False, "该公钥已存在，未重复添加"
        with open(path, "a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write(pubkey_line.strip() + "\n")
        if is_root:
            try:
                import pwd
                pw = pwd.getpwnam(user)
                os.chown(path, pw.pw_uid, pw.pw_gid)
            except Exception:
                pass
        os.chmod(path, 0o600)
    except Exception as e:
        return False, "安装公钥失败: %s" % e
    return True, "公钥已安装到 %s" % path


def ssh_del_key(user, line, home=None):
    """按整行内容删除 authorized_keys 中的公钥。返回 (ok, msg)"""
    path = ssh_auth_keys_file(user, home)
    if not os.path.exists(path):
        return False, "authorized_keys 文件不存在"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return False, "读取失败: %s" % e
    target = line.strip()
    kept, removed = [], False
    for ln in lines:
        if not removed and ln.strip() == target:
            removed = True
            continue
        kept.append(ln)
    if not removed:
        return False, "未找到匹配的公钥（可能已被移除）"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    except Exception as e:
        return False, "写入失败: %s" % e
    return True, "公钥已移除"


def ssh_gen_keypair(algo="ed25519", user="root", home=None):
    """生成密钥对：公钥自动装到用户 authorized_keys，私钥仅返回一次不落盘（临时目录用完即删）。
    返回 (ok, dict)。成功 dict: {private_key, public_key, fingerprint, user, msg}"""
    algo = (algo or "ed25519").lower()
    if algo not in ("ed25519", "rsa"):
        return False, {"error": "算法仅支持 ed25519 或 rsa"}
    try:
        home = home or user_home(user)
    except ValueError as e:
        return False, {"error": str(e)}
    try:
        import socket
        host = socket.gethostname()
    except Exception:
        host = "server"
    comment = "fwpanel-%s-%s" % (host, datetime.date.today().strftime("%Y%m%d"))
    tmpd = tempfile.mkdtemp(prefix="fwpanel-key-")
    try:
        cmd = ["ssh-keygen", "-t", algo, "-C", comment, "-N", "",
               "-f", os.path.join(tmpd, "id")]
        if algo == "rsa":
            cmd += ["-b", "4096"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, {"error": "ssh-keygen 执行失败: %s" % r.stderr.strip()[:200]}
        with open(os.path.join(tmpd, "id"), encoding="utf-8") as f:
            private_key = f.read()
        with open(os.path.join(tmpd, "id.pub"), encoding="utf-8") as f:
            pub_line = f.read().strip()
        fp = ""
        try:
            rf = subprocess.run(["ssh-keygen", "-lf", os.path.join(tmpd, "id.pub")],
                                capture_output=True, text=True, timeout=10)
            parts = rf.stdout.split()
            if rf.returncode == 0 and len(parts) >= 2 and parts[1].startswith("SHA256:"):
                fp = parts[1]
        except Exception:
            pass
        ok, msg = ssh_install_pubkey(user, pub_line, home)
        if not ok:
            return False, {"error": msg}
        return True, {"private_key": private_key, "public_key": pub_line,
                      "fingerprint": fp, "user": user, "msg": msg}
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


# ------------------------------- SSH 防爆破 -------------------------------

BANS_FILE = os.path.join(BASE_DIR, "bans.json")
BAN_COMMENT = "SSH防爆破-自动封禁"
MANUAL_BAN_COMMENT = "手动封禁"
BF_DEFAULTS = {"enabled": False, "max_fails": 5, "ban_seconds": 3600, "fail_window": 300}
BF_PERMANENT_UNTIL = 4102444800   # 2100-01-01 UTC 时间戳，表示永久封禁（不会自动到期）


def bf_cfg(config):
    """读取防爆破配置（合并默认值）"""
    bf = config.get("bruteforce")
    if not isinstance(bf, dict):
        bf = {}
    return {k: bf.get(k, v) for k, v in BF_DEFAULTS.items()}


def load_bans():
    try:
        with open(BANS_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_bans(bans):
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = BANS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(bans, f, ensure_ascii=False)
        os.replace(tmp, BANS_FILE)
    except Exception:
        pass


def get_failed_ssh_attempts(window_seconds):
    """从 journal 读取最近窗口内的 SSH 认证失败记录，返回 {ip: 次数}"""
    svc = ssh_service_name()
    try:
        r = subprocess.run(["journalctl", "-u", svc, "--since", f"-{int(window_seconds)}s",
                            "-o", "cat", "--no-pager"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    counts = {}
    pat = re.compile(r"Failed password for .*? from ([0-9a-fA-F:.]+) port")
    for line in r.stdout.splitlines():
        m = pat.search(line)
        if m:
            ip = m.group(1)
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def get_established_ips(port):
    """端口上已建立连接的远端 IP 集合（豁免封禁，防把自己锁死）"""
    ips = set()
    try:
        r = subprocess.run(["ss", "-tn", "state", "established", f"( sport = :{port} )"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                remote = parts[4]
                ip = remote.rsplit(":", 1)[0].strip("[]")
                if ip and ip != "*":
                    ips.add(ip)
    except Exception:
        pass
    return ips


def bruteforce_cycle(config, store, now=None):
    """执行一轮防爆破扫描：解封到期 IP + 检测并封禁新 IP。返回动作日志列表"""
    logs = []
    bf = bf_cfg(config)
    if not bf["enabled"]:
        return logs
    if not config.get("firewall_enabled", True):
        # 防火墙已关闭：无拦截可言，跳过扫描（开启后自动恢复）
        return logs
    now = time.time() if now is None else now
    bans = load_bans()
    changed = False
    # 1) 到期解封
    expired = [ip for ip, until in bans.items() if until <= now]
    recently_unbanned = set()
    for ip in expired:
        # 删除该 IP 的防爆破相关规则（自动封禁 + 手动封禁都到期解封）
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "ip_deny" and r.get("ip") == ip
                               and r.get("comment") in (BAN_COMMENT, MANUAL_BAN_COMMENT))]
        del bans[ip]
        recently_unbanned.add(ip)
        changed = True
        logs.append(f"SSH 防爆破: {ip} 封禁到期，已自动解封")
    # 2) 检测新失败并封禁
    exempt = get_established_ips(int(config.get("ssh_port", SSH_PORT_DEFAULT)))
    exempt.add("127.0.0.1")
    exempt.add("::1")
    counts = get_failed_ssh_attempts(bf["fail_window"])
    for ip, n in counts.items():
        # 当前连接 IP / 已封禁 / 本轮回避（刚解封）都不重复处理
        if ip in exempt or ip in bans or ip in recently_unbanned:
            continue
        if n >= bf["max_fails"]:
            if not any(r.get("type") == "ip_deny" and r.get("ip") == ip
                       and r.get("comment") == BAN_COMMENT for r in store.rules):
                store.add({"type": "ip_deny", "ip": ip, "comment": BAN_COMMENT})
            bans[ip] = now + bf["ban_seconds"]
            changed = True
            logs.append(f"SSH 防爆破: {ip} 失败 {n} 次，已封禁 {bf['ban_seconds']} 秒")
    if changed:
        store.save()
        save_bans(bans)
        nft = NFTManager(store, config)
        nft.apply()
    return logs


def bruteforce_loop(config, store, interval=30):
    """后台监控线程：每 interval 秒执行一轮防爆破扫描"""
    while True:
        try:
            for msg in bruteforce_cycle(config, store):
                log(msg)
        except Exception as e:
            log(f"SSH 防爆破扫描异常: {e}")
        time.sleep(interval)


# ------------------------------- 网卡流量统计 -------------------------------

TRAFFIC_FILE = os.environ.get("FW_TRAFFIC_FILE", os.path.join(BASE_DIR, "traffic.json"))
TRAFFIC_INTERVAL = 60  # 采样间隔（秒）


def read_net_dev():
    """读取 /proc/net/dev 各网卡累计字节，返回 {iface: {"rx": int, "tx": int}}（排除 lo）"""
    result = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()[2:]  # 跳过表头两行
    except OSError:
        return result
    for line in lines:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name = name.strip()
        if not name or name == "lo":
            continue
        parts = data.split()
        if len(parts) >= 9:
            # /proc/net/dev 行格式: rx_bytes rx_packets ... tx_bytes(第9列) ...
            result[name] = {"rx": int(parts[0]), "tx": int(parts[8])}
    return result


def primary_iface():
    """识别主网卡：/proc/net/route 的默认路由网卡，兜底第一个非 lo 有数据网卡"""
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000" and parts[0] != "lo":
                    return parts[0]
    except OSError:
        pass
    devs = read_net_dev()
    if devs:
        return sorted(devs.keys())[0]
    return "eth0"


class TrafficStore:
    """按天聚合的网卡流量存储：traffic.json = {"since": "YYYY-MM-DD", "days": {"YYYY-MM-DD": {"iface": {"rx":, "tx":}}}}"""

    def __init__(self, path=None):
        self.path = path or TRAFFIC_FILE
        self.data = {"since": None, "days": {}}
        self._last = None  # {iface: {"rx":, "tx":, "ts":}} 上次采样快照
        self._rates = {}   # {iface: {"rx_bps":, "tx_bps":}} 最近一次采样速率
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {"since": None, "days": {}}
        if not isinstance(self.data.get("days"), dict):
            self.data["days"] = {}
        if "since" not in self.data:
            self.data["since"] = None

    def save(self):
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass  # 磁盘不可写不阻断面板

    def record(self, counters=None, now=None):
        """采样一次：当前累计值与上次快照的差值累加到当天；首次采样只建基线（防重启跳变）"""
        counters = counters if counters is not None else read_net_dev()
        now = now if now is not None else time.time()
        today = datetime.date.today().isoformat()
        day = self.data["days"].setdefault(today, {})
        self._rates = {}
        if self._last is None:
            self._last = {name: {"rx": c["rx"], "tx": c["tx"], "ts": now}
                          for name, c in counters.items()}
            if self.data["since"] is None:
                self.data["since"] = today
                self.save()
            return
        for name, c in counters.items():
            prev = self._last.get(name)
            if prev is None:
                self._last[name] = {"rx": c["rx"], "tx": c["tx"], "ts": now}
                continue
            dt = now - prev["ts"]
            if dt <= 0:
                dt = 1
            drx = max(0, c["rx"] - prev["rx"])
            dtx = max(0, c["tx"] - prev["tx"])
            self._rates[name] = {"rx_bps": drx / dt, "tx_bps": dtx / dt}
            if drx > 0 or dtx > 0:
                slot = day.setdefault(name, {"rx": 0, "tx": 0})
                slot["rx"] += drx
                slot["tx"] += dtx
            self._last[name] = {"rx": c["rx"], "tx": c["tx"], "ts": now}
        if self.data["since"] is None:
            self.data["since"] = today
        self.save()

    def totals_for(self, iface, start=None, end=None):
        """按日期范围累加某网卡流量；start/end 为 'YYYY-MM-DD' 或 None"""
        rx = tx = 0
        for date_str, day in self.data["days"].items():
            if start and date_str < start:
                continue
            if end and date_str > end:
                continue
            slot = day.get(iface)
            if slot:
                rx += slot.get("rx", 0)
                tx += slot.get("tx", 0)
        return {"rx": rx, "tx": tx}

    def daily(self, iface, days=7):
        """近 days 天每日流量（无记录的天补 0）"""
        out = []
        today = datetime.date.today()
        for i in range(days - 1, -1, -1):
            d = today - datetime.timedelta(days=i)
            ds = d.isoformat()
            slot = self.data["days"].get(ds, {}).get(iface, {})
            out.append({"date": ds, "rx": slot.get("rx", 0), "tx": slot.get("tx", 0)})
        return out

    def ifaces(self):
        """全部出现过的网卡（含速率表）"""
        ifaces = set()
        for day in self.data["days"].values():
            ifaces.update(day.keys())
        ifaces.update(self._rates.keys())
        return sorted(ifaces)


def traffic_active_iface(store):
    """自动选择当前有流量的网卡：最近采样速率非零 > 今日有流量记录 > 主网卡兜底"""
    # 1. 最近采样速率非零（正在跑流量）
    for name, r in sorted(store._rates.items()):
        if r.get("rx_bps", 0) > 0 or r.get("tx_bps", 0) > 0:
            return name
    # 2. 今日有流量记录
    today = datetime.date.today().isoformat()
    day = store.data.get("days", {}).get(today, {})
    for name, slot in sorted(day.items()):
        if slot.get("rx", 0) > 0 or slot.get("tx", 0) > 0:
            return name
    # 3. 主网卡兜底
    return primary_iface()


def traffic_loop(store, interval=TRAFFIC_INTERVAL):
    """后台线程：定期采样网卡流量并按天聚合"""
    while True:
        try:
            store.record()
        except Exception as e:
            log(f"网卡流量采样异常: {e}")
        time.sleep(interval)


# ------------------------------- 进程流量统计（nethogs） -------------------------------

NETHOGS_TIMEOUT = 25  # nethogs 采样超时（秒）


def nethogs_available():
    """检测 nethogs 是否安装（进程流量统计的数据采集器，可选依赖）"""
    return shutil.which("nethogs") is not None


def install_nethogs():
    """一键安装 nethogs（apt/pacman/dnf 包名均为 nethogs）"""
    if DRY_RUN:
        return True, "DRY_RUN: 安装 nethogs"
    return install_pkgs(["nethogs"])


def parse_nethogs_output(text):
    """解析 nethogs tracemode 输出，按 PID 聚合。

    兼容两种实测格式：
    A. nethogs 0.8.7+（括号端口，bytes/sec）:
        <prog>[/<path>]/<pid>/<local>-<remote>(<lport>-<rport>)/<rx> bytes/sec/<tx> bytes/sec
    B. nethogs 0.8.5 / Debian 系（空格分隔浮点 KB/s，2026-08 用户实测）:
        <progname>/<pid>/<uid>  <sent> KB/s  <recv> KB/s
    返回 [{"name", "pid", "rx", "tx", "conns"}]，按 rx+tx 合计降序。
    无法匹配的行（libpcap 警告 / Unknown connection / Ethernet link 等）直接跳过。
    """
    procs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Refreshing:") or line.startswith("TOTAL:"):
            continue
        # 格式 A：从右往左锚定固定后缀，地址段不拆分（hostname 可能含 '-'）
        m = re.match(r"^(.*)\((\d+)-(\d+)\)/(\d+) bytes/sec/(\d+) bytes/sec$", line)
        if m:
            head, _lport, _rport, rx, tx = m.groups()
            parts = head.rsplit("/", 2)  # head = <prog>/<pid>/<local>-<remote>
            if len(parts) != 3:
                continue
            prog, pid_str, _conn = parts
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            name = prog if not prog.startswith("/") else os.path.basename(prog.rstrip("/")) or prog
            rx, tx = int(rx), int(tx)
        else:
            # 格式 B：progname/pid/uid  sent-KB/s  recv-KB/s
            m2 = re.match(r"^(.+?)/(\d+)/(\d+)\s+([\d.]+)\s+([\d.]+)$", line)
            if not m2:
                continue
            prog, pid_str, _uid, sent, recv = m2.groups()
            try:
                pid = int(pid_str)
            except ValueError:
                continue
            name = prog if not prog.startswith("/") else os.path.basename(prog.rstrip("/")) or prog
            tx = float(sent) * 1024.0  # sent = 进程发送 = 上行，KB/s → B/s
            rx = float(recv) * 1024.0  # recv = 进程接收 = 下行
        p = procs.setdefault(pid, {"name": name, "pid": pid, "rx": 0, "tx": 0, "conns": 0})
        p["rx"] += rx
        p["tx"] += tx
        p["conns"] += 1
    return sorted(procs.values(), key=lambda p: p["rx"] + p["tx"], reverse=True)


def procs_cmdline(pid):
    """读 /proc/<pid>/cmdline 返回完整命令行（NUL 分隔转空格）；进程已退出返回空串"""
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            raw = f.read()
        return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def procs_snapshot():
    """采样一次进程流量：nethogs -t -d 1 -c 2，取最后一次 Refreshing 块（最新速率）。

    返回 {"ok": bool, "error": str, "procs": [{"name","pid","cmdline","rx","tx","conns"}]}
    """
    if not nethogs_available():
        return {"ok": False, "error": "nethogs 未安装", "procs": []}
    if DRY_RUN:
        return {"ok": True, "procs": []}
    try:
        r = subprocess.run(["nethogs", "-t", "-d", "1", "-c", "3"],
                           capture_output=True, text=True, timeout=NETHOGS_TIMEOUT)
    except FileNotFoundError:
        return {"ok": False, "error": "nethogs 未安装", "procs": []}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "采样超时（nethogs 无响应）", "procs": []}
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()[:200]
        return {"ok": False, "error": "nethogs 失败: %s" % err, "procs": []}
    blocks = r.stdout.split("Refreshing:")
    text = blocks[-1] if blocks else ""  # 最后一次 Refreshing 块为最新速率
    procs = parse_nethogs_output(text)
    for p in procs:
        p["cmdline"] = procs_cmdline(p["pid"])
    return {"ok": True, "procs": procs}


# ------------------------------- 进程流量历史（按天累计） -------------------------------

PROCS_FILE = os.environ.get("FW_PROCS_FILE", os.path.join(BASE_DIR, "procs.json"))
PROCS_ACCUM_MAX_DT = 600  # 相邻采样间隔超过 10 分钟不累计（防瞬时进程虚报流量）


class ProcStore:
    """进程流量历史存储：procs.json = {"days": {date: {name: {"rx","tx","last_seen","last_pid"}}}, "last_ts": N}

    - 进程按**名称**为主键（PID 会变化/被复用），名单跨天、跨重启保留
    - 流量估算：每次采样（手动刷新）速率 × 距上次采样间隔，累计到当天
    - last_ts 为空 / 间隔 > PROCS_ACCUM_MAX_DT 时只更新最后活跃不累计
    """

    def __init__(self, path=None):
        self.path = path or PROCS_FILE
        self.data = {"days": {}, "last_ts": None}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {"days": {}, "last_ts": None}
        if not isinstance(self.data.get("days"), dict):
            self.data["days"] = {}
        if "last_ts" not in self.data:
            self.data["last_ts"] = None

    def save(self):
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass  # 磁盘不可写不阻断面板

    def record(self, procs, now=None):
        """procs = 本次采样 [{name, pid, rx, tx, ...}]（rx/tx 为 B/s 速率）"""
        now = now if now is not None else time.time()
        last = self.data.get("last_ts")
        do_accum = last is not None and 0 < (now - last) <= PROCS_ACCUM_MAX_DT
        dt = (now - last) if (last is not None and do_accum) else 0
        day = self.data["days"].setdefault(datetime.date.today().isoformat(), {})
        for p in procs:
            name = (p.get("name") or "").strip()
            if not name:
                continue
            slot = day.setdefault(name, {"rx": 0, "tx": 0, "last_seen": 0, "last_pid": None})
            if do_accum:
                slot["rx"] += float(p.get("rx") or 0) * dt
                slot["tx"] += float(p.get("tx") or 0) * dt
            slot["last_seen"] = now
            slot["last_pid"] = p.get("pid")
        self.data["last_ts"] = now
        self.save()

    def history(self):
        """历史进程汇总（跨天合并）：[{name, last_seen, last_pid, today_rx, today_tx, total_rx, total_tx}]，按最后活跃降序"""
        today = datetime.date.today().isoformat()
        agg = {}
        for date_str, day in self.data["days"].items():
            for name, slot in day.items():
                a = agg.setdefault(name, {"name": name, "last_seen": 0, "last_pid": None,
                                          "today_rx": 0, "today_tx": 0,
                                          "total_rx": 0, "total_tx": 0})
                a["total_rx"] += slot.get("rx", 0)
                a["total_tx"] += slot.get("tx", 0)
                if date_str == today:
                    a["today_rx"] += slot.get("rx", 0)
                    a["today_tx"] += slot.get("tx", 0)
                if slot.get("last_seen", 0) > a["last_seen"]:
                    a["last_seen"] = slot["last_seen"]
                    a["last_pid"] = slot.get("last_pid")
        out = list(agg.values())
        out.sort(key=lambda x: x["last_seen"], reverse=True)
        return out

    def detail(self, name):
        """某进程近 7 天每天流量 + 总累计"""
        days = []
        today = datetime.date.today()
        for i in range(6, -1, -1):
            d = (today - datetime.timedelta(days=i)).isoformat()
            slot = self.data["days"].get(d, {}).get(name, {})
            days.append({"date": d, "rx": slot.get("rx", 0), "tx": slot.get("tx", 0)})
        total_rx = total_tx = 0
        for date_str, day in self.data["days"].items():
            slot = day.get(name)
            if slot:
                total_rx += slot.get("rx", 0)
                total_tx += slot.get("tx", 0)
        return {"name": name, "days": days, "total_rx": total_rx, "total_tx": total_tx}

    def clear(self):
        """清空全部历史（保留当前存储文件）"""
        self.data = {"days": {}, "last_ts": None}
        self.save()


# ------------------------------- 反向代理（Nginx） -------------------------------

PROXIES_FILE = os.path.join(BASE_DIR, "proxies.json")
CERT_FILE = os.path.join(BASE_DIR, "certificates.json")
ACME_WEBROOT = "/var/www/fwpanel-acme"
LE_LIVE = "/etc/letsencrypt/live"
PROXY_TARGET_DENY_COMMENT = "反代目标端口-禁止公网直连"
# acme.sh DNS 验证（v1.25.0：Cloudflare/DNSPod/阿里云 三家通吃，无需 80 端口）
ACME_SH = os.path.expanduser("~/.acme.sh/acme.sh")
DNS_PROVIDERS = {
    "cf":  {"name": "Cloudflare", "dns": "dns_cf",
            "fields": [("CF_Token", "API Token")]},
    "dp":  {"name": "DNSPod（腾讯云）", "dns": "dns_dp",
            "fields": [("DP_Id", "DNSPod ID"), ("DP_Key", "DNSPod Token")]},
    "ali": {"name": "阿里云", "dns": "dns_ali",
            "fields": [("Ali_Key", "AccessKey ID"), ("Ali_Secret", "AccessKey Secret")]},
}


def _cert_meta(entry):
    """兼容新旧 certificates.json 结构：str=旧版 webroot，dict=新版 {email, method, provider, source}"""
    if isinstance(entry, dict):
        return (str(entry.get("email", "")), str(entry.get("method", "http")),
                str(entry.get("provider", "")), str(entry.get("source", "independent")))
    return str(entry or ""), "http", "", "independent"


def load_cert_store():
    """独立申请的证书记录：{domain: email}"""
    try:
        with open(CERT_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cert_store(store):
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = CERT_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(store, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CERT_FILE)
    except OSError:
        pass


class ProxyStore:
    def __init__(self):
        self.proxies = self._load()

    def _load(self):
        try:
            with open(PROXIES_FILE) as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def save(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = PROXIES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.proxies, f, indent=2, ensure_ascii=False)
        os.replace(tmp, PROXIES_FILE)

    def add(self, p):
        p = dict(p)
        p["id"] = secrets.token_hex(6)
        p.setdefault("scheme", "http")
        p.setdefault("websocket", False)
        p.setdefault("ssl", False)
        p.setdefault("enabled", True)
        p["created"] = int(time.time())
        self.proxies.append(p)
        self.save()
        return p

    def get(self, pid):
        for p in self.proxies:
            if p["id"] == pid:
                return p
        return None

    def remove(self, pid):
        for i, p in enumerate(self.proxies):
            if p["id"] == pid:
                self.proxies.pop(i)
                self.save()
                return True
        return False


def nginx_conf_dir():
    """检测 nginx 配置目录（Debian: sites-enabled，Arch/Fedora: conf.d）"""
    for d in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
        if os.path.isdir(d):
            return d
    return None


def reload_nginx():
    """nginx -t 校验后 reload；失败返回错误信息"""
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, f"nginx 配置校验失败: {(r.stderr or r.stdout).strip()[:300]}"
    subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
    return True, "nginx 已重载"


def nginx_available():
    return shutil.which("nginx") is not None


def nginx_active():
    try:
        r = subprocess.run(["systemctl", "is-active", "nginx"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


def certbot_available():
    return shutil.which("certbot") is not None


def cert_files_exist(domain):
    return os.path.isfile(os.path.join(LE_LIVE, domain, "fullchain.pem"))


def _fmt_next_check(next_raw):
    """把下次检测时间格式化为「xxxx年xx月xx日 星期几」"""
    try:
        from datetime import datetime
        # systemctl show 输出的 epoch 微秒
        if next_raw and next_raw.isdigit():
            dt = datetime.fromtimestamp(int(next_raw) / 1e6)
            return f"{dt.year}年{dt.month}月{dt.day}日 星期{'一二三四五六日'[dt.weekday()]}"
    except Exception:
        pass
    return next_raw or ""


def cert_renew_status():
    """检测 certbot 自动续期状态：systemd timer / cron 任务"""
    if not certbot_available():
        return {"enabled": False, "via": "", "next": "", "reason": "certbot 未安装"}
    try:
        r = subprocess.run(["systemctl", "show", "certbot.timer",
                            "-p", "NextElapseUSecRealtime", "-p", "ActiveState"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and "certbot.timer" in r.stdout or "ActiveState=active" in r.stdout:
            usec = ""
            for line in r.stdout.splitlines():
                if line.startswith("NextElapseUSecRealtime="):
                    usec = line.split("=", 1)[1].strip()
            if usec and usec != "0":
                return {"enabled": True, "via": "systemd timer",
                        "next": _fmt_next_check(usec), "reason": ""}
    except Exception:
        pass
    try:
        r = subprocess.run(["systemctl", "list-timers", "certbot.timer", "--no-pager"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and "certbot.timer" in r.stdout:
            for line in r.stdout.splitlines():
                if "certbot.timer" in line:
                    parts = line.split()
                    return {"enabled": True, "via": "systemd timer",
                            "next": _fmt_next_check(" ".join(parts[0:2])), "reason": ""}
    except Exception:
        pass
    if os.path.exists("/etc/cron.d/certbot"):
        return {"enabled": True, "via": "cron", "next": "每天两次随机检查", "reason": ""}
    return {"enabled": False, "via": "", "next": "", "reason": "未找到 systemd timer 或 cron 续期任务"}


def cert_status(domain):
    """返回证书到期时间戳（无证书返回 None）"""
    pem = os.path.join(LE_LIVE, domain, "fullchain.pem")
    if not os.path.isfile(pem):
        return None
    try:
        r = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", pem],
                           capture_output=True, text=True, timeout=10)
        m = re.search(r"notAfter=(.+)", r.stdout)
        if m:
            dt = datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            return int(dt.timestamp())
    except Exception:
        pass
    return None


def host_guard(domain):
    """生成 nginx host 守卫：只允许通过域名访问，IP/其他 Host 直连返回 444"""
    if domain.startswith("*."):
        base = re.escape(domain[2:])
        return f'    if ($host !~ ^(.+\\.)?{base}$) {{ return 444; }}\n'
    return f'    if ($host != "{domain}") {{ return 444; }}\n'


def _proxy_cert(domain, cert_ref):
    """反代证书解析：cert_ref 指定引用的证书（可为 *.example.com 泛域名），否则用反代自身域名。
    返回 (ssl_on, fullchain, key)"""
    ref = (cert_ref or "").strip()
    if not ref:
        ref = domain
    fc = os.path.join(LE_LIVE, ref, "fullchain.pem")
    if os.path.isfile(fc):
        return True, fc, os.path.join(LE_LIVE, ref, "privkey.pem")
    return False, None, None


def render_proxy_conf(p):
    """生成 nginx server block 配置（含 ACME 挑战路径、HTTP→HTTPS 跳转、WebSocket 支持）"""
    ssl_on, ssl_fc, ssl_key = _proxy_cert(p["domain"], p.get("cert_ref"))
    ws = bool(p.get("websocket"))
    hsts = bool(p.get("hsts"))
    block_ip = bool(p.get("block_ip"))
    upstream = f"{p.get('scheme', 'http')}://{p['target_host']}:{p['target_port']}"
    guard = host_guard(p["domain"]) if block_ip else ""
    ws_extra = ("        proxy_http_version 1.1;\n"
                "        proxy_set_header Upgrade $http_upgrade;\n"
                '        proxy_set_header Connection "upgrade";\n'
                # v2.1.22：WebSocket 长连接（面板终端/流式推送）空闲会被默认
                # proxy_read_timeout 60s 掐断 → 终端打开一会就"连接已关闭"
                "        proxy_read_timeout 3600s;\n"
                "        proxy_send_timeout 3600s;\n")
    hdr = ("        proxy_set_header Host $host;\n"
           "        proxy_set_header X-Real-IP $remote_addr;\n"
           "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
           "        proxy_set_header X-Forwarded-Proto $scheme;\n")
    lines = [f"# FW-Panel2 管理: {p['domain']}"]
    # HTTP server（ACME 挑战；有证书时跳转 HTTPS）
    lines.append("server {")
    lines.append("    listen 80;")
    lines.append(f"    server_name {p['domain']};")
    lines.append(f"    location /.well-known/acme-challenge/ {{ root {ACME_WEBROOT}; }}")
    if guard:
        lines.extend(x for x in guard.splitlines() if x)
    if ssl_on:
        lines.append("    location / { return 301 https://$host$request_uri; }")
    else:
        lines.append("    location / {")
        lines.append(f"        proxy_pass {upstream};")
        lines.extend(x for x in hdr.splitlines() if x)
        if ws:
            lines.extend(x for x in ws_extra.splitlines() if x)
        lines.append("    }")
    lines.append("}")
    if ssl_on:
        lines.append("server {")
        lines.append("    listen 443 ssl;")
        lines.append(f"    server_name {p['domain']};")
        lines.append(f"    ssl_certificate {ssl_fc};")
        lines.append(f"    ssl_certificate_key {ssl_key};")
        if hsts:
            lines.append('        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;')
        if guard:
            lines.extend(x for x in guard.splitlines() if x)
        lines.append("    location / {")
        lines.append(f"        proxy_pass {upstream};")
        lines.extend(x for x in hdr.splitlines() if x)
        if ws:
            lines.extend(x for x in ws_extra.splitlines() if x)
        lines.append("    }")
        lines.append("}")
    return "\n".join(lines) + "\n"


# ------------------------------- 网站（站点管理，v3.0.0） -------------------------------
# 设计要点（三条约束，改动前必读）：
# 1) 反代站不复制数据：网站列表 = sites.json(静态站/端口站) ∪ proxies.json(反代站)，
#    反代记录只有一份真相，站点模块只做视图合并，避免两边不同步
# 2) nginx 配置只有一个渲染出口 apply_all_nginx()：旧的 apply_proxies 收敛为它的包装，
#    否则两套渲染互相覆盖/误删（旧实现就踩过）
# 3) 站点配置前缀 fwsite-，与反代 fwpanel- 分开：万一从 v3 退回 v2，v2 的清理循环
#    只认 fwpanel-<12位hex>.conf，不会删掉站点配置（网站不会瞬间全 404）
SITES_FILE = os.path.join(BASE_DIR, "sites.json")
PROXY_CONF_PREFIX = "fwpanel-"
SITE_CONF_PREFIX = "fwsite-"
DEFAULT_SITE_ROOT = "/var/www"
# ⚠ 清理失效配置必须按「12 位小写十六进制 id」校验形状：
# id = secrets.token_hex(6)。旧实现只判断前缀 fwpanel-，于是兜底守卫配置
# fwpanel-default.conf（id 段是 "default"）每次写完后立刻被当过期配置删掉 ——
# default_server 444 / 443 ssl_reject_handshake 守卫实际从未生效（2026-09-10 实测确认）
CONF_ID_RE = re.compile(r"^[0-9a-f]{12}$")
SITE_TYPES = ("static", "port")
# 站点目录禁放区（防误操作毁系统 / 面板自身数据）
SITE_FORBIDDEN_ROOTS = ("/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run",
                        "/usr", "/bin", "/sbin", "/lib", "/var/log", "/var/lib", "/tmp")
SITE_DEFAULT_INDEX = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
 body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
         background:#12141a; color:#e8eaee; }}
 .box {{ text-align:center; padding:48px 36px; border:1px solid #262a33; border-radius:12px; background:#171a21; }}
 h1 {{ font-size:20px; font-weight:600; margin:0 0 12px; }}
 p {{ margin:6px 0 0; color:#98a2b3; font-size:13px; }}
</style>
</head>
<body>
<div class="box">
  <h1>{title}</h1>
  <p>站点已创建，把网站文件放进本目录（入口 index.html）即可访问</p>
  <p>生成自 FW-Panel2 网站模块</p>
</div>
</body>
</html>
"""


def site_root_base(cfg=None):
    """站点根目录：优先 config.json 的 site_root（「网站」设置可改），默认 /var/www"""
    base = ""
    if cfg is not None:
        try:
            base = str(cfg.get("site_root", "") or "")
        except Exception:
            base = ""
    if not base:
        try:
            base = str(Config().get("site_root", "") or "")
        except Exception:
            base = ""
    base = (base or DEFAULT_SITE_ROOT).strip().rstrip("/")
    if not base.startswith("/"):
        base = DEFAULT_SITE_ROOT
    return base or DEFAULT_SITE_ROOT


def site_root_ok(path):
    """站点目录是否允许：绝对路径 + 不在禁放区 + 不落在面板数据/ACME/证书/nginx 目录内"""
    if not path or not os.path.isabs(path):
        return False
    p = os.path.normpath(path)
    if p in SITE_FORBIDDEN_ROOTS:
        return False
    for f in SITE_FORBIDDEN_ROOTS:
        if f != "/" and p.startswith(f.rstrip("/") + "/"):
            return False
    for f in (BASE_DIR, ACME_WEBROOT, LE_LIVE, "/etc/nginx"):
        f = str(f).rstrip("/")
        if f and (p == f or p.startswith(f + "/")):
            return False
    return True


def site_conf_name(sid):
    return f"{SITE_CONF_PREFIX}{sid}.conf"


def proxy_conf_name(pid):
    return f"{PROXY_CONF_PREFIX}{pid}.conf"


class SiteStore:
    """站点清单（静态站 / 无域名端口站）持久化；反代站不入此表（视图合并 proxies.json）"""

    def __init__(self):
        self.sites = self._load()

    def _load(self):
        try:
            with open(SITES_FILE) as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def save(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = SITES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.sites, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SITES_FILE)

    def get(self, sid):
        for s in self.sites:
            if s.get("id") == sid:
                return s
        return None

    def add(self, s):
        s = dict(s)
        s["id"] = secrets.token_hex(6)
        s.setdefault("enabled", True)
        s["created"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.sites.append(s)
        self.save()
        return s

    def update(self, sid, changes):
        s = self.get(sid)
        if not s:
            return None
        s.update(changes)
        self.save()
        return s

    def remove(self, sid):
        if not self.get(sid):
            return False
        self.sites = [x for x in self.sites if x.get("id") != sid]
        self.save()
        return True


def site_validate(data, pstore, sstore, cfg, exclude_id=None):
    """校验并归一化站点配置 → (site_dict, error)"""
    t = str(data.get("type", "static")).strip().lower()
    if t not in SITE_TYPES:
        return None, "站点类型必须是 static（静态站）或 port（无域名端口站）"
    cert_mode = str(data.get("cert_mode", "none")).strip().lower()
    if cert_mode not in ("auto", "none"):
        return None, "证书模式必须是 auto（自动签发）或 none（暂不签）"
    domain = str(data.get("domain", "")).strip().lower()
    port = 0
    panel_port = int(cfg.get("port", 0) or 0)
    ssh_port = int(cfg.get("ssh_port", 0) or 0)
    if t == "static":
        if not domain:
            return None, "域名不能为空（没有域名请选「无域名端口站」）"
        if not re.fullmatch(r"[a-zA-Z0-9.*_-]+", domain):
            return None, "域名格式无效（支持 example.com 或 *.example.com）"
        if domain.startswith("*.") and cert_mode == "auto":
            return None, "泛域名无法用 HTTP-01 自动签发：请先在证书模块用 DNS 验证申请，再在本站点引用"
        for p in pstore.proxies:
            if (p.get("domain") or "").lower() != domain:
                continue
            if p.get("target_port") == panel_port:
                return None, "该域名是面板自身的访问域名，网站模块不可占用（防面板失联）"
            return None, f"域名 {domain} 已在「反向代理」中使用（网站列表里已显示为反代站），请到反代模块管理"
        for s in sstore.sites:
            if s.get("domain") == domain and s.get("id") != exclude_id:
                return None, f"域名 {domain} 已被其它站点占用"
    else:
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            return None, "监听端口必须是数字"
        if not (1024 <= port <= 65535):
            return None, "监听端口范围 1024-65535（1024 以下为系统保留）"
        if port == panel_port:
            return None, "该端口是面板自身端口，不能占用"
        if port == ssh_port:
            return None, "该端口是 SSH 保护端口，不能占用"
        for s in sstore.sites:
            if (s.get("type") == "port" and int(s.get("port", 0) or 0) == port
                    and s.get("id") != exclude_id):
                return None, f"端口 {port} 已被其它站点占用"
    root = str(data.get("root", "")).strip()
    if not root:
        root = os.path.join(site_root_base(cfg),
                            domain if t == "static" else f"port-{port}")
    root = os.path.normpath(root)
    if not os.path.isabs(root):
        return None, "站点目录必须是绝对路径"
    if not site_root_ok(root):
        return None, f"站点目录不合法或属于受保护路径：{root}"
    site = {
        "domain": domain,
        "type": t,
        "root": root,
        "cert_mode": cert_mode,
        "cert_ref": str(data.get("cert_ref", "") or "").strip().lower(),
        "force_https": bool(data.get("force_https")),
        "block_ip": bool(data.get("block_ip", True)),
        "note": str(data.get("note", "") or "").strip()[:120],
        "enabled": bool(data.get("enabled", True)),
    }
    if t == "port":
        site["port"] = port
    return site, None


def site_prepare_dir(site):
    """创建站点目录 + 默认首页；root 运行时把属主交给 www-data（网站可写、面板可管）"""
    root = site["root"]
    created = not os.path.isdir(root)
    os.makedirs(root, exist_ok=True)
    idx = os.path.join(root, "index.html")
    if not os.path.exists(idx):
        title = site.get("domain") or ("端口 " + str(site.get("port", "")))
        with open(idx, "w") as f:
            f.write(SITE_DEFAULT_INDEX.format(title=title))
    if os.geteuid() == 0:
        try:
            import pwd
            u = pwd.getpwnam("www-data")
            for pth, mode in ((root, 0o755), (idx, 0o644)):
                os.chown(pth, u.pw_uid, u.pw_gid)
                os.chmod(pth, mode)
        except Exception:
            pass
    return created


def site_cert_info(site):
    """站点证书状态：{on, ref, days}（days=None = 无证书或读不出到期时间）"""
    domain = site.get("domain") or ""
    if not domain or site.get("cert_mode") != "auto":
        return {"on": False, "ref": "", "days": None}
    ref = (site.get("cert_ref") or domain).strip()
    on, fc, key = _proxy_cert(domain, site.get("cert_ref"))
    days = None
    ts = cert_status(ref)
    if ts:
        try:
            days = int((int(ts) - time.time()) // 86400)
        except Exception:
            days = None
    return {"on": bool(on), "ref": ref if on else "", "days": days}


def site_cert_ready(s):
    """站点证书是否已就绪（无需签发）：cert_mode=auto 且引用/自身的证书文件已存在。
    v3.0.1：引用已有证书（cert_ref）时不再重复签发——旧实现只要 cert_mode=auto 就发起签发，
    白白消耗 Let's Encrypt 配额（实测：引用泛域名证书的站点又被单独签了一张）。"""
    if not s or s.get("cert_mode") != "auto":
        return False
    return bool(site_cert_info(s).get("on"))


def site_view(s):
    """站点 → 前端视图（补访问地址与证书状态）"""
    v = dict(s)
    ci = site_cert_info(s)
    domain = s.get("domain") or ""
    if domain:
        url = f"https://{domain}" if ci["on"] else f"http://{domain}"
    else:
        ip = get_server_ip() or "服务器IP"
        url = f"http://{ip}:{s.get('port')}"
    v.update({"source": "site", "url": url, "cert": ci, "label": "静态站" if s.get("type") == "static" else "端口站"})
    return v


def proxy_site_view(p):
    """反代记录 → 网站视图（只读展示 + 跳转反代模块管理，不复制数据）"""
    domain = p.get("domain") or ""
    on, fc, key = _proxy_cert(domain, p.get("cert_ref"))
    days = None
    ts = cert_status((p.get("cert_ref") or domain).strip())
    if ts:
        try:
            days = int((int(ts) - time.time()) // 86400)
        except Exception:
            days = None
    upstream = f"{p.get('scheme', 'http')}://{p.get('target_host')}:{p.get('target_port')}"
    return {
        "id": "p_" + str(p.get("id")),
        "proxy_id": p.get("id"),
        "source": "proxy",
        "label": "反代站",
        "type": "proxy",
        "domain": domain,
        "root": "",
        "upstream": upstream,
        "cert": {"on": bool(on), "ref": (p.get("cert_ref") or domain) if on else "", "days": days},
        "url": f"https://{domain}" if on else f"http://{domain}",
        "enabled": bool(p.get("enabled", True)),
        "note": "",
        "created": "",
    }


SITE_EDIT_MAX_BYTES = 2 * 1024 * 1024        # 在线编辑上限 2MB
SITE_UPLOAD_MAX_BYTES = 32 * 1024 * 1024     # 单文件上传上限 32MB
SITE_UNZIP_MAX_BYTES = 512 * 1024 * 1024     # 解压后总量上限 512MB（防 zip 炸弹）
SITE_LOG_TAIL_BYTES = 256 * 1024             # 日志只读尾部（避免大文件全量进内存）
# 允许在线编辑的文本类扩展名（白名单：其余一律只给下载，不给编辑）
SITE_TEXT_EXT = {
    ".html", ".htm", ".xhtml", ".css", ".js", ".mjs", ".json", ".txt", ".md", ".markdown",
    ".xml", ".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".env", ".php", ".py", ".sh",
    ".sql", ".csv", ".tsv", ".log", ".svg", ".vue", ".ts", ".jsx", ".tsx", ".htaccess",
}
SITE_TEXT_NAMES = {"CNAME", "README", "LICENSE", "robots.txt", "sitemap.xml", ".htaccess"}

_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<t>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)')


def site_log_name(site):
    """站点日志文件名（与 render_site_conf 生成的一致：域名安全化，端口站用 site-<id>）"""
    domain = (site.get("domain") or "").strip()
    return re.sub(r"[^A-Za-z0-9._-]", "_", domain) if domain else f"site-{site.get('id', 'x')}"


def site_log_paths(site):
    """站点日志路径（access, error）"""
    name = site_log_name(site)
    return (f"/var/log/nginx/{name}.access.log", f"/var/log/nginx/{name}.error.log")


def site_available_certs():
    """可引用的已签发证书（LE_LIVE 下的目录）→ [{ref, days}]"""
    out = []
    try:
        for name in sorted(os.listdir(LE_LIVE)):
            if os.path.isfile(os.path.join(LE_LIVE, name, "fullchain.pem")):
                days = None
                ts = cert_status(name)
                if ts:
                    try:
                        days = int((int(ts) - time.time()) // 86400)
                    except Exception:
                        days = None
                out.append({"ref": name, "days": days})
    except Exception:
        pass
    return out


def site_dns_precheck(domain, cert_ref=""):
    """签发前预检域名是否已解析到本机 —— 避免白等一次注定失败的签发。
    返回 (ok, msg)。引用已有证书/取不到公网 IP/查询异常时一律放行（交给 ACME 结果说话）"""
    if cert_ref or not domain:
        return True, ""
    try:
        server_ip = get_server_ip()
    except Exception:
        server_ip = None
    if not server_ip:
        return True, ""
    try:
        ips = {info[4][0] for info in socket.getaddrinfo(domain, None)}
    except Exception as e:
        return False, (f"域名 {domain} 解析失败（{e}）：请先把 A 记录指向 {server_ip} 再试，"
                       f"或在向导里选「暂不签证书」先用 HTTP 跑起来")
    if server_ip not in ips:
        got = ", ".join(sorted(ips)[:3]) or "无"
        return False, (f"域名 {domain} 当前解析到 {got}，本机公网 IP 是 {server_ip}："
                       f"DNS 未指向本机，签发必然失败。请先改 DNS，或选「暂不签证书」")
    return True, ""


def site_issue_cert(sid):
    """后台任务体：给站点申请证书（HTTP-01）→ 成功后重新渲染 nginx。返回 (ok, msg)"""
    sstore = SiteStore()
    s = sstore.get(sid)
    if not s:
        return False, "站点已不存在"
    domain = (s.get("domain") or "").strip()
    if not domain:
        return False, "端口站（无域名）不需要证书"
    try:
        email = str(Config().get("acme_email", "") or "")
    except Exception:
        email = ""
    ok, msg = issue_cert(domain, email)
    if not ok:
        return False, msg
    ok2, msg2 = apply_all_nginx(ProxyStore(), SiteStore(), None)
    if not ok2:
        return False, f"证书已签发，但 nginx 重载失败：{msg2}"
    return True, f"证书已签发并启用 HTTPS（{msg2}）"


def site_open_ports(store, site):
    """建站放行入口端口（严格模式必需）→ 返回新放行的端口列表。
    静态站：80 必放（ACME HTTP-01 要用），有证书时加 443；端口站：放行自定义端口"""
    ports = []
    if site.get("type") == "static":
        ports = [80]
        if site_cert_info(site)["on"] or site.get("force_https"):
            ports.append(443)
    else:
        p = int(site.get("port", 0) or 0)
        if p:
            ports = [p]
    changed = []
    for p in ports:
        if any(r.get("type") == "port_allow" and r.get("port") == p for r in store.rules):
            continue
        comment = {80: "网站:HTTP", 443: "网站:HTTPS"}.get(p, "网站:自定义端口")
        store.add({"type": "port_allow", "proto": "tcp", "port": p, "comment": comment})
        changed.append(p)
    if changed:
        store.save()
    return changed


def site_close_ports(store, site):
    """删除站点时回收它专属的放行规则（80/443 保留——证书续期与反代可能还要用）"""
    if site.get("type") != "port":
        return []
    p = int(site.get("port", 0) or 0)
    if not p:
        return []
    keep = [r for r in store.rules
            if not (r.get("type") == "port_allow" and r.get("port") == p
                    and r.get("comment") == "网站:自定义端口")]
    removed = len(store.rules) - len(keep)
    if removed:
        store.rules = keep
        store.save()
    return [p] if removed else []


def site_resolve_path(site, rel):
    """站点内路径解析（路径穿越防护）：realpath 归一后必须落在站点根目录内。
    rel 为空 = 站点根。返回 (abs_path, err)"""
    root = os.path.realpath(site["root"])
    rel = (rel or "").strip().replace("\\", "/")
    if rel.startswith("/"):
        return None, "请使用站点内的相对路径"
    rel = rel.lstrip("/")
    if "\x00" in rel:
        return None, "非法路径"
    p = os.path.realpath(os.path.join(root, rel))
    if p != root and not p.startswith(root + os.sep):
        return None, "路径越界：只允许操作站点目录内的文件"
    return p, None


def site_editable(name, size=0):
    """是否允许在线编辑（文本白名单 + 体积上限）"""
    if size and size > SITE_EDIT_MAX_BYTES:
        return False
    if name in SITE_TEXT_NAMES:
        return True
    return os.path.splitext(name)[1].lower() in SITE_TEXT_EXT


def site_file_list(site, rel=""):
    """列目录 → {path, abs, items[]}；符号链接只展示不跟随（点进去会被 realpath 校验挡住）"""
    d, err = site_resolve_path(site, rel)
    if err:
        return None, err
    if not os.path.isdir(d):
        return None, "目录不存在"
    items = []
    for name in os.listdir(d):
        fp = os.path.join(d, name)
        try:
            st = os.lstat(fp)
            is_link = os.path.islink(fp)
            is_dir = os.path.isdir(fp) and not is_link
            items.append({
                "name": name,
                "dir": is_dir,
                "link": is_link,
                "size": 0 if is_dir else st.st_size,
                "mtime": int(st.st_mtime),
                "mode": oct(st.st_mode & 0o777)[2:],
                "editable": (not is_dir) and (not is_link) and site_editable(name, st.st_size),
            })
        except OSError:
            continue
    items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return {"path": (rel or "").strip().strip("/"), "abs": d, "items": items}, None


def site_chown_www(p, mode=None):
    """把站点内的文件/目录属主交给 www-data（root 运行时），确保 nginx 可读"""
    if os.geteuid() != 0:
        return
    try:
        import pwd
        u = pwd.getpwnam("www-data")
        os.chown(p, u.pw_uid, u.pw_gid)
        if mode:
            os.chmod(p, mode)
    except Exception:
        pass


def site_write_file(site, rel, content, overwrite=True):
    """写入/新建站点内文件（限文本白名单 + 2MB）"""
    if not isinstance(content, str):
        return False, "内容格式错误"
    if len(content.encode("utf-8", "replace")) > SITE_EDIT_MAX_BYTES:
        return False, f"内容超过 {SITE_EDIT_MAX_BYTES // 1024 // 1024}MB 上限"
    name = os.path.basename((rel or "").replace("\\", "/").rstrip("/"))
    if not name:
        return False, "请指定文件名"
    if not site_editable(name):
        return False, "该类型文件不支持在线编辑（可在文件列表里下载后修改再上传）"
    p, err = site_resolve_path(site, rel)
    if err:
        return False, err
    if os.path.isdir(p):
        return False, "目标是目录"
    if os.path.islink(p):
        return False, "拒绝写入符号链接（防逃逸）"
    if not overwrite and os.path.exists(p):
        return False, "文件已存在"
    parent = os.path.dirname(p)
    if not os.path.isdir(parent):
        return False, "上级目录不存在"
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        site_chown_www(p, 0o644)
    except OSError as e:
        return False, f"写入失败: {e}"
    return True, f"已保存 {name}"


def site_mkdir(site, rel):
    p, err = site_resolve_path(site, rel)
    if err:
        return False, err
    if os.path.exists(p):
        return False, "同名文件/目录已存在"
    try:
        os.makedirs(p)
        site_chown_www(p, 0o755)
    except OSError as e:
        return False, f"创建目录失败: {e}"
    return True, "目录已创建"


def site_delete_path(site, rel, recursive=False):
    """删除站点内文件/目录；站点根目录禁止删除"""
    p, err = site_resolve_path(site, rel)
    if err:
        return False, err
    root = os.path.realpath(site["root"])
    if p == root:
        return False, "站点根目录不能删除"
    if not os.path.exists(p) and not os.path.islink(p):
        return False, "文件不存在"
    try:
        if os.path.islink(p) or os.path.isfile(p):
            os.remove(p)
        elif recursive:
            shutil.rmtree(p)
        else:
            os.rmdir(p)
    except OSError as e:
        return False, f"删除失败: {e}（目录非空需勾选递归删除）"
    return True, f"已删除 {os.path.basename(p)}"


def site_rename(site, rel, new_name):
    """重命名站点内文件/目录"""
    src, err = site_resolve_path(site, rel)
    if err:
        return False, err
    new_name = (new_name or "").strip().replace("\\", "/")
    if not new_name or "/" in new_name or new_name in (".", ".."):
        return False, "新名称不合法（只能是文件名）"
    if os.path.realpath(site["root"]) == src:
        return False, "站点根目录不能重命名"
    dst = os.path.join(os.path.dirname(src), new_name)
    if not os.path.realpath(dst).startswith(os.path.realpath(site["root"]) + os.sep):
        return False, "路径越界"
    if os.path.exists(dst):
        return False, "目标名称已存在"
    try:
        os.rename(src, dst)
    except OSError as e:
        return False, f"重命名失败: {e}"
    return True, f"已重命名为 {new_name}"


def site_chmod(site, rel, mode):
    """改权限（仅站点目录内；mode 形如 644 / 755）"""
    p, err = site_resolve_path(site, rel)
    if err:
        return False, err
    m = str(mode or "").strip()
    if not re.fullmatch(r"[0-7]{3,4}", m):
        return False, "权限格式无效（如 644 / 755）"
    try:
        os.chmod(p, int(m, 8))
    except OSError as e:
        return False, f"修改权限失败: {e}"
    return True, f"权限已改为 {m}"


def site_unzip(site, rel):
    """解压站点内 zip（防护：条目路径必须在站点目录内、拒绝符号链接、限制解压后总量）"""
    import zipfile
    p, err = site_resolve_path(site, rel)
    if err:
        return False, err
    if not os.path.isfile(p) or not p.lower().endswith(".zip"):
        return False, "请选择一个 .zip 文件"
    root = os.path.realpath(site["root"])
    dest = os.path.dirname(p)
    try:
        with zipfile.ZipFile(p) as zf:
            total = 0
            entries = []
            for info in zf.infolist():
                name = info.filename
                if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                    return False, f"压缩包内含非法路径条目：{name}"
                total += info.file_size
                if total > SITE_UNZIP_MAX_BYTES:
                    return False, f"解压后总量超过 {SITE_UNZIP_MAX_BYTES // 1024 // 1024}MB 上限"
                target = os.path.realpath(os.path.join(dest, name))
                if target != dest and not target.startswith(dest + os.sep):
                    return False, f"条目超出站点目录：{name}"
                entries.append((info, target))
            for info, target in entries:
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                site_chown_www(target, 0o644)
    except zipfile.BadZipFile:
        return False, "不是有效的 zip 文件"
    except OSError as e:
        return False, f"解压失败: {e}"
    return True, "解压完成"


def site_read_file(site, rel):
    """读取站点内文本文件（在线编辑用）"""
    p, err = site_resolve_path(site, rel)
    if err:
        return None, err
    if os.path.isdir(p):
        return None, "目标是目录，不是文件"
    if not os.path.isfile(p) or os.path.islink(p):
        return None, "文件不存在"
    try:
        size = os.path.getsize(p)
    except OSError as e:
        return None, f"读取失败: {e}"
    if not site_editable(os.path.basename(p), size):
        return None, "该类型/大小不支持在线编辑"
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), None
    except OSError as e:
        return None, f"读取失败: {e}"


def site_tail_log(site, kind="access", lines=200):
    """读取站点日志尾部（只读尾部 256KB，避免大文件全量进内存）"""
    ap, ep = site_log_paths(site)
    path = ap if kind == "access" else ep
    lines = max(1, min(int(lines or 200), 5000))
    for cand in (path, path + ".1"):
        if not os.path.isfile(cand):
            continue
        try:
            size = os.path.getsize(cand)
            with open(cand, "rb") as f:
                if size > SITE_LOG_TAIL_BYTES:
                    f.seek(size - SITE_LOG_TAIL_BYTES)
                    f.readline()          # 丢掉可能被截断的半行
                data = f.read().decode("utf-8", "replace")
        except OSError as e:
            return None, f"读取日志失败: {e}"
        rows = [ln for ln in data.splitlines() if ln.strip()]
        return {"kind": kind, "file": cand, "lines": rows[-lines:], "rotated": cand.endswith(".1")}, None
    return {"kind": kind, "file": path, "lines": [], "rotated": False}, None


def site_stats(site, days=7):
    """解析站点 access.log → 今日/昨日/近 N 天 PV、UV（IP 去重）、Top URL、状态码分布"""
    import collections
    ap, _ = site_log_paths(site)
    days = max(1, min(int(days or 7), 30))
    today = datetime.date.today()
    day_keys = [(today - datetime.timedelta(days=i)).strftime("%d/%b/%Y") for i in range(days)]
    pv = {k: 0 for k in day_keys}
    ipset = {k: set() for k in day_keys}
    urls = collections.Counter()
    codes = collections.Counter()
    total_lines = 0
    max_lines = 200000                     # 单次解析上限，防超大日志拖死面板
    files = [ap]
    for i in range(1, 4):                  # 兼容 logrotate
        cand = f"{ap}.{i}"
        if os.path.isfile(cand):
            files.append(cand)
    for path in reversed(files):           # 老的轮转文件先看
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    total_lines += 1
                    if total_lines > max_lines:
                        break
                    m = _ACCESS_RE.match(line)
                    if not m:
                        continue
                    ts = m.group("t").split(":")[0]      # dd/Mon/yyyy
                    if ts not in pv:
                        continue
                    ip = m.group("ip")
                    pv[ts] += 1
                    ipset[ts].add(ip)
                    req = m.group("req").split(" ")
                    if len(req) >= 2:
                        urls[req[1][:120]] += 1
                    codes[m.group("status")] += 1
        except OSError:
            continue
        if total_lines > max_lines:
            break
    d_today = today.strftime("%d/%b/%Y")
    d_yest = (today - datetime.timedelta(days=1)).strftime("%d/%b/%Y")
    return {
        "today": {"pv": pv.get(d_today, 0), "uv": len(ipset.get(d_today, ()))},
        "yesterday": {"pv": pv.get(d_yest, 0), "uv": len(ipset.get(d_yest, ()))},
        "days": [{"date": k, "pv": pv[k], "uv": len(ipset[k])} for k in day_keys],
        "sum_pv": sum(pv.values()),
        "top_urls": urls.most_common(8),
        "codes": codes.most_common(8),
        "log_file": ap,
        "exists": os.path.isfile(ap),
        "truncated": total_lines > max_lines,
    }


def render_site_conf(s):
    """站点 nginx server block：静态站含 ACME 挑战路径 / 强制跳转 / Host 守卫 / 分站日志；
    端口站只监听指定端口（无域名场景）。"""
    domain = (s.get("domain") or "").strip()
    root = s.get("root") or DEFAULT_SITE_ROOT
    ssl_on, ssl_fc, ssl_key = (False, None, None)
    if domain and s.get("cert_mode") == "auto":
        ssl_on, ssl_fc, ssl_key = _proxy_cert(domain, s.get("cert_ref"))
    force = bool(s.get("force_https")) and ssl_on
    guard = host_guard(domain) if (domain and s.get("block_ip")) else ""
    log_name = site_log_name(s)
    acc = f"/var/log/nginx/{log_name}.access.log"
    err = f"/var/log/nginx/{log_name}.error.log"

    def body(ind="    "):
        return [
            ind + f"root {root};",
            ind + "index index.html index.htm;",
            ind + "location / { try_files $uri $uri/ =404; }",
            ind + f"access_log {acc};",
            ind + f"error_log {err};",
        ]

    head = "# FW-Panel2 网站: " + (domain or ("端口 " + str(s.get("port"))))
    lines = [head]
    if not domain:
        lines.append("server {")
        lines.append(f"    listen {int(s.get('port', 8080))};")
        lines.append("    server_name _;")
        lines += body()
        lines.append("}")
    else:
        lines.append("server {")
        lines.append("    listen 80;")
        lines.append(f"    server_name {domain};")
        lines.append(f"    location /.well-known/acme-challenge/ {{ root {ACME_WEBROOT}; }}")
        if guard:
            lines.extend(x for x in guard.splitlines() if x)
        if force:
            lines.append("    location / { return 301 https://$host$request_uri; }")
        else:
            lines += body()
        lines.append("}")
        if ssl_on:
            lines.append("server {")
            lines.append("    listen 443 ssl;")
            lines.append(f"    server_name {domain};")
            lines.append(f"    ssl_certificate {ssl_fc};")
            lines.append(f"    ssl_certificate_key {ssl_key};")
            if guard:
                lines.extend(x for x in guard.splitlines() if x)
            lines += body()
            lines.append("}")
    return "\n".join(lines) + "\n"


def apply_all_nginx(pstore, sstore, cfg=None):
    """nginx 配置唯一渲染出口：反代(fwpanel-<id>.conf) + 站点(fwsite-<id>.conf)
    → nginx -t 校验 → reload；校验失败自动回滚本次改动（旧配置继续提供服务）"""
    if DRY_RUN:
        log("[dry-run] 生成 nginx 配置（反代+站点，跳过写入/reload）")
        return True, "dry-run"
    conf_dir = nginx_conf_dir()
    if not conf_dir:
        return False, "未找到 nginx 配置目录（未安装 nginx？）"
    # 确保默认兜底配置正确（default_server 接管未匹配请求，禁止 IP 直连）
    ensure_nginx_default()
    before = {}

    def _read(path):
        with open(path) as f:
            return f.read()

    def _write(path, content):
        if path not in before:
            before[path] = _read(path) if os.path.exists(path) else None
        with open(path, "w") as f:
            f.write(content)

    def _remove(path):
        if os.path.exists(path):
            before.setdefault(path, _read(path))
            os.remove(path)

    def _rollback():
        for path, old in before.items():
            try:
                if old is None:
                    if os.path.exists(path):
                        os.remove(path)
                else:
                    with open(path, "w") as f:
                        f.write(old)
            except OSError:
                pass

    try:
        for p in pstore.proxies:
            conf = os.path.join(conf_dir, proxy_conf_name(p["id"]))
            if p.get("enabled", True):
                _write(conf, render_proxy_conf(p))
            else:
                _remove(conf)
        for s in sstore.sites:
            conf = os.path.join(conf_dir, site_conf_name(s["id"]))
            if s.get("enabled", True):
                _write(conf, render_site_conf(s))
            else:
                _remove(conf)
        # 清理失效配置：只认「前缀 + 12 位 hex id」，兜底配置等非此形状文件一律不动
        valid = {proxy_conf_name(p["id"]) for p in pstore.proxies if p.get("enabled", True)}
        valid |= {site_conf_name(s["id"]) for s in sstore.sites if s.get("enabled", True)}
        for fn in os.listdir(conf_dir):
            if not fn.endswith(".conf"):
                continue
            for prefix in (PROXY_CONF_PREFIX, SITE_CONF_PREFIX):
                mid = fn[len(prefix):-len(".conf")] if fn.startswith(prefix) else ""
                if mid and CONF_ID_RE.match(mid):
                    if fn not in valid:
                        _remove(os.path.join(conf_dir, fn))
                    break
    except OSError as e:
        _rollback()
        return False, f"写入配置失败: {e}"
    try:
        r = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        _rollback()
        return False, "nginx 不可用（未安装）"
    if r.returncode != 0:
        _rollback()
        # 回滚后重载一次，确保运行中的配置回到改动前
        try:
            subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
        except Exception:
            pass
        return False, f"nginx 配置校验失败（已回滚）: {(r.stderr or r.stdout).strip()[:300]}"
    subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
    return True, "nginx 已重载"


def apply_proxies(store):
    """兼容旧调用点：统一渲染（反代 + 站点一次生成，避免两套渲染互相覆盖/误删）"""
    return apply_all_nginx(store, SiteStore(), None)


def _ensure_http01_port(store):
    """v1.25.8：HTTP-01 证书申请前幂等放行 80（certbot webroot 挑战需公网可达 80）。

    保留不收回：certbot 自动续期走同样的 webroot 验证，收回会导致续期静默失败。
    只在 HTTP-01（issue_cert）触发；DNS 验证（issue_cert_dns）不涉及。"""
    if any(r.get("type") == "port_allow" and r.get("port") == 80
           for r in store.rules):
        return False
    store.add({"type": "port_allow", "proto": "tcp", "port": 80,
               "comment": "ACME:HTTP-01"})
    store.save()
    return True


def issue_cert(domain, email):
    """certbot 申请证书（webroot 方式，需 80 端口公网可达）"""
    if not certbot_available():
        return False, "未安装 certbot，请先安装（apt install certbot / pacman -S certbot / dnf install certbot）"
    # v1.25.8：HTTP-01 挑战前自动放行 80——严格模式（policy drop）下
    # 面板自己的防火墙会挡死 webroot 验证（2026-08-26 用户实测申请失败）
    store = RuleStore()
    if _ensure_http01_port(store):
        NFTManager(store, Config()).apply()
        log("[issue_cert] 已自动放行 80 端口（ACME:HTTP-01 挑战）")
    try:
        os.makedirs(ACME_WEBROOT, exist_ok=True)
        cmd = ["certbot", "certonly", "--webroot", "-w", ACME_WEBROOT,
               "-d", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring"]
        if email:
            cmd += ["-m", email]
        else:
            cmd += ["--register-unsafely-without-email"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return False, "certbot 不可用"
    except subprocess.TimeoutExpired:
        return False, "证书申请超时（180 秒）：80 已自动放行，仍失败请检查云厂商安全组是否放行 80"
    if r.returncode != 0:
        return False, f"证书申请失败（80 已自动放行，仍失败请检查云厂商安全组/80 是否被占用）: {(r.stderr or r.stdout).strip()[:250]}"
    return True, "证书已签发"


def acme_available():
    """acme.sh 是否已安装"""
    return os.path.exists(ACME_SH)


def install_acme_sh():
    """安装 acme.sh（~/.acme.sh，root 用户；自带自动续期 cron）。

    ⚠ systemd 服务环境可能缺 HOME/PATH（v1.25.3 加固：显式补全，失败原因写面板日志，
    不再静默返回 False——此前用户报"acme.sh 安装失败"但手动执行却成功，无法定位）。"""
    env = dict(os.environ)
    env.setdefault("HOME", os.path.expanduser("~"))
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    try:
        r = subprocess.run(["curl", "-fsSL", "https://get.acme.sh"],
                           capture_output=True, text=True, timeout=60, env=env)
        if r.returncode != 0:
            log(f"acme.sh 安装失败: curl 下载 rc={r.returncode} err={(r.stderr or '')[:200]}")
            return False
        r2 = subprocess.run(["sh"], input=r.stdout, capture_output=True, text=True, timeout=120, env=env)
        ok = r2.returncode == 0 and acme_available()
        if not ok:
            log(f"acme.sh 安装失败: 安装脚本 rc={r2.returncode} 输出={(r2.stdout or r2.stderr or '')[-400:]}")
        return ok
    except Exception as e:
        log(f"acme.sh 安装异常: {type(e).__name__}: {e}")
        return False


def issue_cert_dns(domain, email, provider, creds):
    """acme.sh DNS 验证申请证书（Cloudflare/DNSPod/阿里云），证书装到 LE_LIVE 与 certbot 同路径。

    凭证经环境变量传入（acme.sh 会自动持久化到 ~/.acme.sh/account.conf 供自动续期使用），
    面板不落盘凭证文件、API 不回显。"""
    prov = DNS_PROVIDERS.get(provider)
    if not prov:
        return False, f"不支持的 DNS 提供商: {provider}（支持: {', '.join(DNS_PROVIDERS)}）"
    if not acme_available() and not install_acme_sh():
        return False, "acme.sh 安装失败，请手动执行: curl https://get.acme.sh | sh"
    env = dict(os.environ)
    missing = []
    for key, label in prov["fields"]:
        val = str(creds.get(key) or "").strip()
        if not val:
            missing.append(label)
        else:
            env[key] = val
    if missing:
        return False, f"缺少凭证: {'、'.join(missing)}"
    if email:
        env["ACME_EMAIL"] = email
    os.makedirs(f"{LE_LIVE}/{domain}", exist_ok=True)
    try:
        cmd = [ACME_SH, "--issue", "-d", domain, "--dns", prov["dns"],
               "--server", "letsencrypt", "--force"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
        if r.returncode != 0:
            # 完整报错（v1.25.4：不再截断，acme.sh 的失败原因对排查至关重要）
            return False, f"证书申请失败: {(r.stderr or r.stdout).strip()}"
        install = [ACME_SH, "--install-cert", "-d", domain,
                   "--fullchain-file", f"{LE_LIVE}/{domain}/fullchain.pem",
                   "--key-file", f"{LE_LIVE}/{domain}/privkey.pem",
                   "--reloadcmd", "nginx -s reload || true"]
        r2 = subprocess.run(install, capture_output=True, text=True, timeout=60, env=env)
        if r2.returncode != 0:
            return False, f"证书已签发但安装失败: {(r2.stderr or r2.stdout).strip()}"
    except FileNotFoundError:
        return False, "acme.sh 不可用"
    except subprocess.TimeoutExpired:
        return False, "DNS 证书申请超时（300 秒）"
    return True, "证书已签发（DNS 验证）"


def renew_cert_dns(domain):
    """手动续期 DNS 验证的证书（acme.sh --renew），续期后自动重装证书 + reload nginx"""
    if not acme_available():
        return False, "acme.sh 未安装"
    try:
        r = subprocess.run([ACME_SH, "--renew", "-d", domain, "--force"],
                           capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return False, "acme.sh 不可用"
    except subprocess.TimeoutExpired:
        return False, "续期超时（5 分钟）"
    if r.returncode != 0:
        return False, f"续期失败: {(r.stderr or r.stdout).strip()[:300]}"
    return True, "证书已续期（DNS 验证）"


def renew_cert(domain):
    """手动续期证书（强制 renewal）并重载 nginx"""
    if not certbot_available():
        return False, "未安装 certbot"
    try:
        r = subprocess.run(["certbot", "renew", "--cert-name", domain, "--force-renewal",
                            "--non-interactive"], capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return False, "certbot 不可用"
    except subprocess.TimeoutExpired:
        return False, "续期超时（5 分钟）"
    if r.returncode != 0:
        return False, f"续期失败: {(r.stderr or r.stdout).strip()[:300]}"
    if nginx_available():
        subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
    return True, "证书已续期，nginx 已重载"


def pkg_mgr():
    """检测系统包管理器：apt / pacman / dnf"""
    try:
        info = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v.strip('"')
        did = info.get("ID", "")
        if did in ("debian", "ubuntu"):
            return "apt"
        if did in ("arch", "manjaro", "endeavouros"):
            return "pacman"
        if did in ("fedora", "centos", "rocky", "alma", "rhel"):
            return "dnf"
    except Exception:
        pass
    for m in ("apt-get", "pacman", "dnf"):
        if shutil.which(m):
            return m
    return None


def install_pkgs(pkgs):
    """按发行版自动安装系统包（apt-get / pacman / dnf）"""
    mgr = pkg_mgr()
    if not mgr:
        return False, "无法识别包管理器，请手动安装: " + " ".join(pkgs)
    try:
        if mgr == "apt":
            r = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, f"apt-get update 失败: {(r.stderr or r.stdout).strip()[:200]}"
            r = subprocess.run(["apt-get", "install", "-y"] + pkgs,
                               capture_output=True, text=True, timeout=600)
        elif mgr == "pacman":
            r = subprocess.run(["pacman", "-Sy", "--noconfirm"] + pkgs,
                               capture_output=True, text=True, timeout=600)
        else:  # dnf
            r = subprocess.run(["dnf", "install", "-y"] + pkgs,
                               capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return False, f"{mgr} 不可用"
    except subprocess.TimeoutExpired:
        return False, "安装超时（10 分钟）"
    if r.returncode != 0:
        return False, f"安装失败: {(r.stderr or r.stdout).strip()[:300]}"
    return True, f"已安装: {' '.join(pkgs)}"


# ============================ Web 终端（v2.1.19） ============================
# 安全模型（用户确认 2026-09）：
# 1. 打开终端 ≠ 自动 root：PTY 降权到专用低权用户 term（不存在时创建/提示）
# 2. 终端内凭据（用户名/密码/密钥）由用户自己输入，面板不代管不落盘
# 3. 密钥辅助：只列面板机 ~/.ssh 下私钥路径生成 ssh -i 命令，不读取内容
# 4. 仅本机 Web 登录可开终端；远程节点终端经联邦中继（节点端也降权 term）
# 5. 连接关闭即销毁 PTY；并发连接数限流；审计日志
TERM_USER = "term"                # PTY 降权用户
TERM_SHELL = "/bin/bash"
# zsh 语法高亮（v2.1.24）：登录 shell 升级 zsh + zsh-syntax-highlighting，路径多发行版探测
ZSH_HL_PATHS = (
    "/usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh",
    "/usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh",
    "/usr/local/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh",
)
_TERM_SETUP_LOCK = threading.Lock()
_TERM_SETUP_DONE = False
TERM_MAX_CONNS = 8                # 并发终端上限
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_term_conns = 0
_term_conns_lock = threading.Lock()


def ws_accept_key(key):
    """RFC6455 Sec-WebSocket-Accept = base64(sha1(key + GUID))"""
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_encode_frame(payload, opcode=0x1):
    """服务端→客户端帧（不掩码）。opcode: 1=text 2=binary 8=close 9=ping 0xA=pong"""
    if isinstance(payload, str):
        payload = payload.encode()
    hdr = bytearray([0x80 | opcode])   # FIN=1
    n = len(payload)
    if n < 126:
        hdr.append(n)
    elif n < 65536:
        hdr.append(126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(127)
        hdr += struct.pack(">Q", n)
    return bytes(hdr) + payload


def ws_encode_frame_client(payload, opcode=0x1):
    """客户端→服务端帧（RFC6455 客户端帧必须掩码）。中继主控对节点用。"""
    if isinstance(payload, str):
        payload = payload.encode()
    mask_key = secrets.token_bytes(4)
    hdr = bytearray([0x80 | opcode])
    n = len(payload)
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127)
        hdr += struct.pack(">Q", n)
    hdr += mask_key
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return bytes(hdr) + masked


def ws_read_frame(rfile):
    """从 buffered reader 读一帧（客户端→服务端，需解掩码）。返回 (opcode, payload)。
    连接关闭返回 (None, None)。"""
    hdr = _ws_read_exact(rfile, 2)
    if hdr is None:
        return None, None
    b0, b1 = hdr[0], hdr[1]
    opcode = b0 & 0x0F
    masked = b1 & 0x80
    ln = b1 & 0x7F
    if ln == 126:
        ext = _ws_read_exact(rfile, 2)
        if ext is None:
            return None, None
        ln = struct.unpack(">H", ext)[0]
    elif ln == 127:
        ext = _ws_read_exact(rfile, 8)
        if ext is None:
            return None, None
        ln = struct.unpack(">Q", ext)[0]
    mask_key = b""
    if masked:
        mask_key = _ws_read_exact(rfile, 4)
        if mask_key is None:
            return None, None
    payload = _ws_read_exact(rfile, ln) if ln else b""
    if payload is None:
        return None, None
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def _ws_read_exact(rfile, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = rfile.read(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def ws_client_connect(url, token, timeout=15):
    """作为 WS 客户端连接 url（http:// 或 https://），带 X-Fwpanel-Token。
    成功返回 (sock, rfile)；失败抛异常。rfile 用 makefile 便于 read。"""
    from urllib.parse import urlparse as _up
    u = _up(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme: " + u.scheme)
    port = u.port or (443 if u.scheme == "https" else 80)
    host = u.hostname or ""
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = raw
    if u.scheme == "https":
        import ssl
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    req = (
        f"GET {u.path or '/'} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"{FED_HEADER}: {token}\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    rfile = sock.makefile("rb")
    # 读响应行 + 头
    status_line = rfile.readline()
    if not status_line or b" 101 " not in status_line:
        raise ConnectionError("upgrade refused: %r" % (status_line or b"<empty>"))
    while True:
        line = rfile.readline()
        if line in (b"\r\n", b"\n", b""):
            break
    # v2.1.31：握手成功后清残留超时——create_connection(timeout=15) 的超时
    # 会一直挂在 socket 上，中继读线程空闲 15s 即被 socket.timeout 掐断
    # （_ws_read_exact 把超时当连接关闭）→ 远程终端空闲约 15s 断开。
    # 连接阶段 15s 保护保留，长连阶段必须转阻塞，心跳由协议层 25s ping 负责。
    try:
        sock.settimeout(None)
    except Exception:
        pass
    return sock, rfile


def _term_zshrc_content(hl_path=""):
    """term 用户 .zshrc：语法高亮 + 简洁路径提示符。hl_path 为空则不含高亮段。"""
    lines = [
        "# FW-Panel2 Web 终端自动配置 (v2.1.24)",
        "# 语法高亮 zsh-syntax-highlighting + 简洁提示符；手工改动请保留 source 行",
    ]
    if hl_path:
        lines += [
            f"source {hl_path}",
            "# —— 语法高亮配色（跟随默认深色终端）——",
            "ZSH_HIGHLIGHT_STYLES[command]=fg=blue,bold",
            "ZSH_HIGHLIGHT_STYLES[alias]=fg=blue,bold",
            "ZSH_HIGHLIGHT_STYLES[builtin]=fg=blue,bold",
            "ZSH_HIGHLIGHT_STYLES[function]=fg=blue,bold",
            "ZSH_HIGHLIGHT_STYLES[path]=fg=green,underline",
            "ZSH_HIGHLIGHT_STYLES[globbing]=fg=magenta,bold",
            "ZSH_HIGHLIGHT_STYLES[history-expansion]=fg=magenta,bold",
            "ZSH_HIGHLIGHT_STYLES[single-hyphen-option]=fg=yellow",
            "ZSH_HIGHLIGHT_STYLES[double-hyphen-option]=fg=yellow",
            "ZSH_HIGHLIGHT_STYLES[comment]=fg=cyan",
            "ZSH_HIGHLIGHT_STYLES[default]=none",
        ]
    lines += [
        "",
        "# —— 提示符：user@host 目录 ——",
        "setopt prompt_subst",
        'PROMPT="%F{cyan}%n@%m%f %F{green}%~%f %F{white}❯%f "',
        "",
    ]
    return "\n".join(lines) + "\n"


def _term_prepare_zsh(home_dir, uid, gid, timeout=240):
    """为 term 用户配置 zsh 语法高亮：
    1) 探测 zsh / 高亮插件，缺失时用发行版包管理器安装（apt/pacman/dnf）
    2) 写 .zshrc（高亮 + 提示符），chown term
    返回 (ok, msg)。仅 root 调用；任何失败都回落 bash 不影响终端可用。"""
    import shutil as _sh
    zsh = _sh.which("zsh")
    hl = next((p for p in ZSH_HL_PATHS if os.path.isfile(p)), "")
    if not zsh:
        try:
            dist = (detect_distro() or "").lower()
            if "arch" in dist:
                subprocess.run(["pacman", "-S", "--noconfirm", "--needed", "zsh"],
                               capture_output=True, text=True, timeout=timeout)
            elif "fedora" in dist or "centos" in dist or "rhel" in dist or "rocky" in dist or "alma" in dist:
                subprocess.run(["dnf", "install", "-y", "zsh"],
                               capture_output=True, text=True, timeout=timeout)
            else:  # Debian/Ubuntu 及默认
                subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=timeout)
                subprocess.run(["apt-get", "install", "-y", "zsh"],
                               capture_output=True, text=True, timeout=timeout)
            zsh = _sh.which("zsh")
        except Exception as e:
            log(f"[term] zsh 安装失败（回落 bash）: {e}")
            return False, "zsh 安装失败"
    if not hl:
        try:
            dist = (detect_distro() or "").lower()
            if "arch" in dist:
                subprocess.run(["pacman", "-S", "--noconfirm", "--needed", "zsh-syntax-highlighting"],
                               capture_output=True, text=True, timeout=timeout)
            elif "fedora" in dist or "centos" in dist or "rhel" in dist:
                subprocess.run(["dnf", "install", "-y", "zsh-syntax-highlighting"],
                               capture_output=True, text=True, timeout=timeout)
            else:
                subprocess.run(["apt-get", "install", "-y", "zsh-syntax-highlighting"],
                               capture_output=True, text=True, timeout=timeout)
            hl = next((p for p in ZSH_HL_PATHS if os.path.isfile(p)), "")
        except Exception as e:
            log(f"[term] zsh-syntax-highlighting 安装失败: {e}")
    try:
        os.makedirs(home_dir, exist_ok=True)
        zshrc = os.path.join(home_dir, ".zshrc")
        with open(zshrc, "w", encoding="utf-8") as f:
            f.write(_term_zshrc_content(hl))
        try:
            os.chown(home_dir, uid, gid)
            os.chown(zshrc, uid, gid)
        except Exception:
            pass
        if hl:
            log(f"[term] zsh 语法高亮就绪: {hl}")
        else:
            log("[term] zsh 已装但高亮插件不可用（回落无高亮）")
        return bool(hl), "ok"
    except Exception as e:
        log(f"[term] .zshrc 写入失败: {e}")
        return False, "zshrc 写入失败"


def _term_ensure_zsh_async(home_dir, uid, gid):
    """后台准备 zsh 语法高亮（只跑一次，不阻塞终端打开）。"""
    global _TERM_SETUP_DONE
    if _TERM_SETUP_DONE:
        return
    with _TERM_SETUP_LOCK:
        if _TERM_SETUP_DONE:
            return
        _TERM_SETUP_DONE = True
    def _worker():
        try:
            _term_prepare_zsh(home_dir, uid, gid)
        except Exception as e:
            log(f"[term] zsh 准备异常: {e}")
    threading.Thread(target=_worker, daemon=True).start()


def _term_ensure_user():
    """确保低权用户 term 存在。root 下自动创建；非 root 且缺失返回 False。"""
    try:
        import pwd
        pwd.getpwnam(TERM_USER)
        return True
    except KeyError:
        pass
    if os.geteuid() != 0:
        return False
    try:
        subprocess.run(["useradd", "-m", "-s", TERM_SHELL, "-U", TERM_USER],
                       capture_output=True, text=True, timeout=30)
        import pwd
        pwd.getpwnam(TERM_USER)
        log(f"[term] 已创建低权用户 {TERM_USER}")
        return True
    except Exception as e:
        log(f"[term] 创建用户失败: {e}")
        return False


def _term_login_shell():
    """term 登录 shell：zsh 已装则优先（语法高亮 v2.1.24），否则 bash。仅 root/生产环境。"""
    if os.geteuid() == 0:
        z = shutil.which("zsh")
        if z:
            return z
    return TERM_SHELL


def _term_spawn_pty(rows=24, cols=80):
    """fork PTY 会话：以 term 低权用户跑 shell（zsh 优先，语法高亮）。返回 (master_fd, proc)。
    非 root 环境（测试/DRY_RUN）退回当前用户，便于本地验证。"""
    import pty
    import fcntl
    import termios
    import struct as _st
    shell = _term_login_shell()
    pid, master_fd = pty.fork()
    if pid == 0:
        # 子进程：降权到 term
        try:
            import pwd
            pw = pwd.getpwnam(TERM_USER)
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            os.environ["HOME"] = pw.pw_dir
            os.environ["USER"] = TERM_USER
            os.environ["LOGNAME"] = TERM_USER
            os.environ["SHELL"] = shell
        except Exception:
            pass  # 非 root/测试环境：保持当前用户
        # v2.1.26：必须显式给 TERM——systemd 服务环境 TERM 为空，
        # zsh 行编辑(zle)在 dumb/空 TERM 下击键重绘错乱（输入乱跳）；bash readline 容忍才未暴露
        if not os.environ.get("TERM") or os.environ.get("TERM") in ("dumb", "unknown"):
            os.environ["TERM"] = "xterm-256color"
        try:
            os.execv(shell, [shell, "-l"])
        except Exception:
            os.execv(TERM_SHELL, [TERM_SHELL, "-l"])
        os._exit(1)
    # 父进程：立刻设置 PTY 窗口尺寸（pty.fork 新建时 winsize 全 0，
    # zsh 启动读到 0 行 0 列 → 提示符/行编辑错乱）。后续前端 resize 帧会覆盖。
    try:
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                    _st.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass
    return master_fd, pid


def _term_audit(event, peer=""):
    """终端审计日志"""
    log(f"[term] {event} {peer}")


def _cleanup_stale_term_keys():
    """启动时清理残留的临时私钥（>6h 或上次崩溃遗留）。防私钥滞留面板机。"""
    try:
        import pwd
        ssh_dir = os.path.join(pwd.getpwnam(TERM_USER).pw_dir, ".ssh")
    except Exception:
        ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
    try:
        cutoff = time.time() - 6 * 3600
        for fn in os.listdir(ssh_dir):
            if fn.startswith("fwterm_") and fn.endswith(".pem"):
                fp = os.path.join(ssh_dir, fn)
                try:
                    if os.path.getmtime(fp) < cutoff:
                        os.remove(fp)
                        _term_audit("key_stale_clean", fn)
                except Exception:
                    pass
    except Exception:
        pass


# ---------- Docker 模块（v1.24.0）----------

def docker_available():
    """检测 docker CLI 是否存在（docker 命令本身可用）"""
    return shutil.which("docker") is not None


def docker_status():
    """Docker 状态：{installed, service_active, version, containers, running, data_root}"""
    if not docker_available():
        return {"installed": False, "service_active": False,
                "version": "", "containers": 0, "running": 0,
                "data_root": "", "compose_version": ""}
    version = ""
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            version = (r.stdout or r.stderr).strip()
    except Exception:
        pass
    service_active = False
    try:
        r = subprocess.run(["systemctl", "is-active", "docker"],
                           capture_output=True, text=True, timeout=10)
        service_active = (r.returncode == 0 and (r.stdout or "").strip() == "active")
    except Exception:
        pass
    containers = running = 0
    try:
        r = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            containers = len([x for x in r.stdout.splitlines() if x.strip()])
        r2 = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True, timeout=15)
        if r2.returncode == 0:
            running = len([x for x in r2.stdout.splitlines() if x.strip()])
    except Exception:
        pass
    # 读取当前 data-root（docker info）
    data_root = ""
    try:
        ri = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"],
                            capture_output=True, text=True, timeout=15)
        if ri.returncode == 0:
            data_root = ri.stdout.strip()
    except Exception:
        pass
    # compose 版本（docker compose version，提取 vX.Y.Z）
    compose_version = ""
    try:
        rc = subprocess.run(["docker", "compose", "version"],
                            capture_output=True, text=True, timeout=10)
        if rc.returncode == 0:
            compose_version = rc.stdout.strip()
            # 精简：只保留版本号部分（如 Docker Compose version v2.29.7 → v2.29.7）
            m = re.search(r"v?\d+\.\d+\.\d+", compose_version)
            if m:
                compose_version = m.group(0)
    except Exception:
        pass
    return {"installed": True, "service_active": service_active,
            "version": version, "containers": containers, "running": running,
            "data_root": data_root, "compose_version": compose_version}


def install_docker_pkgs(source="official"):
    """一键安装 docker + compose 插件。
    source="official"：发行版官方源（docker.io / docker）
    source="china"：国内镜像源（Debian/Ubuntu 用阿里云 docker-ce 源装 docker-ce 全家桶；
                     Arch 走 pacman 官方源；Fedora/CentOS 用阿里云 docker-ce 源）
    返回 (ok, msg)"""
    if DRY_RUN:
        return True, f"DRY_RUN: 跳过安装（source={source}）"
    mgr = pkg_mgr()
    if not mgr:
        return False, "无法识别包管理器，请手动安装 Docker"
    try:
        if mgr == "apt":
            if source == "china":
                ok, msg = _setup_aliyun_docker_apt()
                if not ok:
                    return False, msg
                r = subprocess.run(["apt-get", "install", "-y",
                                    "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"],
                                   capture_output=True, text=True, timeout=600)
            else:
                r = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300)
                if r.returncode != 0:
                    return False, f"apt-get update 失败: {(r.stderr or r.stdout).strip()[:200]}"
                # 官方源没有 docker-compose-plugin（那是 docker-ce 仓库的包名）：
                # 先试 docker-compose-v2（Debian 12+/Ubuntu 22.10+），失败回退 docker-compose（老版 v1）
                r = subprocess.run(["apt-get", "install", "-y", "docker.io", "docker-compose-v2"],
                                   capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    r = subprocess.run(["apt-get", "install", "-y", "docker.io", "docker-compose"],
                                       capture_output=True, text=True, timeout=600)
        elif mgr == "pacman":
            r = subprocess.run(["pacman", "-Sy", "--noconfirm", "docker", "docker-compose"],
                               capture_output=True, text=True, timeout=600)
        elif mgr == "dnf":
            if source == "china":
                ok, msg = _setup_aliyun_docker_dnf()
                if not ok:
                    return False, msg
                r = subprocess.run(["dnf", "install", "-y", "docker-ce", "docker-ce-cli",
                                    "containerd.io", "docker-compose-plugin"],
                                   capture_output=True, text=True, timeout=600)
            else:
                # Fedora/RHEL 官方源同样没有 docker-compose-plugin：先试 v2，失败回退 v1
                r = subprocess.run(["dnf", "install", "-y", "docker", "docker-compose-v2"],
                                   capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    r = subprocess.run(["dnf", "install", "-y", "docker", "docker-compose"],
                                       capture_output=True, text=True, timeout=600)
        else:
            return False, f"不支持的包管理器: {mgr}"
    except subprocess.TimeoutExpired:
        return False, "安装超时（10 分钟）"
    if r.returncode != 0:
        return False, f"安装失败: {(r.stderr or r.stdout).strip()[:300]}"
    # 启动服务 + 开机自启
    try:
        subprocess.run(["systemctl", "enable", "--now", "docker"],
                       capture_output=True, text=True, timeout=60)
    except Exception:
        pass
    # 轮询确认 docker 服务真正 active（daemon 启动有几秒延迟，装完立即查会显示 inactive，
    # 曾导致远程装完刷新只见"服务未运行"）。上限 30s，超过则明确报错而非假成功
    for _ in range(15):
        try:
            r = subprocess.run(["systemctl", "is-active", "docker"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and (r.stdout or "").strip() == "active":
                return True, "Docker 已安装并启动（国内镜像源）" if source == "china" else "Docker 已安装并启动"
        except Exception:
            pass
        time.sleep(2)
    return False, "Docker 已安装，但服务未能启动（systemctl is-active 非 active）。请手动执行: systemctl start docker 并查看日志"


def uninstall_docker_pkgs():
    """一键卸载 Docker：停止并禁用服务，移除两种来源安装的全部 docker 相关包
    （国内 docker-ce 系列 + 国外 docker.io/docker 系列 + compose），保留 /DockerData 数据目录。
    返回 (ok, msg)"""
    if DRY_RUN:
        return True, "DRY_RUN: 跳过卸载"
    mgr = pkg_mgr()
    if not mgr:
        return False, "无法识别包管理器，请手动卸载 Docker"
    # 1. 停止并禁用服务（两种常见服务名都试）
    for svc in ("docker", "docker.socket"):
        try:
            subprocess.run(["systemctl", "stop", svc], capture_output=True, text=True, timeout=60)
            subprocess.run(["systemctl", "disable", svc], capture_output=True, text=True, timeout=60)
        except Exception:
            pass
    # 2. 移除包（一次性覆盖国内 + 国外两种来源的包名）
    try:
        if mgr == "apt":
            pkgs = ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin",
                    "docker.io", "docker-compose-v2", "docker-compose",
                    "docker-buildx-plugin", "docker-ce-rootless-extras"]
            r = subprocess.run(["apt-get", "remove", "-y", "--purge"] + pkgs,
                               capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, f"apt-get remove 失败: {(r.stderr or r.stdout).strip()[:300]}"
            r = subprocess.run(["apt-get", "autoremove", "-y", "--purge"],
                               capture_output=True, text=True, timeout=300)
        elif mgr == "pacman":
            r = subprocess.run(["pacman", "-Rns", "--noconfirm",
                                "docker", "docker-compose", "docker-compose-plugin",
                                "containerd", "docker-buildx"],
                               capture_output=True, text=True, timeout=300)
            # pacman -Rns 对不存在的包会失败，尝试移除已装的部分
            if r.returncode != 0:
                r2 = subprocess.run(["pacman", "-Rns", "--noconfirm", "docker", "docker-compose"],
                                    capture_output=True, text=True, timeout=300)
                if r2.returncode == 0:
                    r = r2
        elif mgr == "dnf":
            pkgs = ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin",
                    "docker", "docker-compose-v2", "docker-compose",
                    "docker-buildx-plugin", "docker-ce-rootless-extras"]
            r = subprocess.run(["dnf", "remove", "-y"] + pkgs,
                               capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, f"dnf remove 失败: {(r.stderr or r.stdout).strip()[:300]}"
        else:
            return False, f"不支持的包管理器: {mgr}"
    except subprocess.TimeoutExpired:
        return False, "卸载超时（5 分钟）"
    if r.returncode != 0:
        return False, f"卸载失败: {(r.stderr or r.stdout).strip()[:300]}"
    return True, "Docker 已卸载（/DockerData 数据目录已保留）"


def _setup_aliyun_docker_apt():
    """Debian/Ubuntu 配置阿里云 docker-ce 源（自动检测 codename + 架构 + gpg key）"""
    import urllib.request
    # 检测 codename（bookworm / trixie / noble ...）和架构
    codename = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_CODENAME="):
                    codename = line.strip().split("=", 1)[1].strip('"')
                    break
    except Exception:
        pass
    if not codename:
        return False, "无法检测系统 codename，请使用国外直连安装"
    arch = "amd64"
    try:
        r = subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            arch = r.stdout.strip()
    except Exception:
        pass
    if arch not in ("amd64", "arm64", "armhf", "ppc64el", "riscv64", "s390x"):
        return False, f"不支持的架构: {arch}"
    # 安装 gpg + 配置阿里云 docker-ce 源（apt-key 已废弃，用 keyrings + signed-by）
    try:
        os.makedirs("/etc/apt/keyrings", exist_ok=True)
        gpg_url = "https://mirrors.aliyun.com/docker-ce/linux/debian/gpg"
        key_path = "/etc/apt/keyrings/docker.gpg"
        r = subprocess.run(["curl", "-fsSL", gpg_url, "-o", key_path],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"下载阿里云 gpg key 失败: {(r.stderr or r.stdout).strip()[:200]}"
        # 区分 Debian / Ubuntu 的源路径
        dist = "debian"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        if line.strip().split("=", 1)[1].strip('"') == "ubuntu":
                            dist = "ubuntu"
                        break
        except Exception:
            pass
        repo_line = (f"deb [arch={arch} signed-by={key_path}] "
                     f"https://mirrors.aliyun.com/docker-ce/linux/{dist} {codename} stable")
        with open("/etc/apt/sources.list.d/docker-ce.list", "w") as f:
            f.write(repo_line + "\n")
        r = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, f"apt-get update 失败: {(r.stderr or r.stdout).strip()[:300]}"
    except Exception as e:
        return False, f"配置阿里云源失败: {e}"
    return True, ""


def _setup_aliyun_docker_dnf():
    """Fedora/CentOS/RHEL 配置阿里云 docker-ce 源（dnf config-manager）"""
    # 检测大版本
    ver = "9"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_ID="):
                    v = line.strip().split("=", 1)[1].strip('"')
                    ver = v.split(".")[0] if v else "9"
                    break
    except Exception:
        pass
    if ver not in ("7", "8", "9", "10"):
        return False, f"不支持的 CentOS/RHEL 版本: {ver}"
    try:
        r = subprocess.run(["dnf", "config-manager", "--add-repo",
                            f"https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"添加阿里云 docker-ce 源失败: {(r.stderr or r.stdout).strip()[:300]}"
        # 阿里云 repo 文件里的官方地址替换成镜像
        repo = "/etc/yum.repos.d/docker-ce.repo"
        if os.path.exists(repo):
            with open(repo) as f:
                content = f.read()
            content = content.replace("https://download.docker.com", "https://mirrors.aliyun.com/docker-ce")
            with open(repo, "w") as f:
                f.write(content)
    except Exception as e:
        return False, f"配置阿里云源失败: {e}"
    return True, ""


def docker_images():
    """镜像列表（docker images --format json），带 in_use 标记：
    对比 docker ps -a 所有容器（含停止）引用的镜像 ID，被引用 = 使用中"""
    if not docker_available():
        return []
    try:
        r = subprocess.run(["docker", "images", "--format",
                            "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return []
        # 使用中的镜像 ID 集合（docker ps -aq 拿容器 ID → inspect 拿镜像 ID，兼容短 ID 前缀）
        used_ids = set()
        try:
            rp = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True, timeout=15)
            if rp.returncode == 0:
                cids = [x.strip() for x in rp.stdout.splitlines() if x.strip()]
                if cids:
                    ri = subprocess.run(["docker", "inspect", "--format", "{{.Image}}"] + cids,
                                        capture_output=True, text=True, timeout=20)
                    if ri.returncode == 0:
                        for img in ri.stdout.splitlines():
                            img = img.strip()
                            if img.startswith("sha256:"):
                                img = img[7:]  # ⚠ inspect 返回 sha256:64位完整ID，必须去前缀再截断
                            if img:
                                used_ids.add(img[:12])
        except Exception:
            pass
        out = []
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 4:
                iid = p[0][:12]
                out.append({"id": iid, "repository": p[1],
                            "tag": p[2], "size": p[3],
                            "in_use": iid in used_ids})
        return out
    except Exception:
        return []


def docker_image_prune():
    """清理全部未使用镜像（docker image prune -f，悬空+未引用）"""
    if DRY_RUN:
        return True, "DRY_RUN: image prune"
    try:
        r = subprocess.run(["docker", "image", "prune", "-f"],
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "清理超时（5 分钟）"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    # 提取清理摘要（Total reclaimed space）
    msg = (r.stdout or r.stderr or "").strip()
    return True, f"未使用镜像已清理{'：' + msg if msg else ''}"


def docker_containers(all_=True):
    """容器列表（docker ps -a --format json）"""
    if not docker_available():
        return []
    try:
        args = ["docker", "ps", "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"]
        if all_:
            args.insert(2, "-a")
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return []
        out = []
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 4:
                running = p[3].startswith("Up")
                out.append({"id": p[0][:12], "name": p[1], "image": p[2],
                            "status": p[3], "ports": p[4] if len(p) > 4 else "",
                            "running": running})
        return out
    except Exception:
        return []


def docker_stats():
    """资源监控（docker stats --no-stream）"""
    if not docker_available():
        return []
    try:
        r = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        out = []
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 6:
                out.append({"name": p[0], "cpu": p[1], "mem": p[2],
                            "mem_pct": p[3], "net": p[4], "block": p[5]})
        return out
    except Exception:
        return []


def docker_action(act, cid):
    """容器操作：start/stop/restart/remove"""
    if DRY_RUN:
        return True, f"DRY_RUN: {act} {cid}"
    try:
        r = subprocess.run(["docker", act, cid], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "操作超时"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"容器 {act} 成功"


def docker_logs(cid, tail=200):
    """查看容器日志（最后 N 行）"""
    try:
        r = subprocess.run(["docker", "logs", "--tail", str(tail), cid],
                           capture_output=True, text=True, timeout=20)
        return r.stdout[-8000:] + (r.stderr[-2000:] if r.stderr else "")
    except Exception:
        return ""


def docker_pull(name):
    """拉取镜像"""
    if DRY_RUN:
        return True, f"DRY_RUN: pull {name}"
    try:
        r = subprocess.run(["docker", "pull", name], capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return False, "拉取超时（10 分钟）"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"镜像 {name} 拉取成功"


def docker_rmi(image_id):
    """删除镜像"""
    if DRY_RUN:
        return True, f"DRY_RUN: rmi {image_id}"
    try:
        r = subprocess.run(["docker", "rmi", "-f", image_id],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "删除超时"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"镜像 {image_id} 已删除"


def docker_create(name, image, ports="", envs=""):
    """创建容器：name/镜像/端口映射(宿:容,逗号分隔)/环境变量(KEY=V,逗号分隔)。
    自动创建 /DockerData/dockerrun/<容器名> 数据目录并挂载到容器 /data（v1.24.10）"""
    if DRY_RUN:
        return True, f"DRY_RUN: create {name} from {image}"
    args = ["docker", "run", "-d", "--name", name]
    # 自动数据卷：/DockerData/dockerrun/<name> → /data
    vol_dir = os.path.join(DOCKER_DATA_BASE, "dockerrun", name)
    try:
        os.makedirs(vol_dir, exist_ok=True)
    except Exception:
        pass
    args += ["-v", f"{vol_dir}:/data"]
    for kv in [x.strip() for x in ports.split(",") if x.strip()]:
        args += ["-p", kv]
    for kv in [x.strip() for x in envs.split(",") if x.strip()]:
        args += ["-e", kv]
    args.append(image)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "创建超时（5 分钟）"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"容器 {name} 创建成功（数据卷已挂载 {vol_dir}:/data）"


# Compose 文件根目录（/DockerData/dockercompose，env 可覆盖便于测试），
# 每个 compose 按 yml 里第一个镜像名建独立子目录
COMPOSE_FILE_LEGACY = "/etc/fwpanel/docker-compose.yml"


def _compose_dir_from_content(content):
    """从 docker-compose.yml 内容解析第一个服务镜像名，生成独立子目录名。
    找不到镜像名时回退 'default'；镜像名做安全净化（只留字母数字-_.）"""
    name = "default"
    try:
        # 匹配 services: 段内第一个 image: xxx（忽略注释行）
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("#") or ":" not in s:
                continue
            key, _, val = s.partition(":")
            if key.strip() == "image":
                img = val.strip().strip('"\'')
                if img:
                    # 去掉 tag 和仓库前缀，如 docker.io/library/nginx:latest → nginx
                    img = img.rsplit("/", 1)[-1].split(":", 1)[0]
                    img = re.sub(r"[^A-Za-z0-9_.-]", "", img)
                    if img:
                        name = img
                break
    except Exception:
        pass
    return name


def _compose_dir_name(content, folder=""):
    """确定 compose 子目录名：用户指定 folder 优先（安全净化），留空取第一个镜像名"""
    folder = (folder or "").strip()
    if folder:
        folder = re.sub(r"[^A-Za-z0-9_.-]", "", folder)
        return folder or _compose_dir_from_content(content)
    return _compose_dir_from_content(content)


def _compose_file_for(content, folder=""):
    """compose 文件路径：/DockerData/dockercompose/<目录名>/docker-compose.yml"""
    return os.path.join(COMPOSE_BASE, _compose_dir_name(content, folder), "docker-compose.yml")


def docker_compose_up(content, folder=""):
    """保存 docker-compose.yml 到 /DockerData/dockercompose/<目录名>/ 并启动。
    folder 非空用用户指定目录名（安全净化），留空自动取 yml 第一个镜像名。兼容旧路径自动迁移"""
    if DRY_RUN:
        return True, "DRY_RUN: compose up"
    try:
        compose_file = _compose_file_for(content, folder)
        d = os.path.dirname(compose_file)
        os.makedirs(d, exist_ok=True)
        # 旧路径存在且新路径不存在 → 迁移（保留旧数据目录一致）
        if os.path.exists(COMPOSE_FILE_LEGACY) and not os.path.exists(compose_file):
            try:
                shutil.copy2(COMPOSE_FILE_LEGACY, compose_file)
            except Exception:
                pass
        with open(compose_file, "w") as f:
            f.write(content)
        r = subprocess.run(["docker", "compose", "-f", compose_file,
                            "up", "-d"],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:400]
    except Exception as e:
        return False, f"Compose 启动失败: {e}"
    return True, f"Compose 启动成功（已保存到 {compose_file}）"


def docker_compose_list():
    """列出已保存的 compose 项目：扫描 /DockerData/dockercompose/*/docker-compose.yml，
    每条含 folder 名、文件路径、修改时间、运行状态（docker compose ps 是否有运行中容器）"""
    items = []
    try:
        if not os.path.isdir(COMPOSE_BASE):
            return items
        for name in sorted(os.listdir(COMPOSE_BASE)):
            f = os.path.join(COMPOSE_BASE, name, "docker-compose.yml")
            if not os.path.isfile(f):
                continue
            running = False
            try:
                r = subprocess.run(["docker", "compose", "-f", f, "ps", "-q"],
                                   capture_output=True, text=True, timeout=20)
                if r.returncode == 0 and r.stdout.strip():
                    running = True
            except Exception:
                pass
            items.append({"folder": name, "path": f,
                          "mtime": int(os.path.getmtime(f)),
                          "running": running})
    except Exception:
        pass
    return items


def docker_compose_start(folder):
    """重新启动已保存的 compose 项目（docker compose -f <项目目录>/docker-compose.yml up -d）"""
    if DRY_RUN:
        return True, f"DRY_RUN: compose start {folder}"
    folder = (folder or "").strip()
    if not folder:
        return False, "缺少项目文件夹名称"
    compose_file = os.path.join(COMPOSE_BASE, folder, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return False, f"未找到项目 {folder}（{compose_file} 不存在）"
    try:
        r = subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d"],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:400]
    except subprocess.TimeoutExpired:
        return False, "启动超时（5 分钟）"
    except Exception as e:
        return False, f"启动失败: {e}"
    return True, f"项目 {folder} 已启动"


def docker_compose_upgrade(folder):
    """升级已保存的 compose 项目：先 docker compose pull 拉最新镜像，再 up -d 重建容器"""
    if DRY_RUN:
        return True, f"DRY_RUN: compose upgrade {folder}"
    folder = (folder or "").strip()
    if not folder:
        return False, "缺少项目文件夹名称"
    compose_file = os.path.join(COMPOSE_BASE, folder, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return False, f"未找到项目 {folder}（{compose_file} 不存在）"
    try:
        # 1. 拉取最新镜像
        r = subprocess.run(["docker", "compose", "-f", compose_file, "pull"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            return False, f"拉取最新镜像失败: {(r.stderr or r.stdout).strip()[:400]}"
        # 2. 重建容器（检测到镜像变化会自动 recreate）
        r = subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            return False, f"重建容器失败: {(r.stderr or r.stdout).strip()[:400]}"
    except subprocess.TimeoutExpired:
        return False, "升级超时（10 分钟）"
    except Exception as e:
        return False, f"升级失败: {e}"
    return True, f"项目 {folder} 已升级（镜像已更新并重建）"


def docker_compose_down(folder=""):
    """停止并移除指定 compose 项目（folder 必填；兼容旧调用不带 folder 时取最新修改的）"""
    if DRY_RUN:
        return True, "DRY_RUN: compose down"
    target = ""
    folder = (folder or "").strip()
    if folder:
        candidate = os.path.join(COMPOSE_BASE, folder, "docker-compose.yml")
        if os.path.exists(candidate):
            target = candidate
    if not target:
        # 兼容：不带 folder 时扫描 /DockerData/dockercompose/*/（有多个就取最新修改的）
        try:
            if os.path.isdir(COMPOSE_BASE):
                candidates = []
                for root, dirs, files in os.walk(COMPOSE_BASE):
                    if "docker-compose.yml" in files:
                        candidates.append(os.path.join(root, "docker-compose.yml"))
                if candidates:
                    target = max(candidates, key=os.path.getmtime)
        except Exception:
            pass
    if not target:
        target = COMPOSE_FILE_LEGACY if os.path.exists(COMPOSE_FILE_LEGACY) else ""
    if not target:
        return False, "尚未保存 docker-compose.yml，请先执行「Compose 启动」"
    try:
        r = subprocess.run(["docker", "compose", "-f", target, "down"],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:400]
    except Exception as e:
        return False, f"Compose 停止失败: {e}"
    return True, f"Compose 已停止{f'（{folder}）' if folder else ''}"


# Docker 数据目录基础路径（/DockerData，env 可覆盖便于测试）
DOCKER_DATA_BASE = os.environ.get("FW_DOCKER_DATA", "/DockerData")
# 三个核心目录（v1.24.10 精简，用户要求）：
#   dockerimage   → 镜像存储（daemon.json data-root）
#   dockercompose → compose 文件（按镜像名分子目录）
#   dockerrun     → 面板创建容器的数据卷（自动挂载 /data）
DOCKER_DATA_DIRS = ["dockerimage", "dockercompose", "dockerrun"]
# daemon.json 路径（env 可覆盖便于测试）
DOCKER_DAEMON_JSON = os.environ.get("FW_DOCKER_DAEMON_JSON", "/etc/docker/daemon.json")
# Compose 文件根目录（/DockerData/dockercompose，env 可覆盖便于测试），
# 每个 compose 按 yml 里第一个镜像名建独立子目录
COMPOSE_BASE = os.environ.get("FW_COMPOSE_BASE", os.path.join(DOCKER_DATA_BASE, "dockercompose"))


def create_docker_dirs():
    """在根目录创建 /DockerData 及三个核心子目录（幂等，已存在不报错）"""
    if DRY_RUN:
        return True, f"DRY_RUN: 创建目录（{DOCKER_DATA_BASE} + {len(DOCKER_DATA_DIRS)} 个子目录）"
    created = []
    try:
        base = DOCKER_DATA_BASE
        os.makedirs(base, exist_ok=True)
        created.append(base)
        for sub in DOCKER_DATA_DIRS:
            d = os.path.join(base, sub)
            os.makedirs(d, exist_ok=True)
            created.append(d)
    except Exception as e:
        return False, f"创建目录失败: {e}"
    return True, f"已创建 {len(created)} 个目录：{DOCKER_DATA_BASE}（含 {len(DOCKER_DATA_DIRS)} 个核心子目录）"


def set_docker_data_root():
    """配置 Docker 镜像存储目录 → daemon.json data-root=/DockerData/dockerimage。
    保留 daemon.json 已有配置项（合并写入），幂等。返回 (ok, msg)"""
    if DRY_RUN:
        return True, "DRY_RUN: 配置 data-root"
    target = os.path.join(DOCKER_DATA_BASE, "dockerimage")
    try:
        # 先确保目录存在
        os.makedirs(target, exist_ok=True)
        d = os.path.dirname(DOCKER_DAEMON_JSON)
        os.makedirs(d, exist_ok=True)
        # 读已有配置合并（保留其他字段如 registry-mirrors）
        conf = {}
        if os.path.exists(DOCKER_DAEMON_JSON):
            try:
                with open(DOCKER_DAEMON_JSON) as f:
                    conf = json.load(f)
            except Exception:
                conf = {}
        conf["data-root"] = target
        tmp = DOCKER_DAEMON_JSON + ".tmp"
        with open(tmp, "w") as f:
            json.dump(conf, f, indent=2)
            f.write("\n")
        os.replace(tmp, DOCKER_DAEMON_JSON)
        # 重启 docker 使配置生效
        subprocess.run(["systemctl", "restart", "docker"],
                       capture_output=True, text=True, timeout=120)
    except Exception as e:
        return False, f"配置失败: {e}"
    return True, f"镜像存储已指向 {target}（Docker 已重启）"


def nginx_supports_reject_handshake():
    """nginx >= 1.19.4 支持 ssl_reject_handshake（未匹配 SNI 直接拒绝 TLS 握手）"""
    try:
        r = subprocess.run(["nginx", "-v"], capture_output=True, text=True, timeout=10)
        m = re.search(r"nginx/(\d+)\.(\d+)", (r.stderr or "") + (r.stdout or ""))
        if m:
            return (int(m.group(1)), int(m.group(2))) >= (1, 19)
    except Exception:
        pass
    return False


def ensure_nginx_default():
    """写入 nginx 默认兜底配置（default_server：未匹配域名一律 444 / 拒绝 TLS 握手）
    确保公网 IP 直连 80/443 无法访问到任何反代内容（禁止 IP+端口访问的根基）"""
    conf_dir = nginx_conf_dir()
    if not conf_dir or DRY_RUN:
        return
    # 禁用发行版自带默认站点：必须移出 sites-enabled 目录
    # （Debian include sites-enabled/* 不限后缀，仅改名 .bak 仍会被加载 → duplicate default_server）
    for f in ("/etc/nginx/sites-enabled/default",
              "/etc/nginx/sites-enabled/000-default"):
        if os.path.exists(f):
            target = f.replace("/sites-enabled/", "/sites-available/") + ".fwpanel-bak"
            if not os.path.isdir(os.path.dirname(target)):
                target = "/etc/fwpanel/" + os.path.basename(f) + ".fwpanel-bak"
            if not os.path.exists(target):
                try:
                    os.rename(f, target)
                    log(f"已禁用系统默认站点: {f} → {target}")
                except OSError:
                    pass
    # 升级清理：移除旧版兜底文件名变体（避免 duplicate default server 冲突）
    for f in ("00-fwpanel.conf", "fwpanel.conf"):
        p = os.path.join(conf_dir, f)
        if os.path.isfile(p):
            try:
                os.remove(p)
                log(f"已清理旧版兜底配置: {p}")
            except OSError:
                pass
    conf = os.path.join(conf_dir, "fwpanel-default.conf")
    content = ("# FW-Panel2 默认兜底\n"
               "server {\n"
               "    listen 80 default_server;\n"
               "    server_name _;\n"
               f"    location /.well-known/acme-challenge/ {{ root {ACME_WEBROOT}; }}\n"
               "    location / { return 444; }\n"
               "}\n")
    # nginx >= 1.19.4：443 未匹配 SNI 直接拒绝握手（IP 直连 443 无法访问）
    if nginx_supports_reject_handshake():
        content += ("server {\n"
                    "    listen 443 ssl default_server;\n"
                    "    ssl_reject_handshake on;\n"
                    "    server_name _;\n"
                    "}\n")
    try:
        existing = ""
        if os.path.exists(conf):
            with open(conf) as f:
                existing = f.read()
        if existing == content:
            return  # 幂等，无需重写
        with open(conf, "w") as f:
            f.write(content)
        log("nginx 默认兜底配置已更新（default_server 接管未匹配请求）")
    except OSError:
        pass


# ------------------------------- BBR -------------------------------

IPV6_SYSCTL = "/etc/sysctl.d/99-fwpanel-ipv6.conf"
GAI_CONF = "/etc/gai.conf"


def ipv6_status():
    """IPv6 状态：v4_first（IPv6 开+IPv4 优先）/ disabled / enabled"""
    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
            disabled = f.read().strip() == "1"
    except Exception:
        disabled = True
    v4_first = False
    try:
        with open(GAI_CONF) as f:
            for line in f:
                s = line.strip()
                if s.startswith("precedence ::ffff:0:0/96") and not s.startswith("#"):
                    v4_first = True
                    break
    except Exception:
        pass
    if disabled:
        return "disabled"
    return "v4_first" if v4_first else "enabled"


def set_ipv6_mode(mode):
    """设置 IPv6 模式：v4_first / disable / enable（写 sysctl.d + gai.conf，立即生效）"""
    if mode not in ("v4_first", "disable", "enable"):
        return False, "mode 必须是 v4_first / disable / enable"
    disable = "1" if mode == "disable" else "0"
    # 1. sysctl 持久化配置 + 立即生效
    content = (f"net.ipv6.conf.all.disable_ipv6={disable}\n"
               f"net.ipv6.conf.default.disable_ipv6={disable}\n")
    try:
        os.makedirs("/etc/sysctl.d", exist_ok=True)
        tmp = IPV6_SYSCTL + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.replace(tmp, IPV6_SYSCTL)
        if not DRY_RUN:
            r = subprocess.run(["sysctl", "--system"], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return False, f"sysctl 应用失败: {(r.stderr or r.stdout).strip()[:200]}"
            for k in ("net.ipv6.conf.all.disable_ipv6",
                      "net.ipv6.conf.default.disable_ipv6"):
                subprocess.run(["sysctl", "-w", f"{k}={disable}"],
                               capture_output=True, text=True, timeout=10)
    except OSError as e:
        return False, f"写入 {IPV6_SYSCTL} 失败: {e}"
    # 2. gai.conf：IPv4 优先规则（v4_first 添加，其余注释掉）
    try:
        if mode == "v4_first":
            if not os.path.exists(GAI_CONF):
                with open(GAI_CONF, "w") as f:
                    f.write("")
            with open(GAI_CONF) as f:
                lines = f.read().splitlines()
            if not any(s.strip().startswith("precedence ::ffff:0:0/96")
                       and not s.strip().startswith("#") for s in lines):
                lines.append("precedence ::ffff:0:0/96 100")
                with open(GAI_CONF, "w") as f:
                    f.write("\n".join(lines) + "\n")
        else:
            if os.path.exists(GAI_CONF):
                with open(GAI_CONF) as f:
                    lines = f.read().splitlines()
                changed = False
                for i, s in enumerate(lines):
                    if s.strip().startswith("precedence ::ffff:0:0/96") \
                            and not s.strip().startswith("#"):
                        lines[i] = "# " + s.lstrip("# ")
                        changed = True
                if changed:
                    with open(GAI_CONF, "w") as f:
                        f.write("\n".join(lines) + "\n")
    except OSError as e:
        return False, f"gai.conf 修改失败: {e}"
    label = {"v4_first": "IPv4 优先（IPv6 保持开启）",
             "disable": "已禁用 IPv6",
             "enable": "已开启 IPv6（系统默认优先级）"}[mode]
    return True, f"设置完成：{label}"


def bbr_status():
    """BBR 是否已开启"""
    try:
        with open("/proc/sys/net/ipv4/tcp_congestion_control") as f:
            return f.read().strip() == "bbr"
    except Exception:
        return False


def bbr_module_exists():
    """内核是否带有 bbr 模块文件（Debian 等发行版 bbr 为模块化编译）"""
    try:
        rel = os.uname().release
        for ext in ("ko", "ko.xz", "ko.zst", "ko.gz"):
            if os.path.exists(f"/lib/modules/{rel}/kernel/net/ipv4/tcp_bbr.{ext}"):
                return True
        return False
    except Exception:
        return False


def bbr_available():
    """内核是否支持 BBR（含模块化：已加载/可加载/模块文件存在）"""
    try:
        with open("/proc/sys/net/ipv4/tcp_available_congestion_control") as f:
            if "bbr" in f.read():
                return True
    except Exception:
        pass
    # 尝试加载模块（Debian 系 bbr 是 tcp_bbr.ko，设置时本可自动加载，这里主动探测）
    try:
        r = subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    return bbr_module_exists()


def enable_bbr():
    """开启 BBR：写入 sysctl 配置（持久化）并立即生效，回读校验"""
    if DRY_RUN:
        log("[dry-run] 写入 BBR sysctl 配置（跳过）")
        return True, "dry-run"
    if not bbr_available():
        return False, "内核不支持 BBR（需 Linux 4.9+ 且内核包含 bbr 模块）"
    conf = os.environ.get("FW_BBR_CONF", "/etc/sysctl.d/99-fwpanel-bbr.conf")
    content = "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"
    try:
        with open(conf, "w") as f:
            f.write(content)
    except OSError as e:
        return False, f"写入配置失败: {e}"
    try:
        r1 = subprocess.run(["sysctl", "-w", "net.core.default_qdisc=fq"],
                            capture_output=True, text=True, timeout=10)
        if r1.returncode != 0:
            return False, f"设置 qdisc 失败: {(r1.stderr or r1.stdout).strip()[:200]}"
        r2 = subprocess.run(["sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"],
                            capture_output=True, text=True, timeout=10)
        if r2.returncode != 0:
            return False, f"设置 BBR 失败: {(r2.stderr or r2.stdout).strip()[:200]}"
    except FileNotFoundError:
        return False, "sysctl 不可用（配置已写入，重启后生效）"
    except Exception:
        return False, "sysctl 应用失败（配置已写入，重启后生效）"
    # 回读校验：确认内核实际生效
    if not bbr_status():
        return False, "BBR 配置已写入但内核未生效（可能被其他 sysctl 配置覆盖），请重启后检查 /proc/sys/net/ipv4/tcp_congestion_control"
    return True, "BBR 已开启（回读校验通过）"


# ------------------------------- HTTP 服务 -------------------------------

class PanelHandler(BaseHTTPRequestHandler):
    server_version = f"fwpanel2/{CURRENT_VERSION}"

    def log_message(self, fmt, *args):   # 静默默认日志，避免刷屏
        pass

    # ---------- 基础 ----------
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # v3.0.1：客户端提前断开（浏览器切页/探活超时）不是错误，静默即可——
            # 旧实现会往 journalctl 里刷一整段 ConnectionResetError 堆栈
            pass

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return {}

    def _token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def _require_auth(self):
        """会话 Bearer 或联邦 X-Fwpanel-Token 均可（返回 'fed' 标记联邦会话）"""
        fed = self.headers.get(FED_HEADER, "")
        if fed and self.server.auth.check_fed(fed):
            return "fed"
        token = self._token()
        if not token or not self.server.auth.check(token):
            self._send(401, {"error": "未登录或登录已过期"})
            return None
        return token

    def _require_local(self):
        """仅允许本机 Web 登录会话（拒绝联邦令牌）——联邦配置/节点管理等高危操作"""
        token = self._token()
        if token and self.server.auth.check(token):
            return token
        self._send(401, {"error": "需要本机面板登录"})
        return None

    # ---------- 路由 ----------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
        elif path == "/favicon.ico":
            self._serve_static("favicon.ico")
        elif path.startswith("/static/vendor/"):
            self._serve_static(path[len("/static/"):])
        elif path.startswith("/static/fonts/"):
            self._serve_static(path[len("/static/"):])
        elif path == "/api/bbr":
            self._api_bbr()
        elif path == "/api/traffic":
            self._api_traffic()
        elif path == "/api/procs":
            self._api_procs()
        elif path == "/api/ipv6":
            self._api_ipv6()
        elif path == "/api/cert":
            self._api_cert()
        elif path.startswith("/api/cert/"):
            self._api_cert_action(path.rsplit("/", 1)[1])
        elif path == "/api/status":
            self._api_status()
        elif path == "/api/upgrade/check":
            self._api_upgrade_check()
        elif path == "/api/ssh":
            self._api_ssh()
        elif path == "/api/ssh/policy":
            self._api_ssh_policy()
        elif path == "/api/ssh/keys":
            self._api_ssh_keys()
        elif path == "/api/ssh/allow-ips":
            self._api_ssh_allow_ips()
        elif path == "/api/bruteforce":
            self._api_bruteforce()
        elif path == "/api/proxy":
            self._api_proxy()
        elif path == "/api/sites":
            self._api_sites()
        elif path.startswith("/api/sites/"):
            parts = path[len("/api/sites/"):].strip("/").split("/")
            sid = parts[0]
            action = parts[1] if len(parts) > 1 else ""
            if action == "logs":
                self._api_site_logs(sid)
            elif action == "stats":
                self._api_site_stats(sid)
            elif action == "files":
                self._api_site_files(sid)
            elif action == "download":
                self._api_site_download(sid)
            else:
                self._send(404, {"error": "Not Found"})
        elif path == "/api/docker":
            self._api_docker_status()
        elif path == "/api/docker/containers":
            self._api_docker_containers()
        elif path == "/api/docker/images":
            self._api_docker_images()
        elif path == "/api/docker/stats":
            self._api_docker_stats()
        elif path == "/api/docker/dirs":
            self._api_docker_dirs_status()
        elif path == "/api/docker/compose":
            self._api_docker_compose_list()
        elif path.startswith("/api/docker/logs/"):
            self._api_docker_logs(path[len("/api/docker/logs/"):])
        elif path == "/api/rules":
            self._api_list_rules()
        elif path == "/api/logout":
            token = self._token()
            if token:
                self.server.auth.logout(token)
            self._send(200, {"ok": True})
        elif path == "/api/fed":
            self._api_fed_status()
        elif path == "/api/fed/nodes":
            self._api_fed_nodes_list()
        elif path.startswith("/api/fed/"):
            # 终端 WebSocket 升级由 _api_fed_proxy 内部识别（HTTP 头含 Upgrade）
            self._api_fed_proxy()
        elif path.startswith("/api/tasks/"):
            self._api_task_status(path[len("/api/tasks/"):])
        elif path == "/api/term/ws":
            self._api_term_ws()
        elif path == "/api/term/info":
            self._api_term_info()
        else:
            self._send(404, {"error": "Not Found"})

    # ---------- 长任务状态（v2.1.18：异步长任务轮询） ----------
    def _run_long_task(self, action, fn, *args):
        """长任务统一入口：fn 返回 (ok, msg)。
        DRY_RUN/测试环境 → 同步执行直接返回（既有测试语义不变）；
        真实环境 → start_task 后台执行，立即返回 task_id 供前端轮询。"""
        if DRY_RUN:
            try:
                ok, msg = fn(*args)
            except Exception as e:
                ok, msg = False, f"任务异常: {e}"
            self._send(200 if ok else 500, {"ok": ok, "msg": msg})
            return None
        tid = start_task(action, fn, *args)
        self._send(200, {"ok": True, "task": tid,
                         "msg": "任务已开始，后台执行中（可在页面停留等待自动完成）"})
        return tid

    def _api_task_status(self, tid):
        """GET /api/tasks/<id> → 后台任务状态 {status: running|ok|error, ok, msg}"""
        token = self._require_auth()
        if token is None:
            return
        t = get_task(tid.strip())
        if t is None:
            self._send(404, {"error": "任务不存在或已过期"})
            return
        self._send(200, t)

    # ---------- Web 终端（v2.1.19） ----------
    def _api_term_info(self):
        """GET /api/term/info → 终端可用性：term 用户存在、并发占用"""
        token = self._require_auth()
        if token is None:
            return
        with _term_conns_lock:
            busy = _term_conns
        self._send(200, {
            "available": _term_ensure_user() if os.geteuid() == 0 else True,
            "busy": busy, "max": TERM_MAX_CONNS,
            "user": TERM_USER,
        })

    def _api_term_key_upload(self):
        """POST /api/term/key {content, filename?} → 把操作电脑上的私钥临时上传到
        term 用户 ~/.ssh/fwterm_*.pem（600），返回面板机路径供 ssh -i 使用。
        面板不持久保存：终端关闭时前端调 DELETE 删除；服务重启也会清残留。
        支持经联邦代理转发（远程节点开终端时密钥落在节点）。"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        content = data.get("content", "")
        if not isinstance(content, str) or not content.strip():
            self._send(400, {"error": "内容为空"})
            return
        # 安全校验：必须是 PEM 私钥（拒绝任意文件写入）
        head = content.lstrip().encode()[:60]
        if b"PRIVATE KEY" not in head and not content.lstrip().startswith("-----BEGIN"):
            self._send(400, {"error": "不是有效的私钥文件（需 PEM 格式）"})
            return
        try:
            import pwd
            pw = pwd.getpwnam(TERM_USER)
            ssh_dir = os.path.join(pw.pw_dir, ".ssh")
            uid, gid = pw.pw_uid, pw.pw_gid
        except KeyError:
            ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
            uid = gid = os.geteuid()
        try:
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            if uid != os.geteuid():
                os.chown(ssh_dir, uid, gid)
        except Exception:
            pass
        fname = "fwterm_" + secrets.token_hex(8) + ".pem"
        fpath = os.path.join(ssh_dir, fname)
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(fpath, 0o600)
            if uid != os.geteuid():
                os.chown(fpath, uid, gid)
        except Exception as e:
            self._send(500, {"error": f"写入失败: {e}"})
            return
        _term_audit("key_upload", fname)
        self._send(200, {"path": fpath})

    def _api_term_key_delete(self):
        """DELETE /api/term/key {path} → 删除临时上传的私钥（仅限 fwterm_ 前缀，防穿越）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        fpath = str(data.get("path", ""))
        base = os.path.basename(fpath)
        if not base.startswith("fwterm_") or not base.endswith(".pem"):
            self._send(400, {"error": "非法路径"})
            return
        # 只允许删 .ssh 目录下 fwterm_ 前缀（路径穿越防护：忽略目录部分只删 .ssh 内的）
        try:
            import pwd
            ssh_dir = os.path.join(pwd.getpwnam(TERM_USER).pw_dir, ".ssh")
        except (KeyError, Exception):
            ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
        target = os.path.join(ssh_dir, base)
        if os.path.isfile(target):
            try:
                os.remove(target)
                _term_audit("key_delete", base)
            except Exception as e:
                self._send(500, {"error": f"删除失败: {e}"})
                return
        self._send(200, {"ok": True})


    def _ws_token_ok(self):
        """WS 升级鉴权：query token = 本机登录会话，或 X-Fwpanel-Token = 有效联邦令牌（节点被主控中继）。"""
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        qt = (qs.get("token") or [""])[0]
        if qt and self.server.auth.check(qt):
            return True
        fed = self.headers.get(FED_HEADER, "")
        if fed and self.server.auth.check_fed(fed):
            return True
        return False

    def _ws_handshake(self):
        """RFC6455 服务端握手：成功返回 True（已发 101）；失败已发响应返回 False"""
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self._send(400, {"error": "not a websocket upgrade"})
            return False
        accept = ws_accept_key(key)
        self.send_response_only(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        return True

    def _ws_send(self, payload, opcode=0x1):
        try:
            self.wfile.write(ws_encode_frame(payload, opcode))
            self.wfile.flush()
            return True
        except Exception:
            return False

    def _api_term_ws(self):
        """GET /api/term/ws?token=… → 本机 Web 终端（WS 升级，PTY 降权 term 用户）"""
        if not self._ws_token_ok():
            self._send(401, {"error": "未登录"})
            return
        # root 面板必须降权到 term；非 root（低权限环境/测试）允许以当前用户跑
        if os.geteuid() == 0 and not _term_ensure_user():
            self._send(503, {"error": f"低权用户 {TERM_USER} 不存在且无法创建"})
            return
        # v2.1.24：root 环境后台准备 zsh 语法高亮（只跑一次；失败回落 bash 不影响本次连接）
        if os.geteuid() == 0:
            try:
                import pwd
                _pw = pwd.getpwnam(TERM_USER)
                _term_ensure_zsh_async(_pw.pw_dir, _pw.pw_uid, _pw.pw_gid)
            except Exception:
                pass
        with _term_conns_lock:
            global _term_conns
            if _term_conns >= TERM_MAX_CONNS:
                self._send(503, {"error": "终端并发数已达上限"})
                return
            _term_conns += 1
        peer = self.client_address[0] if self.client_address else ""
        _term_audit("open", peer)
        self.close_connection = True   # WS 长连接，禁止 HTTP keep-alive 复用
        if not self._ws_handshake():
            with _term_conns_lock:
                _term_conns -= 1
            return
        try:
            import fcntl
            import termios
            import struct as _struct
            master_fd, pid = _term_spawn_pty()
            stop = threading.Event()

            def _pty_to_ws():
                """PTY 输出 → WS 帧；空闲 25s 发 ping 保活（防 nginx proxy_read_timeout 60s 掐断）"""
                idle = 0
                try:
                    while not stop.is_set():
                        r, _, _ = select.select([master_fd], [], [], 0.3)
                        if master_fd in r:
                            try:
                                data = os.read(master_fd, 8192)
                            except OSError:
                                break
                            if not data:
                                break
                            idle = 0
                            if not self._ws_send(data, 0x1):
                                break
                        else:
                            idle += 1
                            if idle >= 83:      # ≈ 25s（0.3s × 83）
                                idle = 0
                                if not self._ws_send(b"", 0x9):   # ping
                                    break
                except Exception:
                    pass
                stop.set()

            def _ws_to_pty():
                """WS 输入帧 → PTY；resize 帧(二进制 JSON) → ioctl"""
                try:
                    while not stop.is_set():
                        opcode, payload = ws_read_frame(self.rfile)
                        if opcode is None:          # 连接关闭
                            break
                        if opcode == 0x8:           # close
                            self._ws_send(b"", 0x8)
                            break
                        if opcode == 0x9:           # ping → pong
                            self._ws_send(payload, 0xA)
                            continue
                        if opcode == 0x2:           # binary = resize 控制
                            try:
                                j = json.loads(payload.decode())
                                if j.get("type") == "resize":
                                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                                                _struct.pack("HHHH", int(j.get("rows", 24)),
                                                             int(j.get("cols", 80)), 0, 0))
                            except Exception:
                                pass
                            continue
                        if opcode == 0x1 and payload:
                            os.write(master_fd, payload)
                except Exception:
                    pass
                stop.set()

            t1 = threading.Thread(target=_pty_to_ws, daemon=True)
            t2 = threading.Thread(target=_ws_to_pty, daemon=True)
            t1.start(); t2.start()
            # 主线程等待任一端结束 → 全部收尾
            t1.join(); t2.join()
            stop.set()
            try:
                os.close(master_fd)
            except Exception:
                pass
            try:
                os.kill(pid, 9)
            except Exception:
                pass
            _term_audit("close", peer)
        finally:
            with _term_conns_lock:
                _term_conns -= 1
            # 确保剩余数据冲刷（若 wfile 仍打开）
            try:
                self.wfile.flush()
            except Exception:
                pass

    def _api_fed_status(self):
        """本机联邦状态 / 探活（主面板添加节点时探测；本机登录或联邦令牌均可访问）"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "fed_enabled": self.server.auth.fed_enabled(),
            "is_fed": token == "fed",
            "hostname": os.uname().nodename,
            "version": CURRENT_VERSION,
            "panel_port": int(self.server.config.get("port", DEFAULT_PORT)),
        })

    def _api_fed_manage(self):
        """开启/重置/关闭本机联邦令牌（仅本机登录）"""
        if self._require_local() is None:
            return
        data = self._read_json()
        action = data.get("action", "")
        if action == "rotate":
            raw = _gen_fed_token()
            self.server.auth.set_fed_token(raw)
            self._send(200, {"ok": True, "enabled": True,
                             "token": raw,
                             "warn": "令牌仅显示这一次，请立即复制保存"})
        elif action == "clear":
            self.server.auth.clear_fed_token()
            self._send(200, {"ok": True, "enabled": False})
        else:
            self._send(400, {"error": "未知操作（rotate / clear）"})

    def _api_fed_nodes_list(self):
        """节点列表（不含令牌明文）"""
        if self._require_local() is None:
            return
        nodes = _load_fed_nodes()
        lst = [{"id": nid, "name": n.get("name", ""), "url": n.get("url", ""),
                "token_set": bool(n.get("token"))}
               for nid, n in nodes.items()]
        self._send(200, {"nodes": lst})

    def _api_fed_node_add(self):
        """添加节点：预探测连通+令牌，成功后落盘"""
        if self._require_local() is None:
            return
        data = self._read_json()
        name = (data.get("name") or "").strip()
        url = (data.get("url") or "").strip().rstrip("/")
        tok = (data.get("token") or "").strip()
        if not name or not url or not tok:
            self._send(400, {"error": "名称 / 地址 / 令牌均必填"})
            return
        if not (url.startswith("https://") or url.startswith("http://")):
            self._send(400, {"error": "地址需以 http:// 或 https:// 开头"})
            return
        probe = _http_fed_probe(url, tok)
        if not probe:
            self._send(400, {"error": "无法连接节点或令牌无效——请检查地址、令牌，并确认节点已开启联邦令牌（版本需 2.0+）"})
            return
        nodes = _load_fed_nodes()
        nid = secrets.token_hex(6)
        nodes[nid] = {"name": name, "url": url, "token": tok}
        _save_fed_nodes(nodes)
        self._send(200, {"ok": True, "id": nid, "node": {
            "name": name, "url": url,
            "hostname": probe.get("hostname", ""), "version": probe.get("version", "")}})

    def _api_fed_node_update(self, nid):
        """更新节点（改 url/token 时重新探测）"""
        if self._require_local() is None:
            return
        nodes = _load_fed_nodes()
        node = nodes.get(nid)
        if not node:
            self._send(404, {"error": "节点不存在"})
            return
        data = self._read_json()
        new_name = (data.get("name") or node.get("name", "")).strip()
        new_url = (data.get("url") or node.get("url", "")).strip().rstrip("/")
        new_tok = (data.get("token") or node.get("token", "")).strip()
        if data.get("url") is not None and new_url != node.get("url"):
            if not (new_url.startswith("https://") or new_url.startswith("http://")):
                self._send(400, {"error": "地址需以 http:// 或 https:// 开头"})
                return
        if data.get("token") is not None and new_tok != node.get("token"):
            pass
        # url 或 token 变更时重新探测
        if new_url != node.get("url") or new_tok != node.get("token"):
            probe = _http_fed_probe(new_url, new_tok)
            if not probe:
                self._send(400, {"error": "更新后无法连接节点或令牌无效，请检查后重试"})
                return
        node["name"], node["url"], node["token"] = new_name, new_url, new_tok
        _save_fed_nodes(nodes)
        self._send(200, {"ok": True})

    def _api_fed_node_delete(self, nid):
        """删除节点"""
        if self._require_local() is None:
            return
        nodes = _load_fed_nodes()
        if nid not in nodes:
            self._send(404, {"error": "节点不存在"})
            return
        nodes.pop(nid, None)
        _save_fed_nodes(nodes)
        self._send(200, {"ok": True})

    def _api_fed_proxy(self):
        """核心代理：把 /api/fed/<node_id>/api/... 原样转发到节点（带节点联邦令牌）"""
        parsed = urlparse(self.path)
        # WebSocket 升级（远程终端）：浏览器 WS 无法带 Authorization header，token 在 query ——
        # 用 _ws_token_ok 校验（本机登录会话），校验通过后帧级中继到节点
        if (self.headers.get("Upgrade", "").lower() == "websocket"
                and parsed.path.endswith("/api/term/ws")):
            if not self._ws_token_ok():
                self._send(401, {"error": "未登录"})
                return
            self._relay_term_ws()
            return
        if self._require_local() is None:
            return
        parts = parsed.path.split("/")
        # ['', 'api', 'fed', '<node_id>', 'api', ...]
        if len(parts) < 6 or parts[4] != "api":
            self._send(404, {"error": "Not Found"})
            return
        node_id = parts[3]
        rest = "/" + "/".join(parts[4:])
        if parsed.query:
            rest += "?" + parsed.query
        nodes = _load_fed_nodes()
        node = nodes.get(node_id)
        if not node:
            self._send(404, {"error": "节点不存在"})
            return
        base = (node.get("url") or "").rstrip("/")
        if not base:
            self._send(400, {"error": "节点未配置地址"})
            return
        body = None
        if self.command in ("POST", "PUT", "PATCH"):
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length > 0:
                    body = self.rfile.read(length)
            except Exception:
                body = None
        req = urllib.request.Request(base + rest, data=body, method=self.command)
        req.add_header(FED_HEADER, node.get("token", ""))
        req.add_header("Content-Type", self.headers.get("Content-Type", "application/json"))
        try:
            with urllib.request.urlopen(req, timeout=fed_proxy_timeout(rest)) as resp:
                raw = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get(
                    "Content-Type", "application/json; charset=utf-8"))
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(raw)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read()
            except Exception:
                raw = b""
            if e.code == 401:
                self._send(502, {"error": "节点拒绝访问：联邦令牌可能已失效，请在服务器管理里更新节点令牌"})
                return
            self.send_response(e.code)
            self.send_header("Content-Type",
                             (e.headers or {}).get("Content-Type", "application/json; charset=utf-8"))
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if raw:
                self.wfile.write(raw)
        except Exception as e:
            self._send(502, {"error": "节点不可达（%s）：请检查节点地址与网络" % type(e).__name__})

    def _relay_term_ws(self):
        """远程终端中继：浏览器(WS client) ↔ 本主控(WS server) ↔ 节点(WS client)。
        帧级双向解码/重编码——浏览器帧(掩码)解码后以客户端帧(重掩码)发节点，反向同理。"""
        parsed = urlparse(self.path)
        parts = parsed.path.split("/")
        # ['', 'api', 'fed', '<node_id>', 'api', 'term', 'ws']
        if len(parts) < 6 or parts[3] == "":
            self._send(404, {"error": "Not Found"})
            return
        node_id = parts[3]
        nodes = _load_fed_nodes()
        node = nodes.get(node_id)
        if not node:
            self._send(404, {"error": "节点不存在"})
            return
        base = (node.get("url") or "").rstrip("/")
        tok = node.get("token", "")
        if not base or not tok:
            self._send(400, {"error": "节点未配置地址或令牌"})
            return
        # 1) 与浏览器完成服务端握手
        if not self._ws_handshake():
            return
        # 2) 作为客户端连接节点（带联邦令牌）
        try:
            nsock, nrfile = ws_client_connect(base + "/api/term/ws", tok)
        except Exception as e:
            self._send(502, {"error": "节点终端不可达: %s" % type(e).__name__})
            return
        self.close_connection = True
        stop = threading.Event()

        def _browser_to_node():
            """浏览器帧 → 节点（重掩码）"""
            try:
                while not stop.is_set():
                    op, payload = ws_read_frame(self.rfile)
                    if op is None:
                        break
                    if op == 0x8:      # close：通知节点后结束
                        try:
                            nsock.sendall(ws_encode_frame_client(b"", 0x8))
                        except Exception:
                            pass
                        break
                    if op == 0x9:      # ping
                        self._ws_send(payload, 0xA)
                        continue
                    try:
                        nsock.sendall(ws_encode_frame_client(payload or b"", op))
                    except Exception:
                        break
            except Exception:
                pass
            stop.set()

        def _node_to_browser():
            """节点帧 → 浏览器（服务端帧不掩码）"""
            try:
                while not stop.is_set():
                    op, payload = ws_read_frame(nrfile)
                    if op is None:
                        break
                    if op == 0x8:      # 节点关闭
                        self._ws_send(b"", 0x8)
                        break
                    if op == 0x9:      # 节点 ping → 转发浏览器（浏览器自动回 pong，全链路保活）
                        try:
                            self.wfile.write(ws_encode_frame(payload or b"", 0x9))
                            self.wfile.flush()
                        except Exception:
                            break
                        continue
                    try:
                        self.wfile.write(ws_encode_frame(payload or b"", op))
                        self.wfile.flush()
                    except Exception:
                        break
            except Exception:
                pass
            stop.set()

        t1 = threading.Thread(target=_browser_to_node, daemon=True)
        t2 = threading.Thread(target=_node_to_browser, daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        stop.set()
        try:
            nsock.close()
        except Exception:
            pass
        try:
            self.wfile.flush()
        except Exception:
            pass

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/login":
            self._api_login()
        elif path == "/api/rules":
            self._api_add_rule()
        elif path.startswith("/api/rules/"):
            self._api_edit_rule(path.rsplit("/", 1)[1])
        elif path == "/api/service":
            self._api_service()
        elif path == "/api/open-port":
            self._api_open_port()
        elif path == "/api/close-port":
            self._api_close_port()
        elif path == "/api/mode":
            self._api_mode()
        elif path == "/api/password":
            self._api_password()
        elif path == "/api/upgrade":
            self._api_upgrade()
        elif path == "/api/ssh/apply":
            self._api_ssh_apply()
        elif path == "/api/ssh/policy":
            self._api_ssh_policy_set()
        elif path == "/api/ssh/keygen":
            self._api_ssh_keygen()
        elif path == "/api/ssh/keys/delete":
            self._api_ssh_keys_delete()
        elif path == "/api/ssh":
            self._api_ssh_set()
        elif path == "/api/ssh/allow-ips":
            self._api_ssh_allow_ips_set()
        elif path == "/api/panel/port":
            self._api_panel_port()
        elif path == "/api/bbr":
            self._api_bbr_enable()
        elif path == "/api/procs/install":
            self._api_procs_install()
        elif path == "/api/procs/clear":
            self._api_procs_clear()
        elif path == "/api/ipv6":
            self._api_ipv6()
        elif path == "/api/restart":
            self._api_restart()
        elif path == "/api/bruteforce":
            self._api_bruteforce_set()
        elif path == "/api/bruteforce/ban":
            self._api_bruteforce_ban()
        elif path == "/api/bruteforce/unban":
            self._api_bruteforce_unban()
        elif path.startswith("/api/bruteforce/"):
            self._api_bruteforce_unban(path.rsplit("/", 1)[1])
        elif path == "/api/firewall":
            self._api_firewall()
        elif path == "/api/cert":
            self._api_cert_add()
        elif path == "/api/cert/creds":
            self._api_cert_creds_clear()
        elif path.startswith("/api/cert/"):
            self._api_cert_action(path.rsplit("/", 1)[1])
        elif path == "/api/proxy":
            self._api_proxy_add()
        elif path == "/api/sites":
            self._api_site_add()
        elif path == "/api/sites/root":
            self._api_site_root_set()
        elif path.startswith("/api/sites/"):
            parts = path[len("/api/sites/"):].strip("/").split("/")
            sid = parts[0]
            action = parts[1] if len(parts) > 1 else ""
            if action == "toggle":
                self._api_site_toggle(sid)
            elif action == "cert":
                self._api_site_cert(sid)
            elif action == "files":
                self._api_site_files(sid)
            else:
                self._api_site_update(sid)
        elif path == "/api/proxy/install":
            self._api_proxy_install()
        elif path.startswith("/api/proxy/"):
            self._api_proxy_action(path[len("/api/proxy/"):])
        elif path == "/api/username":
            self._api_username()
        elif path == "/api/docker/install":
            self._api_docker_install()
        elif path == "/api/docker/uninstall":
            self._api_docker_uninstall()
        elif path == "/api/docker/action":
            self._api_docker_action()
        elif path == "/api/docker/create":
            self._api_docker_create()
        elif path == "/api/docker/pull":
            self._api_docker_pull()
        elif path == "/api/docker/rmi":
            self._api_docker_rmi()
        elif path == "/api/docker/prune":
            self._api_docker_prune()
        elif path == "/api/docker/data-root":
            self._api_docker_data_root()
        elif path == "/api/docker/compose/up":
            self._api_docker_compose_up()
        elif path == "/api/docker/compose/start":
            self._api_docker_compose_start()
        elif path == "/api/docker/compose/upgrade":
            self._api_docker_compose_upgrade()
        elif path == "/api/docker/compose/down":
            self._api_docker_compose_down()
        elif path == "/api/docker/dirs":
            self._api_docker_dirs_create()
        elif path == "/api/fed":
            self._api_fed_manage()
        elif path == "/api/term/key":
            self._api_term_key_upload()
        elif path == "/api/fed/nodes":
            self._api_fed_node_add()
        elif path.startswith("/api/fed/nodes/"):
            self._api_fed_node_update(path.rsplit("/", 1)[1])
        elif path.startswith("/api/fed/"):
            self._api_fed_proxy()
        else:
            self._send(404, {"error": "Not Found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/rules/"):
            self._api_delete_rule(path.rsplit("/", 1)[1])
        elif path.startswith("/api/bruteforce/"):
            self._api_bruteforce_unban(path.rsplit("/", 1)[1])
        elif path.startswith("/api/proxy/"):
            self._api_proxy_delete(path.rsplit("/", 1)[1])
        elif path.startswith("/api/sites/"):
            self._api_site_delete(path[len("/api/sites/"):].strip("/").split("/")[0])
        elif path == "/api/term/key":
            self._api_term_key_delete()
        elif path.startswith("/api/fed/nodes/"):
            self._api_fed_node_delete(path.rsplit("/", 1)[1])
        elif path.startswith("/api/fed/"):
            self._api_fed_proxy()
        else:
            self._send(404, {"error": "Not Found"})

    # ---------- 静态页面 ----------
    def _serve_static(self, name):
        path = os.path.join(STATIC_DIR, name)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self._send(404, {"error": "Not Found"})
            return
        if name.endswith(".html"):
            ctype = "text/html; charset=utf-8"
            # 注入当前版本号（登录页底部显示）
            data = data.replace(b"__VERSION__", CURRENT_VERSION.encode())
        elif name.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif name.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif name.endswith(".png"):
            ctype = "image/png"
        elif name.endswith(".ico"):
            ctype = "image/x-icon"
        elif name.endswith(".woff2"):
            ctype = "font/woff2"
        else:
            ctype = "application/octet-stream"
        self._send(200, data, ctype)

    # ---------- API ----------
    def _api_login(self):
        data = self._read_json()
        token, msg = self.server.auth.login(data.get("username", ""), data.get("password", ""))
        if token:
            self._send(200, {"token": token})
        else:
            self._send(401, {"error": msg})

    def _api_status(self):
        token = self._require_auth()
        if token is None:
            return
        nft = self.server.nft
        cfg = self.server.config
        hostname = os.uname().nodename
        try:
            mem = subprocess.run(["awk", "/^MemTotal:/{print int($2/1024)}", "/proc/meminfo"],
                                 capture_output=True, text=True).stdout.strip()
        except FileNotFoundError:
            mem = ""
        self._send(200, {
            "hostname": hostname,
            "distro": detect_distro(),
            "mode": cfg.get("mode", "permissive"),
            "ssh_port": int(cfg.get("ssh_port", SSH_PORT_DEFAULT)),
            "loaded": nft.status(),
            "rule_count": len(self.server.store.rules),
            "banned_count": sum(1 for r in self.server.store.rules
                                if r.get("type") == "ip_deny"),
            "server_ip": get_server_ip(),
            "version": CURRENT_VERSION,
            "panel_port": int(cfg.get("port", DEFAULT_PORT)),
            "username": cfg.get("username", ""),
        })

    def _api_upgrade_check(self):
        token = self._require_auth()
        if token is None:
            return
        cur = CURRENT_VERSION
        rels = http_get_json(
            "https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=15", timeout=15)
        stable_latest = beta_latest = current_channel = None
        if isinstance(rels, list):
            beta_tags = []
            for r in rels:
                tag = str(r.get("tag_name", "")).lstrip("v")
                if not tag:
                    continue
                if current_channel is None and tag == cur:
                    current_channel = "beta" if r.get("prerelease") else "stable"
                if r.get("prerelease"):
                    beta_tags.append(tag)
                elif stable_latest is None:
                    stable_latest = tag
            if beta_tags:
                beta_latest = max(beta_tags, key=lambda v: tuple(int(p) for p in v.split(".") if p.isdigit()))
        else:
            # GitHub 列表不可达时退到旧双接口(此时无法判定 current 通道)
            stable_latest = get_latest_version()
            beta_latest = get_latest_prerelease()
        if stable_latest is None and beta_latest is None:
            self._send(502, {"error": "无法连接版本服务器，请稍后再试"})
            return
        prerelease_info = None
        if beta_latest:
            prerelease_info = {
                "tag": beta_latest,
                "update_available": version_gt(beta_latest, cur),
            }
        self._send(200, {
            "current": cur,
            "current_channel": current_channel,   # stable=正式版 / beta=测试版 / None=未知
            "latest": stable_latest,
            "update_available": bool(stable_latest) and version_gt(stable_latest, cur),
            "prerelease": prerelease_info,
        })

    def _api_upgrade(self):
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json() or {}
        channel = str(data.get("channel", "stable"))
        if channel == "beta":
            tag = get_latest_prerelease()
            if not tag:
                self._send(400, {"error": "没有可用的测试版"})
                return
            ok, msg = perform_upgrade(tag=tag)
        else:
            ok, msg = perform_upgrade()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_ssh_allow_ips(self):
        """GET：查询 SSH 白名单 + 当前访问面板的 IP"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "ips": self.server.config.get("ssh_allow_ips") or [],
            "client_ip": self.client_address[0] if self.client_address else "",
        })

    def _api_ssh_allow_ips_set(self):
        """POST：设置 SSH 白名单 {ips: "1.2.3.4,5.6.7.8" | ""}（空 = 恢复所有 IP）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        raw = str(data.get("ips", "")).strip()
        ips = []
        if raw:
            for part in raw.replace("，", ",").split(","):
                ip = part.strip()
                if ip and not is_valid_ip_or_net(ip):
                    self._send(400, {"error": f"IP 格式无效: {ip}（支持 1.2.3.4 / CIDR）"})
                    return
                if ip:
                    ips.append(ip)
        self.server.config.set("ssh_allow_ips", ips)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": f"规则应用失败: {msg}"})
            return
        tip = f"仅允许 {len(ips)} 个 IP/CIDR 访问 SSH" if ips else "所有 IP 均可访问 SSH"
        self._send(200, {"ok": True, "msg": f"SSH 白名单已保存：{tip}（{msg}）"})

    def _api_ssh(self):
        """查询 SSH 端口状态：面板保护端口 vs 系统实际端口"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "protected_port": int(self.server.config.get("ssh_port", SSH_PORT_DEFAULT)),
            "sshd_port": get_sshd_port(),
        })

    def _api_ssh_set(self):
        """仅更新防火墙 SSH 保护端口（不动系统 sshd）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("ssh_port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        self.server.config.set("ssh_port", port)
        self.server.config.set("ssh_port_auto", False)   # 手动设置后停止自动同步
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": f"规则应用失败: {msg}"})
            return
        self._send(200, {"ok": True, "msg": f"SSH 保护端口已更新为 {port}（防火墙规则已生效）"})

    def _api_ssh_apply(self):
        """同步修改系统 SSH 端口（防锁死流程：旧端口临时放行 → 更新保护 → 改 sshd → 重启）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("ssh_port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        old = int(self.server.config.get("ssh_port", SSH_PORT_DEFAULT))
        store = self.server.store
        # 1) 端口变化时先临时放行旧端口（切换期间旧连接不断）
        if port != old:
            exists = any(r.get("type") == "port_allow" and r.get("port") == old
                         and r.get("comment") == SSH_OLD_PORT_COMMENT for r in store.rules)
            if not exists:
                store.add({"type": "port_allow", "proto": "tcp", "port": old,
                           "comment": SSH_OLD_PORT_COMMENT})
        # 2) 更新保护端口并应用规则
        self.server.config.set("ssh_port", port)
        self.server.config.set("ssh_port_auto", False)   # 手动设置后停止自动同步
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": f"防火墙规则应用失败: {msg}"})
            return
        # 3) 修改系统 sshd 端口
        sok, smsg = apply_sshd_port(port)
        if not sok:
            self._send(500, {"error": smsg + "（防火墙已更新，请用 ssh -p 原端口 登录排查）"})
            return
        hint = ""
        if port != old:
            threading.Thread(target=watch_ssh_switch,
                             args=(old, port, self.server.store), daemon=True).start()
            hint = (f"。已启动自动检测：新端口 {port} 出现连接后自动删除旧端口 {old} 的放行规则"
                    f"（规则备注「{SSH_OLD_PORT_COMMENT}」）")
        self._send(200, {"ok": True, "msg": smsg + hint})

    def _api_ssh_policy(self):
        """查询 SSH 登录策略：实际生效值 + 面板管理目标值 + 其它可登录用户"""
        token = self._require_auth()
        if token is None:
            return
        cur = sshd_policy_current()
        managed = sshd_policy_managed()
        self._send(200, {
            "ok": True,
            "current": {
                "port": cur.get("port"),
                "permit_root_login": _norm_root_login(cur.get("permitrootlogin")),
                "password_auth": cur.get("passwordauthentication") == "yes",
                "pubkey_auth": cur.get("pubkeyauthentication") == "yes",
            } if cur else None,
            "managed": {
                "permit_root_login": _norm_root_login(managed.get("permitrootlogin")),
                "password_auth": (managed.get("passwordauthentication") == "yes"
                                  if "passwordauthentication" in managed else None),
                "pubkey_auth": (managed.get("pubkeyauthentication") == "yes"
                                if "pubkeyauthentication" in managed else None),
            },
            "other_users": other_login_users(),
        })

    def _api_ssh_policy_set(self):
        """保存 SSH 登录策略（写 drop-in + 语法检查 + 重启 + 回读验证）。
        支持 {reset: true} 删除面板接管配置、恢复系统默认"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        if data.get("reset"):
            ok, msg = reset_sshd_policy()
            self._send(200 if ok else 400,
                       {"ok": True, "msg": msg} if ok else {"error": msg})
            return
        changes = {}
        for key in ("password_auth", "pubkey_auth"):
            v = data.get(key)
            if v is not None:
                changes[key] = bool(v)
        pr = data.get("permit_root")
        if pr is not None:
            prn = _norm_root_login(pr)
            if prn is None:
                self._send(400, {"error": "permit_root 仅支持 yes / prohibit-password / no"})
                return
            changes["permit_root"] = prn
        if not changes:
            self._send(400, {"error": "没有要修改的项目"})
            return
        ok, msg, after = apply_sshd_policy(changes)
        if not ok:
            self._send(400, {"error": msg})
            return
        after = after or sshd_policy_current()
        self._send(200, {
            "ok": True,
            "msg": msg,
            "current": {
                "port": after.get("port"),
                "permit_root_login": _norm_root_login(after.get("permitrootlogin")),
                "password_auth": after.get("passwordauthentication") == "yes",
                "pubkey_auth": after.get("pubkeyauthentication") == "yes",
            },
        })

    def _api_ssh_keygen(self):
        """生成 SSH 密钥对：公钥自动装到目标用户，私钥仅一次性返回（不落盘）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        user = str(data.get("user") or "root").strip()
        algo = str(data.get("algo") or "ed25519").strip().lower()
        ok, res = ssh_gen_keypair(algo, user)
        if not ok:
            self._send(400, {"error": res.get("error", "生成失败")})
            return
        self._send(200, {"ok": True, "private_key": res["private_key"],
                         "public_key": res["public_key"], "fingerprint": res["fingerprint"],
                         "user": res["user"], "msg": res["msg"]})

    def _api_ssh_keys(self):
        """列出目标用户已安装的公钥（GET /api/ssh/keys?user=xxx，默认 root）"""
        token = self._require_auth()
        if token is None:
            return
        qs = parse_qs(urlparse(self.path).query)
        user = (qs.get("user") or ["root"])[0]
        try:
            keys = ssh_list_keys(user)
            auth_file = ssh_auth_keys_file(user)
        except ValueError as e:
            self._send(400, {"error": str(e)})
            return
        self._send(200, {"ok": True, "user": user, "auth_file": auth_file, "keys": keys})

    def _api_ssh_keys_delete(self):
        """按整行删除目标用户 authorized_keys 中的公钥"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        user = str(data.get("user") or "root").strip()
        line = str(data.get("line") or "").strip()
        if not line:
            self._send(400, {"error": "缺少要删除的公钥行"})
            return
        ok, msg = ssh_del_key(user, line)
        if not ok:
            self._send(400, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_panel_port(self):
        """修改面板端口：更新配置 + 同步防火墙规则 + 重启服务"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        old = int(self.server.config.get("port", DEFAULT_PORT))
        if port == old:
            self._send(200, {"ok": True, "msg": f"面板端口已是 {port}"})
            return
        if port_in_use_py(port):
            self._send(400, {"error": f"端口 {port} 已被占用，请换一个"})
            return
        # 更新配置
        self.server.config.set("port", port)
        # 防火墙规则：删除旧面板端口的全部放行规则（不留残留攻击面），并确保新端口放行
        store = self.server.store
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "port_allow" and r.get("port") == old)]
        exists = any(r.get("type") == "port_allow" and r.get("port") == port
                     and r.get("comment") == PANEL_PORT_COMMENT for r in store.rules)
        if not exists:
            store.add({"type": "port_allow", "proto": "tcp", "port": port,
                       "comment": PANEL_PORT_COMMENT})
        store.save()
        self.server.nft.apply()
        # 反代联动：有代理指向旧面板端口的，同步改为新端口（反代域名访问不受影响）
        proxy_hint = ""
        pstore = ProxyStore()
        synced = [p for p in pstore.proxies if p.get("target_port") == old]
        if synced:
            for p in pstore.proxies:
                if p.get("target_port") == old:
                    p["target_port"] = port
            pstore.save()
            apply_proxies(pstore)
            # 目标端口禁止规则迁移：旧端口 → 新端口
            store.rules = [r for r in store.rules
                           if not (r.get("type") == "port_deny" and r.get("port") == old
                                   and r.get("comment") == PROXY_TARGET_DENY_COMMENT)]
            if not any(r.get("type") == "port_deny" and r.get("port") == port
                       and r.get("comment") == PROXY_TARGET_DENY_COMMENT for r in store.rules):
                store.add({"type": "port_deny", "proto": "tcp", "port": port,
                           "comment": PROXY_TARGET_DENY_COMMENT})
            store.save()
            self.server.nft.apply()
            proxy_hint = f"；已同步 {len(synced)} 个反代目标端口到新端口，域名访问不受影响"
        # 延迟重启，响应先送达
        threading.Timer(1.5, restart_service).start()
        self._send(200, {"ok": True, "msg": f"面板端口已修改为 {port}，服务重启中，"
                                            f"请用 http://<服务器IP>:{port} 访问{proxy_hint}"})

    # ---------------- 网站（站点管理，v3.0.0） ----------------

    def _site_find(self, sid):
        s = SiteStore().get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
        return s

    def _api_sites(self):
        """GET /api/sites → 网站列表（本站点 + 反代站合并视图）"""
        token = self._require_auth()
        if token is None:
            return
        pstore, sstore = ProxyStore(), SiteStore()
        items = [site_view(s) for s in sstore.sites] + [proxy_site_view(p) for p in pstore.proxies]
        items.sort(key=lambda x: (x.get("domain") or "").lower())
        self._send(200, {
            "sites": items,
            "site_root": site_root_base(self.server.config),
            "certs": site_available_certs(),
            "nginx": {"installed": nginx_available(), "active": nginx_active()},
            "server_ip": get_server_ip(),
            "panel_port": int(self.server.config.get("port", 0) or 0),
        })

    def _api_site_add(self):
        """POST /api/sites 创建网站：{domain|port, type, root?, cert_mode, cert_ref?, force_https, block_ip, note}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        # v3.0.1：没装 nginx 时直接给出可操作引导（旧实现等到写配置才失败，报「未找到 nginx 配置目录」，
        # 用户不知道该去哪里装）
        if not nginx_available():
            self._send(400, {"error": "尚未安装 Nginx：网站需要 Nginx 才能对外提供服务。"
                                      "请先到「反代证书」页点「一键安装 Nginx + certbot」，装好后再回来建站",
                             "need_nginx": True})
            return
        pstore, sstore = ProxyStore(), SiteStore()
        site, err = site_validate(data, pstore, sstore, self.server.config)
        if err:
            self._send(400, {"error": err})
            return
        if site["cert_mode"] == "auto":
            okdns, why = site_dns_precheck(site["domain"], site.get("cert_ref"))
            if not okdns:
                self._send(400, {"error": why})
                return
        try:
            site_prepare_dir(site)
        except OSError as e:
            self._send(500, {"error": f"创建站点目录失败: {e}"})
            return
        s = sstore.add(site)
        fw = []
        try:
            fw = site_open_ports(self.server.store, s)
            self.server.nft.apply()
        except Exception as e:
            log(f"[site] 放行入口端口失败: {e}")
        okn, nginx_msg = apply_all_nginx(pstore, sstore, self.server.config)
        if not okn:
            # nginx 失败 → 回滚站点记录与放行端口（目录保留，避免文件白建）
            sstore.remove(s["id"])
            if site_close_ports(self.server.store, s):
                try:
                    self.server.nft.apply()
                except Exception:
                    pass
            self._send(500, {"error": f"nginx 配置失败，站点未创建：{nginx_msg}"})
            return
        task = ""
        reused = ""
        if s["cert_mode"] == "auto":
            if site_cert_ready(s):
                ci = site_cert_info(s)
                reused = f"已引用证书 {ci['ref']}（剩 {ci['days']} 天），未重复签发"
            else:
                task = start_task("site_cert", site_issue_cert, s["id"])
        label = s.get("domain") or f"端口 {s.get('port')}"
        self._send(200, {
            "ok": True,
            "site": site_view(s),
            "nginx": nginx_msg,
            "firewall": ("已放行 " + ", ".join(str(x) for x in fw)) if fw else "无需新增放行",
            "cert_task": task,
            "msg": f"网站 {label} 已创建"
                   + ("，证书正在签发" if task else ("，" + reused if reused else "")),
        })

    def _api_site_update(self, sid):
        """POST /api/sites/<id> 更新网站配置"""
        token = self._require_auth()
        if token is None:
            return
        sstore = SiteStore()
        old = sstore.get(sid)
        if not old:
            self._send(404, {"error": "站点不存在"})
            return
        data = self._read_json()
        if not nginx_available():
            self._send(400, {"error": "尚未安装 Nginx：请先在「反代证书」页一键安装 Nginx + certbot",
                             "need_nginx": True})
            return
        merged = dict(old)
        merged.update({k: v for k, v in data.items() if k not in ("id", "created")})
        pstore = ProxyStore()
        site, err = site_validate(merged, pstore, sstore, self.server.config, exclude_id=sid)
        if err:
            self._send(400, {"error": err})
            return
        if site["cert_mode"] == "auto":
            okdns, why = site_dns_precheck(site["domain"], site.get("cert_ref"))
            if not okdns:
                self._send(400, {"error": why})
                return
        # 目录变更：只把 nginx 指向新目录并建好骨架，不动旧目录里的文件（避免误删用户数据）
        if site["root"] != old.get("root") and not os.path.isdir(site["root"]):
            try:
                site_prepare_dir(site)
            except OSError as e:
                self._send(500, {"error": f"创建新目录失败: {e}"})
                return
        site["id"] = sid
        site["created"] = old.get("created", "")
        for i, x in enumerate(sstore.sites):
            if x.get("id") == sid:
                sstore.sites[i] = site
                break
        sstore.save()
        try:
            site_open_ports(self.server.store, site)
            self.server.nft.apply()
        except Exception:
            pass
        okn, nginx_msg = apply_all_nginx(pstore, sstore, self.server.config)
        if not okn:
            for i, x in enumerate(sstore.sites):
                if x.get("id") == sid:
                    sstore.sites[i] = old
                    break
            sstore.save()
            apply_all_nginx(pstore, sstore, self.server.config)
            self._send(500, {"error": f"nginx 配置失败，已还原：{nginx_msg}"})
            return
        self._send(200, {"ok": True, "site": site_view(sstore.get(sid)), "msg": "网站已更新"})

    def _api_site_toggle(self, sid):
        """POST /api/sites/<id>/toggle 启停网站（禁用=摘掉 nginx 配置，文件保留）"""
        token = self._require_auth()
        if token is None:
            return
        sstore = SiteStore()
        s = sstore.get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        s["enabled"] = not bool(s.get("enabled", True))
        sstore.save()
        okn, nginx_msg = apply_all_nginx(ProxyStore(), sstore, self.server.config)
        self._send(200 if okn else 500, {
            "ok": bool(okn), "enabled": s["enabled"], "site": site_view(s),
            "msg": ("网站已启用" if s["enabled"] else "网站已停用（配置文件已摘除，文件保留）") if okn else nginx_msg,
        })

    def _api_site_delete(self, sid):
        """DELETE /api/sites/<id>?purge=1 删除网站（默认保留目录与文件，purge=1 连文件一起删）"""
        token = self._require_auth()
        if token is None:
            return
        sstore = SiteStore()
        s = sstore.get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        query = parse_qs(urlparse(self.path).query)
        purge = (query.get("purge") or ["0"])[0] in ("1", "true", "yes")
        purged = False
        if purge:
            root = os.path.realpath(s.get("root") or "")
            if not root or not site_root_ok(root):
                self._send(400, {"error": f"目录不在允许范围，拒绝删除文件：{root}"})
                return
            try:
                if os.path.isdir(root):
                    shutil.rmtree(root)
                    purged = True
            except OSError as e:
                self._send(500, {"error": f"删除站点目录失败: {e}"})
                return
        sstore.remove(sid)
        try:
            site_close_ports(self.server.store, s)
            self.server.nft.apply()
        except Exception:
            pass
        okn, nginx_msg = apply_all_nginx(ProxyStore(), sstore, self.server.config)
        label = s.get("domain") or f"端口 {s.get('port')}"
        self._send(200 if okn else 500, {
            "ok": bool(okn), "purged": purged,
            "msg": (f"网站 {label} 已删除" + ("（文件已一并删除）" if purged else "（文件保留）")) if okn else nginx_msg,
        })

    def _api_site_root_set(self):
        """POST /api/sites/root {root} 修改站点根目录（只影响之后新建的站点）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        root = os.path.normpath(str(data.get("root", "")).strip())
        if not root or not os.path.isabs(root):
            self._send(400, {"error": "必须是绝对路径"})
            return
        if not site_root_ok(root):
            self._send(400, {"error": f"该路径不允许作为站点根目录（系统目录受保护）：{root}"})
            return
        try:
            os.makedirs(root, exist_ok=True)
        except OSError as e:
            self._send(500, {"error": f"创建目录失败: {e}"})
            return
        self.server.config.set("site_root", root)
        self._send(200, {"ok": True, "site_root": root, "msg": f"站点根目录已设为 {root}（只影响新建站点）"})

    def _api_site_cert(self, sid):
        """POST /api/sites/<id>/cert 申请证书（后台任务，避免长请求阻塞）"""
        token = self._require_auth()
        if token is None:
            return
        s = SiteStore().get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        if not s.get("domain"):
            self._send(400, {"error": "端口站（无域名）不需要证书"})
            return
        body = self._read_json()
        if site_cert_ready(s) and not body.get("force"):
            ci = site_cert_info(s)
            self._send(200, {"ok": True, "reused": True,
                             "msg": f"证书已就绪（引用 {ci['ref']}，剩 {ci['days']} 天），无需重新签发；"
                                    f"如需续期请到「反代证书」的证书模块操作（或强制重新签发）"})
            return
        okdns, why = site_dns_precheck(s["domain"], s.get("cert_ref"))
        if not okdns:
            self._send(400, {"error": why})
            return
        tid = start_task("site_cert", site_issue_cert, sid)
        self._send(200, {"ok": True, "task": tid, "msg": f"正在为 {s['domain']} 申请证书…"})

    def _api_site_logs(self, sid):
        """GET /api/sites/<id>/logs?kind=access|error&lines=200"""
        token = self._require_auth()
        if token is None:
            return
        s = SiteStore().get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        query = parse_qs(urlparse(self.path).query)
        kind = (query.get("kind") or ["access"])[0]
        lines = (query.get("lines") or ["200"])[0]
        if kind not in ("access", "error"):
            kind = "access"
        try:
            lines = int(lines)
        except ValueError:
            lines = 200
        data, err = site_tail_log(s, kind, lines)
        if err:
            self._send(500, {"error": err})
            return
        self._send(200, data)

    def _api_site_stats(self, sid):
        """GET /api/sites/<id>/stats?days=7 访问统计（PV/UV/Top URL/状态码）"""
        token = self._require_auth()
        if token is None:
            return
        s = SiteStore().get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        query = parse_qs(urlparse(self.path).query)
        try:
            days = int((query.get("days") or ["7"])[0])
        except ValueError:
            days = 7
        self._send(200, site_stats(s, days))

    def _api_site_files(self, sid):
        """GET /api/sites/<id>/files?path=xx  列目录
        GET /api/sites/<id>/files?path=xx&op=read  读文本（在线编辑）
        POST /api/sites/<id>/files {op,...}   mkdir|write|rename|delete|chmod|unzip|upload"""
        token = self._require_auth()
        if token is None:
            return
        s = SiteStore().get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        if self.command == "GET":
            query = parse_qs(urlparse(self.path).query)
            rel = (query.get("path") or [""])[0]
            op = (query.get("op") or [""])[0]
            if op == "read":
                content, err = site_read_file(s, rel)
                if err:
                    self._send(400, {"error": err})
                    return
                self._send(200, {"path": rel.strip("/"), "content": content})
                return
            data, err = site_file_list(s, rel)
            if err:
                self._send(400, {"error": err})
                return
            data["roots"] = [{"name": s.get("domain") or f"端口 {s.get('port')}", "path": ""}]
            self._send(200, data)
            return
        data = self._read_json()
        op = str(data.get("op", "")).strip()
        rel = str(data.get("path", "") or "")
        if op == "mkdir":
            ok, msg = site_mkdir(s, str(data.get("name", "") or "").strip().strip("/"))
        elif op == "write":
            ok, msg = site_write_file(s, rel, data.get("content", ""), bool(data.get("overwrite", True)))
        elif op == "upload":
            ok, msg = self._site_upload(s, data)
        elif op == "rename":
            ok, msg = site_rename(s, rel, str(data.get("name", "")))
        elif op == "delete":
            ok, msg = site_delete_path(s, rel, bool(data.get("recursive")))
        elif op == "chmod":
            ok, msg = site_chmod(s, rel, data.get("mode", ""))
        elif op == "unzip":
            ok, msg = site_unzip(s, rel)
        else:
            self._send(400, {"error": "不支持的操作"})
            return
        self._send(200 if ok else 400, {"ok": bool(ok), "msg": msg})

    def _site_upload(self, s, data):
        """上传文件（前端 FileReader → base64）：{op:upload, path:目录, name:文件名, content_b64}"""
        import base64 as _b64
        name = str(data.get("name", "") or "").strip().replace("\\", "/")
        if not name or "/" in name or name in (".", ".."):
            return False, "文件名不合法"
        raw = data.get("content_b64", "")
        if not isinstance(raw, str) or not raw:
            return False, "文件内容为空"
        if len(raw) > SITE_UPLOAD_MAX_BYTES * 4 // 3 + 1024:
            return False, f"文件超过 {SITE_UPLOAD_MAX_BYTES // 1024 // 1024}MB 上限"
        try:
            blob = _b64.b64decode(raw, validate=False)
        except Exception as e:
            return False, f"内容解码失败: {e}"
        if len(blob) > SITE_UPLOAD_MAX_BYTES:
            return False, f"文件超过 {SITE_UPLOAD_MAX_BYTES // 1024 // 1024}MB 上限"
        rel = str(data.get("path", "") or "").strip().strip("/")
        target, err = site_resolve_path(s, (rel + "/" + name) if rel else name)
        if err:
            return False, err
        if os.path.isdir(target):
            return False, "同名目录已存在"
        if not os.path.isdir(os.path.dirname(target)):
            return False, "上级目录不存在"
        if os.path.islink(target):
            return False, "拒绝写入符号链接（防逃逸）"
        if os.path.exists(target) and not data.get("overwrite"):
            return False, "同名文件已存在"
        try:
            with open(target, "wb") as f:
                f.write(blob)
            site_chown_www(target, 0o644)
        except OSError as e:
            return False, f"写入失败: {e}"
        return True, f"已上传 {name}（{len(blob)} 字节）"

    def _api_site_download(self, sid):
        """GET /api/sites/<id>/download?path=xx 下载站点内文件"""
        token = self._require_auth()
        if token is None:
            return
        s = SiteStore().get(sid)
        if not s:
            self._send(404, {"error": "站点不存在"})
            return
        query = parse_qs(urlparse(self.path).query)
        rel = (query.get("path") or [""])[0]
        p, err = site_resolve_path(s, rel)
        if err or not os.path.isfile(p) or os.path.islink(p):
            self._send(404, {"error": err or "文件不存在"})
            return
        try:
            size = os.path.getsize(p)
            if size > 256 * 1024 * 1024:
                self._send(400, {"error": "文件超过 256MB，请用 SFTP 下载"})
                return
            with open(p, "rb") as f:
                blob = f.read()
        except OSError as e:
            self._send(500, {"error": f"读取失败: {e}"})
            return
        name = os.path.basename(p).replace('"', "")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(blob)

    def _api_username(self):
        """修改面板登录用户名"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = str(data.get("username", "")).strip()
        import re
        if not re.match(r"^[A-Za-z0-9_]{3,32}$", name):
            self._send(400, {"error": "用户名需为 3-32 位字母、数字或下划线"})
            return
        self.server.config.set("username", name)
        self._send(200, {"ok": True, "msg": f"登录用户名已修改为 {name}，下次登录请用新用户名"})

    # ---------- Docker API（v1.24.0）----------

    def _api_docker_status(self):
        """GET /api/docker → 安装状态/版本/容器数"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, docker_status())

    def _api_docker_containers(self):
        """GET /api/docker/containers → 容器列表"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"containers": docker_containers(True)})

    def _api_docker_images(self):
        """GET /api/docker/images → 镜像列表"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"images": docker_images()})

    def _api_docker_stats(self):
        """GET /api/docker/stats → 资源监控"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"stats": docker_stats()})

    def _api_docker_logs(self, cid):
        """GET /api/docker/logs/<id> → 容器日志"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"logs": docker_logs(cid)})

    def _api_docker_install(self):
        """POST /api/docker/install {source: official|china} → 一键安装 docker + compose"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        source = str(data.get("source", "official"))
        if source not in ("official", "china"):
            source = "official"
        self._run_long_task("docker/install", install_docker_pkgs, source)

    def _api_docker_uninstall(self):
        """POST /api/docker/uninstall → 一键卸载 docker（国内/国外源安装均可）"""
        token = self._require_auth()
        if token is None:
            return
        self._run_long_task("docker/uninstall", uninstall_docker_pkgs)

    def _api_docker_action(self):
        """POST /api/docker/action {action, id} → start/stop/restart/remove"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        act = str(data.get("action", ""))
        cid = str(data.get("id", "")).strip()
        if act not in ("start", "stop", "restart", "remove"):
            self._send(400, {"error": "无效操作，支持: start/stop/restart/remove"})
            return
        if not cid:
            self._send(400, {"error": "缺少容器 ID"})
            return
        ok, msg = docker_action(act, cid)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_create(self):
        """POST /api/docker/create {name, image, ports, envs} → 创建容器"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = str(data.get("name", "")).strip()
        image = str(data.get("image", "")).strip()
        if not name or not image:
            self._send(400, {"error": "容器名称和镜像不能为空"})
            return
        self._run_long_task("docker/create", docker_create, name, image,
                            str(data.get("ports", "")),
                            str(data.get("envs", "")))

    def _api_docker_pull(self):
        """POST /api/docker/pull {name} → 拉取镜像"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = str(data.get("name", "")).strip()
        if not name:
            self._send(400, {"error": "镜像名不能为空"})
            return
        self._run_long_task("docker/pull", docker_pull, name)

    def _api_docker_rmi(self):
        """POST /api/docker/rmi {id} → 删除镜像"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        image_id = str(data.get("id", "")).strip()
        if not image_id:
            self._send(400, {"error": "缺少镜像 ID"})
            return
        ok, msg = docker_rmi(image_id)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_prune(self):
        """POST /api/docker/prune → 清理全部未使用镜像"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = docker_image_prune()
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_data_root(self):
        """POST /api/docker/data-root → 配置镜像存储目录为 /DockerData/dockerimage"""
        token = self._require_auth()
        if token is None:
            return
        self._run_long_task("docker/data-root", set_docker_data_root)

    def _api_docker_compose_up(self):
        """POST /api/docker/compose/up {content, folder} → 保存并启动 compose"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        content = str(data.get("content", ""))
        if not content.strip():
            self._send(400, {"error": "docker-compose.yml 内容不能为空"})
            return
        self._run_long_task("docker/compose/up", docker_compose_up,
                            content, str(data.get("folder", "")))

    def _api_docker_compose_list(self):
        """GET /api/docker/compose → 已保存的 compose 项目列表"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"projects": docker_compose_list()})

    def _api_docker_compose_start(self):
        """POST /api/docker/compose/start {folder} → 启动指定已保存项目"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        folder = str(data.get("folder", "")).strip()
        if not folder:
            self._send(400, {"error": "缺少项目文件夹名称"})
            return
        ok, msg = docker_compose_start(folder)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_compose_upgrade(self):
        """POST /api/docker/compose/upgrade {folder} → 升级指定已保存项目（拉最新镜像+重建）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        folder = str(data.get("folder", "")).strip()
        if not folder:
            self._send(400, {"error": "缺少项目文件夹名称"})
            return
        self._run_long_task("docker/compose/upgrade", docker_compose_upgrade, folder)

    def _api_docker_compose_down(self):
        """POST /api/docker/compose/down {folder} → 停止指定 compose 项目"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        folder = str(data.get("folder", ""))
        ok, msg = docker_compose_down(folder)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_dirs_create(self):
        """POST /api/docker/dirs → 一键创建 /DockerData 及常用子目录"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = create_docker_dirs()
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_dirs_status(self):
        """GET /api/docker/dirs → 目录创建状态（是否存在/子目录数）"""
        token = self._require_auth()
        if token is None:
            return
        base = DOCKER_DATA_BASE
        exists = os.path.isdir(base)
        sub_count = 0
        if exists:
            try:
                sub_count = sum(1 for d in DOCKER_DATA_DIRS if os.path.isdir(os.path.join(base, d)))
            except Exception:
                pass
        self._send(200, {"exists": exists, "base": base,
                         "sub_dirs": sub_count, "total": len(DOCKER_DATA_DIRS)})

    def _api_bruteforce_ban(self):
        """手动封禁 IP：{ip, permanent?} → 拒绝规则 + 封禁记录。
        permanent=true 写入永久时间戳（2100 年），不会自动解封；
        对已在封禁列表的 IP 调用 permanent=true = 把临时封禁升级为永久"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        ip = str(data.get("ip", "")).strip()
        if not is_valid_ip_or_net(ip) or "/" in ip or "-" in ip:
            self._send(400, {"error": "请输入单个 IP 地址（IPv4/IPv6）"})
            return
        permanent = bool(data.get("permanent"))
        store = self.server.store
        exists = any(r.get("type") == "ip_deny" and r.get("ip") == ip for r in store.rules)
        bans = load_bans()
        if permanent:
            if not exists:
                store.add({"type": "ip_deny", "ip": ip, "comment": MANUAL_BAN_COMMENT})
            was_permanent = int(bans.get(ip, 0)) >= BF_PERMANENT_UNTIL
            bans[ip] = BF_PERMANENT_UNTIL
            save_bans(bans)
            if not exists:
                ok, msg = self.server.nft.apply()
                if not ok:
                    self._send(500, {"error": msg})
                    return
            self._send(200, {"ok": True,
                             "msg": f"{ip} 已是永久封禁" if was_permanent
                             else f"{ip} 已永久封禁（不会自动解封，只能手动解封）"})
            return
        if exists:
            self._send(400, {"error": f"{ip} 已在封禁列表"})
            return
        store.add({"type": "ip_deny", "ip": ip, "comment": MANUAL_BAN_COMMENT})
        bans[ip] = int(time.time()) + bf_cfg(self.server.config)["ban_seconds"]
        save_bans(bans)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": f"已封禁 {ip}"})

    def _api_bruteforce_unban(self, ip=None):
        """手动解封 IP：{ip} → 删除该 IP 的全部拒绝规则与封禁记录"""
        token = self._require_auth()
        if token is None:
            return
        if ip is None:
            data = self._read_json()
            ip = str(data.get("ip", "")).strip()
        if not ip:
            self._send(400, {"error": "请输入 IP 地址"})
            return
        store = self.server.store
        before = len(store.rules)
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "ip_deny" and r.get("ip") == ip)]
        removed = len(store.rules) < before
        bans = load_bans()
        if ip in bans:
            del bans[ip]
            save_bans(bans)
        if removed:
            store.save()
            ok, msg = self.server.nft.apply()
            if not ok:
                self._send(500, {"error": msg})
                return
        self._send(200, {"ok": True,
                         "msg": f"{ip} 已解封" if removed else f"{ip} 不在封禁列表"})

    def _api_traffic(self):
        """网卡流量统计：GET /api/traffic?iface=eth0&from=YYYY-MM-DD&to=YYYY-MM-DD
        返回 网卡列表/实时速率/今日/昨日/近7天/总累计/自定义日期范围累计"""
        token = self._require_auth()
        if token is None:
            return
        traffic = getattr(self.server, "traffic", None)
        if traffic is None:
            traffic = TrafficStore()  # 兜底（未挂载时独立实例）
        try:
            traffic.record()  # 顺手补一次采样，让今日与速率最新
        except Exception:
            pass
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        iface = (qs.get("iface") or [""])[0].strip()
        if not iface:
            iface = traffic_active_iface(traffic)  # 默认选中当前有流量的网卡
        from_date = (qs.get("from") or [""])[0].strip()
        to_date = (qs.get("to") or [""])[0].strip()
        for name, val in (("开始日期", from_date), ("结束日期", to_date)):
            if val:
                try:
                    datetime.date.fromisoformat(val)
                except ValueError:
                    self._send(400, {"error": f"{name}格式应为 YYYY-MM-DD"})
                    return
        if from_date and to_date and to_date < from_date:
            self._send(400, {"error": "结束日期不能早于开始日期"})
            return
        today = datetime.date.today().isoformat()
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        resp = {
            "ifaces": traffic.ifaces(),
            "primary": primary_iface(),
            "current": iface,
            "rates": traffic._rates,
            "today": traffic.totals_for(iface, start=today),
            "yesterday": traffic.totals_for(iface, start=yesterday, end=yesterday),
            "week": traffic.daily(iface, 7),
            "total": traffic.totals_for(iface),
            "since": traffic.data.get("since"),
        }
        if from_date:
            end = to_date or today
            d0 = datetime.date.fromisoformat(from_date)
            d1 = datetime.date.fromisoformat(end)
            resp["custom"] = {
                "rx": traffic.totals_for(iface, start=from_date, end=end)["rx"],
                "tx": traffic.totals_for(iface, start=from_date, end=end)["tx"],
                "from": from_date,
                "to": end,
                "days": max(0, (d1 - d0).days + 1),
            }
        self._send(200, resp)

    def _api_procs(self):
        """进程流量统计：GET /api/procs?detail=<进程名>
        返回 {installed, ok, error, procs, ts, history}；
        带 detail 参数时返回 {detail: {name, days: 近7天, total_rx, total_tx}}；
        采样约 2-3 秒"""
        token = self._require_auth()
        if token is None:
            return
        store = getattr(self.server, "procs", None) or ProcStore()
        resp = procs_snapshot()
        resp["installed"] = nethogs_available()
        resp["ts"] = int(time.time())
        if resp.get("ok"):
            store.record(resp["procs"])
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        detail_name = (qs.get("detail") or [""])[0].strip()
        if detail_name:
            resp["detail"] = store.detail(detail_name)
        else:
            resp["history"] = store.history()
        self._send(200, resp)

    def _api_procs_install(self):
        """一键安装 nethogs：POST /api/procs/install"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = install_nethogs()
        if ok:
            self._send(200, {"ok": True, "msg": msg, "installed": nethogs_available()})
        else:
            self._send(500, {"error": msg})

    def _api_procs_clear(self):
        """清空进程流量历史：POST /api/procs/clear"""
        token = self._require_auth()
        if token is None:
            return
        store = getattr(self.server, "procs", None) or ProcStore()
        store.clear()
        self._send(200, {"ok": True, "msg": "进程历史已清空"})

    def _api_bbr(self):
        """查询 BBR 状态与内核版本"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "enabled": bbr_status(),
            "supported": bbr_available(),
            "kernel": os.uname().release,
        })

    def _api_bbr_enable(self):
        """一键开启 BBR"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = enable_bbr()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg, "enabled": bbr_status()})

    def _api_ipv6(self):
        """GET：查询 IPv6 状态；POST {mode}：设置 v4_first / disable / enable"""
        token = self._require_auth()
        if token is None:
            return
        if self.command == "GET":
            self._send(200, {"status": ipv6_status()})
            return
        data = self._read_json()
        mode = str(data.get("mode", ""))
        ok, msg = set_ipv6_mode(mode)
        if not ok:
            self._send(400, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg, "status": ipv6_status()})

    def _api_restart(self):
        """重启面板服务（先响应，再延迟重启，前端收到反馈后自动重连）"""
        token = self._require_auth()
        if token is None:
            return
        if DRY_RUN:
            log("[dry-run] 重启面板服务（跳过）")
            self._send(200, {"ok": True, "msg": "dry-run: 重启面板（跳过）"})
            return
        threading.Timer(1.0, restart_service).start()
        self._send(200, {"ok": True, "msg": "面板重启中，约 5 秒后自动重新连接..."})

    def _api_bruteforce(self):
        """查询防爆破配置与当前封禁列表"""
        token = self._require_auth()
        if token is None:
            return
        bf = bf_cfg(self.server.config)
        bans = load_bans()
        now = time.time()
        items = [{"ip": ip, "until": int(u),
                  "permanent": int(u) >= BF_PERMANENT_UNTIL,
                  "remaining": max(0, int(u - now))}
                 for ip, u in sorted(bans.items())]
        self._send(200, {
            "enabled": bool(bf["enabled"]),
            "max_fails": bf["max_fails"],
            "ban_seconds": bf["ban_seconds"],
            "fail_window": bf["fail_window"],
            "bans": items,
        })

    def _api_bruteforce_set(self):
        """更新防爆破配置：{enabled?, max_fails?, ban_seconds?, fail_window?}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        bf = bf_cfg(self.server.config)
        if "enabled" in data:
            bf["enabled"] = bool(data["enabled"])
        for key, lo, hi in (("max_fails", 1, 100), ("ban_seconds", 60, 2592000),
                            ("fail_window", 60, 86400)):
            if key in data:
                try:
                    v = int(data[key])
                except (TypeError, ValueError):
                    self._send(400, {"error": f"{key} 必须是数字"})
                    return
                if not (lo <= v <= hi):
                    self._send(400, {"error": f"{key} 范围 {lo}-{hi}"})
                    return
                bf[key] = v
        self.server.config.set("bruteforce", bf)
        state = "已启用" if bf["enabled"] else "已停用"
        self._send(200, {"ok": True, "msg": f"SSH 防爆破{state}（失败 {bf['max_fails']} 次封禁 {bf['ban_seconds']} 秒）"})

    def _api_firewall(self):
        """一键开启/关闭防火墙：{enabled: true|false}
        关闭=删除 nftables 表（规则配置保留，开启时恢复）；开启=重新加载规则"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        enabled = bool(data.get("enabled"))
        if enabled:
            ok, msg = self.server.nft.apply()
            if not ok:
                self._send(500, {"error": f"开启失败: {msg}"})
                return
            self.server.config.set("firewall_enabled", True)
            self._send(200, {"ok": True, "msg": "防火墙已开启（规则已加载生效）"})
        else:
            ok, msg = self.server.nft.disable()
            if not ok:
                self._send(500, {"error": f"关闭失败: {msg}"})
                return
            self.server.config.set("firewall_enabled", False)
            self._send(200, {"ok": True, "msg": "防火墙已关闭（所有端口放行，规则配置已保留，重新开启恢复）"})

    def _api_proxy_install(self):
        """一键安装 nginx + certbot（按发行版 apt/pacman/dnf），并自动写入 nginx 配置。
        长任务 → 后台执行（nginx 网关 60s 超时不会误报）"""
        token = self._require_auth()
        if token is None:
            return
        self._run_long_task("proxy/install", self._proxy_install_work)

    def _proxy_install_work(self):
        """proxy/install 主体（独立方法便于后台线程执行；返回 (ok, msg)）"""
        todo = []
        if not nginx_available():
            todo.append("nginx")
        if not certbot_available():
            todo.append("certbot")
        if todo:
            ok, msg = install_pkgs(todo)
            if not ok:
                return False, msg
        # 启动 nginx 服务
        if nginx_available() and not nginx_active():
            try:
                subprocess.run(["systemctl", "enable", "--now", "nginx"],
                               capture_output=True, text=True, timeout=30)
            except Exception:
                pass
        # 自动写入 nginx 配置：ACME webroot + 默认兜底 + 已有代理配置
        try:
            os.makedirs(ACME_WEBROOT, exist_ok=True)
        except OSError:
            pass
        ensure_nginx_default()
        ok2, msg2 = apply_proxies(ProxyStore())
        if not ok2:
            return False, f"nginx 配置写入失败: {msg2}"
        return True, f"安装完成（{', '.join(todo) or '已是最新'}）；{msg2}"

    def _api_cert(self):
        """独立证书列表：域名、邮箱、有效期、路径"""
        token = self._require_auth()
        if token is None:
            return
        store = load_cert_store()
        items = []
        for domain, entry in store.items():
            email, method, provider, source = _cert_meta(entry)
            item = {"domain": domain, "email": email, "method": method, "provider": provider,
                    "source": source,
                    "cert_exists": cert_files_exist(domain),
                    "cert_expiry": cert_status(domain)}
            if item["cert_exists"]:
                item["cert_path"] = f"{LE_LIVE}/{domain}/fullchain.pem"
                item["key_path"] = f"{LE_LIVE}/{domain}/privkey.pem"
            items.append(item)
        self._send(200, {
            "installed": nginx_available(),
            "certbot": certbot_available(),
            "renew": cert_renew_status(),
            "certs": items,
            "dns_creds": {p: bool((self.server.config.get("dns_creds") or {}).get(p))
                          for p in DNS_PROVIDERS},
        })

    def _api_cert_creds_clear(self):
        """清除已保存的 DNS 凭证：POST /api/cert/creds {provider}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        provider = str(data.get("provider", "")).strip()
        if provider not in DNS_PROVIDERS:
            self._send(400, {"error": f"不支持的提供商: {provider}"})
            return
        dns_creds = dict(self.server.config.get("dns_creds") or {})
        if provider in dns_creds:
            del dns_creds[provider]
        self.server.config.set("dns_creds", dns_creds)
        self._send(200, {"ok": True, "msg": f"{DNS_PROVIDERS[provider]['name']} 凭证已清除"})

    def _api_cert_add(self):
        """单独申请 SSL 证书：{domain, email?, method?: http|dns, provider?, credentials?}

        http = certbot webroot（需 80 可达）；dns = acme.sh DNS 验证（Cloudflare/DNSPod/阿里云）
        签发为长任务 → 后台执行（nginx 网关 60s 超时不会误报）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        domain = str(data.get("domain", "")).strip().lower()
        email = str(data.get("email", "")).strip()
        method = str(data.get("method", "http")).strip().lower()
        if not re.match(r"^[a-zA-Z0-9.\-*]+$", domain) or not domain:
            self._send(400, {"error": "域名格式无效（如 example.com 或 *.example.com）"})
            return
        if method == "dns":
            provider = str(data.get("provider", "")).strip()
            creds = {k: str(v).strip() for k, v in (data.get("credentials") or {}).items() if str(v).strip()}
            # 凭证保存（v1.25.4 用户要求）：新输入保存到 config.json dns_creds，留空=用已保存
            cfg = self.server.config
            saved = (cfg.get("dns_creds") or {}).get(provider) or {}
            if creds:
                dns_creds = dict(cfg.get("dns_creds") or {})
                dns_creds[provider] = {**saved, **creds}
                cfg.set("dns_creds", dns_creds)
                merged = dns_creds[provider]
            else:
                merged = saved

            def _issue_dns_work():
                ok, msg = issue_cert_dns(domain, email, provider, merged)
                if not ok:
                    return False, msg
                store = load_cert_store()
                store[domain] = {"email": email, "method": "dns", "provider": provider}
                save_cert_store(store)
                return True, f"{domain} 证书已签发（DNS 验证）"

            self._run_long_task("cert/issue-dns", _issue_dns_work)
            return
        if method != "http":
            self._send(400, {"error": "method 必须是 http 或 dns"})
            return
        if not nginx_available():
            self._send(400, {"error": "未安装 nginx，请先在反向代理模块一键安装（ACME 挑战需要）"})
            return
        ensure_nginx_default()   # 确保 80 挑战路径兜底配置存在
        ok, msg = reload_nginx()  # 新配置必须立即生效，否则挑战仍 404
        if not ok:
            self._send(500, {"error": msg})
            return

        def _issue_http_work():
            ok, msg = issue_cert(domain, email)
            if not ok:
                return False, msg
            store = load_cert_store()
            store[domain] = {"email": email, "method": "http"}
            save_cert_store(store)
            return True, f"{domain} 证书已签发"

        self._run_long_task("cert/issue", _issue_http_work)

    def _api_cert_action(self, suffix):
        """证书操作：POST /api/cert/<domain> {action: renew|delete}"""
        token = self._require_auth()
        if token is None:
            return
        domain = suffix.strip().lower()
        data = self._read_json()
        action = str(data.get("action", ""))
        store = load_cert_store()
        if domain not in store:
            self._send(400, {"error": "该域名不在独立证书列表中"})
            return
        if action == "renew":
            email, method, provider, source = _cert_meta(store.get(domain))

            def _renew_work():
                if method == "dns":
                    ok, msg = renew_cert_dns(domain)
                else:
                    ok, msg = renew_cert(domain)
                if not ok:
                    return False, msg
                return True, f"{domain} 证书已续期"

            self._run_long_task("cert/renew", _renew_work)
        elif action == "delete":
            del store[domain]
            save_cert_store(store)
            self._send(200, {"ok": True, "msg": f"{domain} 已从列表移除（证书文件保留，供服务引用）"})
        else:
            self._send(400, {"error": "action 必须是 renew 或 delete"})

    def _api_proxy(self):
        """查询反向代理列表与 nginx/certbot 状态"""
        token = self._require_auth()
        if token is None:
            return
        items = []
        for p in ProxyStore().proxies:
            item = {**p}
            ref = (p.get("cert_ref") or "").strip() or p["domain"]
            item["cert_ref_resolved"] = ref
            item["cert_expiry"] = cert_status(ref)
            item["cert_exists"] = cert_files_exist(ref)
            if item["cert_exists"]:
                item["cert_path"] = f"{LE_LIVE}/{ref}/fullchain.pem"
                item["key_path"] = f"{LE_LIVE}/{ref}/privkey.pem"
            items.append(item)
        self._send(200, {
            "installed": nginx_available(),
            "active": nginx_active(),
            "certbot": certbot_available(),
            "renew": cert_renew_status(),
            "proxies": items,
        })

    def _api_proxy_add(self):
        """添加反向代理：{domain, target_host, target_port, scheme?, websocket?, ssl?}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        domain = str(data.get("domain", "")).strip().lower()
        host = str(data.get("target_host", "")).strip()
        try:
            port = int(data.get("target_port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "目标端口必须是数字"})
            return
        if not re.match(r"^[a-zA-Z0-9.\-*]+$", domain) or not domain:
            self._send(400, {"error": "域名格式无效（支持域名 / IP / 通配符 *.example.com）"})
            return
        if not host:
            self._send(400, {"error": "目标主机不能为空"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "目标端口范围 1-65535"})
            return
        scheme = data.get("scheme", "http")
        if scheme not in ("http", "https"):
            self._send(400, {"error": "scheme 必须是 http 或 https"})
            return
        pstore = ProxyStore()
        if any(p["domain"] == domain for p in pstore.proxies):
            self._send(400, {"error": f"域名 {domain} 已存在代理"})
            return
        # 证书引用（v1.25.2）：cert_ref 指定复用已申请证书（含 *.example.com 泛域名），空=自动申请
        cert_ref = str(data.get("cert_ref", "") or "").strip().lower()
        if cert_ref and not os.path.isfile(os.path.join(LE_LIVE, cert_ref, "fullchain.pem")):
            self._send(400, {"error": f"证书不存在: {cert_ref}（请先在「单独申请 SSL 证书」申请，或选「自动申请」）"})
            return
        p = pstore.add({
            "domain": domain, "target_host": host, "target_port": port,
            "scheme": scheme, "websocket": bool(data.get("websocket")),
            "hsts": bool(data.get("hsts")),
            "ssl": bool(data.get("ssl")),
            "cert_ref": cert_ref,
        })
        # 防火墙放行反代入口端口（幂等）：有证书（ssl 或 cert_ref）→ 80+443，http 反代 → 80
        # ⚠ v1.24.64 修复：http 反代（ssl:false）nginx 监听 80，若不放行 80，
        # 严格模式（policy drop）下公网入口被自己防火墙挡死（Oracle 新机实测）
        # ⚠ v1.25.7 修复：复用证书反代（ssl:false + cert_ref 有值）nginx 监听 443，
        # 旧逻辑只看 ssl 字段漏放 443，严格模式下公网 https 被防火墙挡死（伦敦新机实测）
        store = self.server.store
        changed = False
        https_on = bool(p.get("ssl") or p.get("cert_ref"))
        for entry_port in ([443, 80] if https_on else [80]):
            entry_comment = "反代:HTTPS" if entry_port == 443 else "反代:HTTP"
            if not any(r.get("type") == "port_allow" and r.get("port") == entry_port
                       for r in store.rules):
                store.add({"type": "port_allow", "proto": "tcp", "port": entry_port,
                           "comment": entry_comment})
                changed = True
        # 禁止公网直连目标端口（80/443 除外——入口端口由 nginx 兜底 444 控制）
        # 拒绝规则含回环豁免，不影响 nginx 本机转发
        if port not in (80, 443) and not any(
                r.get("type") == "port_deny" and r.get("port") == port
                and r.get("comment") == PROXY_TARGET_DENY_COMMENT for r in store.rules):
            store.add({"type": "port_deny", "proto": "tcp", "port": port,
                       "comment": PROXY_TARGET_DENY_COMMENT})
            changed = True
        if changed:
            store.save()
        self.server.nft.apply()
        ok, msg = apply_proxies(pstore)
        self._send(200, {"ok": True, "msg": f"代理 {domain} 已添加（{msg}）", "proxy": p})

    def _api_proxy_action(self, suffix):
        """代理操作：POST /api/proxy/<id>  {action: enable|ssl, ...}
        或 POST /api/proxy/<id>/enable  /ssl"""
        token = self._require_auth()
        if token is None:
            return
        parts = suffix.split("/")
        pid = parts[0]
        path_action = parts[1] if len(parts) > 1 else None
        data = self._read_json()
        action = path_action or str(data.get("action", ""))
        pstore = ProxyStore()
        p = pstore.get(pid)
        if not p:
            self._send(400, {"error": "代理不存在"})
            return
        if action == "enable":
            p["enabled"] = bool(data.get("enabled", True))
            pstore.save()
            ok, msg = apply_proxies(pstore)
            self._send(200, {"ok": True, "msg": f"代理 {p['domain']} 已{'启用' if p['enabled'] else '停用'}（{msg}）"})
        elif action == "ssl":
            def _ssl_work():
                ok, msg = issue_cert(p["domain"], str(data.get("email", "")).strip())
                if not ok:
                    return False, msg
                p["ssl"] = True
                pstore.save()
                # 反代申请的证书自动登记进证书列表（source=proxy，与独立申请统一管理）
                store = load_cert_store()
                if p["domain"] in store and isinstance(store[p["domain"]], dict):
                    store[p["domain"]]["source"] = "proxy"
                else:
                    store[p["domain"]] = {"email": str(data.get("email", "")).strip(),
                                          "method": "http", "source": "proxy"}
                save_cert_store(store)
                ok2, msg2 = apply_proxies(pstore)
                tail = f"；{msg2}" if ok2 else f"；配置应用失败: {msg2}"
                return True, msg + tail

            self._run_long_task("proxy/ssl", _ssl_work)
        elif action == "renew":
            ref = (p.get("cert_ref") or "").strip() or p["domain"]
            cstore = load_cert_store()
            _, method, _, _ = _cert_meta(cstore.get(ref))

            def _renew_work():
                if method == "dns":
                    ok, msg = renew_cert_dns(ref)
                else:
                    ok, msg = renew_cert(ref)
                if not ok:
                    return False, msg
                return True, msg

            self._run_long_task("proxy/renew", _renew_work)
        elif action == "blockip":
            p["block_ip"] = bool(data.get("enabled", True))
            pstore.save()
            ok, msg = apply_proxies(pstore)
            state = "已开启" if p["block_ip"] else "已关闭"
            # 规则联动（v1.24.28 用户明确要求"总开关"心智）：
            # 开启 → 幂等补建目标端口拒绝规则（缺失自动重建）
            # 关闭 → 删除该端口的拒绝规则（nginx 入口 + 防火墙保护同时放开）
            # ⚠ 用户已知悉：关闭后目标端口（含 Docker 发布端口）公网直连不再受防火墙保护
            tail = ""
            tport = p.get("target_port")
            if tport and tport not in (80, 443):
                store = self.server.store
                if p["block_ip"]:
                    # 开启：补建（幂等）
                    if not any(r.get("type") == "port_deny" and r.get("port") == tport
                               and r.get("comment") == PROXY_TARGET_DENY_COMMENT
                               for r in store.rules):
                        store.add({"type": "port_deny", "proto": "tcp", "port": tport,
                                   "comment": PROXY_TARGET_DENY_COMMENT})
                        store.save()
                        self.server.nft.apply()
                        tail = "；已重建目标端口拒绝规则"
                else:
                    # 关闭：删除（联动）
                    before = len(store.rules)
                    store.rules = [r for r in store.rules
                                   if not (r.get("type") == "port_deny" and r.get("port") == tport
                                           and r.get("comment") == PROXY_TARGET_DENY_COMMENT)]
                    if len(store.rules) != before:
                        store.save()
                        self.server.nft.apply()
                        tail = "；已删除目标端口拒绝规则"
            self._send(200, {"ok": True, "msg": f"{p['domain']} 禁止 IP+端口访问{state}（{msg}）{tail}"})
        elif action == "edit":
            if "scheme" in data:
                sc = str(data.get("scheme"))
                if sc not in ("http", "https"):
                    self._send(400, {"error": "scheme 必须是 http 或 https"})
                    return
                p["scheme"] = sc
            # 证书引用可更换（v1.25.2）：空=自动申请/自身域名，非空=复用已申请证书
            if "cert_ref" in data:
                ref = str(data.get("cert_ref") or "").strip().lower()
                if ref and not os.path.isfile(os.path.join(LE_LIVE, ref, "fullchain.pem")):
                    self._send(400, {"error": f"证书不存在: {ref}（请先在「单独申请 SSL 证书」申请）"})
                    return
                p["cert_ref"] = ref
            p["websocket"] = bool(data.get("websocket", p.get("websocket", False)))
            p["hsts"] = bool(data.get("hsts", p.get("hsts", False)))
            pstore.save()
            ok, msg = apply_proxies(pstore)
            tail = "" if ok else f"；配置应用失败: {msg}"
            self._send(200, {"ok": True, "msg": f"{p['domain']} 已更新（WebSocket: {'开' if p['websocket'] else '关'} / HSTS: {'开' if p['hsts'] else '关'}）{tail}"})
        else:
            self._send(400, {"error": f"未知操作: {action}（支持 enable / ssl / renew / blockip / edit）"})

    def _api_proxy_delete(self, pid):
        """删除代理"""
        token = self._require_auth()
        if token is None:
            return
        pstore = ProxyStore()
        p = pstore.get(pid)
        if not p:
            self._send(400, {"error": "代理不存在"})
            return
        domain = p["domain"]
        target_port = p.get("target_port")
        pstore.remove(pid)
        # 清理目标端口禁止规则（若没有其他代理仍指向该端口）
        if target_port and target_port not in (80, 443):
            store = self.server.store
            if not any(q.get("target_port") == target_port for q in pstore.proxies):
                store.rules = [r for r in store.rules
                               if not (r.get("type") == "port_deny" and r.get("port") == target_port
                                       and r.get("comment") == PROXY_TARGET_DENY_COMMENT)]
                store.save()
                self.server.nft.apply()
        ok, msg = apply_proxies(pstore)
        self._send(200, {"ok": True, "msg": f"代理 {domain} 已删除（{msg}）"})

    def _api_list_rules(self):
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"rules": self.server.store.rules})

    def _api_edit_rule(self, rid):
        """修改规则备注：{comment}"""
        token = self._require_auth()
        if token is None:
            return
        store = self.server.store
        r = store.get(rid)
        if not r:
            self._send(400, {"error": "规则不存在"})
            return
        data = self._read_json()
        if "comment" not in data:
            self._send(400, {"error": "未提供备注内容"})
            return
        r["comment"] = str(data.get("comment", "")).strip()[:100]
        store.save()
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": "备注已修改"})

    def _api_add_rule(self):
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        rtype = data.get("type")
        if rtype not in RuleStore.RULE_TYPES:
            self._send(400, {"error": f"type 必须是 {RuleStore.RULE_TYPES} 之一"})
            return
        rule = {"type": rtype, "comment": str(data.get("comment", ""))[:60]}
        if rtype.startswith("port"):
            proto = data.get("proto", "tcp")
            if proto not in VALID_PROTOS:
                self._send(400, {"error": f"proto 必须是 {VALID_PROTOS} 之一"})
                return
            try:
                port = int(data.get("port", 0))
            except (TypeError, ValueError):
                self._send(400, {"error": "端口必须是数字"})
                return
            if not (1 <= port <= 65535):
                self._send(400, {"error": "端口范围 1-65535"})
                return
            rule["proto"] = proto
            rule["port"] = port
        else:
            ip = str(data.get("ip", "")).strip()
            if not ip:
                self._send(400, {"error": "IP 不能为空"})
                return
            if not is_valid_ip_or_net(ip):
                self._send(400, {"error": "IP 格式无效（支持 1.2.3.4 / 1.2.3.0/24 / 1.2.3.1-1.2.3.50 / IPv6）"})
                return
            rule["ip"] = ip
        rule = self.server.store.add(rule)
        ok, msg = self.server.nft.apply()
        if not ok:
            # 应用失败：回滚规则清单
            self.server.store.remove(rule["id"])
            self._send(500, {"error": f"规则应用失败，已回滚: {msg}"})
            return
        self._send(200, {"ok": True, "rule": rule, "msg": msg})

    def _api_delete_rule(self, rule_id):
        token = self._require_auth()
        if token is None:
            return
        ok, msg = self.server.store.remove(rule_id)
        if not ok:
            self._send(400, {"error": msg})
            return
        nft_ok, nft_msg = self.server.nft.apply()
        if not nft_ok:
            self._send(500, {"error": f"规则应用失败: {nft_msg}"})
            return
        self._send(200, {"ok": True, "msg": nft_msg})

    def _api_service(self):
        """服务模板开关：{name: 'http', enabled: true}
        SSH 服务端口跟随当前保护端口（不固定 22），其余服务固定"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = data.get("name")
        enabled = bool(data.get("enabled"))
        if name not in SERVICES:
            self._send(400, {"error": f"服务必须是 {list(SERVICES)} 之一"})
            return
        if name == "ssh":
            proto, port = "tcp", int(self.server.config.get("ssh_port", SSH_PORT_DEFAULT))
        else:
            proto, port = SERVICES[name]
        # 找同名规则
        existing = [r for r in self.server.store.rules
                    if r.get("type") == "port_allow" and r.get("port") == port]
        if enabled and not existing:
            self.server.store.add({"type": "port_allow", "proto": proto, "port": port,
                                   "comment": f"服务:{name}"})
        elif not enabled:
            # 关闭服务：删除该端口全部非保护放行规则（含手动开放的「面板开放」注释规则）
            for r in existing:
                if not r.get("protected"):
                    self.server.store.remove(r["id"])
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_close_port(self):
        """一键删除端口放行规则：{port, proto?} proto ∈ tcp|udp|both
        tcp 删 tcp+both，udp 删 udp+both，both 删该端口全部放行"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        proto = data.get("proto", "tcp")
        if proto not in VALID_PROTOS:
            self._send(400, {"error": f"proto 必须是 {VALID_PROTOS} 之一"})
            return
        store = self.server.store
        before = len(store.rules)
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "port_allow" and r.get("port") == port
                               and (r.get("proto") == proto or r.get("proto") == "both"
                                    or proto == "both"))]
        removed = before - len(store.rules)
        if removed == 0:
            self._send(200, {"ok": True, "msg": f"端口 {port} 没有可删除的放行规则", "removed": 0})
            return
        store.save()
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": f"已删除端口 {port} 的 {removed} 条放行规则", "removed": removed})

    def _api_open_port(self):
        """一键开放端口给公网：{port, proto?}（等价于添加放行规则，幂等）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        proto = data.get("proto", "tcp")
        if proto not in VALID_PROTOS:
            self._send(400, {"error": f"proto 必须是 {VALID_PROTOS} 之一"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        # 已放行则直接返回成功（幂等）；传入 comment 时更新注释便于识别
        comment = str(data.get("comment", "")).strip() or "面板开放"
        for r in self.server.store.rules:
            if r.get("type") == "port_allow" and r.get("port") == port and r.get("proto") == proto:
                if comment and r.get("comment") != comment:
                    r["comment"] = comment
                    self.server.store.save()
                self._send(200, {"ok": True, "msg": f"端口 {port}/{proto} 已在放行列表中", "id": r["id"]})
                return
        rule = self.server.store.add({"type": "port_allow", "proto": proto, "port": port,
                                      "comment": comment})
        ok, msg = self.server.nft.apply()
        if not ok:
            self.server.store.remove(rule["id"])
            self._send(500, {"error": f"规则应用失败，已回滚: {msg}"})
            return
        self._send(200, {"ok": True, "msg": f"端口 {port}/{proto} 已开放给公网", "rule": rule})

    def _api_mode(self):
        """切换宽松/严格模式：{mode: 'permissive'|'strict'}
        切严格模式时自动放行面板端口，防止面板自身被锁死"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        mode = data.get("mode")
        if mode not in ("permissive", "strict"):
            self._send(400, {"error": "mode 必须是 permissive 或 strict"})
            return
        store = self.server.store
        if mode == "strict":
            # 严格模式：确保面板端口已放行（防锁死）
            panel_port = int(self.server.config.get("port", DEFAULT_PORT))
            exists = any(r.get("type") == "port_allow" and r.get("port") == panel_port
                         and r.get("comment") == PANEL_PORT_COMMENT for r in store.rules)
            if not exists:
                store.add({"type": "port_allow", "proto": "tcp", "port": panel_port,
                           "comment": PANEL_PORT_COMMENT})
        self.server.config.set("mode", mode)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        extra = ""
        if mode == "strict":
            extra = f"（已自动放行面板端口 {panel_port}，防止面板被锁死）"
        self._send(200, {"ok": True, "msg": f"模式已切换为 {'严格' if mode == 'strict' else '宽松'}{extra}"})

    def _api_password(self):
        """修改密码/用户名：{old_password, new_password?, username?}
        新密码/新用户名至少提供一项（可只改其一）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        old = data.get("old_password", "")
        stored = self.server.config.get("password_hash", "")
        if not verify_password(old, stored):
            self._send(400, {"error": "原密码错误"})
            return
        new = data.get("new_password")
        if new is not None:
            new = str(new)
            if len(new) < 8:
                self._send(400, {"error": "新密码至少 8 位"})
                return
            self.server.config.set("password_hash", hash_password(new))
        name = data.get("username")
        if name is not None:
            name = str(name).strip()
            if not re.match(r"^[A-Za-z0-9_]{3,32}$", name):
                self._send(400, {"error": "用户名需为 3-32 位字母、数字或下划线"})
                return
            self.server.config.set("username", name)
        if new is None and name is None:
            self._send(400, {"error": "未提供要修改的新密码或新用户名"})
            return
        self._send(200, {"ok": True, "msg": "账户设置已更新，下次登录生效"})


# ------------------------------- 服务启动 -------------------------------

class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, config, store, nft, auth):
        super().__init__(addr, handler)
        self.config = config
        self.store = store
        self.nft = nft
        self.auth = auth


def cmd_reset_password():
    """交互式重置密码（安装脚本 --change-password 调用）"""
    if not os.path.exists(CONFIG_FILE):
        print("面板未初始化，请先运行安装脚本", file=sys.stderr)
        sys.exit(1)
    cfg = Config()
    import getpass
    while True:
        p1 = getpass.getpass("输入新密码（至少 8 位）: ")
        if len(p1) < 8:
            print("密码太短")
            continue
        p2 = getpass.getpass("再次输入: ")
        if p1 != p2:
            print("两次输入不一致")
            continue
        break
    cfg.set("password_hash", hash_password(p1))
    print("密码已更新")


def cmd_apply(config):
    """应用规则（systemd ExecStartPre 或手动）"""
    store = RuleStore()
    nft = NFTManager(store, config)
    ok, msg = nft.apply()
    if not ok:
        print(f"规则应用失败: {msg}", file=sys.stderr)
        sys.exit(1)
    print(f"规则已应用: {msg}")


def cmd_open_port(port, proto="tcp"):
    """CLI 一键开放端口给公网：fwpanel open-port 8080 [tcp|udp|both]"""
    config = Config()
    store = RuleStore()
    if not (1 <= port <= 65535) or proto not in VALID_PROTOS:
        print("用法: fwpanel open-port <端口(1-65535)> [tcp|udp|both]  （默认 tcp）", file=sys.stderr)
        sys.exit(1)
    for r in store.rules:
        if r.get("type") == "port_allow" and r.get("port") == port and r.get("proto") == proto:
            print(f"端口 {port}/{proto} 已在放行列表中")
            return
    rule = store.add({"type": "port_allow", "proto": proto, "port": port, "comment": "CLI 开放"})
    nft = NFTManager(store, config)
    ok, msg = nft.apply()
    if not ok:
        store.remove(rule["id"])
        print(f"规则应用失败，已回滚: {msg}", file=sys.stderr)
        sys.exit(1)
    print(f"✓ 端口 {port}/{proto} 已开放给公网")
    print(f"  当前放行端口: " + ", ".join(
        f"{r['port']}/{r['proto']}" for r in store.rules
        if r.get("type") == "port_allow") or "（无）")


def resume_ssh_switch_watch(store, config):
    """v1.25.6：面板启动时检测残留的「旧SSH端口-切换保护」规则并恢复监控线程。

    解决：改 SSH 端口后面板重启/升级（systemd restart）导致 watch_ssh_switch 线程丢失、
    旧端口放行规则永远残留的问题（2026-08-22 Oracle 实例实测：22 端口规则残留到下次手动清理）。"""
    old_rules = [r for r in store.rules
                 if r.get("type") == "port_allow" and r.get("comment") == SSH_OLD_PORT_COMMENT]
    if not old_rules:
        return False
    new_port = int(config.get("ssh_port", SSH_PORT_DEFAULT))
    for r in old_rules:
        old_port = int(r.get("port"))
        if old_port == new_port:
            continue
        threading.Thread(target=watch_ssh_switch,
                         args=(old_port, new_port, store), daemon=True).start()
        log(f"检测到残留 SSH 切换保护（旧端口 {old_port} → 新端口 {new_port}），已恢复监控线程")
    return True


def ensure_proxy_entry_ports(store):
    """v1.25.7：启动时补齐反代入口端口放行（修复存量 https 反代漏放 443）。

    背景：v1.25.2 引入「复用证书」功能（cert_ref）后，ssl:false + cert_ref 有值的
    反代 nginx 会监听 443，但旧版创建逻辑只看 ssl 字段，只放行了 80、漏放 443；
    严格模式（policy drop）下公网 https 被防火墙挡死（2026-08-26 伦敦新机实测）。
    此处幂等补齐：有证书（ssl 或 cert_ref）的反代缺 80/443 放行则补上，
    http 反代缺 80 则补上。升级后无需手动操作，重启服务即自愈。"""
    try:
        pstore = ProxyStore()
    except Exception as e:
        log(f"[ensure_proxy_entry_ports] 读取代理列表失败: {e}")
        return
    changed = False
    for p in pstore.proxies:
        if not p.get("enabled", True):
            continue
        https_on = bool(p.get("ssl") or p.get("cert_ref"))
        for entry_port in ([443, 80] if https_on else [80]):
            if any(r.get("type") == "port_allow" and r.get("port") == entry_port
                   for r in store.rules):
                continue
            store.add({"type": "port_allow", "proto": "tcp", "port": entry_port,
                       "comment": "反代:HTTPS" if entry_port == 443 else "反代:HTTP"})
            changed = True
            log(f"[ensure_proxy_entry_ports] 反代 {p['domain']} 补放行入口端口 {entry_port}")
    if changed:
        store.save()


def main():
    parser = argparse.ArgumentParser(description="fwpanel2 简易VPS管理面板2.0")
    parser.add_argument("cmd", nargs="?", default="serve",
                        choices=["serve", "reset-password", "apply", "open-port"])
    parser.add_argument("arg1", nargs="?", help="open-port 的端口（如 8080 或 8080/udp）")
    parser.add_argument("arg2", nargs="?", help="open-port 的协议（tcp/udp，默认 tcp）")
    parser.add_argument("--port", type=int, default=None,
                        help="面板端口（默认读 /etc/fwpanel/config.json，安装参数 --port 写入）")
    parser.add_argument("--bind", default=None,
                        help="监听地址（默认读 /etc/fwpanel/config.json，安装参数 --bind 写入）")
    args = parser.parse_args()

    config = Config()
    if args.cmd == "reset-password":
        cmd_reset_password()
        return
    if args.cmd == "apply":
        cmd_apply(config)
        return
    if args.cmd == "open-port":
        arg = args.arg1 or ""
        proto = args.arg2 or "tcp"
        if "/" in arg:
            arg, proto = arg.split("/", 1)
        if not arg.isdigit():
            print("用法: fwpanel open-port <端口(1-65535)> [tcp|udp]  （如: fwpanel open-port 8080）",
                  file=sys.stderr)
            sys.exit(1)
        cmd_open_port(int(arg), proto)
        return

    # serve：端口/监听地址以 config.json 为权威（安装时写入），CLI 显式参数可覆盖
    bind = args.bind or config.get("bind", "127.0.0.1")
    port = args.port or int(config.get("port", DEFAULT_PORT))
    # 长任务表启动加载：把上次进程遗留的 running 标记为 error（v2.1.18）
    _tasks_load()
    # 自动同步 SSH 保护端口到系统实际端口（防锁死保护跟随当前 SSH 端口，手动设置后停止）
    sync_ssh_port(config)
    store = RuleStore()
    # v1.25.6：恢复残留的 SSH 切换保护监控（面板重启/升级后线程丢失的补救）
    resume_ssh_switch_watch(store, config)
    # v1.25.7：补齐存量反代入口端口放行（修复 https 反代漏放 443，重启即自愈）
    ensure_proxy_entry_ports(store)
    # v3.0.1：启动时确保 nginx 兜底守卫配置存在并生效（default_server 444 / 443 ssl_reject_handshake）。
    # 从 v2.1.32 升级上来的机器，该文件在旧版本里被清理逻辑误删过（见 v2.1.33 hotfix），
    # 若不在启动补写，则要等到第一次建站/改反代才恢复，此期间 IP 直连落到第一个 server block。
    try:
        if nginx_available():
            ensure_nginx_default()
            ok_guard, msg_guard = reload_nginx()
            if not ok_guard:
                log(f"[v3.0.1] nginx 兜底守卫 reload 失败: {msg_guard}")
    except Exception as e:
        log(f"[v3.0.1] 兜底守卫检查异常: {e}")
    nft = NFTManager(store, config)
    auth = Auth(config)
    server = PanelServer((bind, port), PanelHandler, config, store, nft, auth)
    _cleanup_stale_term_keys()   # v2.1.22：清理残留的临时终端私钥（重启不滞留）
    # SSH 防爆破后台监控（配置启用后生效）
    threading.Thread(target=bruteforce_loop, args=(config, store), daemon=True).start()
    log("SSH 防爆破监控线程已启动")
    # 网卡流量统计后台线程（按天聚合）
    traffic = TrafficStore()
    traffic.record()  # 启动建立采样基线
    server.traffic = traffic
    threading.Thread(target=traffic_loop, args=(traffic,), daemon=True).start()
    threading.Thread(target=warm_server_ip, daemon=True).start()   # 预热状态卡公网 IP 缓存
    log("网卡流量统计线程已启动")
    # 进程流量历史存储（按天累计，跨重启保留）
    server.procs = ProcStore()
    log("进程流量历史存储已加载")

    # 启动时应用一次规则（保证面板规则生效）
    ok, msg = nft.apply()
    if not ok:
        log(f"警告：启动时规则应用失败: {msg}")

    log(f"面板已启动: http://{bind}:{port}  (dry-run={DRY_RUN})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("收到退出信号")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
