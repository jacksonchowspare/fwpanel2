#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwpanel 单元测试 + HTTP API 冒烟测试（无需 root，使用临时目录 + dry-run）"""
import json
import os
import shutil
import sys
import tempfile
import threading
import types
import unittest
import urllib.request

# ---- 必须在 import panel 前设置测试环境 ----
TMP = tempfile.mkdtemp(prefix="fwpanel-test-")
os.environ["FW_TEST_DIR"] = TMP
os.environ["FW_SSHD_DIR"] = os.path.join(TMP, "sshd_d")   # SSH 策略 drop-in 目录隔离
os.environ["FW_DRY_RUN"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import panel  # noqa: E402

# ---- 准备测试配置 ----
TEST_USER = "tester"
TEST_PASS = "TestPass123"
panel.Config.__init__ = lambda self: setattr(self, "data", {})  # 避免读真实配置


def make_cfg(user=TEST_USER, pwd=TEST_PASS, mode="permissive"):
    """每个测试独立配置，避免状态污染"""
    cfg = panel.Config()
    cfg.data = {
        "username": user,
        "password_hash": panel.hash_password(pwd),
        "port": 17999,
        "bind": "127.0.0.1",
        "mode": mode,
        "ssh_port": 22,
    }
    return cfg


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg()
        self.auth = panel.Auth(self.cfg)

    def test_login_ok(self):
        token, msg = self.auth.login(TEST_USER, TEST_PASS)
        self.assertTrue(token, msg)
        self.assertTrue(self.auth.check(token))

    def test_login_wrong(self):
        token, msg = self.auth.login(TEST_USER, "wrongpass")
        self.assertIsNone(token)

    def test_lockout(self):
        auth = panel.Auth(make_cfg())
        for _ in range(panel.LOCK_MAX_FAIL):
            auth.login(TEST_USER, "bad")
        self.assertTrue(auth.check_locked())
        token, _ = auth.login(TEST_USER, TEST_PASS)
        self.assertIsNone(token, "锁定期内不应允许登录")

    def test_hash(self):
        h = panel.hash_password("abc12345")
        self.assertTrue(panel.verify_password("abc12345", h))
        self.assertFalse(panel.verify_password("abc12346", h))


class TestRules(unittest.TestCase):
    def setUp(self):
        panel.RuleStore._load = lambda self: []   # 隔离：不读磁盘
        self.store = panel.RuleStore()
        self.store.rules = []
        self.cfg = make_cfg()

    def test_render_permissive(self):
        self.store.rules = [
            {"id": "1", "type": "port_allow", "proto": "tcp", "port": 80, "comment": "web"},
            {"id": "2", "type": "port_deny", "proto": "tcp", "port": 23, "comment": ""},
            {"id": "3", "type": "ip_allow", "ip": "1.2.3.4", "comment": ""},
            {"id": "4", "type": "ip_deny", "ip": "5.6.7.8", "comment": "bad"},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("policy accept", text)
        self.assertIn("tcp dport 80 accept", text)
        self.assertIn("# web", text)
        self.assertIn("tcp dport 23 drop", text)
        self.assertIn("ip saddr 1.2.3.4 accept", text)
        self.assertIn("ip saddr 5.6.7.8 drop", text)
        self.assertIn("# bad", text)
        # SSH 保护永远存在
        self.assertIn("tcp dport 22 accept   # SSH 保护", text)
        # 顺序：SSH 保护必须在用户规则之前
        self.assertLess(text.index("SSH 保护"), text.index("tcp dport 80"))

    def test_render_prerouting_docker_port(self):
        """port_deny 规则必须生成 PREROUTING 拦截链（priority -200，Docker DNAT 之前）"""
        store = panel.RuleStore()
        store.rules = [
            {"id": "1", "type": "port_deny", "proto": "tcp", "port": 8807, "comment": ""},
            {"id": "2", "type": "port_allow", "proto": "tcp", "port": 443, "comment": ""},
        ]
        text = store.render(self.cfg)
        self.assertIn("chain prerouting_drop", text)
        self.assertIn("type filter hook prerouting priority -200", text)
        self.assertIn('iifname != "lo" tcp dport 8807 drop', text)
        # 无 port_deny 时不生成
        store.rules = [{"id": "2", "type": "port_allow", "proto": "tcp", "port": 443, "comment": ""}]
        text2 = store.render(self.cfg)
        self.assertNotIn("prerouting_drop", text2)

    def test_render_strict(self):
        strict_cfg = make_cfg(mode="strict")
        text = self.store.render(strict_cfg)
        self.assertIn("policy drop", text)

    def test_render_ipv6(self):
        self.store.rules = [{"id": "1", "type": "ip_allow", "ip": "2001:db8::1", "comment": ""}]
        text = self.store.render(self.cfg)
        self.assertIn("ip6 saddr 2001:db8::1 accept", text)

    def test_render_both(self):
        self.store.rules = [
            {"id": "1", "type": "port_allow", "proto": "both", "port": 8080, "comment": "双协议"},
            {"id": "2", "type": "port_deny", "proto": "both", "port": 4444, "comment": ""},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("tcp dport 8080 accept", text)
        self.assertIn("udp dport 8080 accept", text)
        self.assertIn("# 双协议", text)
        self.assertIn("tcp dport 4444 drop", text)
        self.assertIn("udp dport 4444 drop", text)

    def test_ip_net_rule_render(self):
        """IP 段黑名单/白名单渲染（IPv4+IPv6 CIDR）"""
        self.store.rules = [
            {"id": "1", "type": "ip_deny", "ip": "1.2.3.0/24", "comment": "封禁段"},
            {"id": "2", "type": "ip_deny", "ip": "2001:db8::/32", "comment": "封禁v6段"},
            {"id": "3", "type": "ip_allow", "ip": "10.0.0.0/8", "comment": "白名单段"},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("ip saddr 1.2.3.0/24 drop", text)
        self.assertIn("ip6 saddr 2001:db8::/32 drop", text)
        self.assertIn("ip saddr 10.0.0.0/8 accept", text)
        self.assertIn("封禁段", text)

    def test_deny_before_ssh_accept(self):
        """黑名单规则必须排在 SSH 保护 accept 之前（否则封禁对 SSH 失效）"""
        self.store.rules = [
            {"id": "1", "type": "port_allow", "proto": "tcp", "port": 8080, "comment": ""},
            {"id": "2", "type": "ip_deny", "ip": "1.2.3.4", "comment": "封禁"},
            {"id": "3", "type": "port_deny", "proto": "tcp", "port": 9999, "comment": ""},
        ]
        text = self.store.render(self.cfg)
        self.assertLess(text.index("ip saddr 1.2.3.4 drop"), text.index("tcp dport 22 accept"))
        self.assertLess(text.index("tcp dport 9999 drop"), text.index("tcp dport 22 accept"))
        self.assertGreater(text.index("tcp dport 8080 accept"), text.index("tcp dport 22 accept"))

    def test_protected_rule_not_deletable(self):
        self.store.rules = [{"id": "x1", "type": "port_allow", "proto": "tcp",
                             "port": 22, "comment": "SSH 保护(不可删除)", "protected": True}]
        ok, msg = self.store.remove("x1")
        self.assertFalse(ok)
        self.assertIn("不可删除", msg)

    def test_add_remove(self):
        r = self.store.add({"type": "port_allow", "proto": "tcp", "port": 8080, "comment": "t"})
        self.assertIn("id", r)
        self.assertEqual(len(self.store.rules), 1)
        ok, _ = self.store.remove(r["id"])
        self.assertTrue(ok)
        self.assertEqual(len(self.store.rules), 0)


class TestAPI(unittest.TestCase):
    """HTTP API 冒烟测试：真实起服务 + urllib 请求（dry-run 不执行 nft）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17999), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17999"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def test_open_port(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 一键开放端口
        code, d = self._req("POST", "/api/open-port", {"port": 9000, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200, d)
        self.assertIn("已开放", d["msg"])
        # 幂等：重复开放返回成功且不报错
        code, d = self._req("POST", "/api/open-port", {"port": 9000, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200)
        self.assertIn("已在放行列表", d["msg"])
        # 规则确实存在
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("port") == 9000 for r in d["rules"]))
        # 非法端口
        code, d = self._req("POST", "/api/open-port", {"port": 99999}, token=token)
        self.assertEqual(code, 400)

    def test_open_port_both(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # TCP+UDP 同时开放
        code, d = self._req("POST", "/api/open-port", {"port": 9100, "proto": "both"}, token=token)
        self.assertEqual(code, 200, d)
        # 幂等
        code, d = self._req("POST", "/api/open-port", {"port": 9100, "proto": "both"}, token=token)
        self.assertEqual(code, 200)
        self.assertIn("已在放行列表", d["msg"])
        # 渲染应生成 tcp+udp 两行
        text = self.store.render(self.cfg)
        self.assertIn("tcp dport 9100 accept", text)
        self.assertIn("udp dport 9100 accept", text)
        # 非法协议
        code, d = self._req("POST", "/api/open-port", {"port": 9200, "proto": "icmp"}, token=token)
        self.assertEqual(code, 400)

    def test_ssh_api(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 查询状态
        code, d = self._req("GET", "/api/ssh", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["protected_port"], 22)
        # 仅更新保护端口
        code, d = self._req("POST", "/api/ssh", {"ssh_port": 2222}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh", token=token)
        self.assertEqual(d["protected_port"], 2222)
        # 规则渲染应保护新端口
        text = self.store.render(self.cfg)
        self.assertIn("tcp dport 2222 accept   # SSH 保护", text)
        # 恢复
        self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)

    def test_ssh_apply(self):
        """同步修改系统 SSH 端口：验证防锁死流程（旧端口临时放行 + 保护更新）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real = panel.apply_sshd_port
        panel.apply_sshd_port = lambda port: (True, f"系统 SSH 端口已切换为 {port}")
        # 屏蔽后台监控（mock 函数本身，不能 mock threading.Thread——那是标准库全局对象）
        real_watch = panel.watch_ssh_switch
        panel.watch_ssh_switch = lambda old, new, timeout=3600: None
        try:
            code, d = self._req("POST", "/api/ssh/apply", {"ssh_port": 3333}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("已启动自动检测", d["msg"])
            # 保护端口已更新
            code, d = self._req("GET", "/api/ssh", token=token)
            self.assertEqual(d["protected_port"], 3333)
            # 旧端口临时放行规则存在
            code, d = self._req("GET", "/api/rules", token=token)
            self.assertTrue(any(r.get("comment") == panel.SSH_OLD_PORT_COMMENT
                                and r.get("port") == 22 for r in d["rules"]),
                            "应存在旧端口临时放行规则")
            # 渲染：新保护端口 + 旧端口临时放行都在
            text = self.store.render(self.cfg)
            self.assertIn("tcp dport 3333 accept   # SSH 保护", text)
            self.assertIn(f"tcp dport 22 accept  # {panel.SSH_OLD_PORT_COMMENT}", text)
        finally:
            panel.apply_sshd_port = real
            panel.watch_ssh_switch = real_watch
            # 清理测试痕迹
            self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)
            code, d = self._req("GET", "/api/rules", token=token)
            for r in d["rules"]:
                if r.get("comment") == panel.SSH_OLD_PORT_COMMENT:
                    self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_mode_strict_auto_port(self):
        """切严格模式自动放行面板端口（防锁死）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/mode", {"mode": "strict"}, token=token)
        self.assertEqual(code, 200, d)
        self.assertIn("已自动放行面板端口", d["msg"])
        # 面板端口规则已添加（cfg port=17999）
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("comment") == panel.PANEL_PORT_COMMENT
                            and r.get("port") == 17999 for r in d["rules"]),
                        "严格模式下应自动放行面板端口")
        text = self.store.render(self.cfg)
        self.assertIn("policy drop", text)
        self.assertIn("tcp dport 17999 accept", text)
        # 恢复宽松
        code, d = self._req("POST", "/api/mode", {"mode": "permissive"}, token=token)
        self.assertEqual(code, 200)
        # 清理自动添加的面板端口规则（避免影响后续测试）
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("comment") == panel.PANEL_PORT_COMMENT:
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_panel_port(self):
        """修改面板端口：旧端口放行规则全部删除 + 新端口自动放行"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 预置：面板端口规则 + 一条手动开放的旧端口规则（模拟残留）
        self.store.add({"type": "port_allow", "proto": "tcp", "port": 17999,
                        "comment": panel.PANEL_PORT_COMMENT})
        self.store.add({"type": "port_allow", "proto": "tcp", "port": 17999,
                        "comment": "手动开放"})
        # mock 重启动作（只 mock restart_service，不碰 subprocess.run，避免影响 status 等接口）
        real_timer, real_restart = panel.threading.Timer, panel.restart_service
        class FakeTimer:
            def __init__(self, delay, fn):
                self.fn = fn
            def start(self):
                pass
        panel.threading.Timer = FakeTimer
        panel.restart_service = lambda: None
        try:
            # 改端口
            code, d = self._req("POST", "/api/panel/port", {"port": 18001}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("18001", d["msg"])
            # 配置已更新
            code, d = self._req("GET", "/api/status", token=token)
            self.assertEqual(d["panel_port"], 18001)
            # 旧端口 17999 的所有放行规则已删除（含手动开放的）
            code, d = self._req("GET", "/api/rules", token=token)
            self.assertFalse(any(r.get("type") == "port_allow" and r.get("port") == 17999
                                 for r in d["rules"]),
                             "旧端口放行规则应全部删除")
            # 新端口有面板端口放行规则（1 条）
            new_rules = [r for r in d["rules"] if r.get("comment") == panel.PANEL_PORT_COMMENT]
            self.assertEqual(len(new_rules), 1)
            self.assertEqual(new_rules[0]["port"], 18001)
            # 占用端口拒绝
            code, d = self._req("POST", "/api/panel/port", {"port": 17999}, token=token)
            self.assertEqual(code, 400)
            # 非法端口
            code, d = self._req("POST", "/api/panel/port", {"port": "abc"}, token=token)
            self.assertEqual(code, 400)
        finally:
            panel.threading.Timer = real_timer
            panel.restart_service = real_restart
            # 恢复配置和规则
            self.server.config.set("port", 17999)
            code, d = self._req("GET", "/api/rules", token=token)
            for r in d["rules"]:
                if r.get("comment") == panel.PANEL_PORT_COMMENT:
                    self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_panel_port_auto_allow(self):
        """无面板端口规则时改端口，应自动添加新端口放行（防严格模式锁死）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real_timer, real_restart = panel.threading.Timer, panel.restart_service
        class FakeTimer:
            def __init__(self, delay, fn):
                self.fn = fn
            def start(self):
                pass
        panel.threading.Timer = FakeTimer
        panel.restart_service = lambda: None
        try:
            # 不预置任何面板端口规则，直接改端口
            code, d = self._req("POST", "/api/panel/port", {"port": 18002}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/rules", token=token)
            self.assertTrue(any(r.get("comment") == panel.PANEL_PORT_COMMENT
                                and r.get("port") == 18002 for r in d["rules"]),
                            "改端口后应自动添加新端口放行规则")
            # 渲染应包含新端口放行
            text = self.store.render(self.cfg)
            self.assertIn("tcp dport 18002 accept", text)
        finally:
            panel.threading.Timer = real_timer
            panel.restart_service = real_restart
            self.server.config.set("port", 17999)
            code, d = self._req("GET", "/api/rules", token=token)
            for r in d["rules"]:
                if r.get("comment") == panel.PANEL_PORT_COMMENT:
                    self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_username(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 修改用户名
        code, d = self._req("POST", "/api/username", {"username": "newadmin"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/status", token=token)
        self.assertEqual(d["username"], "newadmin")
        # 非法用户名
        code, d = self._req("POST", "/api/username", {"username": "a!"}, token=token)
        self.assertEqual(code, 400)
        # 恢复
        code, d = self._req("POST", "/api/username", {"username": TEST_USER}, token=token)
        self.assertEqual(code, 200)

    def test_ssh_service_dynamic_port(self):
        """SSH 服务开关端口跟随保护端口（不固定 22）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 设置保护端口 2222
        code, d = self._req("POST", "/api/ssh", {"ssh_port": 2222}, token=token)
        self.assertEqual(code, 200)
        # 打开 SSH 服务开关
        code, d = self._req("POST", "/api/service", {"name": "ssh", "enabled": True}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("port") == 2222 and r.get("comment") == "服务:ssh"
                            for r in d["rules"]),
                        "SSH 服务开关应放行当前保护端口 2222")
        self.assertFalse(any(r.get("port") == 22 and r.get("comment") == "服务:ssh"
                             for r in d["rules"]),
                         "不应再放行固定 22")
        # 恢复
        self._req("POST", "/api/service", {"name": "ssh", "enabled": False}, token=token)
        self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)

    def test_ssh_set_disables_auto(self):
        """手动设置保护端口后关闭自动同步"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        self._req("POST", "/api/ssh", {"ssh_port": 2222}, token=token)
        self.assertFalse(self.cfg.get("ssh_port_auto"), "手动设置后应关闭自动同步")
        self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)

    def test_cleanup_old_ssh_rules(self):
        """清理旧 SSH 端口规则：删除全部放行规则（含手动开放），保留面板端口规则"""
        store = panel.RuleStore()
        store.rules = [
            {"id": "1", "type": "port_allow", "proto": "tcp", "port": 22, "comment": panel.SSH_OLD_PORT_COMMENT},
            {"id": "2", "type": "port_allow", "proto": "tcp", "port": 22, "comment": "服务:ssh"},
            {"id": "3", "type": "port_allow", "proto": "tcp", "port": 22, "comment": "手动开放"},
            {"id": "4", "type": "port_allow", "proto": "tcp", "port": 22, "comment": panel.PANEL_PORT_COMMENT},
            {"id": "5", "type": "port_allow", "proto": "tcp", "port": 80, "comment": "其他"},
        ]
        store.save()
        changed = panel.cleanup_old_ssh_rules(22, store)
        self.assertTrue(changed)
        rules = panel.RuleStore().rules
        pairs = [(r["port"], r["comment"]) for r in rules]
        self.assertNotIn((22, panel.SSH_OLD_PORT_COMMENT), pairs)
        self.assertNotIn((22, "服务:ssh"), pairs)
        self.assertNotIn((22, "手动开放"), pairs)
        self.assertIn((22, panel.PANEL_PORT_COMMENT), pairs, "面板端口规则应保留")
        self.assertIn((80, "其他"), pairs)
        # 无匹配规则时返回 False
        self.assertFalse(panel.cleanup_old_ssh_rules(9999, store))
        # 清理测试痕迹
        panel.RuleStore().rules = []
        panel.RuleStore().save()

    def test_watch_ssh_switch_delayed_cleanup(self):
        """连接确认后延迟 600 秒再清理旧端口规则"""
        calls = {"sleep": [], "cleanup": 0}
        real_sleep = panel.time.sleep
        real_has = panel.has_established_on_port
        real_cleanup = panel.cleanup_old_ssh_rules
        panel.time.sleep = lambda s: calls["sleep"].append(s)
        panel.has_established_on_port = lambda p: True   # 立即检测到连接
        panel.cleanup_old_ssh_rules = lambda p, s: (calls.__setitem__("cleanup", calls["cleanup"] + 1) or True)
        try:
            panel.watch_ssh_switch(22, 3333, panel.RuleStore(), confirm_delay=600, wait_timeout=600)
            self.assertEqual(calls["cleanup"], 1, "确认连接后应执行清理")
            self.assertEqual(calls["sleep"][-1], 600, "清理前应延迟 600 秒")
        finally:
            panel.time.sleep = real_sleep
            panel.has_established_on_port = real_has
            panel.cleanup_old_ssh_rules = real_cleanup

    def test_has_established_on_port(self):
        """连接检测：ss 输出非空 = 有连接"""
        import subprocess as sp
        real = panel.subprocess.run
        def fake(cmd, *a, **k):
            out = "ESTAB 0 0 1.2.3.4:3333 5.6.7.8:51234\n" if "3333" in " ".join(cmd) else ""
            return sp.CompletedProcess(cmd, 0, stdout=out, stderr="")
        panel.subprocess.run = fake
        try:
            self.assertTrue(panel.has_established_on_port(3333))
            self.assertFalse(panel.has_established_on_port(4444))
        finally:
            panel.subprocess.run = real

    def test_ip_net_validation(self):
        """IP/IP 段校验：单 IP 与 CIDR（IPv4/IPv6）合法，非法拒绝"""
        for ok in ("1.2.3.4", "1.2.3.0/24", "10.0.0.0/8", "2001:db8::1",
                   "2001:db8::/32", "0.0.0.0/0", "::/0"):
            self.assertTrue(panel.is_valid_ip_or_net(ok), f"{ok} 应合法")
        for bad in ("", "1.2.3.999", "1.2.3.0/33", "999.1.1.1", "abc",
                    "1.2.3.4/24/32", "2001:db8::/129"):
            self.assertFalse(panel.is_valid_ip_or_net(bad), f"{bad} 应非法")

    def test_ip_net_api(self):
        """API 添加 IP 段规则 + 非法格式拒绝"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/rules",
                            {"type": "ip_deny", "ip": "203.0.113.0/24", "comment": "攻击段"},
                            token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("ip") == "203.0.113.0/24" for r in d["rules"]))
        # 非法格式
        code, d = self._req("POST", "/api/rules",
                            {"type": "ip_deny", "ip": "1.2.3.0/33"}, token=token)
        self.assertEqual(code, 400)
        # 清理
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("ip") == "203.0.113.0/24":
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_ip_range_validation(self):
        """IP 范围格式校验：start-end 同版本且正序"""
        for ok in ("1.2.3.1-1.2.3.50", "10.0.0.1-10.0.0.255",
                   "2001:db8::1-2001:db8::ff"):
            self.assertTrue(panel.is_valid_ip_or_net(ok), f"{ok} 应合法")
        for bad in ("1.2.3.50-1.2.3.1",          # 反序
                    "1.2.3.1-2001:db8::1",       # 跨版本
                    "1.2.3.1-1.2.3.999",         # 非法端点
                    "1.2.3.1-1.2.3.2-1.2.3.3",   # 多个 -
                    "1.2.3.1-"):                 # 缺终点
            self.assertFalse(panel.is_valid_ip_or_net(bad), f"{bad} 应非法")

    def test_ip_range_render(self):
        """IP 范围规则渲染（IPv4+IPv6）"""
        self.store.rules = [
            {"id": "1", "type": "ip_deny", "ip": "1.2.3.1-1.2.3.50", "comment": "范围封禁"},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("ip saddr 1.2.3.1-1.2.3.50 drop", text)

    def test_ip_range_api(self):
        """API 添加 IP 范围规则"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/rules",
                            {"type": "ip_deny", "ip": "198.51.100.1-198.51.100.50",
                             "comment": "范围封禁"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("ip") == "198.51.100.1-198.51.100.50" for r in d["rules"]))
        # 清理
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("ip") == "198.51.100.1-198.51.100.50":
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_bruteforce_api(self):
        """防爆破配置 API：查询/保存/校验/手动解封"""
        # 注意：本测试按字母序最先执行，密码还是初始值 TEST_PASS
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("GET", "/api/bruteforce", token=token)
        self.assertEqual(code, 200)
        self.assertFalse(d["enabled"])
        # 保存配置
        code, d = self._req("POST", "/api/bruteforce",
                            {"enabled": True, "max_fails": 3, "ban_seconds": 600},
                            token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/bruteforce", token=token)
        self.assertTrue(d["enabled"])
        self.assertEqual(d["max_fails"], 3)
        self.assertEqual(d["ban_seconds"], 600)
        # 非法参数
        code, d = self._req("POST", "/api/bruteforce", {"max_fails": 0}, token=token)
        self.assertEqual(code, 400)
        # 手动解封不存在 IP（幂等）
        code, d = self._req("DELETE", "/api/bruteforce/203.0.113.66", token=token)
        self.assertEqual(code, 200)
        # 恢复默认
        self._req("POST", "/api/bruteforce", {"enabled": False}, token=token)

    def test_detect_distro(self):
        """发行版自动识别：读 /etc/os-release，返回非空"""
        d = panel.detect_distro()
        self.assertIsInstance(d, str)
        self.assertTrue(len(d) > 0, "发行版识别不应为空")

    def test_status_includes_distro(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("GET", "/api/status", token=token)
        self.assertEqual(code, 200)
        self.assertTrue(d.get("distro"), "status 应包含发行版信息")
        self.assertTrue(d.get("hostname"))

    def test_firewall_api(self):
        """一键开关防火墙 API"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 关闭（dry-run 环境：disable 走 dry-run 返回成功）
        code, d = self._req("POST", "/api/firewall", {"enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        self.assertFalse(self.cfg.get("firewall_enabled"), "关闭后应记录状态")
        # 开启
        code, d = self._req("POST", "/api/firewall", {"enabled": True}, token=token)
        self.assertEqual(code, 200, d)
        self.assertTrue(self.cfg.get("firewall_enabled"))

    def test_password_with_username(self):
        """账户设置：一次请求同时修改用户名和密码"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 同时改用户名和密码
        code, d = self._req("POST", "/api/password",
                            {"old_password": "NewPass123", "new_password": "NewPass456",
                             "username": "newadmin2"}, token=token)
        self.assertEqual(code, 200, d)
        # 新密码可登录
        code, d = self._req("POST", "/api/login",
                            {"username": "newadmin2", "password": "NewPass456"})
        self.assertEqual(code, 200)
        # 只改密码（不带 username）
        code, d = self._req("POST", "/api/password",
                            {"old_password": "NewPass456", "new_password": "NewPass123"},
                            token=token)
        self.assertEqual(code, 200)
        # 原密码错误拒绝
        code, d = self._req("POST", "/api/password",
                            {"old_password": "wrong", "new_password": "NewPass789"},
                            token=token)
        self.assertEqual(code, 400)
        # 恢复
        self._req("POST", "/api/password",
                  {"old_password": "NewPass123", "username": TEST_USER}, token=token)

    def test_proxy_api(self):
        """反向代理 API：添加/查询/删除 + 防火墙 80/443 联动"""
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 查询（空）
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["proxies"], [])
        # 添加
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "app.example.com", "target_host": "127.0.0.1",
                             "target_port": 8080, "websocket": True}, token=token)
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        # 防火墙自动放行入口端口：http 反代 → 80（v1.24.64 修复，原只放行 443）
        code, d = self._req("GET", "/api/rules", token=token)
        ports = {r.get("port") for r in d["rules"] if r.get("type") == "port_allow"}
        self.assertIn(80, ports, "http 反代应自动放行 80")
        self.assertNotIn(443, ports, "http 反代不应放行 443")
        # 目标端口 8080 自动禁止公网直连
        deny = [r for r in d["rules"] if r.get("type") == "port_deny" and r.get("port") == 8080]
        self.assertTrue(deny, "目标端口应有禁止规则")
        self.assertEqual(deny[0]["comment"], panel.PROXY_TARGET_DENY_COMMENT)
        # https 反代 → 自动放行 443
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "tls.example.com", "target_host": "127.0.0.1",
                             "target_port": 8081, "ssl": True}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        ports = {r.get("port") for r in d["rules"] if r.get("type") == "port_allow"}
        self.assertIn(443, ports, "https 反代应自动放行 443")
        # 查询列表（http + https 两个代理）
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertEqual(len(d["proxies"]), 2)
        self.assertEqual(d["proxies"][0]["domain"], "app.example.com")
        # 重复域名拒绝
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "app.example.com", "target_host": "1.2.3.4",
                             "target_port": 80}, token=token)
        self.assertEqual(code, 400)
        # v1.24.28：关闭 blockip 联动删除拒绝规则（用户明确要求总开关心智）
        code, d = self._req("POST", f"/api/proxy/{pid}",
                            {"action": "blockip", "enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        self.assertIn("删除", d["msg"])
        code, d = self._req("GET", "/api/rules", token=token)
        deny = [r for r in d["rules"] if r.get("type") == "port_deny" and r.get("port") == 8080
                and r.get("comment") == panel.PROXY_TARGET_DENY_COMMENT]
        self.assertFalse(deny, "关闭 blockip 后拒绝规则应联动删除")
        # 停用/启用
        code, d = self._req("POST", f"/api/proxy/{pid}", {"action": "enable", "enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("DELETE", f"/api/proxy/{pid}", token=token)
        self.assertEqual(code, 200, d)
        # 删除 https 反代（tls.example.com）
        code, d = self._req("GET", "/api/proxy", token=token)
        tls_pid = [p["id"] for p in d["proxies"] if p["domain"] == "tls.example.com"]
        self.assertEqual(len(tls_pid), 1)
        code, d = self._req("DELETE", f"/api/proxy/{tls_pid[0]}", token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertEqual(d["proxies"], [])
        # 清理 80/443 规则（避免影响其他测试）
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("comment") in ("反代:HTTPS", "反代:HTTP"):
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_proxy_cert_ref_api(self):
        """反代证书引用 API：cert_ref 校验/解析/编辑更换 + 反代申请证书登记列表"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        if os.path.exists(panel.CERT_FILE):
            os.remove(panel.CERT_FILE)
        # 准备一个"已申请"的泛域名证书文件（LE_LIVE 指向临时目录）
        import tempfile as _tf
        tmp_le = _tf.mkdtemp(prefix="fwpanel-le-")
        wc_dir = os.path.join(tmp_le, "*.example.com")
        os.makedirs(wc_dir)
        with open(os.path.join(wc_dir, "fullchain.pem"), "w") as f:
            f.write("fake-fullchain")
        with open(os.path.join(wc_dir, "privkey.pem"), "w") as f:
            f.write("fake-key")
        old_le = panel.LE_LIVE
        panel.LE_LIVE = tmp_le
        real_issue, real_apply = panel.issue_cert, panel.apply_proxies
        panel.issue_cert = lambda dom, email: (True, "证书已签发")
        panel.apply_proxies = lambda store: (True, "nginx 已重载")
        try:
            # 添加反代引用泛域名证书
            code, d = self._req("POST", "/api/proxy",
                                {"domain": "sub.example.com", "target_host": "127.0.0.1",
                                 "target_port": 8080, "cert_ref": "*.example.com"}, token=token)
            self.assertEqual(code, 200, d)
            pid = d["proxy"]["id"]
            code, d = self._req("GET", "/api/proxy", token=token)
            p = d["proxies"][0]
            self.assertEqual(p["cert_ref"], "*.example.com")
            self.assertEqual(p["cert_ref_resolved"], "*.example.com")
            self.assertTrue(p["cert_exists"])
            # 非法 cert_ref 拒绝
            code, d = self._req("POST", "/api/proxy",
                                {"domain": "bad.example.com", "target_host": "127.0.0.1",
                                 "target_port": 8081, "cert_ref": "*.notexists.com"}, token=token)
            self.assertEqual(code, 400)
            self.assertIn("证书不存在", d["error"])
            # 编辑更换 cert_ref（清空=自动申请）
            code, d = self._req("POST", f"/api/proxy/{pid}",
                                {"action": "edit", "cert_ref": ""}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/proxy", token=token)
            self.assertEqual(d["proxies"][0]["cert_ref"], "")
            self.assertEqual(d["proxies"][0]["cert_ref_resolved"], "sub.example.com")
            # 反代申请证书 → 自动登记进证书列表（source=proxy）
            code, d = self._req("POST", f"/api/proxy/{pid}", {"action": "ssl"}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/cert", token=token)
            cert = [c for c in d["certs"] if c["domain"] == "sub.example.com"]
            self.assertEqual(len(cert), 1, "反代申请的证书应登记进证书列表")
            self.assertEqual(cert[0]["source"], "proxy")
        finally:
            panel.LE_LIVE = old_le
            panel.issue_cert, panel.apply_proxies = real_issue, real_apply
            import shutil as _sh
            _sh.rmtree(tmp_le, ignore_errors=True)
            if os.path.exists(panel.PROXIES_FILE):
                os.remove(panel.PROXIES_FILE)
            if os.path.exists(panel.CERT_FILE):
                os.remove(panel.CERT_FILE)

    def test_proxy_install_api(self):
        """一键安装 API：缺组件时安装，装好后自动应用配置"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real_nginx, real_cert, real_install = (panel.nginx_available,
                                               panel.certbot_available, panel.install_pkgs)
        panel.nginx_available = lambda: False
        panel.certbot_available = lambda: False
        panel.install_pkgs = lambda pkgs: (True, "已安装: " + " ".join(pkgs))
        try:
            code, d = self._req("POST", "/api/proxy/install", {}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("nginx", d["msg"])
            self.assertIn("certbot", d["msg"])
        finally:
            panel.nginx_available = real_nginx
            panel.certbot_available = real_cert
            panel.install_pkgs = real_install

    def test_proxy_renew_blockip_api(self):
        """代理续期 + 禁止 IP 访问 API"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "renew.example.com", "target_host": "127.0.0.1",
                             "target_port": 9001}, token=token)
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        real_renew = panel.renew_cert
        panel.renew_cert = lambda dom: (True, "证书已续期")
        try:
            code, d = self._req("POST", f"/api/proxy/{pid}", {"action": "renew"}, token=token)
            self.assertEqual(code, 200, d)
        finally:
            panel.renew_cert = real_renew
        # 禁止 IP 访问
        code, d = self._req("POST", f"/api/proxy/{pid}",
                            {"action": "blockip", "enabled": True}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertTrue(d["proxies"][0]["block_ip"])
        # 关闭
        code, d = self._req("POST", f"/api/proxy/{pid}",
                            {"action": "blockip", "enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        self._req("DELETE", f"/api/proxy/{pid}", token=token)
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_proxy_cert_paths(self):
        """有证书的代理返回公钥/私钥路径"""
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "path.example.com", "target_host": "127.0.0.1",
                             "target_port": 9002}, token=token)
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        real_exists = panel.cert_files_exist
        panel.cert_files_exist = lambda dom: dom == "path.example.com"
        try:
            code, d = self._req("GET", "/api/proxy", token=token)
            p = d["proxies"][0]
            self.assertEqual(p["cert_path"], "/etc/letsencrypt/live/path.example.com/fullchain.pem")
            self.assertEqual(p["key_path"], "/etc/letsencrypt/live/path.example.com/privkey.pem")
        finally:
            panel.cert_files_exist = real_exists
            self._req("DELETE", f"/api/proxy/{pid}", token=token)
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_edit_rule_comment(self):
        """修改规则备注 API（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/rules",
                            {"type": "port_allow", "proto": "tcp", "port": 9991,
                             "comment": "原始备注"}, token=token)
        self.assertEqual(code, 200, d)
        rid = d["rule"]["id"]
        # 修改备注
        code, d = self._req("POST", f"/api/rules/{rid}",
                            {"comment": "新备注"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        r = next(x for x in d["rules"] if x["id"] == rid)
        self.assertEqual(r["comment"], "新备注")
        # 不存在的规则
        code, d = self._req("POST", "/api/rules/nonexist",
                            {"comment": "x"}, token=token)
        self.assertEqual(code, 400)
        self._req("DELETE", f"/api/rules/{rid}", token=token)

    def test_bruteforce_manual_ban(self):
        """手动封禁/解封 IP API（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 手动封禁
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.77"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.77"
                            for r in d["rules"]), "应存在封禁规则")
        # 封禁记录写入 bans（防爆破模块显示剩余时间）
        self.assertIn("198.51.100.77", panel.load_bans(), "手动封禁应写入封禁记录")
        # 重复封禁拒绝
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.77"}, token=token)
        self.assertEqual(code, 400)
        # 非法 IP
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "1.2.3.0/24"}, token=token)
        self.assertEqual(code, 400)
        # 手动解封
        code, d = self._req("POST", "/api/bruteforce/unban",
                            {"ip": "198.51.100.77"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertFalse(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.77"
                             for r in d["rules"]), "解封后不应有封禁规则")

    def test_manual_ban_expires_removes_rule(self):
        """手动封禁到期后：bans 记录与规则同时清理（回归：规则残留）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.88"}, token=token)
        self.assertEqual(code, 200, d)
        # 到期时间改为过去（固定值，配合 now=2000 触发到期）
        bans = panel.load_bans()
        self.assertIn("198.51.100.88", bans)
        bans["198.51.100.88"] = 1000
        panel.save_bans(bans)
        # 手动封禁的规则在磁盘上存在
        before = panel.RuleStore().rules
        self.assertTrue(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.88"
                            for r in before), "封禁后应有规则")
        # 触发一轮扫描（mock 失败检测为空，避免新增其他封禁）
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 99, "ban_seconds": 600, "fail_window": 300})
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {}
        panel.get_established_ips = lambda p: set()
        try:
            logs = panel.bruteforce_cycle(cfg, panel.RuleStore(), now=2000)
            self.assertTrue(any("198.51.100.88" in log for log in logs), logs)
        finally:
            panel.get_failed_ssh_attempts, panel.get_established_ips = real_a, real_e
        # 磁盘规则应已删除（含手动封禁）
        after = panel.RuleStore().rules
        self.assertFalse(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.88"
                             for r in after), "到期后规则应被清理")
        # 清理
        self._req("POST", "/api/bruteforce/unban",
                  {"ip": "198.51.100.88"}, token=token)
        self._req("POST", "/api/bruteforce",
                  {"enabled": False}, token=token)

    def test_close_port_api(self):
        """一键删除端口放行规则 API（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 放行 tcp 5005 和 both 5006
        self._req("POST", "/api/open-port", {"port": 5005, "proto": "tcp"}, token=token)
        self._req("POST", "/api/open-port", {"port": 5006, "proto": "both"}, token=token)
        # tcp 删 5005
        code, d = self._req("POST", "/api/close-port", {"port": 5005, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertFalse(any(r.get("port") == 5005 for r in d["rules"]), "5005 应已删除")
        # both 删 5006（存储为 1 条 both 规则，渲染时拆 tcp/udp 两条 nft 规则）
        code, d = self._req("POST", "/api/close-port", {"port": 5006, "proto": "both"}, token=token)
        self.assertEqual(code, 200, d)
        self.assertEqual(d["removed"], 1)
        # 无规则端口
        code, d = self._req("POST", "/api/close-port", {"port": 59999, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["removed"], 0)
        # 非法
        code, d = self._req("POST", "/api/close-port", {"port": 0}, token=token)
        self.assertEqual(code, 400)

    def test_bbr_api(self):
        """BBR API：查询 + 开启（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("GET", "/api/bbr", token=token)
        self.assertEqual(code, 200)
        self.assertIn("enabled", d)
        self.assertTrue(d.get("kernel"), "应返回内核版本")
        code, d = self._req("POST", "/api/bbr", {}, token=token)
        self.assertEqual(code, 200, d)

    def test_restart_api(self):
        """重启面板 API：dry-run 环境直接返回成功"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/restart", {}, token=token)
        self.assertEqual(code, 200, d)
        self.assertTrue(d.get("ok"))

    def test_panel_port_syncs_proxy(self):
        """修改面板端口：指向旧端口的反代自动同步 + 目标端口 deny 规则迁移"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        cur_port = int(self._req("GET", "/api/status", token=token)[1]["panel_port"])
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "sync.example.com", "target_host": "127.0.0.1",
                             "target_port": cur_port}, token=token)
        self.assertEqual(code, 200, d)
        new_port = cur_port + 1 if cur_port + 1 <= 65535 else cur_port - 1
        real_restart = panel.restart_service
        panel.restart_service = lambda: None   # 避免真的 systemctl restart
        try:
            code, d = self._req("POST", "/api/panel/port",
                                {"port": new_port}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("已同步", d["msg"])
        finally:
            panel.restart_service = real_restart
        # 代理 target_port 已更新为新端口
        code, d = self._req("GET", "/api/proxy", token=token)
        p = [x for x in d["proxies"] if x["domain"] == "sync.example.com"][0]
        self.assertEqual(p["target_port"], new_port)
        # deny 规则迁移：新端口有、旧端口无
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("type") == "port_deny" and r.get("port") == new_port
                            and r.get("comment") == panel.PROXY_TARGET_DENY_COMMENT
                            for r in d["rules"]), "新端口应有目标端口禁止规则")
        self.assertFalse(any(r.get("type") == "port_deny" and r.get("port") == cur_port
                             and r.get("comment") == panel.PROXY_TARGET_DENY_COMMENT
                             for r in d["rules"]), "旧端口禁止规则应已迁移")
        # 清理：删代理 + 恢复端口
        self._req("DELETE", "/api/proxy/" + p["id"], token=token)
        self._req("POST", "/api/panel/port", {"port": cur_port}, token=token)

    def test_cert_api(self):
        """独立证书 API：申请/列表/续期/移除（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        if os.path.exists(panel.CERT_FILE):
            os.remove(panel.CERT_FILE)
        real_issue, real_renew, real_nginx, real_reload = panel.issue_cert, panel.renew_cert, panel.nginx_available, panel.reload_nginx
        panel.issue_cert = lambda dom, email: (True, "证书已签发")
        panel.renew_cert = lambda dom: (True, "证书已续期")
        panel.nginx_available = lambda: True
        panel.reload_nginx = lambda: (True, "nginx 已重载")
        try:
            # 申请
            code, d = self._req("POST", "/api/cert",
                                {"domain": "solo.example.com", "email": "a@b.com"}, token=token)
            self.assertEqual(code, 200, d)
            # 列表
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["certs"]), 1)
            self.assertEqual(d["certs"][0]["domain"], "solo.example.com")
            # 续期
            code, d = self._req("POST", "/api/cert/solo.example.com",
                                {"action": "renew"}, token=token)
            self.assertEqual(code, 200, d)
            # 移除
            code, d = self._req("POST", "/api/cert/solo.example.com",
                                {"action": "delete"}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertEqual(len(d["certs"]), 0)
            # 非法域名
            code, d = self._req("POST", "/api/cert",
                                {"domain": "bad domain!"}, token=token)
            self.assertEqual(code, 400)
        finally:
            panel.issue_cert, panel.renew_cert, panel.nginx_available, panel.reload_nginx = real_issue, real_renew, real_nginx, real_reload
            if os.path.exists(panel.CERT_FILE):
                os.remove(panel.CERT_FILE)

    def test_cert_api_dns(self):
        """独立证书 API：DNS 验证申请（acme.sh 三家）+ 续期分流 + 旧格式兼容"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        if os.path.exists(panel.CERT_FILE):
            os.remove(panel.CERT_FILE)
        real_issue_dns, real_renew_dns = panel.issue_cert_dns, panel.renew_cert_dns
        calls = {}

        def fake_issue_dns(domain, email, provider, creds):
            calls["issue"] = (domain, email, provider, dict(creds))
            return True, "证书已签发（DNS 验证）"

        def fake_renew_dns(domain):
            calls["renew"] = domain
            return True, "证书已续期（DNS 验证）"
        panel.issue_cert_dns = fake_issue_dns
        panel.renew_cert_dns = fake_renew_dns
        try:
            # DNS 申请（Cloudflare）
            code, d = self._req("POST", "/api/cert",
                                {"domain": "dns.example.com", "method": "dns",
                                 "provider": "cf", "credentials": {"CF_Token": "tok123"}}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("DNS", d["msg"])
            self.assertEqual(calls["issue"][0], "dns.example.com")
            self.assertEqual(calls["issue"][2], "cf")
            self.assertEqual(calls["issue"][3], {"CF_Token": "tok123"})
            # 列表显示 method/provider
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertEqual(code, 200)
            cert = [c for c in d["certs"] if c["domain"] == "dns.example.com"][0]
            self.assertEqual(cert["method"], "dns")
            self.assertEqual(cert["provider"], "cf")
            # 续期分流到 renew_cert_dns
            code, d = self._req("POST", "/api/cert/dns.example.com",
                                {"action": "renew"}, token=token)
            self.assertEqual(code, 200, d)
            self.assertEqual(calls["renew"], "dns.example.com")
            # 旧格式（str 值）兼容
            panel.save_cert_store({"old.example.com": "a@b.com"})
            code, d = self._req("GET", "/api/cert", token=token)
            old = [c for c in d["certs"] if c["domain"] == "old.example.com"][0]
            self.assertEqual(old["method"], "http")
            # 凭证保存状态（v1.25.4）
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertTrue(d["dns_creds"].get("cf"), "申请后凭证应标记已保存")
            self.assertFalse(d["dns_creds"].get("ali"))
            # 留空凭证再次申请 → 使用已保存凭证
            code, d = self._req("POST", "/api/cert",
                                {"domain": "dns2.example.com", "method": "dns",
                                 "provider": "cf", "credentials": {}}, token=token)
            self.assertEqual(code, 200, d)
            self.assertEqual(calls["issue"][3], {"CF_Token": "tok123"}, "应复用已保存凭证")
            # 清除凭证
            code, d = self._req("POST", "/api/cert/creds", {"provider": "cf"}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertFalse(d["dns_creds"].get("cf"), "清除后凭证状态应为 False")
            # 非法 method
            code, d = self._req("POST", "/api/cert",
                                {"domain": "x.example.com", "method": "ftp"}, token=token)
            self.assertEqual(code, 400)
        finally:
            panel.issue_cert_dns, panel.renew_cert_dns = real_issue_dns, real_renew_dns
            if os.path.exists(panel.CERT_FILE):
                os.remove(panel.CERT_FILE)

    def test_upgrade_check_prerelease(self):
        """升级检测：返回 prerelease 字段；beta 升级指定 tag、stable 不带 tag"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real_pre, real_perform = panel.get_latest_prerelease, panel.perform_upgrade
        real_http = panel.http_get_json
        cur = [int(x) for x in panel.CURRENT_VERSION.split(".")]
        nxt = "%d.%d.%d" % (cur[0], cur[1], cur[2] + 1)   # 始终高于当前版本，升版免维护
        panel.get_latest_prerelease = lambda: nxt
        # _api_upgrade_check 现直接请求 releases 列表:mock 返回 [最新 beta nxt, 最新正式 1.25.1]
        panel.http_get_json = lambda url, timeout=15: [
            {"tag_name": "v" + nxt, "prerelease": True},
            {"tag_name": "v1.25.1", "prerelease": False},
        ]
        called = {}

        def fake_perform(tag=None):
            called["tag"] = tag
            return True, "升级成功"
        panel.perform_upgrade = fake_perform
        try:
            code, d = self._req("GET", "/api/upgrade/check", token=token)
            self.assertEqual(code, 200)
            self.assertEqual(d["latest"], "1.25.1")
            self.assertEqual(d["prerelease"]["tag"], nxt)
            self.assertTrue(d["prerelease"]["update_available"])
            # beta 升级：perform_upgrade 收到测试版 tag
            code, d = self._req("POST", "/api/upgrade", {"channel": "beta"}, token=token)
            self.assertEqual(code, 200, d)
            self.assertEqual(called["tag"], nxt)
            # stable 升级：不带 tag
            code, d = self._req("POST", "/api/upgrade", {"channel": "stable"}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIsNone(called["tag"])
            # 无测试版时 beta 升级 400
            panel.get_latest_prerelease = lambda: None
            code, d = self._req("POST", "/api/upgrade", {"channel": "beta"}, token=token)
            self.assertEqual(code, 400)
        finally:
            panel.get_latest_prerelease, panel.perform_upgrade = real_pre, real_perform
            panel.http_get_json = real_http

    def test_ipv6_mode(self):
        """IPv6 模式设置：sysctl.d + gai.conf 写入（隔离路径）"""
        import tempfile
        d = tempfile.mkdtemp()
        real_sysctl, real_gai = panel.IPV6_SYSCTL, panel.GAI_CONF
        panel.IPV6_SYSCTL = os.path.join(d, "99-ipv6.conf")
        panel.GAI_CONF = os.path.join(d, "gai.conf")
        try:
            ok, msg = panel.set_ipv6_mode("v4_first")
            self.assertTrue(ok, msg)
            self.assertIn("disable_ipv6=0", open(panel.IPV6_SYSCTL).read())
            self.assertIn("precedence ::ffff:0:0/96 100", open(panel.GAI_CONF).read())
            ok, msg = panel.set_ipv6_mode("disable")
            self.assertTrue(ok, msg)
            self.assertIn("disable_ipv6=1", open(panel.IPV6_SYSCTL).read())
            self.assertTrue(open(panel.GAI_CONF).read().strip().startswith("#"),
                            "gai.conf 的 precedence 行应被注释")
            ok, msg = panel.set_ipv6_mode("xxx")
            self.assertFalse(ok)
        finally:
            panel.IPV6_SYSCTL, panel.GAI_CONF = real_sysctl, real_gai

    def test_ipv6_api(self):
        """IPv6 API：查询 + 设置（隔离路径，不触碰真实 /etc）"""
        import tempfile
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        d0 = tempfile.mkdtemp()
        real_s, real_g = panel.IPV6_SYSCTL, panel.GAI_CONF
        panel.IPV6_SYSCTL = os.path.join(d0, "ipv6.conf")
        panel.GAI_CONF = os.path.join(d0, "gai.conf")
        try:
            code, d = self._req("GET", "/api/ipv6", token=token)
            self.assertEqual(code, 200)
            self.assertIn("status", d)
            code, d = self._req("POST", "/api/ipv6",
                                {"mode": "bad"}, token=token)
            self.assertEqual(code, 400)
            code, d = self._req("POST", "/api/ipv6",
                                {"mode": "enable"}, token=token)
            self.assertEqual(code, 200, d)
        finally:
            panel.IPV6_SYSCTL, panel.GAI_CONF = real_s, real_g

    def test_open_port_comment(self):
        """开放端口支持自定义注释（服务开关用「服务:标签」区分规则）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        port = 31555
        code, d = self._req("POST", "/api/open-port",
                            {"port": port, "proto": "tcp", "comment": "服务:3X-UI"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        r = [x for x in d["rules"] if x.get("port") == port and x.get("type") == "port_allow"]
        self.assertTrue(r and r[0].get("comment") == "服务:3X-UI", d)
        # 幂等重开：注释更新
        code, d = self._req("POST", "/api/open-port",
                            {"port": port, "proto": "tcp", "comment": "服务:Reality"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        r = [x for x in d["rules"] if x.get("port") == port and x.get("type") == "port_allow"]
        self.assertEqual(r[0].get("comment"), "服务:Reality", "幂等时应更新注释")
        # 清理
        self._req("DELETE", "/api/rules/" + r[0]["id"], token=token)

    def test_ssh_allow_ips(self):
        """SSH 白名单：渲染 ip saddr + drop；空列表恢复默认"""
        rules = panel.RuleStore()
        cfg = panel.Config()
        # 白名单模式
        cfg.set("mode", "strict")
        cfg.set("ssh_port", 2222)
        cfg.set("ssh_allow_ips", ["1.2.3.4", "2001:db8::1"])
        txt = rules.render(cfg)
        self.assertIn("ip saddr {1.2.3.4} tcp dport 2222 accept", txt)
        self.assertIn("ip6 saddr {2001:db8::1} tcp dport 2222 accept", txt)
        self.assertIn("tcp dport 2222 drop", txt)
        # 空列表恢复默认
        cfg.set("ssh_allow_ips", [])
        txt = rules.render(cfg)
        self.assertIn("tcp dport 2222 accept   # SSH 保护(不可删除)", txt)
        self.assertNotIn("tcp dport 2222 drop", txt)

    def test_ssh_allow_ips_api(self):
        """SSH 白名单 API：设置/查询/非法 IP"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/ssh/allow-ips",
                            {"ips": "1.2.3.4, 5.6.7.0/24"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh/allow-ips", token=token)
        self.assertEqual(sorted(d["ips"]), ["1.2.3.4", "5.6.7.0/24"])
        # 非法 IP
        code, d = self._req("POST", "/api/ssh/allow-ips",
                            {"ips": "999.1.1.1"}, token=token)
        self.assertEqual(code, 400)
        # 清空恢复
        code, d = self._req("POST", "/api/ssh/allow-ips",
                            {"ips": ""}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh/allow-ips", token=token)
        self.assertEqual(d["ips"], [])

    def test_cert_renew_status(self):
        """证书自动续期状态检测：结构完整（测试环境无 certbot.timer）"""
        info = panel.cert_renew_status()
        self.assertIn("enabled", info)
        self.assertIsInstance(info["enabled"], bool)
        if info["enabled"]:
            self.assertIn("via", info)

    def _token(self):
        """登录拿 token（测试通用；兼容字母序前后密码变化）"""
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def test_proxy_edit(self):
        """代理编辑：修改 scheme/websocket/hsts"""
        # 先添加一个代理（dry-run 环境 apply_proxies 安全）
        code, d = self._req("POST", "/api/proxy", {
            "domain": "edit.example.com", "target_host": "127.0.0.1",
            "target_port": 8080, "scheme": "http"}, token=self._token())
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        code, d = self._req("POST", "/api/proxy/" + pid, {
            "action": "edit", "scheme": "https",
            "websocket": True, "hsts": True}, token=self._token())
        self.assertEqual(code, 200, d)
        self.assertIn("HSTS: 开", d.get("msg", ""))
        code, d = self._req("GET", "/api/proxy", token=self._token())
        p = next(x for x in d["proxies"] if x["id"] == pid)
        self.assertEqual(p["scheme"], "https")
        self.assertTrue(p["websocket"])
        self.assertTrue(p["hsts"])
        # 非法 scheme
        code, d = self._req("POST", "/api/proxy/" + pid, {
            "action": "edit", "scheme": "ftp"}, token=self._token())
        self.assertEqual(code, 400)
        # 清理
        self._req("DELETE", "/api/proxy/" + pid, token=self._token())

    def test_proxy_hsts(self):
        """反代 HSTS：配置渲染包含 Strict-Transport-Security"""
        p = {"domain": "hsts.example.com", "target_host": "127.0.0.1",
             "target_port": 8080, "scheme": "http", "ssl": True,
             "websocket": False, "hsts": True}
        # mock 证书文件存在
        real = panel.LE_LIVE
        panel.LE_LIVE = tempfile.mkdtemp(prefix="fwpanel-le-")
        try:
            os.makedirs(os.path.join(panel.LE_LIVE, "hsts.example.com"), exist_ok=True)
            for f in ("fullchain.pem", "privkey.pem"):
                with open(os.path.join(panel.LE_LIVE, "hsts.example.com", f), "w") as fh:
                    fh.write("x")
            conf = panel.render_proxy_conf(p)
            self.assertIn('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', conf)
            # 未启用 HSTS 不渲染
            p["hsts"] = False
            conf2 = panel.render_proxy_conf(p)
            self.assertNotIn("Strict-Transport-Security", conf2)
        finally:
            tmp_le = panel.LE_LIVE
            panel.LE_LIVE = real
            shutil.rmtree(tmp_le, ignore_errors=True)

    def test_upgrade_api_check(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real = panel.http_get_json
        panel.http_get_json = lambda url, timeout=15: [{"tag_name": "v9.9.9", "prerelease": False}]
        try:
            code, d = self._req("GET", "/api/upgrade/check", token=token)
            self.assertEqual(code, 200)
            self.assertEqual(d["current"], panel.CURRENT_VERSION)
            self.assertEqual(d["latest"], "9.9.9")
            self.assertTrue(d["update_available"])
            # 未登录拒绝
            code, _ = self._req("GET", "/api/upgrade/check")
            self.assertEqual(code, 401)
        finally:
            panel.http_get_json = real

    def test_full_flow(self):
        # 未登录访问被拒
        code, _ = self._req("GET", "/api/status")
        self.assertEqual(code, 401)
        # 登录
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 状态
        code, d = self._req("GET", "/api/status", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["mode"], "permissive")
        # 添加端口规则
        code, d = self._req("POST", "/api/rules",
                            {"type": "port_allow", "proto": "tcp", "port": 8080,
                             "comment": "test-web"}, token=token)
        self.assertEqual(code, 200, d)
        # 添加非法规则被拒
        code, d = self._req("POST", "/api/rules",
                            {"type": "port_allow", "proto": "tcp", "port": "abc"}, token=token)
        self.assertEqual(code, 400)
        # 列表
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(len(d["rules"]), 1)
        rid = d["rules"][0]["id"]
        # 删除
        code, d = self._req("DELETE", f"/api/rules/{rid}", token=token)
        self.assertEqual(code, 200)
        # 服务开关
        code, d = self._req("POST", "/api/service", {"name": "http", "enabled": True}, token=token)
        self.assertEqual(code, 200)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r["port"] == 80 for r in d["rules"]))
        # 模式切换
        code, d = self._req("POST", "/api/mode", {"mode": "strict"}, token=token)
        self.assertEqual(code, 200)
        # 改密码（错误旧密码）
        code, d = self._req("POST", "/api/password",
                            {"old_password": "wrong", "new_password": "NewPass123"}, token=token)
        self.assertEqual(code, 400)
        # 改密码（正确）
        code, d = self._req("POST", "/api/password",
                            {"old_password": TEST_PASS, "new_password": "NewPass123"}, token=token)
        self.assertEqual(code, 200)
        # 新密码可登录
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        # 登出后 token 失效
        self._req("GET", "/api/logout", token=token)
        code, _ = self._req("GET", "/api/status", token=token)
        self.assertEqual(code, 401)


class TestUpgrade(unittest.TestCase):
    """一键升级核心逻辑：备份/替换/回滚（APP_DIR 指向临时目录，不碰真实系统）"""

    def setUp(self):
        self.app_tmp = tempfile.mkdtemp(prefix="fwpanel-app-")
        os.makedirs(os.path.join(self.app_tmp, "static"))
        self.old_app_dir = panel.APP_DIR
        panel.APP_DIR = self.app_tmp
        # 模拟"已安装"的旧文件
        with open(os.path.join(self.app_tmp, "panel.py"), "w") as f:
            f.write('# CURRENT_VERSION = "1.2.0"\nprint("old panel")\n')
        with open(os.path.join(self.app_tmp, "static", "index.html"), "w") as f:
            f.write("<html>old</html>")
        # 屏蔽重启动作
        self.real_timer = panel.threading.Timer
        class FakeTimer:
            def __init__(self, delay, fn):
                self.fn = fn
            def start(self):
                pass
        panel.threading.Timer = FakeTimer
        self.real_restart = panel.restart_service
        panel.restart_service = lambda: None

    def tearDown(self):
        panel.APP_DIR = self.old_app_dir
        panel.threading.Timer = self.real_timer
        panel.restart_service = self.real_restart
        shutil.rmtree(self.app_tmp, ignore_errors=True)

    def _make_new_files(self, version="9.9.9", broken=False, base=None):
        src = base or tempfile.mkdtemp(prefix="fwpanel-new-")
        py_content = f'CURRENT_VERSION = "{version}"\nprint("new panel")\n'
        if broken:
            py_content = "def broken(:\n"
        with open(os.path.join(src, "panel.py"), "w") as f:
            f.write(py_content)
        with open(os.path.join(src, "index.html"), "w") as f:
            f.write("<html>new</html>")
        logo = os.path.join(src, "github-logo.png")
        with open(logo, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\nfake-logo")
        ico = os.path.join(src, "favicon.ico")
        with open(ico, "wb") as f:
            f.write(b"\x00\x00\x01\x00fake-ico")
        # v2.1.20：模拟新版下载含 static/vendor + fonts 子资源（面板内升级需部署）
        vdir = os.path.join(src, "static", "vendor")
        os.makedirs(vdir, exist_ok=True)
        with open(os.path.join(vdir, "xterm.js"), "w") as f:
            f.write("!function(){console.log('xterm')}();")
        with open(os.path.join(vdir, "xterm.css"), "w") as f:
            f.write("/* xterm css */")
        with open(os.path.join(vdir, "xterm-addon-fit.js"), "w") as f:
            f.write("!function(){console.log('fit')}();")
        fdir = os.path.join(src, "static", "fonts")
        os.makedirs(fdir, exist_ok=True)
        with open(os.path.join(fdir, "fw-sans-sc-regular.woff2"), "wb") as f:
            f.write(b"wOF2fake-font")
        return os.path.join(src, "panel.py"), os.path.join(src, "index.html"), logo, ico

    def test_upgrade_success(self):
        panel.get_latest_version = lambda: "9.9.9"
        # mock 下载：文件建在 perform_upgrade 传入的 tmpdir 下（与真实 download_panel_files 一致）
        panel.download_panel_files = lambda tag, tmp: self._make_new_files("9.9.9", base=tmp)
        ok, msg = panel.perform_upgrade()
        self.assertTrue(ok, msg)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("9.9.9", f.read())
        self.assertTrue(os.path.exists(os.path.join(self.app_tmp, "panel.py.bak")),
                        "升级应生成备份文件")
        self.assertTrue(os.path.exists(os.path.join(self.app_tmp, "static", "favicon.ico")),
                        "升级应部署 favicon.ico")
        # v2.1.20：面板内升级必须部署 static/vendor + fonts 子资源（否则 xterm.js 404 终端白屏）
        self.assertTrue(os.path.exists(
            os.path.join(self.app_tmp, "static", "vendor", "xterm.js")),
            "升级应部署 static/vendor/xterm.js")
        self.assertTrue(os.path.exists(
            os.path.join(self.app_tmp, "static", "fonts", "fw-sans-sc-regular.woff2")),
            "升级应部署 static/fonts 字体")

    def test_download_panel_files_includes_vendor(self):
        """download_panel_files 应下载 vendor/fonts 子资源到 tmpdir/static/（v2.1.20）"""
        real_dl = panel.http_download
        got = []
        src = tempfile.mkdtemp(prefix="fwpanel-dl-")
        try:
            def fake_dl(url, dest, expect=None, timeout=30):
                # 按 URL 路径回写对应文件（panel.py 无 static/ 前缀；其余都在 static/ 下）
                rel = url.split("/static/")[-1] if "/static/" in url else url.split("/")[-1]
                data = {
                    "panel.py": b"#!/usr/bin/env python3\nCURRENT_VERSION = \"9.9.9\"\n",
                    "index.html": b"<!DOCTYPE html>\n<html lang=\"zh-CN\">new</html>",
                    "github-logo.png": b"\x89PNG\r\n\x1a\nlogo",
                    "favicon.ico": b"\x00\x00\x01\x00ico",
                    "vendor/xterm.js": b"!function(){}();",
                    "vendor/xterm.css": b"/* css */",
                    "vendor/xterm-addon-fit.js": b"!function(){}();",
                    "fonts/fw-sans-sc-regular.woff2": b"wOF2font",
                }
                body = data.get(rel)
                if body is None:
                    return False
                if expect and not body.startswith(expect):
                    return False
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(body)
                got.append(rel)
                return True
            panel.http_download = fake_dl
            files = panel.download_panel_files("v9.9.9", src)
            self.assertIsNotNone(files)
            for rel in ("vendor/xterm.js", "vendor/xterm.css",
                        "vendor/xterm-addon-fit.js",
                        "fonts/fw-sans-sc-regular.woff2"):
                self.assertTrue(os.path.exists(os.path.join(src, "static", rel)),
                                f"应下载 {rel}，实际: {got}")
        finally:
            panel.http_download = real_dl
            shutil.rmtree(src, ignore_errors=True)

    def test_issue_cert_dns(self):
        """DNS 证书申请：acme.sh 命令参数 + 凭证环境变量 + 缺凭证拒绝 + 不支持提供商"""
        real_run = panel.subprocess.run
        calls = []

        def fake_run(cmd, **kw):
            calls.append((list(cmd), dict(kw.get("env") or {})))
            class R:
                returncode = 0
                stdout = "ok"
                stderr = ""
            return R()
        panel.subprocess.run = fake_run
        old_sh, old_le = panel.ACME_SH, panel.LE_LIVE
        old_acme_avail, old_install = panel.acme_available, panel.install_acme_sh
        panel.ACME_SH = "/root/.acme.sh/acme.sh"
        panel.LE_LIVE = os.path.join(self.app_tmp, "le-live")
        panel.acme_available = lambda: True
        panel.install_acme_sh = lambda: True
        try:
            ok, msg = panel.issue_cert_dns("dns.example.com", "a@b.com", "cf", {"CF_Token": "tok"})
            self.assertTrue(ok, msg)
            issue_cmd = calls[0][0]
            self.assertEqual(issue_cmd, ["/root/.acme.sh/acme.sh", "--issue", "-d", "dns.example.com",
                                         "--dns", "dns_cf", "--server", "letsencrypt", "--force"])
            self.assertEqual(calls[0][1].get("CF_Token"), "tok")
            self.assertEqual(calls[0][1].get("ACME_EMAIL"), "a@b.com")
            install_cmd = calls[1][0]
            self.assertIn("--install-cert", install_cmd)
            self.assertIn(os.path.join(self.app_tmp, "le-live", "dns.example.com", "fullchain.pem"), install_cmd)
            # 缺凭证拒绝
            ok, msg = panel.issue_cert_dns("d.example.com", "", "ali", {})
            self.assertFalse(ok)
            self.assertIn("缺少凭证", msg)
            # 不支持的提供商
            ok, msg = panel.issue_cert_dns("d.example.com", "", "xxx", {})
            self.assertFalse(ok)
            self.assertIn("不支持的 DNS 提供商", msg)
        finally:
            panel.subprocess.run = real_run
            panel.ACME_SH, panel.LE_LIVE = old_sh, old_le
            panel.acme_available, panel.install_acme_sh = old_acme_avail, old_install

    def test_prerelease_detect(self):
        """测试版检测：releases 列表过滤 prerelease + 语义最大 + 与正式版共存"""
        real_json = panel.http_get_json

        def fake_json(url, **kw):
            if "releases?per_page" in url:
                return [
                    {"tag_name": "v1.24.66", "prerelease": False},
                    {"tag_name": "v1.25.0", "prerelease": True},
                    {"tag_name": "v1.25.0-beta", "prerelease": True},
                ]
            if "releases/latest" in url:
                return {"tag_name": "v1.24.66"}
            return None
        panel.http_get_json = fake_json
        try:
            self.assertEqual(panel.get_latest_prerelease(), "1.25.0")
            self.assertEqual(panel.get_latest_version(), "1.24.66")
        finally:
            panel.http_get_json = real_json

    def test_prerelease_none(self):
        """无测试版时返回 None"""
        real_json = panel.http_get_json

        def fake_json(url, **kw):
            if "releases?per_page" in url:
                return [{"tag_name": "v1.24.65", "prerelease": False}]
            return None
        panel.http_get_json = fake_json
        try:
            self.assertIsNone(panel.get_latest_prerelease())
        finally:
            panel.http_get_json = real_json

    def test_upgrade_specific_tag(self):
        """perform_upgrade(tag=...) 升级到指定测试版 tag"""
        panel.get_latest_version = lambda: "9.9.9"  # 不应被调用（指定 tag 时）
        panel.download_panel_files = lambda tag, tmp: self._make_new_files(tag, base=tmp)
        cur = [int(x) for x in panel.CURRENT_VERSION.split(".")]
        nxt = "%d.%d.%d" % (cur[0], cur[1], cur[2] + 1)   # 高于当前版本才允许升级
        ok, msg = panel.perform_upgrade(tag=nxt)
        self.assertTrue(ok, msg)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn(nxt, f.read())

    def test_resume_ssh_switch_watch(self):
        """启动恢复：残留切换保护规则 → 恢复监控线程（v1.25.6）"""
        if os.path.exists(panel.RULES_FILE):
            os.remove(panel.RULES_FILE)
        store = panel.RuleStore()
        store.add({"type": "port_allow", "proto": "tcp", "port": 22,
                   "comment": panel.SSH_OLD_PORT_COMMENT})
        store.add({"type": "port_allow", "proto": "tcp", "port": 42606,
                   "comment": "SSH保护(安装自动放行)"})
        cfg = panel.Config()
        cfg.set("ssh_port", 42606)
        started = []
        real_thread = panel.threading.Thread

        class FakeThread:
            def __init__(self, target, args=(), daemon=False):
                started.append((target, args))
            def start(self):
                pass
        panel.threading.Thread = FakeThread
        try:
            ok = panel.resume_ssh_switch_watch(store, cfg)
            self.assertTrue(ok)
            self.assertEqual(len(started), 1)
            # v1.25.9：线程参数含共享 store（防竞态）
            self.assertEqual(started[0][1][:2], (22, 42606))
            self.assertIs(started[0][1][2], store, "必须传共享 store 实例")
        finally:
            panel.threading.Thread = real_thread
            if os.path.exists(panel.RULES_FILE):
                os.remove(panel.RULES_FILE)

    def test_resume_ssh_switch_watch_none(self):
        """无残留切换保护规则 → 不启动监控"""
        if os.path.exists(panel.RULES_FILE):
            os.remove(panel.RULES_FILE)
        store = panel.RuleStore()
        store.add({"type": "port_allow", "proto": "tcp", "port": 42606,
                   "comment": "SSH保护(安装自动放行)"})
        cfg = panel.Config()
        started = []
        real_thread = panel.threading.Thread

        class FakeThread:
            def __init__(self, target, args=(), daemon=False):
                started.append(1)
            def start(self):
                pass
        panel.threading.Thread = FakeThread
        try:
            ok = panel.resume_ssh_switch_watch(store, cfg)
            self.assertFalse(ok)
            self.assertEqual(len(started), 0)
        finally:
            panel.threading.Thread = real_thread
            if os.path.exists(panel.RULES_FILE):
                os.remove(panel.RULES_FILE)

    def test_version_compare(self):
        self.assertTrue(panel.version_gt("1.10.0", "1.9.0"))
        self.assertTrue(panel.version_gt("1.2.1", "1.2.0"))
        self.assertFalse(panel.version_gt("1.2.0", "1.2.0"))
        self.assertFalse(panel.version_gt("1.1.3", "1.2.0"))

    def test_http_download_expect(self):
        """http_download 内容头校验：镜像返回的 HTML 错误页被拒绝，正确内容正常写入"""
        class FakeResp:
            def __init__(self, data):
                self._d = data
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return self._d
        saved = panel.urllib.request.urlopen
        try:
            # 错误页（GitHub 404 HTML）不符合 index.html 专属前缀 → 拒绝且不写文件
            panel.urllib.request.urlopen = lambda url, timeout=15: FakeResp(
                b"<!DOCTYPE html>\n<html lang=\"en\"><title>GitHub</title>404</html>")
            dest = os.path.join(TMP, "expect-bad.html")
            self.assertFalse(panel.http_download("http://x/", dest,
                             expect=b'<!DOCTYPE html>\n<html lang="zh-CN">'))
            self.assertFalse(os.path.exists(dest))
            # 正确前缀 → 写入成功
            panel.urllib.request.urlopen = lambda url, timeout=15: FakeResp(
                b'<!DOCTYPE html>\n<html lang="zh-CN">\n<title>FW-Panel</title>')
            dest2 = os.path.join(TMP, "expect-ok.html")
            self.assertTrue(panel.http_download("http://x/", dest2,
                            expect=b'<!DOCTYPE html>\n<html lang="zh-CN">'))
            self.assertTrue(os.path.exists(dest2))
            # panel.py 前缀 #!
            dest3 = os.path.join(TMP, "expect-ok.py")
            panel.urllib.request.urlopen = lambda url, timeout=15: FakeResp(
                b"#!/usr/bin/env python3\nCURRENT_VERSION = \"1.24.44\"\n")
            self.assertTrue(panel.http_download("http://x/", dest3, expect=b"#!"))
            panel.urllib.request.urlopen = lambda url, timeout=15: FakeResp(b"<html>bad</html>")
            self.assertFalse(panel.http_download("http://x/", dest3, expect=b"#!"))
        finally:
            panel.urllib.request.urlopen = saved

    def test_ssh_service_name(self):
        """SSH 服务名检测：有 ssh.service 用 ssh，否则 sshd"""
        import subprocess as sp
        real = panel.subprocess.run
        def fake(cmd, *a, **k):
            out = "ssh.service enabled\nsshd.service enabled\n" if "list-unit" in " ".join(cmd) else ""
            return sp.CompletedProcess(cmd, 0, stdout=out, stderr="")
        panel.subprocess.run = fake
        try:
            self.assertEqual(panel.ssh_service_name(), "ssh")
        finally:
            panel.subprocess.run = real
        def fake2(cmd, *a, **k):
            return sp.CompletedProcess(cmd, 0, stdout="sshd.service enabled\n", stderr="")
        panel.subprocess.run = fake2
        try:
            self.assertEqual(panel.ssh_service_name(), "sshd")
        finally:
            panel.subprocess.run = real

    def test_bf_cfg_defaults(self):
        cfg = make_cfg()
        bf = panel.bf_cfg(cfg)
        self.assertEqual(bf["enabled"], False)
        self.assertEqual(bf["max_fails"], 5)
        self.assertEqual(bf["ban_seconds"], 3600)
        self.assertEqual(bf["fail_window"], 300)
        cfg.set("bruteforce", {"enabled": True, "max_fails": 3, "ban_seconds": 600, "fail_window": 120})
        bf = panel.bf_cfg(cfg)
        self.assertEqual(bf["max_fails"], 3)
        self.assertEqual(bf["ban_seconds"], 600)

    def test_bf_cycle_bans_and_expires(self):
        """防爆破一轮扫描：封禁超阈值 IP + 到期自动解封"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 3, "ban_seconds": 600, "fail_window": 300})
        store = panel.RuleStore()
        store.rules = []
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {"203.0.113.66": 3, "127.0.0.1": 99}
        panel.get_established_ips = lambda p: set()
        try:
            logs = panel.bruteforce_cycle(cfg, store, now=1000)
            # 超阈值被封禁，回环 IP 豁免
            self.assertTrue(any(r.get("ip") == "203.0.113.66" for r in store.rules))
            self.assertFalse(any(r.get("ip") == "127.0.0.1" for r in store.rules))
            bans = panel.load_bans()
            self.assertEqual(bans["203.0.113.66"], 1600, "封禁到期时间 = now + ban_seconds")
            # 到期后自动解封
            panel.bruteforce_cycle(cfg, store, now=1700)
            self.assertFalse(any(r.get("ip") == "203.0.113.66" for r in store.rules),
                             "到期应自动解封")
            self.assertNotIn("203.0.113.66", panel.load_bans())
        finally:
            panel.get_failed_ssh_attempts = real_a
            panel.get_established_ips = real_e
            panel.RuleStore().rules = []
            panel.RuleStore().save()
            if os.path.exists(panel.BANS_FILE):
                os.remove(panel.BANS_FILE)

    def test_bf_cycle_exempt_established(self):
        """当前已连接 IP 豁免封禁（防把自己锁死）"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 2, "ban_seconds": 600, "fail_window": 300})
        store = panel.RuleStore()
        store.rules = []
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {"198.51.100.9": 5}
        panel.get_established_ips = lambda p: {"198.51.100.9"}
        try:
            panel.bruteforce_cycle(cfg, store, now=1000)
            self.assertFalse(any(r.get("ip") == "198.51.100.9" for r in store.rules),
                             "当前连接 IP 应豁免")
        finally:
            panel.get_failed_ssh_attempts = real_a
            panel.get_established_ips = real_e
            panel.RuleStore().rules = []
            panel.RuleStore().save()
            if os.path.exists(panel.BANS_FILE):
                os.remove(panel.BANS_FILE)

    def test_bf_disabled_no_action(self):
        cfg = make_cfg()   # 默认未启用
        store = panel.RuleStore()
        store.rules = []
        real_a = panel.get_failed_ssh_attempts
        panel.get_failed_ssh_attempts = lambda w: {"1.2.3.4": 999}
        try:
            logs = panel.bruteforce_cycle(cfg, store, now=1000)
            self.assertEqual(logs, [])
            self.assertEqual(store.rules, [])
        finally:
            panel.get_failed_ssh_attempts = real_a

    def test_disable_deletes_table(self):
        """关闭防火墙：删除 fwpanel 表"""
        import subprocess as sp
        calls = []
        real_run = panel.subprocess.run
        real_dry = panel.DRY_RUN

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        panel.subprocess.run = fake_run
        panel.DRY_RUN = False
        try:
            nft = panel.NFTManager(panel.RuleStore(), make_cfg())
            ok, msg = nft.disable()
            self.assertTrue(ok, msg)
            self.assertIn(["nft", "delete", "table", "inet", "fwpanel"], calls)
        finally:
            panel.subprocess.run = real_run
            panel.DRY_RUN = real_dry

    def test_bf_skipped_when_fw_disabled(self):
        """防火墙关闭时防爆破扫描跳过"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 2, "ban_seconds": 600, "fail_window": 300})
        cfg.set("firewall_enabled", False)
        store = panel.RuleStore()
        store.rules = []
        real_a = panel.get_failed_ssh_attempts
        panel.get_failed_ssh_attempts = lambda w: {"1.2.3.4": 99}
        try:
            logs = panel.bruteforce_cycle(cfg, store, now=1000)
            self.assertEqual(logs, [])
            self.assertEqual(store.rules, [])
        finally:
            panel.get_failed_ssh_attempts = real_a

    def test_render_proxy_conf(self):
        """nginx 反代配置生成：HTTP/ACME 挑战/WebSocket/HTTPS 跳转"""
        real_pc = panel._proxy_cert
        panel._proxy_cert = lambda domain, ref: (False, None, None)  # 无证书
        try:
            conf = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": True, "ssl": False,
            })
            self.assertIn("server_name app.example.com;", conf)
            self.assertIn("proxy_pass http://127.0.0.1:8080;", conf)
            self.assertIn("location /.well-known/acme-challenge/", conf)
            self.assertIn("proxy_set_header Upgrade $http_upgrade;", conf)
            self.assertNotIn("listen 443", conf)
        finally:
            panel._proxy_cert = real_pc
        # 有证书时：HTTP 跳转 + HTTPS server
        panel._proxy_cert = lambda domain, ref: (
            True, "/etc/letsencrypt/live/app.example.com/fullchain.pem",
            "/etc/letsencrypt/live/app.example.com/privkey.pem")
        try:
            conf = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "10.0.0.2",
                "target_port": 3000, "scheme": "http", "websocket": False, "ssl": True,
            })
            self.assertIn("listen 443 ssl;", conf)
            self.assertIn("ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;", conf)
            self.assertIn("return 301 https://$host$request_uri;", conf)
        finally:
            panel._proxy_cert = real_pc

    def test_render_proxy_conf_cert_ref(self):
        """反代引用泛域名证书（cert_ref=*.example.com）时 nginx 用泛域名证书路径"""
        real_pc = panel._proxy_cert
        panel._proxy_cert = lambda domain, ref: (
            True, f"/etc/letsencrypt/live/{ref}/fullchain.pem",
            f"/etc/letsencrypt/live/{ref}/privkey.pem")
        try:
            conf = panel.render_proxy_conf({
                "domain": "sub.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": False, "ssl": True,
                "cert_ref": "*.example.com",
            })
            self.assertIn("ssl_certificate /etc/letsencrypt/live/*.example.com/fullchain.pem;", conf)
            self.assertNotIn("live/sub.example.com/fullchain.pem", conf)
        finally:
            panel._proxy_cert = real_pc

    def test_proxy_store_crud(self):
        """ProxyStore 增删查"""
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        store = panel.ProxyStore()
        p = store.add({"domain": "a.example.com", "target_host": "127.0.0.1",
                       "target_port": 8080, "scheme": "http", "websocket": False, "ssl": False})
        self.assertTrue(p["id"])
        self.assertEqual(store.get(p["id"])["domain"], "a.example.com")
        store2 = panel.ProxyStore()
        self.assertEqual(len(store2.proxies), 1, "应持久化到文件")
        self.assertTrue(store.remove(p["id"]))
        self.assertFalse(store.remove(p["id"]))
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_apply_proxies_dry_run(self):
        """apply_proxies 在 dry-run 环境返回成功"""
        store = panel.ProxyStore()
        ok, msg = panel.apply_proxies(store)
        self.assertTrue(ok, msg)

    def test_pkg_mgr_detected(self):
        """包管理器检测（本机应为 apt）"""
        mgr = panel.pkg_mgr()
        self.assertIn(mgr, ("apt", "pacman", "dnf"))

    def test_install_pkgs_apt(self):
        """install_pkgs：apt 系执行 update + install"""
        import subprocess as sp
        calls = []
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        panel.subprocess.run = fake_run
        panel.pkg_mgr = lambda: "apt"
        try:
            ok, msg = panel.install_pkgs(["nginx", "certbot"])
            self.assertTrue(ok, msg)
            self.assertTrue(any(c[0] == "apt-get" and c[1] == "update" for c in calls))
            self.assertTrue(any(c[0] == "apt-get" and "install" in c and "nginx" in c for c in calls))
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr

    def test_host_guard(self):
        """host 守卫：普通域名精确匹配，通配符域名正则匹配"""
        g = panel.host_guard("app.example.com")
        self.assertIn('if ($host != "app.example.com")', g)
        self.assertIn("return 444", g)
        g2 = panel.host_guard("*.example.com")
        self.assertIn("!~", g2)
        self.assertNotIn('$host != "', g2)

    def test_render_proxy_conf_block_ip(self):
        """开启禁止 IP 访问时配置包含 host 守卫"""
        real = panel.cert_files_exist
        panel.cert_files_exist = lambda d: False
        try:
            conf = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": False,
                "ssl": False, "block_ip": True,
            })
            self.assertIn('if ($host != "app.example.com")', conf)
            self.assertIn("return 444", conf)
            conf2 = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": False,
                "ssl": False, "block_ip": False,
            })
            self.assertNotIn("return 444", conf2)
        finally:
            panel.cert_files_exist = real

    def test_bbr_status_detected(self):
        """BBR 状态检测：返回布尔值（本机 Linux 有 /proc/sys）"""
        self.assertIsInstance(panel.bbr_status(), bool)
        self.assertIsInstance(panel.bbr_available(), bool)

    def test_enable_bbr_dry_run(self):
        """BBR 开启在 dry-run 环境：不写文件直接返回成功"""
        ok, msg = panel.enable_bbr()
        self.assertTrue(ok, msg)

    def test_enable_bbr_verify(self):
        """BBR 开启后回读校验：生效返回成功，未生效返回失败"""
        import subprocess as sp
        real_run, real_avail, real_status = (panel.subprocess.run,
                                             panel.bbr_available, panel.bbr_status)
        real_dry, real_conf = panel.DRY_RUN, os.environ.get("FW_BBR_CONF")
        os.environ["FW_BBR_CONF"] = "/tmp/fwpanel-bbr-test.conf"
        panel.DRY_RUN = False
        panel.bbr_available = lambda: True
        panel.subprocess.run = lambda cmd, *a, **k: sp.CompletedProcess(cmd, 0, stdout="", stderr="")
        try:
            panel.bbr_status = lambda: True
            ok, msg = panel.enable_bbr()
            self.assertTrue(ok, msg)
            panel.bbr_status = lambda: False
            ok, msg = panel.enable_bbr()
            self.assertFalse(ok, "回读未生效应返回失败")
            self.assertIn("未生效", msg)
        finally:
            panel.subprocess.run, panel.bbr_available, panel.bbr_status = real_run, real_avail, real_status
            panel.DRY_RUN = real_dry
            if real_conf is None:
                os.environ.pop("FW_BBR_CONF", None)
            else:
                os.environ["FW_BBR_CONF"] = real_conf
            if os.path.exists("/tmp/fwpanel-bbr-test.conf"):
                os.remove("/tmp/fwpanel-bbr-test.conf")

    def test_ensure_nginx_default_blocks_ip(self):
        """默认兜底配置：80 default_server + 443 ssl_reject_handshake（禁止 IP 直连）"""
        import tempfile
        d = tempfile.mkdtemp()
        real_dir, real_dry, real_ver = (panel.nginx_conf_dir, panel.DRY_RUN,
                                        panel.nginx_supports_reject_handshake)
        panel.nginx_conf_dir = lambda: d
        panel.DRY_RUN = False
        panel.nginx_supports_reject_handshake = lambda: True
        try:
            panel.ensure_nginx_default()
            content = open(os.path.join(d, "fwpanel-default.conf")).read()
            self.assertIn("listen 80 default_server;", content)
            self.assertIn("return 444;", content)
            self.assertIn("listen 443 ssl default_server;", content)
            self.assertIn("ssl_reject_handshake on;", content)
            # 幂等：再次调用不报错且内容不变
            panel.ensure_nginx_default()
            content2 = open(os.path.join(d, "fwpanel-default.conf")).read()
            self.assertEqual(content, content2)
        finally:
            panel.nginx_conf_dir, panel.DRY_RUN = real_dir, real_dry
            panel.nginx_supports_reject_handshake = real_ver

    def test_sync_ssh_port(self):
        """SSH 保护端口自动同步：自动模式跟随系统端口，手动模式不覆盖"""
        cfg = make_cfg()
        real = panel.get_sshd_port
        panel.get_sshd_port = lambda: 2222
        try:
            # 自动模式：同步到检测端口
            cfg.set("ssh_port_auto", True)
            cfg.set("ssh_port", 22)
            changed = panel.sync_ssh_port(cfg)
            self.assertTrue(changed)
            self.assertEqual(int(cfg.get("ssh_port")), 2222)
            # 手动模式：不覆盖
            cfg.set("ssh_port_auto", False)
            cfg.set("ssh_port", 33)
            changed = panel.sync_ssh_port(cfg)
            self.assertFalse(changed)
            self.assertEqual(int(cfg.get("ssh_port")), 33)
        finally:
            panel.get_sshd_port = real

    def test_apply_is_idempotent(self):
        """apply 必须先删旧表再加载（防 nft -f 追加累积），回归测试"""
        import subprocess as sp
        calls = []
        real_run = panel.subprocess.run
        real_dry = panel.DRY_RUN

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        panel.subprocess.run = fake_run
        panel.DRY_RUN = False
        try:
            store = panel.RuleStore()
            store.rules = [{"id": "1", "type": "port_allow", "proto": "tcp",
                            "port": 8080, "comment": "t"}]
            nft = panel.NFTManager(store, make_cfg())
            ok, msg = nft.apply()
            self.assertTrue(ok, msg)
            # 调用序列中 delete 必须在 nft -f 之前
            delete_idx = next(i for i, c in enumerate(calls)
                              if c[:5] == ["nft", "delete", "table", "inet", "fwpanel"])
            load_idx = next(i for i, c in enumerate(calls) if c[:2] == ["nft", "-f"])
            self.assertLess(delete_idx, load_idx, "必须先删除旧表再加载新规则")
        finally:
            panel.subprocess.run = real_run
            panel.DRY_RUN = real_dry

    def test_upgrade_same_version(self):
        panel.get_latest_version = lambda: panel.CURRENT_VERSION
        ok, msg = panel.perform_upgrade()
        self.assertFalse(ok)
        self.assertIn("已是最新", msg)

    def test_upgrade_download_fail_keeps_old(self):
        panel.get_latest_version = lambda: "9.9.9"
        panel.download_panel_files = lambda tag, tmp: None
        ok, msg = panel.perform_upgrade()
        self.assertFalse(ok)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("old panel", f.read())

    def test_upgrade_broken_file_keeps_old(self):
        panel.get_latest_version = lambda: "9.9.9"
        panel.download_panel_files = lambda tag, tmp: self._make_new_files(broken=True)
        ok, msg = panel.perform_upgrade()
        self.assertFalse(ok)
        self.assertIn("校验失败", msg)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("old panel", f.read())


class TestDocker(unittest.TestCase):
    """Docker 模块 API 测试：mock docker_* 辅助函数（真实环境无 docker）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17998), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17998"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                self._last_content_type = resp.headers.get("Content-Type", "")
                raw = resp.read()
                try:
                    return resp.status, json.loads(raw)
                except Exception:
                    return resp.status, raw
        except urllib.error.HTTPError as e:
            self._last_content_type = e.headers.get("Content-Type", "") if e.headers else ""
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        raise RuntimeError("无法登录")

    def _patch_docker(self, **mocks):
        saved = {}
        for name, fn in mocks.items():
            saved[name] = getattr(panel, name)
            setattr(panel, name, fn)
        return saved

    def test_docker_status_not_installed(self):
        tok = self._token()
        saved = self._patch_docker(docker_available=lambda: False)
        try:
            code, d = self._req("GET", "/api/docker", token=tok)
            self.assertEqual(code, 200)
            self.assertFalse(d["installed"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_status_installed(self):
        tok = self._token()
        saved = self._patch_docker(
            docker_available=lambda: True,
            docker_status=lambda: {"installed": True, "service_active": True,
                                   "version": "Docker version 27.0.0",
                                   "containers": 2, "running": 1})
        try:
            code, d = self._req("GET", "/api/docker", token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["installed"])
            self.assertEqual(d["containers"], 2)
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_containers(self):
        tok = self._token()
        saved = self._patch_docker(
            docker_containers=lambda all_: [
                {"id": "abc123", "name": "nginx", "image": "nginx:latest",
                 "status": "Up 2 hours", "ports": "0.0.0.0:80->80/tcp", "running": True}])
        try:
            code, d = self._req("GET", "/api/docker/containers", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["containers"]), 1)
            self.assertEqual(d["containers"][0]["name"], "nginx")
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_official(self):
        tok = self._token()
        saved = self._patch_docker(install_docker_pkgs=lambda source="official": (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/install",
                                {"source": "official"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_china(self):
        tok = self._token()
        saved = self._patch_docker(install_docker_pkgs=lambda source="official": (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/install",
                                {"source": "china"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_invalid_source_defaults(self):
        """非法 source 应回退 official（不报错）"""
        tok = self._token()
        calls = []
        saved = self._patch_docker(
            install_docker_pkgs=lambda source="official": calls.append(source) or (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/install",
                                {"source": "hack"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_official_apt_fallback(self):
        """apt 官方源：docker-compose-v2 不存在时回退 docker-compose（v1）"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            # apt-get update 成功；install v2 失败（找不到包）；install v1 成功
            if args[0] == "apt-get" and args[1] == "update":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            if "docker-compose-v2" in args:
                return types.SimpleNamespace(
                    returncode=100, stdout="",
                    stderr="E: Unable to locate package docker-compose-v2")
            # systemctl is-active docker → active（安装后轮询确认服务启动）
            if args[:2] == ["systemctl", "is-active"]:
                return types.SimpleNamespace(returncode=0, stdout="active", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            ok, msg = panel.install_docker_pkgs("official")
            self.assertTrue(ok)
            # 断言第二次 install 用了 docker-compose（v1 回退）
            self.assertTrue(any("docker-compose" in a and "docker-compose-v2" not in a
                                for a in calls))
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry

    def test_docker_install_official_apt_both_fail(self):
        """apt 官方源：v2 和 v1 都失败 → 返回失败"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            if args[0] == "apt-get" and args[1] == "update":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return types.SimpleNamespace(
                returncode=100, stdout="",
                stderr="E: Unable to locate package docker-compose")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            ok, msg = panel.install_docker_pkgs("official")
            self.assertFalse(ok)
            self.assertIn("安装失败", msg)
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry

    def test_docker_action_valid(self):
        tok = self._token()
        saved = self._patch_docker(docker_action=lambda act, cid: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/action",
                                {"action": "restart", "id": "abc123"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_action_invalid(self):
        tok = self._token()
        code, d = self._req("POST", "/api/docker/action",
                            {"action": "hack", "id": "abc123"}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_create_missing_fields(self):
        tok = self._token()
        code, d = self._req("POST", "/api/docker/create",
                            {"name": "", "image": ""}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_pull(self):
        tok = self._token()
        saved = self._patch_docker(docker_pull=lambda name: (True, "pulled"))
        try:
            code, d = self._req("POST", "/api/docker/pull",
                                {"name": "nginx:latest"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_rmi(self):
        tok = self._token()
        saved = self._patch_docker(docker_rmi=lambda iid: (True, "removed"))
        try:
            code, d = self._req("POST", "/api/docker/rmi",
                                {"id": "abc123"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_up(self):
        tok = self._token()
        saved = self._patch_docker(docker_compose_up=lambda content, folder="": (True, "up"))
        try:
            code, d = self._req("POST", "/api/docker/compose/up",
                                {"content": "services:\n  web:\n    image: nginx\n"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_up_empty(self):
        tok = self._token()
        code, d = self._req("POST", "/api/docker/compose/up",
                            {"content": ""}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_compose_down(self):
        tok = self._token()
        saved = self._patch_docker(docker_compose_down=lambda folder="": (True, "down"))
        try:
            code, d = self._req("POST", "/api/docker/compose/down", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_stats(self):
        tok = self._token()
        saved = self._patch_docker(
            docker_stats=lambda: [{"name": "nginx", "cpu": "0.10%",
                                   "mem": "10MiB / 500MiB", "mem_pct": "2.00%",
                                   "net": "1MB / 2MB", "block": "0B / 0B"}])
        try:
            code, d = self._req("GET", "/api/docker/stats", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["stats"]), 1)
            self.assertEqual(d["stats"][0]["name"], "nginx")
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_dirs_create(self):
        """一键创建目录：mock create_docker_dirs 返回成功"""
        tok = self._token()
        saved = self._patch_docker(create_docker_dirs=lambda: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/dirs", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_dirs_status(self):
        """目录状态 API 返回结构（mock 已存在）"""
        tok = self._token()
        saved = self._patch_docker(
            create_docker_dirs=lambda: (True, "ok"))
        # mock os.path.isdir 和 DOCKER_DATA_DIRS 用真实值
        real_isdir = os.path.isdir
        try:
            os.path.isdir = lambda p: p.startswith("/DockerData")
            code, d = self._req("GET", "/api/docker/dirs", token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["exists"])
            self.assertEqual(d["base"], "/DockerData")
            self.assertEqual(d["total"], len(panel.DOCKER_DATA_DIRS))
        finally:
            os.path.isdir = real_isdir
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_create_docker_dirs_idempotent(self):
        """重复创建不报错（exist_ok）"""
        real_makedirs = os.makedirs
        real_base = panel.DOCKER_DATA_BASE
        try:
            panel.DOCKER_DATA_BASE = tempfile.mkdtemp(prefix="fw-dockerdata-")
            panel.DRY_RUN = False
            calls = []
            os.makedirs = lambda p, exist_ok=False: calls.append(p)
            ok, msg = panel.create_docker_dirs()
            self.assertTrue(ok)
            self.assertIn("已创建", msg)
            # 第二次调用（已存在）也应成功
            ok2, _ = panel.create_docker_dirs()
            self.assertTrue(ok2)
        finally:
            os.makedirs = real_makedirs
            panel.DOCKER_DATA_BASE = real_base
            panel.DRY_RUN = True

    def test_docker_uninstall_api(self):
        """卸载 API：mock uninstall_docker_pkgs 返回成功"""
        tok = self._token()
        saved = self._patch_docker(uninstall_docker_pkgs=lambda: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/uninstall", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_uninstall_docker_apt_covers_both_sources(self):
        """apt 卸载命令必须包含国内(docker-ce) + 国外(docker.io)两种来源包名"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            ok, msg = panel.uninstall_docker_pkgs()
            self.assertTrue(ok)
            # 找到 apt-get remove 命令，断言同时含 docker-ce 和 docker.io
            remove_calls = [a for a in calls if a[0] == "apt-get" and a[1] == "remove"]
            self.assertTrue(remove_calls)
            self.assertTrue(any("docker-ce" in a for a in remove_calls))
            self.assertTrue(any("docker.io" in a for a in remove_calls))
            self.assertTrue(any("docker-compose-plugin" in a for a in remove_calls))
            # 停止服务命令存在
            self.assertTrue(any(a[0] == "systemctl" and a[1] == "stop" for a in calls))
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry

    def test_compose_file_saved_to_dockerdata(self):
        """compose up 必须把文件保存到 /DockerData/dockercompose/<镜像名>/（用户要求）"""
        import types
        real_run = panel.subprocess.run
        real_base = panel.COMPOSE_BASE
        real_legacy = panel.COMPOSE_FILE_LEGACY
        real_dry = panel.DRY_RUN
        real_makedirs = os.makedirs
        try:
            tmp = tempfile.mkdtemp(prefix="fw-compose-test-")
            panel.COMPOSE_BASE = os.path.join(tmp, "dockercompose")
            panel.COMPOSE_FILE_LEGACY = os.path.join(tmp, "etc-fwpanel", "docker-compose.yml")
            panel.DRY_RUN = False
            os.makedirs = lambda p, exist_ok=False: real_makedirs(p, exist_ok=True)

            def fake_run(args, **kw):
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")

            panel.subprocess.run = fake_run
            content = "services:\n  web:\n    image: nginx:latest\n"
            ok, msg = panel.docker_compose_up(content)
            self.assertTrue(ok)
            # 文件必须落在 dockercompose/<镜像名>/ 子目录
            expected = os.path.join(tmp, "dockercompose", "nginx", "docker-compose.yml")
            self.assertTrue(os.path.exists(expected))
            self.assertIn("nginx", msg)
        finally:
            panel.subprocess.run = real_run
            panel.COMPOSE_BASE = real_base
            panel.COMPOSE_FILE_LEGACY = real_legacy
            panel.DRY_RUN = real_dry
            os.makedirs = real_makedirs
            shutil.rmtree(tmp, ignore_errors=True)

    def test_compose_legacy_migrated(self):
        """旧路径（/etc/fwpanel）已有文件时，up 自动迁移到新路径"""
        import types
        real_run = panel.subprocess.run
        real_base = panel.COMPOSE_BASE
        real_legacy = panel.COMPOSE_FILE_LEGACY
        real_dry = panel.DRY_RUN
        real_makedirs = os.makedirs
        try:
            tmp = tempfile.mkdtemp(prefix="fw-compose-legacy-")
            panel.COMPOSE_BASE = os.path.join(tmp, "dockercompose")
            legacy_dir = os.path.join(tmp, "etc-fwpanel")
            os.makedirs(legacy_dir, exist_ok=True)
            panel.COMPOSE_FILE_LEGACY = os.path.join(legacy_dir, "docker-compose.yml")
            with open(panel.COMPOSE_FILE_LEGACY, "w") as f:
                f.write("legacy content")
            panel.DRY_RUN = False
            os.makedirs = lambda p, exist_ok=False: real_makedirs(p, exist_ok=True)

            def fake_run(args, **kw):
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")

            panel.subprocess.run = fake_run
            ok, _ = panel.docker_compose_up("services:\n  web:\n    image: redis:7\n")
            self.assertTrue(ok)
            # 新文件已存在（up 写入内容覆盖迁移的旧内容，文件必须在新路径）
            expected = os.path.join(tmp, "dockercompose", "redis", "docker-compose.yml")
            self.assertTrue(os.path.exists(expected))
        finally:
            panel.subprocess.run = real_run
            panel.COMPOSE_BASE = real_base
            panel.COMPOSE_FILE_LEGACY = real_legacy
            panel.DRY_RUN = real_dry
            os.makedirs = real_makedirs
            shutil.rmtree(tmp, ignore_errors=True)

    def test_docker_images_in_use_real_parse(self):
        """真实解析逻辑：inspect 返回 sha256:64位完整ID 时必须匹配上 images 的 12 位短 ID
        （v1.24.12 修复：不带 sha256: 前缀截断会全部误判未使用）"""
        import types
        real_run = panel.subprocess.run
        real_avail = panel.docker_available
        try:
            panel.docker_available = lambda: True

            def fake_run(args, **kw):
                if args[0] == "docker" and args[1] == "images":
                    # 12 位短 ID
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout="6f6e3a1f3e6d\tnginx\tlatest\t100MB\n"
                               "9d4c2b8a7f11\tbusybox\tlatest\t5MB\n",
                        stderr="")
                if args[0] == "docker" and args[1] == "ps":
                    # ps -aq：容器 ID
                    return types.SimpleNamespace(returncode=0, stdout="c1c2c3c4\n", stderr="")
                if args[0] == "docker" and args[1] == "inspect":
                    # inspect 返回 sha256:64位完整 ID（前 12 位对应 nginx 的 6f6e3a1f3e6d）
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout="sha256:6f6e3a1f3e6d4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c\n",
                        stderr="")
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")

            panel.subprocess.run = fake_run
            imgs = panel.docker_images()
            self.assertEqual(len(imgs), 2)
            nginx = [i for i in imgs if i["repository"] == "nginx"][0]
            busybox = [i for i in imgs if i["repository"] == "busybox"][0]
            self.assertTrue(nginx["in_use"], "nginx 被容器引用应标记使用中（sha256 前缀 bug）")
            self.assertFalse(busybox["in_use"], "busybox 未被引用应标记未使用")
        finally:
            panel.subprocess.run = real_run
            panel.docker_available = real_avail

    def test_docker_images_in_use_flag(self):
        """docker_images 必须带 in_use 标记（使用中的镜像删除按钮禁用）"""
        tok = self._token()
        saved = self._patch_docker(
            docker_images=lambda: [
                {"id": "abc123", "repository": "nginx", "tag": "latest",
                 "size": "100MB", "in_use": True},
                {"id": "def456", "repository": "busybox", "tag": "latest",
                 "size": "5MB", "in_use": False},
            ])
        try:
            code, d = self._req("GET", "/api/docker/images", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["images"]), 2)
            self.assertTrue(d["images"][0]["in_use"])
            self.assertFalse(d["images"][1]["in_use"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_prune_api(self):
        """清理未使用镜像 API"""
        tok = self._token()
        saved = self._patch_docker(docker_image_prune=lambda: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/prune", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_set_docker_data_root(self):
        """配置 data-root：daemon.json 写入 /DockerData/dockerimage，保留已有字段"""
        import types
        real_daemon = panel.DOCKER_DAEMON_JSON
        real_base = panel.DOCKER_DATA_BASE
        real_dry = panel.DRY_RUN
        real_run = panel.subprocess.run
        try:
            tmp = tempfile.mkdtemp(prefix="fw-daemon-test-")
            panel.DOCKER_DAEMON_JSON = os.path.join(tmp, "daemon.json")
            panel.DOCKER_DATA_BASE = os.path.join(tmp, "DockerData")
            panel.DRY_RUN = False
            # 预置已有配置（保留字段）
            with open(panel.DOCKER_DAEMON_JSON, "w") as f:
                json.dump({"registry-mirrors": ["https://x.example"]}, f)
            panel.subprocess.run = lambda args, **kw: types.SimpleNamespace(
                returncode=0, stdout="", stderr="")
            ok, msg = panel.set_docker_data_root()
            self.assertTrue(ok)
            with open(panel.DOCKER_DAEMON_JSON) as f:
                conf = json.load(f)
            self.assertEqual(conf["data-root"], os.path.join(tmp, "DockerData", "dockerimage"))
            # 已有字段保留
            self.assertEqual(conf["registry-mirrors"], ["https://x.example"])
            self.assertIn("dockerimage", msg)
        finally:
            panel.DOCKER_DAEMON_JSON = real_daemon
            panel.DOCKER_DATA_BASE = real_base
            panel.DRY_RUN = real_dry
            panel.subprocess.run = real_run
            shutil.rmtree(tmp, ignore_errors=True)

    def test_docker_create_auto_volume(self):
        """创建容器自动挂载 /DockerData/dockerrun/<容器名>:/data"""
        import types
        real_run = panel.subprocess.run
        real_base = panel.DOCKER_DATA_BASE
        real_dry = panel.DRY_RUN
        try:
            tmp = tempfile.mkdtemp(prefix="fw-run-test-")
            panel.DOCKER_DATA_BASE = os.path.join(tmp, "DockerData")
            panel.DRY_RUN = False
            calls = []

            def fake_run(args, **kw):
                calls.append(args)
                return types.SimpleNamespace(returncode=0, stdout="abc123", stderr="")

            panel.subprocess.run = fake_run
            ok, msg = panel.docker_create("web1", "nginx:latest", ports="8080:80", envs="A=1")
            self.assertTrue(ok)
            self.assertTrue(calls)
            run_args = calls[-1]
            # 断言 -v /DockerData/dockerrun/web1:/data 存在
            vol = os.path.join(tmp, "DockerData", "dockerrun", "web1") + ":/data"
            self.assertIn("-v", run_args)
            self.assertIn(vol, run_args)
            self.assertIn("-p", run_args)
            self.assertIn("8080:80", run_args)
            # 数据目录已创建
            self.assertTrue(os.path.isdir(os.path.join(tmp, "DockerData", "dockerrun", "web1")))
        finally:
            panel.subprocess.run = real_run
            panel.DOCKER_DATA_BASE = real_base
            panel.DRY_RUN = real_dry
            shutil.rmtree(tmp, ignore_errors=True)

    def test_compose_custom_folder_priority(self):
        """用户指定 folder 时优先用 folder 名，不用第一个镜像名"""
        import types
        real_run = panel.subprocess.run
        real_base = panel.COMPOSE_BASE
        real_dry = panel.DRY_RUN
        try:
            tmp = tempfile.mkdtemp(prefix="fw-compose-folder-")
            panel.COMPOSE_BASE = os.path.join(tmp, "dockercompose")
            panel.DRY_RUN = False
            panel.subprocess.run = lambda args, **kw: types.SimpleNamespace(
                returncode=0, stdout="", stderr="")
            content = "services:\n  web:\n    image: nginx:latest\n  db:\n    image: redis:7\n"
            ok, msg = panel.docker_compose_up(content, folder="my-web")
            self.assertTrue(ok)
            expected = os.path.join(tmp, "dockercompose", "my-web", "docker-compose.yml")
            self.assertTrue(os.path.exists(expected))
            self.assertIn("my-web", msg)
        finally:
            panel.subprocess.run = real_run
            panel.COMPOSE_BASE = real_base
            panel.DRY_RUN = real_dry
            shutil.rmtree(tmp, ignore_errors=True)

    def test_docker_compose_list_api(self):
        """已保存 compose 项目列表 API"""
        tok = self._token()
        saved = self._patch_docker(
            docker_compose_list=lambda: [{"folder": "nginx", "path": "/x/docker-compose.yml",
                                          "mtime": 1234567890, "running": True}])
        try:
            code, d = self._req("GET", "/api/docker/compose", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["projects"]), 1)
            self.assertEqual(d["projects"][0]["folder"], "nginx")
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_start_api(self):
        """启动指定 compose 项目 API"""
        tok = self._token()
        saved = self._patch_docker(docker_compose_start=lambda folder: (True, "started"))
        try:
            code, d = self._req("POST", "/api/docker/compose/start",
                                {"folder": "nginx"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_start_missing_folder(self):
        """启动缺少 folder 应 400"""
        tok = self._token()
        code, d = self._req("POST", "/api/docker/compose/start", {}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_compose_down_with_folder(self):
        """停止指定项目：docker compose down 必须用 folder 对应文件"""
        import types
        real_run = panel.subprocess.run
        real_base = panel.COMPOSE_BASE
        real_dry = panel.DRY_RUN
        try:
            tmp = tempfile.mkdtemp(prefix="fw-compose-down-")
            panel.COMPOSE_BASE = os.path.join(tmp, "dockercompose")
            # 造两个项目
            for name in ("nginx", "webstack"):
                d = os.path.join(panel.COMPOSE_BASE, name)
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "docker-compose.yml"), "w") as f:
                    f.write("services: {}\n")
            panel.DRY_RUN = False
            calls = []
            panel.subprocess.run = lambda args, **kw: calls.append(args) or types.SimpleNamespace(
                returncode=0, stdout="", stderr="")
            ok, msg = panel.docker_compose_down("webstack")
            self.assertTrue(ok)
            # 断言用的文件是 webstack 的
            down_calls = [a for a in calls if a[0] == "docker" and a[1] == "compose" and a[-1] == "down"]
            self.assertTrue(down_calls)
            self.assertIn("webstack", down_calls[0][down_calls[0].index("-f") + 1])
            self.assertNotIn("nginx", down_calls[0][down_calls[0].index("-f") + 1])
        finally:
            panel.subprocess.run = real_run
            panel.COMPOSE_BASE = real_base
            panel.DRY_RUN = real_dry
            shutil.rmtree(tmp, ignore_errors=True)

    def test_docker_compose_upgrade_api(self):
        """升级 compose 项目 API"""
        tok = self._token()
        saved = self._patch_docker(docker_compose_upgrade=lambda folder: (True, "upgraded"))
        try:
            code, d = self._req("POST", "/api/docker/compose/upgrade",
                                {"folder": "nginx"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_upgrade_sequence(self):
        """升级命令序列：先 pull 后 up -d"""
        import types
        real_run = panel.subprocess.run
        real_base = panel.COMPOSE_BASE
        real_dry = panel.DRY_RUN
        try:
            tmp = tempfile.mkdtemp(prefix="fw-compose-upgrade-")
            panel.COMPOSE_BASE = os.path.join(tmp, "dockercompose")
            d = os.path.join(panel.COMPOSE_BASE, "nginx")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "docker-compose.yml"), "w") as f:
                f.write("services: {}\n")
            panel.DRY_RUN = False
            calls = []
            panel.subprocess.run = lambda args, **kw: calls.append(args) or types.SimpleNamespace(
                returncode=0, stdout="", stderr="")
            ok, msg = panel.docker_compose_upgrade("nginx")
            self.assertTrue(ok)
            # 命令格式: ['docker','compose','-f',file,'pull'] / [...'up','-d']
            actions = [a[-2] if a[-1] == "-d" else a[-1] for a in calls]
            self.assertIn("pull", actions)
            self.assertIn("up", actions)
            # pull 在 up 之前
            self.assertLess(actions.index("pull"), actions.index("up"))
        finally:
            panel.subprocess.run = real_run
            panel.COMPOSE_BASE = real_base
            panel.DRY_RUN = real_dry
            shutil.rmtree(tmp, ignore_errors=True)

    def test_font_static_route(self):
        """字体文件必须能通过 /static/fonts/ 访问（MIME font/woff2）"""
        import types
        real_run = panel.subprocess.run
        real_dir = panel.STATIC_DIR
        try:
            tmp = tempfile.mkdtemp(prefix="fw-font-route-")
            fonts_dir = os.path.join(tmp, "fonts")
            os.makedirs(fonts_dir, exist_ok=True)
            font_file = os.path.join(fonts_dir, "fw-sans-sc-regular.woff2")
            with open(font_file, "wb") as f:
                f.write(b"wOF2testdata")
            panel.STATIC_DIR = tmp
            panel.subprocess.run = lambda args, **kw: types.SimpleNamespace(
                returncode=0, stdout="", stderr="")
            tok = self._token()
            code, body = self._req("GET", "/static/fonts/fw-sans-sc-regular.woff2", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(body, b"wOF2testdata")
            # 校验响应头 MIME
            self.assertIn("font/woff2", self._last_content_type)
        finally:
            panel.subprocess.run = real_run
            panel.STATIC_DIR = real_dir
            shutil.rmtree(tmp, ignore_errors=True)

    def test_docker_logs(self):
        tok = self._token()
        saved = self._patch_docker(docker_logs=lambda cid, tail=200: "log line 1")
        try:
            code, d = self._req("GET", "/api/docker/logs/abc123", token=tok)
            self.assertEqual(code, 200)
            self.assertIn("log line", d["logs"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)


class TestTraffic(unittest.TestCase):
    """网卡流量统计：TrafficStore 聚合逻辑 + /api/traffic API"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17997), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.tmp = tempfile.mkdtemp(prefix="fwpanel-traffic-")
        cls.traffic = panel.TrafficStore(os.path.join(cls.tmp, "traffic.json"))
        cls.server.traffic = cls.traffic  # 挂载（与 main serve 相同）
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17997"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def test_traffic_store_record(self):
        """record 增量累加 + 速率计算 + 计数器回退不产生负值"""
        ts = panel.TrafficStore(os.path.join(self.tmp, "t-record.json"))
        now = 1000.0
        ts.record({"eth0": {"rx": 1000, "tx": 2000}}, now=now)  # 首次只建基线
        # setdefault 会创建当天空条目，但不累加流量
        self.assertEqual(ts.data["days"], {panel.datetime.date.today().isoformat(): {}})
        ts.record({"eth0": {"rx": 7000, "tx": 5000}}, now=now + 10)  # 10 秒后
        day = list(ts.data["days"].values())[0]
        self.assertEqual(day["eth0"]["rx"], 6000)
        self.assertEqual(day["eth0"]["tx"], 3000)
        self.assertAlmostEqual(ts._rates["eth0"]["rx_bps"], 600.0)
        self.assertAlmostEqual(ts._rates["eth0"]["tx_bps"], 300.0)
        # 计数器回退（网卡重置）应跳过，不产生负值
        ts.record({"eth0": {"rx": 100, "tx": 100}}, now=now + 20)
        day = list(ts.data["days"].values())[0]
        self.assertEqual(day["eth0"]["rx"], 6000)
        self.assertEqual(day["eth0"]["tx"], 3000)
        # 持久化（重载后数据还在）
        ts2 = panel.TrafficStore(ts.path)
        self.assertEqual(ts2.data["days"], ts.data["days"])

    def test_traffic_totals_daily(self):
        """totals_for 区间累计 + daily 近 7 天补 0"""
        ts = panel.TrafficStore(os.path.join(self.tmp, "t-totals.json"))
        d0 = panel.datetime.date.today()
        ds0 = d0.isoformat()
        ds1 = (d0 - panel.datetime.timedelta(days=1)).isoformat()
        ts.data["days"] = {
            ds0: {"eth0": {"rx": 10, "tx": 20}},
            ds1: {"eth0": {"rx": 30, "tx": 40}},
        }
        self.assertEqual(ts.totals_for("eth0"), {"rx": 40, "tx": 60})
        self.assertEqual(ts.totals_for("eth0", start=ds1, end=ds1), {"rx": 30, "tx": 40})
        self.assertEqual(ts.totals_for("eth0", start=ds0), {"rx": 10, "tx": 20})
        week = ts.daily("eth0", 7)
        self.assertEqual(len(week), 7)
        self.assertEqual(week[-1]["date"], ds0)   # 最后一项是今天
        self.assertEqual(week[-1]["rx"], 10)
        self.assertEqual(week[-2]["rx"], 30)      # 昨天
        self.assertEqual(week[0]["rx"], 0)        # 更早的天补 0

    def test_traffic_active_iface(self):
        """自动选网卡：速率非零 > 今日有流量 > 主网卡兜底"""
        ts = panel.TrafficStore(os.path.join(self.tmp, "t-active.json"))
        ts._rates = {"eth1": {"rx_bps": 100, "tx_bps": 0},
                     "eth0": {"rx_bps": 0, "tx_bps": 0}}
        self.assertEqual(panel.traffic_active_iface(ts), "eth1")
        ts._rates = {"eth0": {"rx_bps": 0, "tx_bps": 0}}
        today = panel.datetime.date.today().isoformat()
        ts.data["days"] = {today: {"eth2": {"rx": 1, "tx": 0}}}
        self.assertEqual(panel.traffic_active_iface(ts), "eth2")
        ts.data["days"] = {}
        self.assertEqual(panel.traffic_active_iface(ts), panel.primary_iface())

    def test_traffic_api(self):
        """/api/traffic：today/yesterday/week/total/rates + 自定义起始日期 + 非法日期 400"""
        ts = self.traffic
        today = panel.datetime.date.today().isoformat()
        yest = (panel.datetime.date.today() - panel.datetime.timedelta(days=1)).isoformat()
        ts.data["days"] = {
            today: {"eth0": {"rx": 1000, "tx": 2000}},
            yest: {"eth0": {"rx": 500, "tx": 700}},
        }
        ts._last = {"eth0": {"rx": 100000, "tx": 200000, "ts": panel.time.time() - 10}}
        saved = panel.read_net_dev
        panel.read_net_dev = lambda: {"eth0": {"rx": 100000, "tx": 200000}}
        try:
            # 默认（主网卡可能不是 eth0，显式指定）
            code, d = self._req("GET", "/api/traffic?iface=eth0", token=self._token())
            self.assertEqual(code, 200, d)
            self.assertIn("eth0", d["ifaces"])
            self.assertEqual(d["current"], "eth0")
            self.assertEqual(d["today"], {"rx": 1000, "tx": 2000})
            self.assertEqual(d["yesterday"], {"rx": 500, "tx": 700})
            self.assertEqual(len(d["week"]), 7)
            self.assertEqual(d["total"], {"rx": 1500, "tx": 2700})
            self.assertIn("rates", d)
            self.assertIn("eth0", d["rates"])
            # 自定义起始日期：昨天起 → 两天合计
            code, d = self._req("GET", "/api/traffic?iface=eth0&from=" + yest,
                                token=self._token())
            self.assertEqual(code, 200, d)
            self.assertEqual(d["custom"]["rx"], 1500)
            self.assertEqual(d["custom"]["tx"], 2700)
            self.assertEqual(d["custom"]["days"], 2)
            self.assertEqual(d["custom"]["from"], yest)
            # 自定义起止日期：昨天至昨天 → 只算昨天一天
            code, d = self._req("GET", "/api/traffic?iface=eth0&from=" + yest + "&to=" + yest,
                                token=self._token())
            self.assertEqual(code, 200, d)
            self.assertEqual(d["custom"]["rx"], 500)
            self.assertEqual(d["custom"]["tx"], 700)
            self.assertEqual(d["custom"]["days"], 1)
            self.assertEqual(d["custom"]["to"], yest)
            # 结束日期早于开始日期 → 400
            code, d = self._req("GET", "/api/traffic?from=" + today + "&to=" + yest,
                                token=self._token())
            self.assertEqual(code, 400)
            # 非法日期 → 400
            code, d = self._req("GET", "/api/traffic?from=2026-13-99", token=self._token())
            self.assertEqual(code, 400)
            code, d = self._req("GET", "/api/traffic?from=" + yest + "&to=2026-13-99",
                                token=self._token())
            self.assertEqual(code, 400)
        finally:
            panel.read_net_dev = saved


class TestProcs(unittest.TestCase):
    """进程流量统计：parse_nethogs_output 解析 + /api/procs API + 一键安装 nethogs"""

    NETHOGS_SAMPLE = """Refreshing:
/usr/sbin/nginx/1234/1.2.3.4-5.6.7.8(443-51234)/1024 bytes/sec/2048 bytes/sec
/usr/sbin/nginx/1234/1.2.3.4-9.9.9.9(80-40000)/512 bytes/sec/256 bytes/sec
/usr/bin/python3/5678/127.0.0.1-10.0.0.1(17890-60000)/300 bytes/sec/100 bytes/sec
TOTAL: 1836 2404
"""

    # 2026-08 用户服务器实测（Debian 系 nethogs 0.8.5 tracemode 格式）
    NETHOGS_SAMPLE_DEBIAN = """Ethernet link detected
Adding local address: 172.19.0.1
Refreshing:
sshd-session: root@pts/0/139480/0       0.118359        0.113281
unknown TCP/0/0 0       0.0257812
Unknown connection: 45.192.200.237:80-172.69.40.187:12093
TOTAL: 0.118359 0.139062
"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17996), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.tmp = tempfile.mkdtemp(prefix="fwpanel-procs-")
        cls.pstore = panel.ProcStore(os.path.join(cls.tmp, "procs.json"))
        cls.server.procs = cls.pstore  # 挂载（与 main serve 相同）
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17996"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def _patch(self, **mocks):
        saved = {}
        for name, fn in mocks.items():
            saved[name] = getattr(panel, name)
            setattr(panel, name, fn)
        return saved

    # ---------- 解析器 ----------

    def test_parse_aggregates_by_pid(self):
        """多连接同进程按 PID 聚合，按合计降序"""
        procs = panel.parse_nethogs_output(self.NETHOGS_SAMPLE)
        self.assertEqual(len(procs), 2)
        nginx = [p for p in procs if p["pid"] == 1234][0]
        self.assertEqual(nginx["name"], "nginx")          # 路径取 basename
        self.assertEqual(nginx["rx"], 1536)               # 1024 + 512
        self.assertEqual(nginx["tx"], 2304)               # 2048 + 256
        self.assertEqual(nginx["conns"], 2)
        self.assertEqual(procs[0]["pid"], 1234)           # 合计 3840 > python3 400

    def test_parse_no_path_prog(self):
        """-C 模式下程序名无路径（老版本 nethogs 兼容）"""
        text = "Refreshing:\nnginx/1234/1.1.1.1-2.2.2.2(80-1111)/10 bytes/sec/20 bytes/sec\n"
        procs = panel.parse_nethogs_output(text)
        self.assertEqual(procs[0]["name"], "nginx")
        self.assertEqual(procs[0]["rx"], 10)
        self.assertEqual(procs[0]["tx"], 20)

    def test_parse_noise_and_blank(self):
        """libpcap 警告/空行/仅 TOTAL 都应忽略"""
        text = "Refreshing:\n\nsome libpcap warning line\nTOTAL: 0 0\n"
        self.assertEqual(panel.parse_nethogs_output(text), [])
        self.assertEqual(panel.parse_nethogs_output(""), [])

    def test_parse_hostname_with_dash(self):
        """地址段为 hostname 含 '-' 也能解析（从右往左锚定后缀）"""
        text = "Refreshing:\nsshd/42/my-host-1-remote-host-2(22-33333)/77 bytes/sec/88 bytes/sec\n"
        procs = panel.parse_nethogs_output(text)
        self.assertEqual(procs[0]["name"], "sshd")
        self.assertEqual(procs[0]["pid"], 42)
        self.assertEqual(procs[0]["rx"], 77)
        self.assertEqual(procs[0]["tx"], 88)

    def test_parse_debian_format(self):
        """Debian 系 nethogs 0.8.5 实测格式：progname/pid/uid  sent-KB/s  recv-KB/s"""
        procs = panel.parse_nethogs_output(self.NETHOGS_SAMPLE_DEBIAN)
        self.assertEqual(len(procs), 2)
        sshd = [p for p in procs if p["pid"] == 139480][0]
        # 程序名含 '/'（sshd-session: root@pts/0）应原样保留，不做 basename
        self.assertEqual(sshd["name"], "sshd-session: root@pts/0")
        # KB/s → B/s：0.118359 KB/s ≈ 121.2 B/s（sent=上行=tx）
        self.assertAlmostEqual(sshd["tx"], 0.118359 * 1024, places=1)
        self.assertAlmostEqual(sshd["rx"], 0.113281 * 1024, places=1)
        unk = [p for p in procs if p["pid"] == 0][0]
        self.assertEqual(unk["name"], "unknown TCP")
        # nethogs 0.8.5 源码 Line::log(): m_name/m_pid/m_uid sent recv —— 先 sent 后 recv
        self.assertEqual(unk["tx"], 0)  # sent = 0 → 上行 0
        self.assertAlmostEqual(unk["rx"], 0.0257812 * 1024, places=1)  # recv = 下行
        # 排序：sshd 合计 > unknown
        self.assertEqual(procs[0]["pid"], 139480)
        # 噪音行（Ethernet link / Adding local address / Unknown connection）不产生进程
        self.assertNotIn("Ethernet link detected", [p["name"] for p in procs])

    def test_cmdline_missing_pid(self):
        """不存在的 PID 返回空串，不抛异常"""
        self.assertEqual(panel.procs_cmdline(99999999), "")
        # 自己的 PID 应能读到命令行（非内核线程）
        self.assertTrue(len(panel.procs_cmdline(os.getpid())) > 0)

    # ---------- API ----------

    def test_procs_api_installed(self):
        """GET /api/procs：已安装 + 采样成功"""
        saved = self._patch(
            procs_snapshot=lambda: {"ok": True, "procs": [
                {"name": "nginx", "pid": 1234, "cmdline": "nginx -g daemon off;",
                 "rx": 100, "tx": 200, "conns": 2}]},
            nethogs_available=lambda: True,
        )
        try:
            code, d = self._req("GET", "/api/procs", token=self._token())
            self.assertEqual(code, 200)
            self.assertTrue(d["installed"])
            self.assertTrue(d["ok"])
            self.assertEqual(d["procs"][0]["name"], "nginx")
            self.assertIsInstance(d["ts"], int)
        finally:
            panel.procs_snapshot = saved["procs_snapshot"]
            panel.nethogs_available = saved["nethogs_available"]

    def test_procs_api_not_installed(self):
        """GET /api/procs：未安装 → installed=False + 提示"""
        saved = self._patch(
            procs_snapshot=lambda: {"ok": False, "error": "nethogs 未安装", "procs": []},
            nethogs_available=lambda: False,
        )
        try:
            code, d = self._req("GET", "/api/procs", token=self._token())
            self.assertEqual(code, 200)
            self.assertFalse(d["installed"])
            self.assertFalse(d["ok"])
            self.assertEqual(d["procs"], [])
        finally:
            panel.procs_snapshot = saved["procs_snapshot"]
            panel.nethogs_available = saved["nethogs_available"]

    def test_procs_install_ok(self):
        """POST /api/procs/install：安装成功 → 200"""
        saved = self._patch(
            install_nethogs=lambda: (True, "已安装: nethogs"),
            nethogs_available=lambda: True,
        )
        try:
            code, d = self._req("POST", "/api/procs/install", token=self._token())
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
            self.assertTrue(d["installed"])
        finally:
            panel.install_nethogs = saved["install_nethogs"]
            panel.nethogs_available = saved["nethogs_available"]

    def test_procs_install_fail(self):
        """POST /api/procs/install：安装失败 → 500 + 错误信息"""
        saved = self._patch(
            install_nethogs=lambda: (False, "安装失败: 无法识别包管理器"),
        )
        try:
            code, d = self._req("POST", "/api/procs/install", token=self._token())
            self.assertEqual(code, 500)
            self.assertIn("安装失败", d.get("error", ""))
        finally:
            panel.install_nethogs = saved["install_nethogs"]

    def test_procs_requires_auth(self):
        """未登录访问 /api/procs → 401"""
        code, d = self._req("GET", "/api/procs")
        self.assertEqual(code, 401)

    # ---------- ProcStore（进程历史按天累计） ----------

    def _new_store(self):
        return panel.ProcStore(os.path.join(self.tmp, "t-" + str(id(self)) + ".json"))

    def test_store_first_sample_no_accum(self):
        """首次采样只记 last_seen 不累计（无上次时间基准）"""
        ps = self._new_store()
        ps.record([{"name": "curl", "pid": 1, "rx": 100, "tx": 200}], now=1000.0)
        day = list(ps.data["days"].values())[0]
        slot = day["curl"]
        self.assertEqual(slot["rx"], 0)    # 首次不累计流量
        self.assertEqual(slot["tx"], 0)
        self.assertEqual(slot["last_seen"], 1000.0)  # 但记录最后活跃
        self.assertEqual(slot["last_pid"], 1)
        self.assertEqual(ps.data["last_ts"], 1000.0)

    def test_store_accumulates_rate_times_dt(self):
        """第二次采样：速率 × 间隔累计到当天"""
        ps = self._new_store()
        ps.record([{"name": "curl", "pid": 1, "rx": 0, "tx": 0}], now=1000.0)
        ps.record([{"name": "curl", "pid": 1, "rx": 100, "tx": 200}], now=1010.0)
        day = list(ps.data["days"].values())[0]
        slot = day["curl"]
        self.assertEqual(slot["rx"], 1000)   # 100 B/s × 10s
        self.assertEqual(slot["tx"], 2000)   # 200 B/s × 10s
        self.assertEqual(slot["last_pid"], 1)

    def test_store_no_accum_over_max_dt(self):
        """间隔超过 10 分钟不累计（瞬时进程防虚报），但仍更新最后活跃"""
        ps = self._new_store()
        ps.record([{"name": "curl", "pid": 1, "rx": 100, "tx": 100}], now=1000.0)
        ps.record([{"name": "curl", "pid": 2, "rx": 100, "tx": 100}], now=1000.0 + panel.PROCS_ACCUM_MAX_DT + 1)
        day = list(ps.data["days"].values())[0]
        self.assertEqual(day["curl"]["rx"], 0)  # 不累计
        self.assertEqual(day["curl"]["last_pid"], 2)  # 但 last_seen/last_pid 更新

    def test_store_history_aggregates(self):
        """history 跨天合并：今日 + 总累计 + 最后活跃降序"""
        ps = self._new_store()
        today = panel.datetime.date.today().isoformat()
        ps.data["days"] = {
            today: {"curl": {"rx": 100, "tx": 200, "last_seen": 2000, "last_pid": 1},
                    "nginx": {"rx": 300, "tx": 400, "last_seen": 3000, "last_pid": 2}},
        }
        hist = ps.history()
        self.assertEqual(len(hist), 2)
        nginx = [h for h in hist if h["name"] == "nginx"][0]
        self.assertEqual(nginx["today_rx"], 300)
        self.assertEqual(nginx["total_tx"], 400)
        self.assertEqual(hist[0]["name"], "nginx")  # last_seen 3000 > 2000 → 降序在前

    def test_store_detail_and_clear(self):
        """detail 近 7 天补 0 + 总累计；clear 清空"""
        ps = self._new_store()
        today = panel.datetime.date.today().isoformat()
        ps.data["days"] = {today: {"curl": {"rx": 50, "tx": 60}}}
        d = ps.detail("curl")
        self.assertEqual(len(d["days"]), 7)
        self.assertEqual(d["days"][-1]["rx"], 50)  # 今天
        self.assertEqual(d["total_rx"], 50)
        self.assertEqual(d["total_tx"], 60)
        self.assertEqual(ps.detail("not-exist")["total_rx"], 0)
        ps.clear()
        self.assertEqual(ps.data["days"], {})
        self.assertIsNone(ps.data["last_ts"])

    def test_store_persist_reload(self):
        """持久化：落盘后重载数据仍在（跨重启保留）"""
        path = os.path.join(self.tmp, "t-persist.json")
        ps = panel.ProcStore(path)
        ps.record([{"name": "curl", "pid": 1, "rx": 0, "tx": 0}], now=1000.0)
        ps.record([{"name": "curl", "pid": 1, "rx": 100, "tx": 100}], now=1010.0)
        ps2 = panel.ProcStore(path)  # 模拟重启重载
        day = list(ps2.data["days"].values())[0]
        self.assertEqual(day["curl"]["rx"], 1000)
        self.assertEqual(ps2.data["last_ts"], 1010.0)

    # ---------- API：history / detail / clear ----------

    def test_procs_api_history(self):
        """GET /api/procs 返回 history（历史名单）"""
        self.pstore.record([{"name": "curl", "pid": 1, "rx": 100, "tx": 200}], now=1000.0)
        saved = self._patch(
            procs_snapshot=lambda: {"ok": True, "procs": []},
            nethogs_available=lambda: True,
        )
        try:
            code, d = self._req("GET", "/api/procs", token=self._token())
            self.assertEqual(code, 200)
            names = [h["name"] for h in d["history"]]
            self.assertIn("curl", names)
        finally:
            panel.procs_snapshot = saved["procs_snapshot"]
            panel.nethogs_available = saved["nethogs_available"]

    def test_procs_api_detail(self):
        """GET /api/procs?detail=<name> 返回该进程近 7 天"""
        self.pstore.record([{"name": "nginx", "pid": 2, "rx": 100, "tx": 100}], now=1000.0)
        saved = self._patch(
            procs_snapshot=lambda: {"ok": True, "procs": []},
            nethogs_available=lambda: True,
        )
        try:
            code, d = self._req("GET", "/api/procs?detail=nginx", token=self._token())
            self.assertEqual(code, 200)
            self.assertEqual(d["detail"]["name"], "nginx")
            self.assertEqual(len(d["detail"]["days"]), 7)
        finally:
            panel.procs_snapshot = saved["procs_snapshot"]
            panel.nethogs_available = saved["nethogs_available"]

    def test_procs_clear_api(self):
        """POST /api/procs/clear 清空历史"""
        self.pstore.record([{"name": "curl", "pid": 1, "rx": 100, "tx": 100}], now=1000.0)
        self.assertGreater(len(self.pstore.history()), 0)
        code, d = self._req("POST", "/api/procs/clear", token=self._token())
        self.assertEqual(code, 200)
        self.assertEqual(self.pstore.history(), [])


class TestProxyEntryPorts(unittest.TestCase):
    """v1.25.7：反代入口端口放行补齐（修复 https 反代漏放 443）

    背景：v1.25.2 复用证书（cert_ref）反代 ssl:false 时 nginx 监听 443，
    旧创建逻辑只看 ssl 字段漏放 443，严格模式下公网 https 被防火墙挡死。"""

    def setUp(self):
        self._orig_rule_load = panel.RuleStore._load
        self._orig_proxy_load = panel.ProxyStore._load
        panel.RuleStore._load = lambda self: []
        panel.ProxyStore._load = lambda self: []
        self.store = panel.RuleStore()
        self.store.rules = []

    def tearDown(self):
        panel.RuleStore._load = self._orig_rule_load
        panel.ProxyStore._load = self._orig_proxy_load

    def _proxy(self, **kw):
        p = {
            "domain": "fwpanel.example.com", "target_host": "127.0.0.1",
            "target_port": 42608, "scheme": "http", "ssl": False,
            "cert_ref": "", "enabled": True,
        }
        p.update(kw)
        return p

    def test_https_certref_proxy_gets_80_and_443(self):
        """复用证书（cert_ref 有值、ssl:false）→ 补齐 443（+80）放行"""
        p = self._proxy(cert_ref="*.example.com")
        panel.ProxyStore._load = lambda self: [p]
        panel.ensure_proxy_entry_ports(self.store)
        ports = [r["port"] for r in self.store.rules if r["type"] == "port_allow"]
        self.assertIn(443, ports, "cert_ref 反代必须放行 443")
        self.assertIn(80, ports, "cert_ref 反代同时放行 80（301/acme）")

    def test_ssl_true_proxy_gets_443(self):
        """ssl:true 反代 → 放行 443"""
        p = self._proxy(ssl=True)
        panel.ProxyStore._load = lambda self: [p]
        panel.ensure_proxy_entry_ports(self.store)
        ports = [r["port"] for r in self.store.rules if r["type"] == "port_allow"]
        self.assertIn(443, ports)

    def test_http_proxy_gets_80_only(self):
        """无证书 http 反代 → 只放行 80"""
        p = self._proxy(target_port=8080)
        panel.ProxyStore._load = lambda self: [p]
        panel.ensure_proxy_entry_ports(self.store)
        ports = [r["port"] for r in self.store.rules if r["type"] == "port_allow"]
        self.assertIn(80, ports)
        self.assertNotIn(443, ports)

    def test_disabled_proxy_skipped(self):
        """停用的反代不补齐"""
        p = self._proxy(cert_ref="*.example.com", enabled=False)
        panel.ProxyStore._load = lambda self: [p]
        panel.ensure_proxy_entry_ports(self.store)
        self.assertEqual(self.store.rules, [])

    def test_idempotent(self):
        """重复调用不重复加规则"""
        p = self._proxy(cert_ref="*.example.com")
        panel.ProxyStore._load = lambda self: [p]
        panel.ensure_proxy_entry_ports(self.store)
        panel.ensure_proxy_entry_ports(self.store)
        ports = [r["port"] for r in self.store.rules if r["type"] == "port_allow"]
        self.assertEqual(ports.count(443), 1)
        self.assertEqual(ports.count(80), 1)


class TestCertHttp01Port(unittest.TestCase):
    """v1.25.8：HTTP-01 证书申请自动放行 80（严格模式下防火墙不再挡死 webroot 验证）"""

    def setUp(self):
        self._orig_rule_load = panel.RuleStore._load
        self._orig_certbot = panel.certbot_available
        self._orig_run = panel.subprocess.run
        self._orig_webroot = panel.ACME_WEBROOT
        panel.RuleStore._load = lambda self: []
        panel.certbot_available = lambda: True
        panel.ACME_WEBROOT = os.path.join(panel.BASE_DIR, "acme-webroot")
        if os.path.exists(panel.RULES_FILE):
            os.remove(panel.RULES_FILE)

    def tearDown(self):
        panel.RuleStore._load = self._orig_rule_load
        panel.certbot_available = self._orig_certbot
        panel.subprocess.run = self._orig_run
        panel.ACME_WEBROOT = self._orig_webroot

    def test_ensure_http01_port_adds_80(self):
        """_ensure_http01_port 幂等添加 80 放行（ACME:HTTP-01 注释）"""
        store = panel.RuleStore()
        self.assertTrue(panel._ensure_http01_port(store))
        ports = [r["port"] for r in store.rules if r["type"] == "port_allow"]
        self.assertEqual(ports, [80])
        self.assertEqual(store.rules[0]["comment"], "ACME:HTTP-01")

    def test_ensure_http01_port_idempotent(self):
        """已有 80 放行时不重复添加"""
        store = panel.RuleStore()
        panel._ensure_http01_port(store)
        self.assertFalse(panel._ensure_http01_port(store))
        ports = [r["port"] for r in store.rules if r["type"] == "port_allow"]
        self.assertEqual(ports.count(80), 1)

    def test_issue_cert_opens_80_and_persists(self):
        """issue_cert 申请前自动放行 80 并持久化"""
        panel.subprocess.run = lambda *a, **kw: types.SimpleNamespace(
            returncode=0, stdout="ok", stderr="")
        ok, msg = panel.issue_cert("example.com", "a@b.c")
        self.assertTrue(ok, msg)
        with open(panel.RULES_FILE) as f:
            rules = json.load(f)
        ports = [r["port"] for r in rules if r["type"] == "port_allow"]
        self.assertIn(80, ports)

    def test_issue_cert_failure_hints_port80(self):
        """失败提示应包含「80 已自动放行」（引导查云厂商安全组而非怀疑面板）"""
        panel.subprocess.run = lambda *a, **kw: types.SimpleNamespace(
            returncode=1, stdout="", stderr="boom")
        ok, msg = panel.issue_cert("example.com", "")
        self.assertFalse(ok)
        self.assertIn("80 已自动放行", msg)


class TestSshSwitchCleanupRace(unittest.TestCase):
    """v1.25.9：SSH 切换清理竞态回归——清理必须作用于共享 store 实例，
    防止防爆破线程用旧内存 save() 把已删的旧端口规则覆盖回来（伦敦机 2026-08-26 实测）"""

    def setUp(self):
        self._orig_rule_load = panel.RuleStore._load
        panel.RuleStore._load = lambda self: []
        if os.path.exists(panel.RULES_FILE):
            os.remove(panel.RULES_FILE)
        # 模拟 main() 传入防爆破/API 的共享 store 实例
        self.store = panel.RuleStore()
        self.store.rules = [
            {"id": "a1", "type": "port_allow", "proto": "tcp", "port": 22,
             "comment": "SSH保护(安装自动放行)", "protected": True},
            {"id": "a2", "type": "port_allow", "proto": "tcp", "port": 22,
             "comment": panel.SSH_OLD_PORT_COMMENT},
            {"id": "a3", "type": "port_allow", "proto": "tcp", "port": 42608,
             "comment": panel.PANEL_PORT_COMMENT},
            {"id": "a4", "type": "port_deny", "proto": "tcp", "port": 42608,
             "comment": "反代目标端口-禁止公网直连"},
        ]

    def tearDown(self):
        panel.RuleStore._load = self._orig_rule_load

    def test_cleanup_shared_store_memory_synced(self):
        """cleanup 后共享 store 内存立即同步（无旧数据残留）"""
        self.assertTrue(panel.cleanup_old_ssh_rules(22, self.store))
        ports = [r["port"] for r in self.store.rules if r["type"] == "port_allow"]
        self.assertNotIn(22, ports, "共享 store 内存必须同步删除旧端口规则")

    def test_no_race_after_cleanup(self):
        """清理后防爆破风格操作（add+save）不会把旧端口规则覆盖回来（回归核心）"""
        panel.cleanup_old_ssh_rules(22, self.store)
        # 模拟防爆破线程继续用同一实例加封禁 + save
        self.store.add({"type": "ip_deny", "ip": "1.2.3.4", "comment": panel.BAN_COMMENT})
        self.store.save()
        with open(panel.RULES_FILE) as f:
            rules = json.load(f)
        old22 = [r for r in rules if r.get("type") == "port_allow" and r.get("port") == 22]
        self.assertEqual(old22, [], "防爆破后续 save() 不得把旧端口规则写回文件")

    def test_save_under_lock_basic(self):
        """加锁后 save 内容完整（基本可用性）"""
        self.store.save()
        with open(panel.RULES_FILE) as f:
            rules = json.load(f)
        self.assertEqual(len(rules), len(self.store.rules))


class TestSshPolicy(unittest.TestCase):
    """SSH 登录策略：sshd -T 解析 / 防锁死校验 / drop-in 写入与回滚（mock subprocess）"""

    def setUp(self):
        # 隔离 drop-in 目录（FW_SSHD_DIR 已在 import 前指向 TMP）
        self.conf = panel.SSHD_AUTH_CONF
        self.sshd_d = os.path.dirname(self.conf)
        os.makedirs(self.sshd_d, exist_ok=True)
        if os.path.exists(self.conf):
            os.remove(self.conf)
        # passwd 探测文件（other_login_users 用）
        self.pw = os.path.join(TMP, "test-passwd")
        with open(self.pw, "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n"
                    "ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n"
                    "nobody:x:65534::/nonexistent:/usr/sbin/nologin\n")
        self._pw_old = os.environ.get("FW_PASSWD_FILE")
        os.environ["FW_PASSWD_FILE"] = self.pw
        self._orig_run = panel.subprocess.run

    def tearDown(self):
        panel.subprocess.run = self._orig_run
        if self._pw_old is None:
            os.environ.pop("FW_PASSWD_FILE", None)
        else:
            os.environ["FW_PASSWD_FILE"] = self._pw_old
        if os.path.exists(self.conf):
            os.remove(self.conf)

    def _sshd_out(self, extra=None, ignore_dropin=False):
        """构造 sshd -T 输出；默认从 drop-in 文件读键（模拟配置生效）"""
        base = {"port": "22", "permitrootlogin": "yes",
                "passwordauthentication": "yes", "pubkeyauthentication": "yes"}
        if extra:
            base.update(extra)
        if not ignore_dropin and os.path.exists(self.conf):
            with open(self.conf) as f:
                for line in f:
                    p = line.strip().split(None, 1)
                    if len(p) == 2 and not p[0].startswith("#"):
                        base[p[0].lower()] = p[1].lower()
        return "\n".join("%s %s" % (k, v) for k, v in base.items()) + "\n"

    def _mock_run(self, fail_t=False, fail_restart=False, ignore_dropin=False,
                  extra=None, calls=None):
        """mock subprocess.run：sshd -T 读 drop-in；systemctl 计数"""
        def fake(cmd, capture_output=True, text=True, timeout=None, **kw):
            if calls is not None:
                calls.append(cmd)
            if cmd and cmd[0] == "sshd" and "-T" in cmd:
                return type("R", (), {"returncode": 0,
                                      "stdout": self._sshd_out(extra, ignore_dropin),
                                      "stderr": ""})()
            if cmd and cmd[0] == "sshd" and "-t" in cmd:
                return type("R", (), {"returncode": 1 if fail_t else 0,
                                      "stdout": "", "stderr": "bad option"})()
            if cmd and cmd[0] == "systemctl":
                return type("R", (), {"returncode": 1 if fail_restart else 0,
                                      "stdout": "", "stderr": "unit failed"})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        panel.subprocess.run = fake

    def test_current_parse_and_norm(self):
        self._mock_run(extra={"permitrootlogin": "prohibit-password",
                              "passwordauthentication": "no"})
        cur = panel.sshd_policy_current()
        self.assertEqual(cur["port"], "22")
        self.assertEqual(cur["permitrootlogin"], "prohibit-password")
        self.assertEqual(cur["passwordauthentication"], "no")
        self.assertEqual(panel._norm_root_login("WITHOUT-PASSWORD"), "prohibit-password")
        self.assertEqual(panel._norm_root_login("Yes"), "yes")
        self.assertEqual(panel._norm_root_login("no"), "no")
        self.assertIsNone(panel._norm_root_login("maybe"))

    def test_validate_all_off_rejected(self):
        ok, err = panel.sshd_validate_changes({"password_auth": False, "pubkey_auth": False})
        self.assertFalse(ok)
        self.assertIn("不能同时关闭", err)
        # 只关密码保留密钥 → 允许
        ok, _ = panel.sshd_validate_changes({"password_auth": False})
        self.assertTrue(ok)

    def test_validate_root_no_needs_other_users(self):
        with open(self.pw, "w") as f:   # 只有 root + nologin 用户
            f.write("root:x:0:0:root:/root:/bin/bash\n"
                    "www:x:33::/var/www:/usr/sbin/nologin\n")
        ok, err = panel.sshd_validate_changes({"permit_root": "no"})
        self.assertFalse(ok)
        self.assertIn("锁死", err)
        with open(self.pw, "w") as f:   # 补一个可登录普通用户
            f.write("root:x:0:0:root:/root:/bin/bash\n"
                    "ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n")
        ok, _ = panel.sshd_validate_changes({"permit_root": "no"})
        self.assertTrue(ok)

    def test_apply_success_and_idempotent_keep(self):
        # 预置面板已管理的其它项（幂等保留）
        os.makedirs(self.sshd_d, exist_ok=True)
        with open(self.conf, "w") as f:
            f.write("# Managed by fwpanel — SSH 登录策略\npermitrootlogin no\n")
        self._mock_run()
        ok, msg, after = panel.apply_sshd_policy({"password_auth": False})
        self.assertTrue(ok, msg)
        with open(self.conf) as f:
            content = f.read()
        self.assertIn("passwordauthentication no", content)
        self.assertIn("permitrootlogin no", content)   # 其它托管项保留
        self.assertEqual(after["passwordauthentication"], "no")
        self.assertEqual(after["permitrootlogin"], "no")

    def test_apply_t_fail_rollback_removes_file(self):
        self._mock_run(fail_t=True)
        ok, msg, _ = panel.apply_sshd_policy({"password_auth": False})
        self.assertFalse(ok)
        self.assertIn("语法检查失败", msg)
        self.assertFalse(os.path.exists(self.conf), "语法失败后 drop-in 应被还原删除")

    def test_apply_t_fail_rollback_restores_backup(self):
        os.makedirs(self.sshd_d, exist_ok=True)
        with open(self.conf, "w") as f:
            f.write("# Managed by fwpanel — SSH 登录策略\npasswordauthentication yes\n")
        self._mock_run(fail_t=True)
        ok, msg, _ = panel.apply_sshd_policy({"password_auth": False})
        self.assertFalse(ok)
        with open(self.conf) as f:
            self.assertIn("passwordauthentication yes", f.read())

    def test_apply_restart_fail_rollback(self):
        self._mock_run(fail_restart=True)
        ok, msg, _ = panel.apply_sshd_policy({"password_auth": False})
        self.assertFalse(ok)
        self.assertIn("重启", msg)
        self.assertFalse(os.path.exists(self.conf))

    def test_apply_verify_mismatch_rollback(self):
        # drop-in 写成功、服务重启成功，但 sshd -T 回读不生效（主配置 Include 前写死场景）
        self._mock_run(ignore_dropin=True)
        ok, msg, _ = panel.apply_sshd_policy({"password_auth": False})
        self.assertFalse(ok)
        self.assertIn("未达到目标", msg)
        self.assertFalse(os.path.exists(self.conf), "回读不一致应还原 drop-in")

    def test_reset_policy(self):
        os.makedirs(self.sshd_d, exist_ok=True)
        with open(self.conf, "w") as f:
            f.write("# Managed by fwpanel — SSH 登录策略\npasswordauthentication no\n")
        self._mock_run()
        ok, msg = panel.reset_sshd_policy()
        self.assertTrue(ok, msg)
        self.assertFalse(os.path.exists(self.conf))


class TestSshPolicyApi(unittest.TestCase):
    """SSH 策略 API：GET/POST policy（含防锁死 400）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17996), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17996"
        cls.conf = panel.SSHD_AUTH_CONF
        os.makedirs(os.path.dirname(cls.conf), exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        if os.path.exists(self.conf):
            os.remove(self.conf)
        self._pw_old = os.environ.get("FW_PASSWD_FILE")
        self.pw = os.path.join(TMP, "test-passwd-api")
        with open(self.pw, "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n"
                    "ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n")
        os.environ["FW_PASSWD_FILE"] = self.pw
        self._orig_run = panel.subprocess.run

        def fake(cmd, capture_output=True, text=True, timeout=None, **kw):
            if cmd and cmd[0] == "sshd" and "-T" in cmd:
                base = {"port": "22", "permitrootlogin": "yes",
                        "passwordauthentication": "yes", "pubkeyauthentication": "yes"}
                if os.path.exists(self.conf):
                    with open(self.conf) as f:
                        for line in f:
                            p = line.strip().split(None, 1)
                            if len(p) == 2 and not p[0].startswith("#"):
                                base[p[0].lower()] = p[1].lower()
                return type("R", (), {"returncode": 0, "stdout": "\n".join(
                    "%s %s" % (k, v) for k, v in base.items()) + "\n", "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        panel.subprocess.run = fake

    def tearDown(self):
        panel.subprocess.run = self._orig_run
        if self._pw_old is None:
            os.environ.pop("FW_PASSWD_FILE", None)
        else:
            os.environ["FW_PASSWD_FILE"] = self._pw_old
        if os.path.exists(self.conf):
            os.remove(self.conf)

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def test_policy_get(self):
        code, d = self._req("GET", "/api/ssh/policy", token=self._token())
        self.assertEqual(code, 200)
        self.assertEqual(d["current"]["password_auth"], True)
        self.assertIsNone(d["managed"]["password_auth"])
        self.assertIn("ubuntu", d["other_users"])

    def test_policy_post_all_off_400(self):
        code, d = self._req("POST", "/api/ssh/policy",
                            {"password_auth": False, "pubkey_auth": False},
                            token=self._token())
        self.assertEqual(code, 400)
        self.assertIn("不能同时关闭", d["error"])

    def test_policy_post_apply_then_reset(self):
        tok = self._token()
        code, d = self._req("POST", "/api/ssh/policy",
                            {"password_auth": False, "permit_root": "prohibit-password"},
                            token=tok)
        self.assertEqual(code, 200, d)
        with open(self.conf) as f:
            content = f.read()
        self.assertIn("passwordauthentication no", content)
        self.assertIn("permitrootlogin prohibit-password", content)
        code, d = self._req("POST", "/api/ssh/policy", {"reset": True}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertFalse(os.path.exists(self.conf))


class TestSshKeygen(unittest.TestCase):
    """SSH 密钥对：生成（真实 ssh-keygen 于临时目录）/安装/列出/删除/API"""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="fwpanel-keyhome-")
        self._orig_run = panel.subprocess.run

    def tearDown(self):
        panel.subprocess.run = self._orig_run
        shutil.rmtree(self.home, ignore_errors=True)

    def _n_tmpdirs(self):
        import glob
        return len(glob.glob(tempfile.gettempdir() + "/fwpanel-key-*"))

    def test_gen_ed25519_installs_and_no_private_leak(self):
        n0 = self._n_tmpdirs()
        ok, res = panel.ssh_gen_keypair("ed25519", "root", home=self.home)
        self.assertTrue(ok, res)
        self.assertTrue(res["private_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertTrue(res["public_key"].startswith("ssh-ed25519 "))
        self.assertTrue(res["fingerprint"].startswith("SHA256:"))
        auth = os.path.join(self.home, ".ssh", "authorized_keys")
        self.assertTrue(os.path.exists(auth))
        with open(auth) as f:
            self.assertIn(res["public_key"], f.read())
        self.assertEqual(self._n_tmpdirs(), n0, "生成密钥的临时目录必须清理干净（私钥不落盘）")

    def test_gen_rsa(self):
        ok, res = panel.ssh_gen_keypair("rsa", "root", home=self.home)
        self.assertTrue(ok, res)
        self.assertTrue(res["public_key"].startswith("ssh-rsa "))

    def test_gen_bad_algo_and_user(self):
        ok, res = panel.ssh_gen_keypair("dsa", "root", home=self.home)
        self.assertFalse(ok)
        ok, res = panel.ssh_gen_keypair("ed25519", "no_such_user_zzz")
        self.assertFalse(ok)
        self.assertIn("用户不存在", res["error"])

    def test_install_idempotent(self):
        ok, res = panel.ssh_gen_keypair("ed25519", "root", home=self.home)
        self.assertTrue(ok)
        ok2, msg2 = panel.ssh_install_pubkey("root", res["public_key"], home=self.home)
        self.assertFalse(ok2)
        self.assertIn("已存在", msg2)
        with open(os.path.join(self.home, ".ssh", "authorized_keys")) as f:
            self.assertEqual(len([l for l in f if l.strip()]), 1)

    def test_list_parses_various_lines_and_del(self):
        ssh_dir = os.path.join(self.home, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        # 生成两把真实密钥装进去 + 一行带 options 的假行 + 注释/空行
        panel.ssh_gen_keypair("ed25519", "root", home=self.home)
        panel.ssh_gen_keypair("ed25519", "root", home=self.home)
        path = os.path.join(ssh_dir, "authorized_keys")
        with open(path, "a") as f:
            f.write("# 注释行\n")
            f.write('command="/bin/echo x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmdvcHRpb25za2V5eWFtbWFtYW1h fake-option-key\n')
            f.write("\n")
        keys = panel.ssh_list_keys("root", home=self.home)
        self.assertEqual(len(keys), 3, keys)
        types = [k["type"] for k in keys]
        self.assertTrue(all(t.startswith("ssh-ed25519") for t in types))
        option_key = [k for k in keys if k["comment"] == "fake-option-key"]
        self.assertEqual(len(option_key), 1, "options 前缀行应能解析出类型与备注")
        # 删除：删掉 options 行
        ok, msg = panel.ssh_del_key("root", option_key[0]["line"], home=self.home)
        self.assertTrue(ok, msg)
        self.assertEqual(len(panel.ssh_list_keys("root", home=self.home)), 2)
        ok, msg = panel.ssh_del_key("root", "ssh-ed25519 AAAA 不存在的行", home=self.home)
        self.assertFalse(ok)


class TestSshKeygenApi(unittest.TestCase):
    """密钥 API 冒烟：keygen 一次性私钥 / keys 列表 / delete（user_home 指向临时目录）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17995), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17995"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="fwpanel-keyhome-api-")
        self._orig_home = panel.user_home
        panel.user_home = lambda user: self.home

    def tearDown(self):
        panel.user_home = self._orig_home
        shutil.rmtree(self.home, ignore_errors=True)

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def test_keygen_list_delete_flow(self):
        tok = self._token()
        code, d = self._req("POST", "/api/ssh/keygen",
                            {"algo": "ed25519", "user": "root"}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertIn("private_key", d)
        self.assertNotIn("PRIVATE KEY", open(
            os.path.join(self.home, ".ssh", "authorized_keys")).read(),
            "authorized_keys 只能含公钥")
        code, d = self._req("GET", "/api/ssh/keys?user=root", token=tok)
        self.assertEqual(code, 200)
        self.assertEqual(len(d["keys"]), 1)
        self.assertTrue(d["keys"][0]["fp"].startswith("SHA256:"))
        code, d = self._req("POST", "/api/ssh/keys/delete",
                            {"user": "root", "line": d["keys"][0]["line"]}, token=tok)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh/keys?user=root", token=tok)
        self.assertEqual(len(d["keys"]), 0)
        # 未登录访问应 401
        code, _ = self._req("GET", "/api/ssh/keys?user=root")
        self.assertEqual(code, 401)


class TestServerIp(unittest.TestCase):
    """服务器 IP 状态卡数据：外网回显优先 + 主网卡回退 + 缓存"""

    def setUp(self):
        self._orig = (panel._fetch_public_ip, panel.local_ipv4_pairs,
                      panel.primary_iface, panel.subprocess.run)
        panel.SRV_IP_CACHE.update(ip=None, ts=0.0)

    def tearDown(self):
        panel._fetch_public_ip, panel.local_ipv4_pairs = self._orig[0], self._orig[1]
        panel.primary_iface, panel.subprocess.run = self._orig[2], self._orig[3]
        panel.SRV_IP_CACHE.update(ip=None, ts=0.0)

    def test_fetch_public_dry_run_none(self):
        """DRY_RUN 测试环境不做外网查询"""
        self.assertIsNone(panel._fetch_public_ip())

    def test_local_ipv4_pairs_parse(self):
        out = ("2: eth0    inet 198.51.100.7/24 brd 198.51.100.255 scope global eth0\\n"
               "    valid_lft forever preferred_lft forever\\n"
               "3: lo    inet 127.0.0.1/8 scope host lo\\n")
        panel.subprocess.run = lambda cmd, **kw: type("R", (), {
            "returncode": 0, "stdout": out, "stderr": ""})()
        self.assertEqual(panel.local_ipv4_pairs(), [("eth0", "198.51.100.7")])

    def test_get_server_ip_public_preferred_and_cached(self):
        calls = []
        panel._fetch_public_ip = lambda: (calls.append(1), "203.0.113.9")[1]
        self.assertEqual(panel.get_server_ip(), "203.0.113.9")
        self.assertEqual(panel.get_server_ip(), "203.0.113.9")
        self.assertEqual(len(calls), 1, "缓存命中不应重复外网查询")

    def test_get_server_ip_fallback_local_primary(self):
        panel._fetch_public_ip = lambda: None
        panel.local_ipv4_pairs = lambda: [("eth0", "10.0.0.5"), ("ens3", "198.51.100.8")]
        panel.primary_iface = lambda: "ens3"
        self.assertEqual(panel.get_server_ip(), "198.51.100.8")

    def test_get_server_ip_none(self):
        panel._fetch_public_ip = lambda: None
        panel.local_ipv4_pairs = lambda: []
        self.assertIsNone(panel.get_server_ip())


class TestBruteforcePermanent(unittest.TestCase):
    """防爆破增强：封禁时长上限放宽 30 天 + 永久封禁（API + 到期逻辑）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17994), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17994"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.store.rules = []
        self.store.save()
        panel.save_bans({})

    def tearDown(self):
        self.store.rules = []
        self.store.save()
        panel.save_bans({})

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def _get_bans(self, tok):
        _, d = self._req("GET", "/api/bruteforce", token=tok)
        return {b["ip"]: b for b in d["bans"]}

    def test_set_ban_seconds_30d_allowed(self):
        """封禁时长上限：2592000（30 天）可保存"""
        tok = self._token()
        code, d = self._req("POST", "/api/bruteforce", {"ban_seconds": 2592000}, token=tok)
        self.assertEqual(code, 200, d)
        _, d = self._req("GET", "/api/bruteforce", token=tok)
        self.assertEqual(d["ban_seconds"], 2592000)

    def test_set_ban_seconds_over_30d_rejected(self):
        tok = self._token()
        code, d = self._req("POST", "/api/bruteforce", {"ban_seconds": 2592001}, token=tok)
        self.assertEqual(code, 400)
        self.assertIn("范围", d["error"])

    def test_manual_ban_default_temporary(self):
        """不带 permanent 的手动封禁仍是临时（remaining > 0 且非永久）"""
        tok = self._token()
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.201"}, token=tok)
        self.assertEqual(code, 200, d)
        bans = self._get_bans(tok)
        self.assertIn("198.51.100.201", bans)
        self.assertFalse(bans["198.51.100.201"]["permanent"])
        self.assertGreater(bans["198.51.100.201"]["remaining"], 0)

    def test_manual_ban_permanent_new_ip(self):
        """新 IP 永久封禁：permanent=True + 规则添加"""
        tok = self._token()
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.202", "permanent": True}, token=tok)
        self.assertEqual(code, 200, d)
        bans = self._get_bans(tok)
        self.assertTrue(bans["198.51.100.202"]["permanent"])
        self.assertTrue(any(r.get("ip") == "198.51.100.202" for r in self.store.rules))

    def test_upgrade_existing_ban_to_permanent(self):
        """列表中的临时封禁 → 永久封禁：不报已在列表、规则不重复添加"""
        tok = self._token()
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.203"}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertEqual(len([r for r in self.store.rules if r.get("ip") == "198.51.100.203"]), 1)
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.203", "permanent": True}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertIn("永久", d["msg"])
        self.assertEqual(len([r for r in self.store.rules if r.get("ip") == "198.51.100.203"]), 1,
                         "升级永久不得重复添加规则")
        bans = self._get_bans(tok)
        self.assertTrue(bans["198.51.100.203"]["permanent"])

    def test_status_banned_count_and_server_ip(self):
        """status API：banned_count 统计 ip_deny 规则数 + server_ip 字段"""
        tok = self._token()
        self.store.add({"type": "ip_deny", "ip": "198.51.100.220", "comment": "手动封禁"})
        code, d = self._req("GET", "/api/status", token=tok)
        self.assertEqual(code, 200)
        self.assertEqual(d["banned_count"], 1)
        self.assertEqual(d["rule_count"], 1)
        self.assertIn("server_ip", d)
        self.assertIsNone(d["server_ip"]) if d["server_ip"] is None else self.assertIsInstance(
            d["server_ip"], str)
        # 走 API 永久封禁一个 → 计数 +1
        code, _ = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.221", "permanent": True}, token=tok)
        self.assertEqual(code, 200)
        code, d = self._req("GET", "/api/status", token=tok)
        self.assertEqual(d["banned_count"], 2)

    def test_permanent_never_auto_unbanned(self):
        """到期扫描：临时封禁到期解封，永久封禁保留"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 3,
                               "ban_seconds": 600, "fail_window": 300})
        store = panel.RuleStore()
        store.rules = [
            {"type": "ip_deny", "ip": "198.51.100.204", "comment": panel.MANUAL_BAN_COMMENT},
            {"type": "ip_deny", "ip": "198.51.100.205", "comment": panel.MANUAL_BAN_COMMENT},
        ]
        now = panel.time.time()
        panel.save_bans({"198.51.100.204": panel.BF_PERMANENT_UNTIL,
                         "198.51.100.205": int(now) - 10})
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {}
        panel.get_established_ips = lambda p: set()
        try:
            panel.bruteforce_cycle(cfg, store, now=now)
            ips = [r.get("ip") for r in store.rules]
            self.assertNotIn("198.51.100.205", ips, "过期的临时封禁应解封")
            self.assertIn("198.51.100.204", ips, "永久封禁不得自动解封")
            bans = panel.load_bans()
            self.assertIn("198.51.100.204", bans)
            self.assertNotIn("198.51.100.205", bans)
        finally:
            panel.get_failed_ssh_attempts = real_a
            panel.get_established_ips = real_e
            panel.save_bans({})


class TestFed(unittest.TestCase):
    """联邦多机管理端到端（2.0）：双实例 master(node 可被管) + 节点(fed 令牌)"""

    @classmethod
    def setUpClass(cls):
        # 清掉共享目录里可能残留的联邦节点配置
        fed_file = os.path.join(TMP, "fed_nodes.json")
        if os.path.exists(fed_file):
            os.remove(fed_file)
        cls.cfgA = make_cfg(user="fedmaster", pwd="MasterPass123", mode="strict")
        cls.cfgA.data["port"] = 17996
        cls.storeA = panel.RuleStore()
        cls.storeA.rules = []
        cls.nftA = panel.NFTManager(cls.storeA, cls.cfgA)
        cls.authA = panel.Auth(cls.cfgA)
        cls.serverA = panel.PanelServer(("127.0.0.1", 17996), panel.PanelHandler,
                                        cls.cfgA, cls.storeA, cls.nftA, cls.authA)
        cls.threadA = threading.Thread(target=cls.serverA.serve_forever, daemon=True)
        cls.threadA.start()
        cls.baseA = "http://127.0.0.1:17996"

        cls.cfgB = make_cfg(user="fednode", pwd="NodePass123", mode="strict")
        cls.cfgB.data["port"] = 17995
        cls.storeB = panel.RuleStore()
        cls.storeB.rules = []
        cls.nftB = panel.NFTManager(cls.storeB, cls.cfgB)
        cls.authB = panel.Auth(cls.cfgB)
        cls.serverB = panel.PanelServer(("127.0.0.1", 17995), panel.PanelHandler,
                                        cls.cfgB, cls.storeB, cls.nftB, cls.authB)
        cls.threadB = threading.Thread(target=cls.serverB.serve_forever, daemon=True)
        cls.threadB.start()
        cls.baseB = "http://127.0.0.1:17995"

    @classmethod
    def tearDownClass(cls):
        cls.serverA.shutdown(); cls.serverA.server_close()
        cls.serverB.shutdown(); cls.serverB.server_close()

    def _req(self, base, method, path, data=None, token=None, fed=None):
        r = urllib.request.Request(base + path, method=method)
        if token:
            r.add_header("Authorization", "Bearer " + token)
        if fed:
            r.add_header(panel.FED_HEADER, fed)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r, body, timeout=15) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}
        except Exception as e:
            return -1, {"error": str(e)}

    def test_fed_end_to_end(self):
        # 1) 登录两侧
        code, d = self._req(self.baseA, "POST", "/api/login",
                            {"username": "fedmaster", "password": "MasterPass123"})
        self.assertEqual(code, 200, d)
        tokA = d["token"]
        code, d = self._req(self.baseB, "POST", "/api/login",
                            {"username": "fednode", "password": "NodePass123"})
        self.assertEqual(code, 200, d)
        tokB = d["token"]

        # 2) 节点开启联邦令牌：明文一次性返回；错误令牌被拒
        code, d = self._req(self.baseB, "POST", "/api/fed", {"action": "rotate"}, token=tokB)
        self.assertEqual(code, 200, d)
        node_tok = d.get("token", "")
        self.assertTrue(len(node_tok) >= 20, "令牌长度异常")
        code, _ = self._req(self.baseB, "GET", "/api/status", fed="bad-token")
        self.assertEqual(code, 401, "错误联邦令牌应被拒")
        code, _ = self._req(self.baseB, "GET", "/api/status")
        self.assertEqual(code, 401, "无凭据应被拒")
        # 联邦令牌可读状态（探活语义）
        code, d = self._req(self.baseB, "GET", "/api/fed", fed=node_tok)
        self.assertEqual(code, 200, d)
        self.assertTrue(d.get("fed_enabled"))

        # 3) 主面板添加节点（预探测）；令牌错时被拒
        code, d = self._req(self.baseA, "POST", "/api/fed/nodes",
                            {"name": "NodeB", "url": self.baseB, "token": node_tok}, token=tokA)
        self.assertEqual(code, 200, d)
        nid = d["id"]
        code, _ = self._req(self.baseA, "POST", "/api/fed/nodes",
                            {"name": "Bad", "url": self.baseB, "token": "wrong"}, token=tokA)
        self.assertEqual(code, 400, "错误令牌添加节点应被拒")

        # 4) 代理读/写均命中节点
        code, d = self._req(self.baseA, "GET", "/api/fed/%s/api/status" % nid, token=tokA)
        self.assertEqual(code, 200, d)
        self.assertEqual(d.get("username"), "fednode", "代理 status 应来自节点")
        code, d = self._req(self.baseA, "POST", "/api/fed/%s/api/open-port" % nid,
                            {"port": 18777, "proto": "tcp"}, token=tokA)
        self.assertEqual(code, 200, d)
        code, d = self._req(self.baseA, "GET", "/api/rules", token=tokA)
        self.assertFalse(any(r.get("port") == 18777 for r in d.get("rules", [])),
                         "主面板本机不应有远程规则")
        code, d = self._req(self.baseA, "GET", "/api/fed/%s/api/rules" % nid, token=tokA)
        self.assertTrue(any(r.get("port") == 18777 for r in d.get("rules", [])),
                        "规则应只落在节点")

        # 5) 节点令牌轮换 → 旧代理 502；更新节点令牌后恢复
        code, d = self._req(self.baseB, "POST", "/api/fed", {"action": "rotate"}, token=tokB)
        self.assertEqual(code, 200)
        new_tok = d["token"]
        code, _ = self._req(self.baseA, "GET", "/api/fed/%s/api/status" % nid, token=tokA)
        self.assertEqual(code, 502, "旧令牌应导致代理 502")
        code, d = self._req(self.baseA, "POST", "/api/fed/nodes/%s" % nid,
                            {"token": new_tok}, token=tokA)
        self.assertEqual(code, 200, d)
        code, d = self._req(self.baseA, "GET", "/api/fed/%s/api/status" % nid, token=tokA)
        self.assertEqual(code, 200)
        self.assertEqual(d.get("username"), "fednode")

        # 6) 安全隔离：联邦令牌不能改配置/管节点；列表不带明文
        code, _ = self._req(self.baseB, "POST", "/api/fed", {"action": "rotate"}, fed=new_tok)
        self.assertEqual(code, 401, "联邦令牌不应允许 rotate")
        code, _ = self._req(self.baseA, "GET", "/api/fed/nodes", fed="x")
        self.assertEqual(code, 401, "节点列表不接受联邦令牌")
        code, d = self._req(self.baseA, "GET", "/api/fed/nodes", token=tokA)
        self.assertEqual(code, 200)
        lst = d.get("nodes", [])
        self.assertTrue(any(n.get("id") == nid for n in lst))
        self.assertTrue(all("token" not in n for n in lst), "列表不得返回令牌明文")

        # 7) 删除节点 → 代理 404
        code, _ = self._req(self.baseA, "DELETE", "/api/fed/nodes/%s" % nid, token=tokA)
        self.assertEqual(code, 200)
        code, _ = self._req(self.baseA, "GET", "/api/fed/%s/api/status" % nid, token=tokA)
        self.assertEqual(code, 404)

        # 8) 关闭联邦令牌
        code, d = self._req(self.baseB, "POST", "/api/fed", {"action": "clear"}, token=tokB)
        self.assertEqual(code, 200)
        code, d = self._req(self.baseB, "GET", "/api/fed", fed=new_tok)
        self.assertEqual(code, 401, "clear 后令牌应失效")

    def test_fed_proxy_timeout_tiered(self):
        """代理超时分档：长任务端点 600s，常规 25s"""
        long_paths = ["/api/docker/install", "/api/docker/uninstall",
                      "/api/docker/pull", "/api/docker/create", "/api/docker/rmi",
                      "/api/docker/compose/up", "/api/docker/compose/upgrade",
                      "/api/docker/data-root", "/api/proxy/install",
                      "/api/proxy/abc123", "/api/cert/example.com",
                      "/api/upgrade"]
        short_paths = ["/api/status", "/api/docker", "/api/docker/dirs",
                       "/api/docker/containers", "/api/rules", "/api/traffic",
                       "/api/ssh", "/api/proxy"]
        for p in long_paths:
            self.assertEqual(panel.fed_proxy_timeout(p), 600, f"{p} 应 600s")
        for p in short_paths:
            self.assertEqual(panel.fed_proxy_timeout(p), 25, f"{p} 应 25s")

    def test_install_docker_waits_service_active(self):
        """安装后轮询 systemctl is-active 直到 active 才返回成功；超时未 active 报错不假成功"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        real_sleep = panel.time.sleep
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            if args[0] == "apt-get" and args[1] == "update":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:2] == ["systemctl", "is-active"]:
                # 前 2 次 inactive（服务启动中），第 3 次 active
                n = sum(1 for a in calls if a[:2] == ["systemctl", "is-active"])
                return types.SimpleNamespace(
                    returncode=0 if n >= 3 else 3,
                    stdout="active" if n >= 3 else "inactive", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            panel.time.sleep = lambda s: None
            ok, msg = panel.install_docker_pkgs("official")
            self.assertTrue(ok, msg)
            self.assertIn("已安装并启动", msg)
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry
            panel.time.sleep = real_sleep

    def test_install_docker_service_never_active_reports_error(self):
        """服务一直起不来 → 返回失败提示手动处理，不假成功"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        real_sleep = panel.time.sleep

        def fake_run(args, **kw):
            if args[0] == "apt-get" and args[1] == "update":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:2] == ["systemctl", "is-active"]:
                return types.SimpleNamespace(returncode=3, stdout="inactive", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            panel.time.sleep = lambda s: None
            ok, msg = panel.install_docker_pkgs("official")
            self.assertFalse(ok)
            self.assertIn("未能启动", msg)
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry
            panel.time.sleep = real_sleep


class TestTasks(unittest.TestCase):
    """长任务后台执行机制（v2.1.18）：start_task 异步 + 状态落盘 + 重启恢复"""

    def setUp(self):
        # 隔离：重置任务表并清掉共享目录里的任务文件
        panel._tasks = {}
        panel._tasks_loaded = False
        if os.path.exists(panel.TASKS_FILE):
            os.remove(panel.TASKS_FILE)

    def tearDown(self):
        panel._tasks = {}
        panel._tasks_loaded = False
        if os.path.exists(panel.TASKS_FILE):
            os.remove(panel.TASKS_FILE)

    def test_start_task_async_and_poll(self):
        """start_task 立即返回 tid；任务完成后 get_task 能查到结果"""
        import time as _t

        def slow_work():
            _t.sleep(0.1)
            return True, "干完了"

        tid = panel.start_task("test/slow", slow_work)
        self.assertTrue(tid)
        # 立即查：应存在且 running（线程还没跑完）
        t0 = panel.get_task(tid)
        self.assertIsNotNone(t0)
        # 轮询至完成（上限 3s）
        deadline = _t.time() + 3
        while _t.time() < deadline:
            t = panel.get_task(tid)
            if t and t["status"] != "running":
                break
            _t.sleep(0.02)
        self.assertEqual(t["status"], "ok", t)
        self.assertTrue(t["ok"])
        self.assertEqual(t["msg"], "干完了")
        self.assertTrue(t["done"])

    def test_start_task_error_captured(self):
        """任务函数抛异常 → status=error，不崩线程"""
        import time as _t

        def boom():
            raise RuntimeError("炸了")

        tid = panel.start_task("test/boom", boom)
        deadline = _t.time() + 3
        while _t.time() < deadline:
            t = panel.get_task(tid)
            if t and t["status"] != "running":
                break
            _t.sleep(0.02)
        self.assertEqual(t["status"], "error", t)
        self.assertFalse(t["ok"])
        self.assertIn("炸了", t["msg"])

    def test_tasks_persist_to_disk(self):
        """任务结果落盘：完成后磁盘文件可读且含该任务（模拟面板重启后仍能查到）"""
        import time as _t
        tid = panel.start_task("test/persist", lambda: (True, "已落盘"))
        deadline = _t.time() + 3
        while _t.time() < deadline:
            t = panel.get_task(tid)
            if t and t["status"] != "running":
                break
            _t.sleep(0.02)
        self.assertTrue(os.path.exists(panel.TASKS_FILE), "任务文件应写入磁盘")
        with open(panel.TASKS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn(tid, data.get("tasks", {}), "磁盘记录应含该任务")
        self.assertEqual(data["tasks"][tid]["status"], "ok")

    def test_reload_marks_stale_running_as_error(self):
        """模拟重启：磁盘遗留 running 任务，重新加载后标记 error（进程中断）"""
        import time as _t
        # 手工构造磁盘文件：一个 running 任务
        os.makedirs(os.path.dirname(panel.TASKS_FILE), exist_ok=True)
        with open(panel.TASKS_FILE, "w", encoding="utf-8") as f:
            json.dump({"tasks": {
                "deadbeef": {"action": "x", "status": "running", "ok": False,
                             "msg": "执行中...", "started": _t.time() - 10,
                             "finished": None, "done": False},
                "beefdead": {"action": "y", "status": "ok", "ok": True,
                             "msg": "完成", "started": _t.time() - 20,
                             "finished": _t.time(), "done": True},
            }}, f)
        # 重置加载标志 → 模拟新进程首次访问
        panel._tasks_loaded = False
        t = panel.get_task("deadbeef")
        self.assertEqual(t["status"], "error", "遗留 running 应标记 error")
        self.assertIn("中断", t["msg"])
        t2 = panel.get_task("beefdead")
        self.assertEqual(t2["status"], "ok", "已完成任务不受影响")

    def test_docker_install_handler_async_in_real_mode(self):
        """真实模式（非 DRY_RUN）POST docker/install → 返回 task_id 而非同步结果"""
        saved_dry = panel.DRY_RUN
        real_install = panel.install_docker_pkgs
        import types
        try:
            panel.DRY_RUN = False
            panel.install_docker_pkgs = lambda source="official": (True, "装好了")
            panel.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr="")
            # 用真实 HTTP 请求（复用一个临时 PanelServer）
            import threading
            cfg = make_cfg(user="taskuser", pwd="TaskPass123", mode="permissive")
            cfg.data["port"] = 17990
            cfg.data["bind"] = "127.0.0.1"
            store = panel.RuleStore(); store.rules = []
            nft = panel.NFTManager(store, cfg)
            auth = panel.Auth(cfg)
            srv = panel.PanelServer(("127.0.0.1", 17990), panel.PanelHandler,
                                    cfg, store, nft, auth)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                base = "http://127.0.0.1:17990"
                r = urllib.request.Request(base + "/api/login", method="POST",
                                           data=json.dumps({"username": "taskuser", "password": "TaskPass123"}).encode())
                r.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(r, timeout=10) as resp:
                    tok = json.loads(resp.read())["token"]
                req = urllib.request.Request(base + "/api/docker/install", method="POST",
                                             data=b"{}")
                req.add_header("Content-Type", "application/json")
                req.add_header("Authorization", "Bearer " + tok)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    d = json.loads(resp.read())
                self.assertIn("task", d, "真实模式应返回 task_id: %s" % d)
                # 轮询到完成
                import time as _t
                deadline = _t.time() + 3
                while _t.time() < deadline:
                    q = urllib.request.Request(base + "/api/tasks/" + d["task"])
                    q.add_header("Authorization", "Bearer " + tok)
                    with urllib.request.urlopen(q, timeout=10) as resp:
                        st = json.loads(resp.read())
                    if st["status"] != "running":
                        break
                    _t.sleep(0.05)
                self.assertEqual(st["status"], "ok", st)
                self.assertEqual(st["msg"], "装好了")
            finally:
                srv.shutdown(); srv.server_close()
        finally:
            panel.DRY_RUN = saved_dry
            panel.install_docker_pkgs = real_install


class TestWsFrames(unittest.TestCase):
    """Web 终端 WS 帧层（v2.1.19）：握手 accept、帧编解码往返、掩码、长帧、分片无关性"""

    def test_accept_key(self):
        # RFC6455 官方示例：key "dGhlIHNhbXBsZSBub25jZQ==" → accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        self.assertEqual(panel.ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_encode_server_frame_no_mask(self):
        frame = panel.ws_encode_frame(b"hi", 0x1)
        # FIN+text: 0x81；长度 2 不掩码 → 0x02
        self.assertEqual(frame, b"\x81\x02hi")

    def test_server_frame_roundtrip(self):
        for n in (0, 1, 125, 126, 65535, 65536, 100000):
            payload = b"x" * n
            frame = panel.ws_encode_frame(payload, 0x1)
            # 用 BytesIO 模拟 buffered reader 读回
            import io
            op, out = panel.ws_read_frame(io.BytesIO(frame))
            self.assertEqual(op, 0x1)
            self.assertEqual(out, payload)

    def test_client_masked_frame_roundtrip(self):
        """客户端帧带掩码：服务端 ws_read_frame 必须正确解掩码"""
        import io
        payload = b"echo hello\n"
        frame = panel.ws_encode_frame_client(payload, 0x1)
        # 帧头第一字节 FIN+text
        self.assertEqual(frame[0], 0x81)
        # 客户端帧第二字节必须带掩码位 (0x80|len)
        self.assertTrue(frame[1] & 0x80)
        op, out = panel.ws_read_frame(io.BytesIO(frame))
        self.assertEqual(op, 0x1)
        self.assertEqual(out, payload)

    def test_client_masked_long_payload(self):
        import io
        payload = os.urandom(70000)  # 127 扩展长度路径
        frame = panel.ws_encode_frame_client(payload, 0x2)
        self.assertEqual(frame[1] & 0x80, 0x80)
        self.assertEqual(frame[1] & 0x7F, 127)
        op, out = panel.ws_read_frame(io.BytesIO(frame))
        self.assertEqual(op, 0x2)
        self.assertEqual(out, payload)

    def test_ws_read_frame_empty_returns_none(self):
        import io
        self.assertEqual(panel.ws_read_frame(io.BytesIO(b"")), (None, None))
        # 只有半个头 → 也视为关闭
        self.assertEqual(panel.ws_read_frame(io.BytesIO(b"\x81")), (None, None))

    def test_split_frames_are_assembled(self):
        """TCP 分片：帧被拆成多段到达仍能正确组装（_ws_read_exact 补读）"""
        import io
        payload = b"A" * 5000
        frame = panel.ws_encode_frame(payload, 0x1)
        # 模拟 recv 每次只给 7 字节的慢速流
        class Chunked:
            def __init__(self, data, chunk):
                self.data, self.chunk, self.i = data, chunk, 0
            def read(self, n):
                if self.i >= len(self.data):
                    return b""
                # 模拟慢速流：最多给 chunk 字节，且尊重 read(n) 的上限
                take = min(self.chunk, n, len(self.data) - self.i)
                out = self.data[self.i:self.i + take]
                self.i += take
                return out
        op, out = panel.ws_read_frame(Chunked(frame, 7))
        self.assertEqual(op, 0x1)
        self.assertEqual(out, payload)

    def test_close_ping_opcodes_roundtrip(self):
        import io
        for op, payload in ((0x8, b""), (0x9, b"ping"), (0xA, b"pong")):
            frame = panel.ws_encode_frame(payload, op)
            got_op, got_payload = panel.ws_read_frame(io.BytesIO(frame))
            self.assertEqual(got_op, op)
            self.assertEqual(got_payload, payload)


class TestTermKeyApi(unittest.TestCase):
    """终端临时私钥上传/删除端点（v2.1.22）：校验 PEM、路径防穿越、删除后文件消失"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17998), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17998"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def _login(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        return d["token"]

    def _ssh_dir(self):
        # 测试环境（无 term 用户）→ 上传 fallback 到当前用户 ~/.ssh，与实现一致
        return os.path.join(os.path.expanduser("~"), ".ssh")

    def test_upload_and_delete(self):
        tok = self._login()
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
        code, d = self._req("POST", "/api/term/key", {"content": pem}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertIn("fwterm_", d["path"])
        self.assertTrue(d["path"].endswith(".pem"))
        fpath = d["path"]
        # 文件确实落盘、权限 600
        self.assertTrue(os.path.exists(fpath))
        self.assertEqual(os.stat(fpath).st_mode & 0o777, 0o600)
        with open(fpath, encoding="utf-8") as f:
            self.assertIn("PRIVATE KEY", f.read())
        # 删除
        code, d = self._req("DELETE", "/api/term/key", {"path": fpath}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertFalse(os.path.exists(fpath), "删除后文件应消失")

    def test_reject_non_pem(self):
        tok = self._login()
        code, d = self._req("POST", "/api/term/key",
                            {"content": "随便的内容不是密钥"}, token=tok)
        self.assertEqual(code, 400, d)
        self.assertIn("私钥", d["error"])

    def test_delete_traversal_guarded(self):
        tok = self._login()
        # 任意路径（非 fwterm_ 前缀）→ 拒绝
        code, d = self._req("DELETE", "/api/term/key",
                            {"path": "/etc/passwd"}, token=tok)
        self.assertEqual(code, 400, d)
        # 路径穿越：../ 被 basename 剥掉 → 只会在 .ssh 内找 fwterm_x.pem（不存在），
        # 不会删除 .ssh 之外任何文件——目标文件不存在时 ok:true 无害
        victim = os.path.join(self._ssh_dir(), "..", "fwterm_x.pem")
        code, d = self._req("DELETE", "/api/term/key", {"path": victim}, token=tok)
        self.assertEqual(code, 200, d)
        self.assertFalse(os.path.exists(victim), "不创建也不删外部文件")

    def test_requires_auth(self):
        code, _ = self._req("POST", "/api/term/key", {"content": "-----BEGIN x"})
        self.assertEqual(code, 401)


class TestTermZsh(unittest.TestCase):
    """term 终端 zsh 语法高亮配置（v2.1.24）：zshrc 生成、登录 shell 选择、安装分支"""

    def tearDown(self):
        panel._TERM_SETUP_DONE = False

    def test_zshrc_content_with_highlight(self):
        c = panel._term_zshrc_content("/usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh")
        self.assertIn("source /usr/share/zsh-syntax-highlighting", c)
        self.assertIn("ZSH_HIGHLIGHT_STYLES[command]", c)
        self.assertIn("PROMPT=", c)

    def test_zshrc_content_without_highlight(self):
        c = panel._term_zshrc_content("")
        self.assertNotIn("\nsource ", c)   # 无高亮时不含 source 指令（注释里的字样除外）
        self.assertIn("PROMPT=", c)   # 提示符始终有

    def test_prepare_zsh_writes_rc(self):
        """已有 zsh 和高亮插件时：只写 .zshrc + chown，不触发任何安装"""
        home = tempfile.mkdtemp(prefix="fwterm-home-")
        real_which = panel.shutil.which
        real_paths = panel.ZSH_HL_PATHS
        real_run = panel.subprocess.run
        calls = []
        try:
            panel.shutil.which = lambda n: "/usr/bin/zsh" if n == "zsh" else None
            # 让探测路径指向临时目录里的伪插件
            fake_hl = os.path.join(home, "hl.zsh")
            with open(fake_hl, "w") as f:
                f.write("# hl")
            panel.ZSH_HL_PATHS = (fake_hl,)
            panel.subprocess.run = lambda *a, **k: calls.append(a) or type("R", (), {"returncode": 0})()
            ok, msg = panel._term_prepare_zsh(home, os.geteuid(), os.geteuid())
            self.assertTrue(ok, msg)
            self.assertEqual(calls, [], "zsh 与插件都已存在时不应触发任何安装")
            zshrc = os.path.join(home, ".zshrc")
            self.assertTrue(os.path.exists(zshrc))
            with open(zshrc, encoding="utf-8") as f:
                self.assertIn("ZSH_HIGHLIGHT_STYLES[command]", f.read())
        finally:
            panel.shutil.which = real_which
            panel.ZSH_HL_PATHS = real_paths
            panel.subprocess.run = real_run
            shutil.rmtree(home, ignore_errors=True)

    def test_login_shell_fallback_nonroot(self):
        """非 root（测试环境）：zsh 装了也不用，回落 bash（保持测试语义）"""
        real_euid = panel.os.geteuid
        real_which = panel.shutil.which
        try:
            panel.os.geteuid = lambda: 1000
            panel.shutil.which = lambda n: "/usr/bin/zsh" if n == "zsh" else None
            self.assertEqual(panel._term_login_shell(), panel.TERM_SHELL)
        finally:
            panel.os.geteuid = real_euid
            panel.shutil.which = real_which

    def test_ensure_async_runs_once(self):
        """_term_ensure_zsh_async 内部锁：并发调用只启动一个后台线程"""
        home = tempfile.mkdtemp(prefix="fwterm-home-")
        real_which, real_run = panel.shutil.which, panel.subprocess.run
        started = []
        real_thread = panel.threading.Thread
        try:
            panel.shutil.which = lambda n: None   # 触发安装分支（但被 mock 吞）
            panel.subprocess.run = lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            class FakeThread:
                def __init__(self, target=None, daemon=False, *a, **k):
                    self.target = target
                def start(self):
                    started.append(self.target)
            panel.threading.Thread = FakeThread
            panel._term_ensure_zsh_async(home, os.geteuid(), os.geteuid())
            panel._term_ensure_zsh_async(home, os.geteuid(), os.geteuid())
            self.assertEqual(len(started), 1, "重复调用只应启动一次后台准备")
            panel._term_ensure_zsh_async(home, os.geteuid(), os.geteuid())
            self.assertEqual(len(started), 1)
        finally:
            panel.shutil.which = real_which
            panel.subprocess.run = real_run
            panel.threading.Thread = real_thread
            panel._TERM_SETUP_DONE = False
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
