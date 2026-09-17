#!/usr/bin/env bash
# 端到端演练（回归用）：全新安装 → 卸载 → 重装，验证端口/账号不变且地址真能打开
# 端到端演练 v2：全新安装 → 卸载 → 重装（真实 panel.py + 隔离目录 + systemctl 替身）
set -u
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E=/tmp/e2e
rm -rf "$E2E"; mkdir -p "$E2E/app/static" "$E2E/etc" "$E2E/bin" "$E2E/sd"
CALLS="$E2E/calls.log"; : > "$CALLS"

# 1) 被测脚本副本（去掉末尾 main "$@"，所有落盘路径指向 $E2E）
sed -e "s|^readonly APP_DIR=\"/usr/local/lib/fwpanel\"|readonly APP_DIR=\"$E2E/app\"|" \
    -e "s|^readonly ETC_DIR=\"/etc/fwpanel\"|readonly ETC_DIR=\"$E2E/etc\"|" \
    -e "s|^readonly LOG_FILE=\"/var/log/fwpanel-install.log\"|readonly LOG_FILE=\"$E2E/install.log\"|" \
    -e "s|^readonly WRAPPER_PATH=\"/usr/local/bin/fwp\"|readonly WRAPPER_PATH=\"$E2E/bin/fwp\"|" \
    -e "s|^readonly SERVICE_NAME=\"fwpanel.service\"|readonly SERVICE_NAME=\"fwpanel_e2e.service\"|" \
    -e "s|^readonly SYSTEMD_DIR=\"\${FW_SYSTEMD_DIR:-/etc/systemd/system}\"|readonly SYSTEMD_DIR=\"$E2E/sd\"|" \
    <(head -n -1 "$SRC/install.sh") > "$E2E/install.sh"
cp "$SRC/panel.py" "$E2E/app/panel.py"
cp -r "$SRC/static/." "$E2E/app/static/"

# 2) systemctl 替身（quoted heredoc + 占位符替换，避免被外层展开）
cat > "$E2E/bin/systemctl" <<'STUBBODY'
#!/usr/bin/env bash
APP="@E2E@/app"
LOG="@E2E@/calls.log"
echo "systemctl $*" >> "$LOG"
pids() { pgrep -f "$APP/panel.py" 2>/dev/null || true; }
case "$1" in
    daemon-reload|enable|disable|reset-failed) exit 0 ;;
    stop)
        p="$(pids)"
        if [ -n "$p" ]; then printf '%s\n' "$p" | xargs -r kill 2>/dev/null || true; fi
        exit 0
        ;;
    restart)
        p="$(pids)"
        if [ -n "$p" ]; then printf '%s\n' "$p" | xargs -r kill -9 2>/dev/null || true; fi
        sleep 0.3
        FW_TEST_DIR="@E2E@/etc" nohup python3 "$APP/panel.py" serve >/dev/null 2>&1 &
        exit 0
        ;;
    is-active)
        p="$(pids)"
        if [ -n "$p" ]; then exit 0; else exit 3; fi
        ;;
    *) exit 0 ;;
esac
STUBBODY
sed -i "s|@E2E@|$E2E|g" "$E2E/bin/systemctl"
chmod +x "$E2E/bin/systemctl"
export PATH="$E2E/bin:$PATH"

PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
echo "演练端口: $PORT"
ok=0; bad=0
chk() { if [ "$2" = "$3" ]; then echo "  ✓ $1"; ok=$((ok+1)); else echo "  ✗ $1（期望 [$3] 实际 [$2]）"; bad=$((bad+1)); fi; }

# ---------------- 阶段 1：全新安装 ----------------
echo "== 阶段1：全新安装（write_config + install_service） =="
bash -c "
source '$E2E/install.sh'
check_root() { :; }
PANEL_USER=e2euser; PANEL_PASS=E2ePass12345; PANEL_PORT=$PORT; PANEL_BIND=0.0.0.0; OPEN_PORTS=''
write_config
install_service
" > /tmp/e2e_p1.log 2>&1
chk "config.json 端口 = $PORT" "$(python3 -c "import json;print(json.load(open('$E2E/etc/config.json'))['port'])" 2>/dev/null || echo ERR)" "$PORT"
chk "rules.json 放行了面板端口" "$(python3 -c "
import json;rs=json.load(open('$E2E/etc/rules.json'))
print('yes' if any(r.get('type')=='port_allow' and r.get('port')==$PORT for r in rs) else 'no')" 2>/dev/null || echo ERR)" "yes"
chk "面板进程在跑" "$(pgrep -f "$E2E/app/panel.py" >/dev/null && echo yes || echo no)" "yes"
chk "本机访问返回 200" "$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1:$PORT/ 2>/dev/null || true)" "200"
HASH1=$(python3 -c "import json;print(json.load(open('$E2E/etc/config.json'))['password_hash'])" 2>/dev/null || echo "")

# ---------------- 阶段 2：卸载 ----------------
echo "== 阶段2：卸载（do_uninstall） =="
bash -c "
source '$E2E/install.sh'
check_root() { :; }
do_uninstall
" > /tmp/e2e_p2.log 2>&1
grep -q "无残留面板进程" /tmp/e2e_p2.log && { echo "  ✓ 有残留自检输出"; ok=$((ok+1)); } || { echo "  ✗ 缺残留自检输出"; bad=$((bad+1)); }
chk "无残留进程" "$(pgrep -f "$E2E/app/panel.py" >/dev/null && echo alive || echo gone)" "gone"
chk "程序文件已删" "$([ -f "$E2E/app/panel.py" ] && echo exists || echo gone)" "gone"
chk "service 单元已删" "$([ -f "$E2E/sd/fwpanel_e2e.service" ] && echo exists || echo gone)" "gone"
chk "配置按设计保留" "$([ -f "$E2E/etc/config.json" ] && echo kept || echo lost)" "kept"

# ---------------- 阶段 3：重装（真实场景：程序文件已删、配置保留） ----------------
echo "== 阶段3：重装（do_upgrade，等价重跑一键命令） =="
bash -c "
source '$E2E/install.sh'
check_root() { :; }
resolve_src_tag() { SRC_TAG=v9.9.9; }
fetch_source() { cp '$SRC/panel.py' \"\$1\"; return 0; }
install_shortcut() { return 0; }
BETA=1; VERSION_TAG=''
do_upgrade
" > /tmp/e2e_p3.log 2>&1
echo "  ── 重装输出尾部 ──"; tail -8 /tmp/e2e_p3.log | sed 's/^/    | /'
chk "端口仍是 $PORT（没被随机改掉）" "$(python3 -c "import json;print(json.load(open('$E2E/etc/config.json'))['port'])" 2>/dev/null || echo ERR)" "$PORT"
chk "账号仍是 e2euser" "$(python3 -c "import json;print(json.load(open('$E2E/etc/config.json'))['username'])" 2>/dev/null || echo ERR)" "e2euser"
chk "密码哈希未变" "$(python3 -c "
import json;d=json.load(open('$E2E/etc/config.json'))
print('same' if d['password_hash']=='$HASH1' else 'changed')" 2>/dev/null || echo ERR)" "same"
chk "service 单元已补装" "$([ -f "$E2E/sd/fwpanel_e2e.service" ] && echo exists || echo missing)" "exists"
chk "面板进程在跑" "$(pgrep -f "$E2E/app/panel.py" >/dev/null && echo yes || echo no)" "yes"
chk "本机访问返回 200" "$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1:$PORT/ 2>/dev/null || true)" "200"
grep -q "自检通过\|返回 200" /tmp/e2e_p3.log && { echo "  ✓ 收尾打印了自检结论"; ok=$((ok+1)); } || { echo "  ✗ 收尾没有自检结论"; bad=$((bad+1)); }

pkill -f "$E2E/app/panel.py" 2>/dev/null || true
echo "=========================================="
echo "演练结果: $ok 通过, $bad 失败"
exit $bad
