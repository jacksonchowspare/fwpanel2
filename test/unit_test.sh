#!/usr/bin/env bash
# install.sh 函数级单元测试（提取函数源码后 source，不触发 main）
set -u
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/install.sh"
TMPF=$(mktemp)
head -n -1 "$SCRIPT" > "$TMPF"      # 去掉最后一行 main "$@"
# shellcheck disable=SC1090
source "$TMPF"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

echo "== gen_password：16位且含大写/小写/数字 =="
for i in 1 2 3; do
    pw=$(gen_password)
    [ "${#pw}" -eq 16 ] && echo "$pw" | grep -qE '[A-Z]' && echo "$pw" | grep -qE '[a-z]' \
        && echo "$pw" | grep -qE '[0-9]' && ok "第${i}个密码格式正确" || bad "第${i}个密码异常: $pw"
done

echo "== gen_user：8位小写字母数字 =="
u=$(gen_user)
[ "${#u}" -eq 8 ] && echo "$u" | grep -qE '^[a-z0-9]+$' && ok "用户名: $u" || bad "用户名异常: $u"

echo "== resolve_params 默认值 =="
PANEL_PORT=""; PANEL_BIND=""; PANEL_USER=""; PANEL_PASS=""
resolve_params
[ -n "$PANEL_PORT" ] && [ "$PANEL_BIND" = "0.0.0.0" ] && [ -n "$PANEL_USER" ] \
    && [ "${#PANEL_PASS}" -ge 8 ] && ok "默认参数齐全 PORT=$PANEL_PORT BIND=$PANEL_BIND" || bad "默认参数缺失"

echo "== resolve_params 非法端口应报错（子shell） =="
PANEL_PORT="abc"; PANEL_BIND=""; PANEL_USER="x"; PANEL_PASS="12345678"
( resolve_params >/dev/null 2>&1 ) && bad "非法端口未拦截" || ok "非法端口已拦截"

echo "== resolve_params 短密码应报错（子shell） =="
PANEL_PORT="17890"; PANEL_BIND=""; PANEL_USER="xx"; PANEL_PASS="short"
( resolve_params >/dev/null 2>&1 ) && bad "短密码未拦截" || ok "短密码已拦截"

echo "== 环境变量读取（FW_* 普通名，\${VAR:-} 直接可用） =="
head -n -1 "$SCRIPT" > /tmp/install_funcs_fw.sh
FW_PORT=18888 FW_BIND=0.0.0.0 FW_USER=envuser FW_PASS=EnvPass123 \
    bash -c 'source /tmp/install_funcs_fw.sh
    init_params
    [ "$PANEL_PORT" = "18888" ] && [ "$PANEL_BIND" = "0.0.0.0" ] && [ "$PANEL_USER" = "envuser" ] \
        && [ "$PANEL_PASS" = "EnvPass123" ] && echo "  ✓ 环境变量读取正确" || echo "  ✗ 失败: $PANEL_PORT/$PANEL_BIND"'

echo "== 命令行参数优先级 =="
PANEL_PORT="17890"
parse_args -p 19001
[ "$PANEL_PORT" = "19001" ] && ok "参数覆盖环境变量" || bad "参数未生效"

echo "== check_root 非root无sudo应报错（子shell） =="
if [ "$(id -u)" -ne 0 ]; then
    ( PATH=/nonexistent bash -c "source '$TMPF'; check_root" >/dev/null 2>&1 ) \
        && bad "非root无sudo未拦截" || ok "已拦截（提示切换root）"
else
    echo "  （root 环境跳过）"
fi

echo "== check_existing 已安装时进入升级（不跳过） =="
head -n -1 "$SCRIPT" > /tmp/install_funcs_up.sh
mkdir -p /tmp/fakebin
cat > /tmp/fakebin/systemctl <<'EOF'
#!/bin/bash
if [ "$1" = "list-unit-files" ]; then echo "fwpanel.service enabled"; fi
exit 0
EOF
chmod +x /tmp/fakebin/systemctl
bash -c 'PATH=/tmp/fakebin:$PATH
source /tmp/install_funcs_up.sh
do_upgrade() { echo "UPGRADE_CALLED"; exit 0; }
out=$(check_existing)
if echo "$out" | grep -q UPGRADE_CALLED; then echo "  ✓ 已安装 → 进入升级流程"; else echo "  ✗ 未进入升级: $out"; exit 1; fi'

echo "== check_existing 体检模式已安装不升级 =="
bash -c 'PATH=/tmp/fakebin:$PATH
source /tmp/install_funcs_up.sh
do_upgrade() { echo "UPGRADE_CALLED"; exit 0; }
out=$(check_existing check)
if echo "$out" | grep -q UPGRADE_CALLED; then echo "  ✗ 体检模式不应升级"; exit 1; else echo "  ✓ 体检模式跳过升级"; fi'
rm -f /tmp/install_funcs_up.sh
rm -rf /tmp/fakebin

echo "== do_upgrade 防降级（当前 ≥ 下载版本时跳过） =="
mkdir -p /tmp/fwpanel-dg-cur /tmp/fwpanel-dg-tmp
echo 'CURRENT_VERSION = "1.23.20"' > /tmp/fwpanel-dg-cur/panel.py
head -n -1 "$SCRIPT" | sed 's|readonly APP_DIR="/usr/local/lib/fwpanel"|readonly APP_DIR="/tmp/fwpanel-dg-cur"|' > /tmp/install_funcs_dg.sh
bash -c 'source /tmp/install_funcs_dg.sh
curl() {
  if [[ "$*" == *"/panel.py"* && "$*" == *"-o"* ]]; then
    printf "#!/usr/bin/env python3\nCURRENT_VERSION = \"1.23.19\"\n" > "$(echo "$*" | grep -oP "(?<=-o )\S+")"
    return 0
  fi
  return 1
}
mktemp() { echo /tmp/fwpanel-dg-tmp; }
out=$(do_upgrade 2>&1)
if echo "$out" | grep -q "不降级"; then echo "  ✓ 防降级生效（1.23.20 ≥ 1.23.19 跳过）"; else echo "  ✗ $out"; exit 1; fi'
rm -f /tmp/install_funcs_dg.sh
rm -rf /tmp/fwpanel-dg-cur /tmp/fwpanel-dg-tmp

echo "== gen_initial_rules 生成 SSH+面板端口放行 =="
RULES_TMP="$(mktemp -u)"
rm -f "$RULES_TMP"
gen_initial_rules 2222 17890 "$RULES_TMP"
python3 - "$RULES_TMP" <<'PYEOF'
import json, sys
rules = json.load(open(sys.argv[1]))
assert len(rules) == 2, f"规则数 {len(rules)} != 2"
ports = {r["port"]: r for r in rules}
assert 2222 in ports and ports[2222]["protected"] is True, "SSH 保护规则缺失或未保护"
assert 17890 in ports and ports[17890]["protected"] is True, "面板端口规则缺失或未保护"
print("  ✓ 初始规则正确（SSH 2222 + 面板 17890，均 protected）")
PYEOF
gen_initial_rules 2222 17890 "$RULES_TMP" && echo "  ✓ 已存在不覆盖" || bad "已存在规则被覆盖"
rm -f "$RULES_TMP"

echo "== check_os 发行版识别（本机） =="
DISTRO_ID="unknown"; PKG_MGR=""
check_os
[ -n "$DISTRO_ID" ] && [ -n "$PKG_MGR" ] \
    && ok "识别发行版: $DISTRO_ID (包管理器: $PKG_MGR, python包: $PY_PKG)" \
    || bad "发行版识别失败"

echo "== resolve_src_tag 无 python3（全新最小机）不挂 + sed/awk 回退解析 =="
# v3.2.8 真机回归：标签解析发生在 install_deps 之前，最小系统没有 python3 时
# 直接调 python3 会以 127 挂掉整个安装（横幅之后只有一行「退出码 127」）
mkdir -p /tmp/fakebin_nopy
for _c in sed head awk grep cat; do ln -sf "$(command -v "$_c")" "/tmp/fakebin_nopy/$_c"; done
cat > /tmp/fakebin_nopy/curl <<'EOF'
#!/bin/bash
# 模拟 GitHub API 返回（美化多行 JSON，与真实 API 一致）
for a in "$@"; do
    case "$a" in
        */releases/latest)
            printf '%s\n' '{' '  "tag_name": "v9.9.9",' '  "prerelease": false' '}'; exit 0 ;;
        */releases\?*)
            printf '%s\n' '[' '  {' '    "assets": [ {"name": "a.tar.gz", "size": 1} ],' '    "tag_name": "v9.9.9",' '    "prerelease": false' '  },' '  {' '    "assets": [ {"name": "b.tar.gz", "size": 2} ],' '    "tag_name": "v9.9.10-beta",' '    "prerelease": true' '  }' ']'; exit 0 ;;
    esac
done
exit 1
EOF
chmod +x /tmp/fakebin_nopy/curl

bash -c 'source '"$TMPF"'; PATH=/tmp/fakebin_nopy
command -v python3 >/dev/null 2>&1 && { echo "  ✗ 测试环境隔离失败（仍能看见 python3）"; exit 1; }
BETA=0; VERSION_TAG=""; SRC_TAG=""
rc=0; resolve_src_tag 2>/dev/null || rc=$?
[ "$rc" -eq 0 ] && [ "$SRC_TAG" = "v9.9.9" ] \
    && echo "  ✓ 无 python3：正式版解析回退 sed 成功（$SRC_TAG，退出码 $rc）" \
    || { echo "  ✗ 无 python3 解析失败 rc=$rc tag=[$SRC_TAG]"; exit 1; }
BETA=1; VERSION_TAG=""; SRC_TAG=""
rc=0; resolve_src_tag 2>/dev/null || rc=$?
[ "$rc" -eq 0 ] && [ "$SRC_TAG" = "v9.9.10-beta" ] \
    && echo "  ✓ 无 python3：测试版解析回退 awk 成功（$SRC_TAG，跳过正式版）" \
    || { echo "  ✗ 无 python3 beta 解析失败 rc=$rc tag=[$SRC_TAG]"; exit 1; }
# 压缩成单行的 JSON 也必须能解析（代理/镜像改写过的响应）
one_line=$(printf '%s' "[ {\"tag_name\": \"v8.1.0\", \"prerelease\": false }, {\"tag_name\": \"v8.1.1-beta\", \"prerelease\": true } ]" | json_tag_prerelease)
[ "$one_line" = "v8.1.1-beta" ] \
    && echo "  ✓ 单行压缩 JSON 也能解析（$one_line）" \
    || { echo "  ✗ 单行 JSON 解析失败: [$one_line]"; exit 1; }'

echo "== 无 python3 + 无网络：回退 main 且不挂 =="
rm -rf /tmp/fakebin_failcurl && mkdir -p /tmp/fakebin_failcurl
for _c in sed head awk grep cat; do ln -sf "$(command -v "$_c")" "/tmp/fakebin_failcurl/$_c"; done
printf '#!/bin/bash\nexit 1\n' > /tmp/fakebin_failcurl/curl && chmod +x /tmp/fakebin_failcurl/curl
bash -c 'source '"$TMPF"'; PATH=/tmp/fakebin_failcurl
BETA=0; VERSION_TAG=""; SRC_TAG=""
rc=0; resolve_src_tag >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] && [ "$SRC_TAG" = "main" ] \
    && echo "  ✓ 网络失败时回退 main 且不挂（退出码 $rc）" \
    || { echo "  ✗ 网络失败路径异常 rc=$rc tag=[$SRC_TAG]"; exit 1; }'
rm -rf /tmp/fakebin_failcurl

echo "== valid_tag 只接受版本号形状（防解析残渣当版本） =="
bash -c 'source '"$TMPF"'
valid_tag "v3.2.8" && valid_tag "3.2.8" && ! valid_tag "" && ! valid_tag "{\"a\":1}" \
    && echo "  ✓ valid_tag 正常/空/垃圾值判定正确" || { echo "  ✗ valid_tag 判定错误"; exit 1; }'

echo "== err_trap 只报一次 + 指名失败命令（127 提示） =="
out=$(bash -c 'source '"$TMPF"'; defintely_no_such_command_127' 2>&1 || true)
n=$(printf '%s' "$out" | grep -c '退出码 127' || true)
case "$out" in
    *defintely_no_such_command_127*) cmd_ok=1 ;;
    *) cmd_ok=0 ;;
esac
[ "$n" -eq 1 ] && [ "$cmd_ok" -eq 1 ] \
    && ok "单次提示且报出失败命令（127）" \
    || bad "err_trap 输出异常（次数=$n 含命令=$cmd_ok）: $out"
rm -rf /tmp/fakebin_nopy

echo "============================================"
echo "结果: $PASS 通过, $FAIL 失败"
rm -f "$TMPF" /tmp/install_funcs_fw.sh
exit $FAIL
