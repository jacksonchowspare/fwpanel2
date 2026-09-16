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
# 大 JSON（>64KB，模拟 GitHub 真实响应）：解析器提前退出时上游 printf 会 SIGPIPE(141)
# —— 用几百字节的假数据测不出这个坑（v3.2.10 真机 --beta 踩坑），所以必须放大
python3 - <<'PYGEN'
import json, random
rels = [{'assets': [{'name': f'fwpanel2-v{i}.{j}-linux-amd64-asset-with-a-long-name.tar.gz',
                     'size': random.randint(1000, 99999999), 'download_count': i,
                     'content_type': 'application/octet-stream', 'state': 'uploaded',
                     'url': 'https://api.github.com/repos/x/y/releases/assets/' + '9' * 12 + str(j)}
                    for j in range(60)]} for i in range(20)]
rels[0].update({'tag_name': 'v9.9.10-beta', 'prerelease': True})
for i, r in enumerate(rels[1:], 1):
    r.update({'tag_name': f'v9.9.{10 - i}', 'prerelease': False})
open('/tmp/fakebin_nopy/big_rel.json', 'w').write(json.dumps(rels, indent=2))
PYGEN
echo "  （测试用大 JSON: $(wc -c < /tmp/fakebin_nopy/big_rel.json) 字节，须 >65536 才能复现 SIGPIPE）"
cat > /tmp/fakebin_nopy/curl <<'EOF'
#!/bin/bash
# 模拟 GitHub API 返回：/releases/latest 用美化多行 JSON，列表用 >64KB 的大 JSON
for a in "$@"; do
    case "$a" in
        */releases/latest)
            printf '%s\n' '{' '  "tag_name": "v9.9.9",' '  "prerelease": false' '}'; exit 0 ;;
        */releases\?*)
            cat /tmp/fakebin_nopy/big_rel.json; exit 0 ;;
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
# 直接测管道本身：>64KB 输入 + 解析器提前退出，不得让上游 printf 吃 SIGPIPE（退出码 141）
big=$(cat /tmp/fakebin_nopy/big_rel.json)
for fn in json_tag_prerelease json_tag_latest; do
    rc=0; got=$(printf '%s' "$big" | $fn 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ] && [ -n "$got" ] \
        && echo "  ✓ 大 JSON(>64KB) 管道经 $fn 不触发 SIGPIPE（退出码 $rc，得到 $got）" \
        || { echo "  ✗ $fn 管道失败 rc=$rc out=[$got]"; exit 1; }
done
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

echo "== print_banner：横幅显示的是【目标面板版本】，不是脚本版本 =="
# 用户实测反馈：横幅原来印 SCRIPT_VERSION，让人以为正式版安装会装 3.x 脚本的版本
bash -c 'source '"$TMPF"'
chk() { # chk <期望片段> <说明>
    case "$1" in *"$2"*) return 0 ;; *) echo "  ✗ $3：$1"; return 1 ;; esac
}
BETA=0; VERSION_TAG=""; SRC_TAG="v2.1.33"
out=$(print_banner)
chk "$out" "目标版本 : 面板 v2.1.33（最新正式版）" "正式版横幅" || exit 1
BETA=1; VERSION_TAG=""; SRC_TAG="v3.2.10"
out=$(print_banner)
chk "$out" "目标版本 : 面板 v3.2.10（最新测试版）" "测试版横幅" || exit 1
BETA=0; VERSION_TAG="v1.24.42"; SRC_TAG="v1.24.42"
out=$(print_banner)
chk "$out" "目标版本 : 面板 v1.24.42（指定版本）" "指定版本横幅" || exit 1
VERSION_TAG=""; BETA=0; SRC_TAG="main"
out=$(print_banner)
chk "$out" "目标版本 : 面板 main（主线" "主线回退横幅" || exit 1
# 脚本版本必须仍可见（排查要用），但必须标注为「非面板版本」
chk "$out" "安装脚本 : v" "脚本版本行" || exit 1
echo "  ✓ 四种模式（正式版/测试版/指定版本/主线回退）横幅都显示目标面板版本"'

echo "== installed_panel_version：从磁盘 panel.py 读真实版本 =="
mkdir -p /tmp/fw_pv && printf 'CURRENT_VERSION = "2.1.33"\nother = 1\n' > /tmp/fw_pv/panel.py
bash -c 'source '"$TMPF"'
v=$(installed_panel_version /tmp/fw_pv/panel.py)
[ "$v" = "2.1.33" ] && echo "  ✓ 读出 v$v" || { echo "  ✗ 读到 [$v]"; exit 1; }
v=$(installed_panel_version /tmp/fw_pv/nope.py)
[ -z "$v" ] && echo "  ✓ 文件不存在时返回空（不报错）" || { echo "  ✗ 应为空: [$v]"; exit 1; }'
rm -rf /tmp/fw_pv

echo "== 指定版本按真实通道标注（测试版/正式版/查不到则指定版本） =="
# 用户预期：--version v3.1.1 应显示「测试版」而不是笼统的「指定版本」
rm -rf /tmp/fakebin_chan && mkdir -p /tmp/fakebin_chan
for _c in sed head awk grep cat; do ln -sf "$(command -v "$_c")" "/tmp/fakebin_chan/$_c"; done
cat > /tmp/fakebin_chan/curl <<'EOF'
#!/bin/bash
for a in "$@"; do
    case "$a" in
        */releases/tags/v3.1.1)  printf '%s\n' '{' '  "tag_name": "v3.1.1",' '  "prerelease": true,' '  "name": "v3.1.1 测试版 (beta)"' '}'; exit 0 ;;
        */releases/tags/v2.1.33) printf '%s\n' '{' '  "tag_name": "v2.1.33",' '  "prerelease": false,' '  "name": "v2.1.33 正式版"' '}'; exit 0 ;;
        */releases/tags/v9.9.9)  printf '%s\n' '{' '  "tag_name": "v9.9.9"' '}'; exit 0 ;;   # 没有 prerelease 字段
    esac
done
exit 1   # 其余一律当 404（无 release 的 tag / 网络失败）
EOF
chmod +x /tmp/fakebin_chan/curl
bash -c 'source '"$TMPF"'; PATH=/tmp/fakebin_chan
BETA=0
VERSION_TAG="v3.1.1";  SRC_TAG="";  resolve_src_tag
[ "$(target_channel_label)" = "测试版" ] && echo "  ✓ v3.1.1 → 测试版" || { echo "  ✗ v3.1.1 标注=[$(target_channel_label)]"; exit 1; }
out=$(print_banner); case "$out" in *"面板 v3.1.1（测试版）"*) echo "  ✓ 横幅: 面板 v3.1.1（测试版）" ;; *) echo "  ✗ 横幅不对: $out"; exit 1 ;; esac
VERSION_TAG="v2.1.33"; SRC_TAG="";  resolve_src_tag
[ "$(target_channel_label)" = "正式版" ] && echo "  ✓ v2.1.33 → 正式版" || { echo "  ✗ v2.1.33 标注=[$(target_channel_label)]"; exit 1; }
VERSION_TAG="v1.24.42"; SRC_TAG=""; resolve_src_tag
[ "$(target_channel_label)" = "指定版本" ] && echo "  ✓ 查不到 release 的 tag → 指定版本（回退）" || { echo "  ✗ 回退标注=[$(target_channel_label)]"; exit 1; }
VERSION_TAG="v9.9.9"; SRC_TAG="";   resolve_src_tag
[ "$(target_channel_label)" = "指定版本" ] && echo "  ✓ 响应里没有 prerelease 字段 → 指定版本（不猜）" || { echo "  ✗ =[$(target_channel_label)]"; exit 1; }
# 无网络时不得挂、不得影响安装（SRC_TAG 已由 --version 定死）
PATH=/nonexistent
VERSION_TAG="v3.1.1"; SRC_TAG=""; rc=0; resolve_src_tag >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 0 ] && [ "$SRC_TAG" = "v3.1.1" ] || { echo "  ✗ 无网络时解析失败 rc=$rc tag=[$SRC_TAG]"; exit 1; }
lbl=$(target_channel_label 2>/dev/null)
[ "$lbl" = "指定版本" ] && [ -n "$SRC_TAG" ] \
    && echo "  ✓ 无网络：标注回退「指定版本」，目标版本不受影响" \
    || { echo "  ✗ 无网络: label=[$lbl] tag=[$SRC_TAG]"; exit 1; }'
rm -rf /tmp/fakebin_chan

echo "== 交互菜单：三选项 / 版本号输入（自动补 v、格式校验、非法输入重问） =="
rm -rf /tmp/fakebin_menu && mkdir -p /tmp/fakebin_menu
for _c in bash sh sed head awk grep cat id uname dirname mktemp tee tail sort tr; do ln -sf "$(command -v "$_c")" "/tmp/fakebin_menu/$_c"; done
cat > /tmp/fakebin_menu/curl <<'EOF'
#!/bin/bash
for a in "$@"; do
    case "$a" in
        */releases/latest) printf '%s\n' '{' '  "tag_name": "v9.9.9",' '  "prerelease": false' '}'; exit 0 ;;
        */releases\?*)     printf '%s\n' '[' '  { "tag_name": "v9.9.10-beta", "prerelease": true }' ']'; exit 0 ;;
    esac
done
exit 1   # releases/tags/<tag> 一律当查不到
EOF
chmod +x /tmp/fakebin_menu/curl
# FW_MENU=1 让菜单从 stdin 读（真实管道模式走 /dev/tty，测试里用 stdin 喂输入）
menu_run() {
    printf '%s\n' "$1" | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp bash -c '
        source '"$TMPF"'
        ACTION=install; VERSION_TAG=""; BETA=0; YES=0
        interactive_channel_menu >/dev/null 2>&1
        printf "BETA=%s VERSION_TAG=%s" "$BETA" "$VERSION_TAG"'
}
chk_menu() { # $1=输入 $2=期望
    local got; got="$(menu_run "$1")"
    if [ "$got" = "$2" ]; then echo "  ✓ 输入[$(printf '%s' "$1" | tr '\n' '/')] → $got"
    else echo "  ✗ 输入[$(printf '%s' "$1" | tr '\n' '/')] 得到 [$got] 期望 [$2]"; FAIL=$((FAIL+1)); return 1; fi
}
chk_menu "1"               "BETA=0 VERSION_TAG="
chk_menu ""                "BETA=0 VERSION_TAG="        # 直接回车 = 正式版
chk_menu "2"               "BETA=1 VERSION_TAG="
chk_menu "3
3.1.1"                     "BETA=0 VERSION_TAG=3.1.1"   # 不用带 v
chk_menu "3
v3.1.1"                    "BETA=0 VERSION_TAG=3.1.1"   # 带了 v 也接受
chk_menu "3
abc
3.1.1"                     "BETA=0 VERSION_TAG=3.1.1"   # 格式错 → 重问
chk_menu "9
x
y"                        "BETA=0 VERSION_TAG="        # 乱填 3 次 → 按默认正式版
# 参数/开关给定时不得弹菜单（管道里喂的输入必须原封不动）
menu_skip() { # $1=已设变量赋值 $2=输入（注意 bash -c 的第一个位置参数是 $0，所以用环境变量传）
    printf '%s\n' "$2" | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp FW_SKIP_SETUP="$1" bash -c '
        source '"$TMPF"'
        ACTION=install; VERSION_TAG=""; BETA=0; YES=0
        eval "$FW_SKIP_SETUP"
        interactive_channel_menu >/dev/null 2>&1
        printf "BETA=%s VERSION_TAG=%s" "$BETA" "$VERSION_TAG"'
}
[ "$(menu_skip 'BETA=1' '3
9.9.9')" = "BETA=1 VERSION_TAG=" ] && ok "--beta 时跳过菜单（不吃 stdin）" || bad "--beta 时菜单没跳过"
[ "$(menu_skip 'VERSION_TAG=v1.2.3' '2')" = "BETA=0 VERSION_TAG=v1.2.3" ] && ok "--version 时跳过菜单" || bad "--version 时菜单没跳过"
[ "$(menu_skip 'YES=1' '2')" = "BETA=0 VERSION_TAG=" ] && ok "--yes 时跳过菜单" || bad "--yes 时菜单没跳过"
# 无控制终端（systemd/cron/CI）→ 不弹菜单、保持正式版默认，绝不阻塞
if command -v setsid >/dev/null 2>&1; then
    rc=0; setsid bash -c 'source '"$TMPF"'; unset FW_MENU; menu_can_read' >/dev/null 2>&1 || rc=$?
    [ "$rc" -ne 0 ] && ok "无终端时 menu_can_read 返回失败（→ 跳过菜单）" || bad "无终端时仍认为可读"
else
    echo "  （无 setsid，跳过无终端用例）"
fi
# 指定版本输错 3 次要明确报错退出（不静默继续）
rc=0; out=$(printf '3\nabc\nabc\nabc\n' | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp bash -c '
    source '"$TMPF"'; ACTION=install; VERSION_TAG=""; BETA=0; YES=0
    interactive_channel_menu' 2>&1) || rc=$?
[ "$rc" -ne 0 ] && case "$out" in *"版本号格式不对"*) ok "版本号错 3 次 → 报错退出（退出码 $rc）" ;; *) bad "报错文案缺失: $out" ;; esac \
    || bad "版本号错 3 次竟然退出码 0"
# 端到端：真脚本 + FW_MENU=1 + 选项 2 → 横幅必须是「目标版本 : 面板 v9.9.10-beta（最新测试版）」
out=$(printf '2\n' | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/root TERM=dumb bash "$SCRIPT" 2>&1 || true)
case "$out" in
    *"目标版本 : 面板 v9.9.10-beta（最新测试版）"*) ok "菜单选 2 端到端 → 目标版本 v9.9.10-beta（最新测试版）" ;;
    *) bad "端到端菜单失败: $(printf '%s' "$out" | head -8)" ;;
esac
# 4) 环境体检 / 5) 改密码 / 6) 卸载：用 stub 替换真实动作，只验证菜单分发与确认弹窗
menu_action() {  # $1=输入
    printf '%s\n' "$1" | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp bash -c '
        source '"$TMPF"'
        ACTION=install; VERSION_TAG=""; BETA=0; YES=0
        do_check() { echo "DO_CHECK_CALLED"; }
        do_change_password() { echo "DO_CHANGE_PW_CALLED"; }
        do_uninstall() { echo "DO_UNINSTALL_CALLED"; }
        do_show_login_info() { echo "DO_SHOW_INFO_CALLED"; }
        interactive_channel_menu
        echo "MENU_RETURNED BETA=$BETA VERSION_TAG=$VERSION_TAG"' 2>/dev/null
}
t4="$(menu_action 4)";  case "$t4" in *DO_CHECK_CALLED*) case "$t4" in *MENU_RETURNED*) bad "选 4 不该继续走安装" ;; *) ok "菜单 4) 环境体检 → 执行体检并退出（不走安装）" ;; esac ;; *) bad "选 4 未触发体检: $t4" ;; esac
t5="$(menu_action 5)";  case "$t5" in *DO_CHANGE_PW_CALLED*) case "$t5" in *MENU_RETURNED*) bad "选 5 不该继续走安装" ;; *) ok "菜单 5) 改密码 → 执行改密并退出" ;; esac ;; *) bad "选 5 未触发改密: $t5" ;; esac
t6y="$(menu_action '6
yes')"; case "$t6y" in *DO_UNINSTALL_CALLED*) case "$t6y" in *MENU_RETURNED*) bad "选 6 确认后不该继续走安装" ;; *) ok "菜单 6) 卸载 → 确认 yes 后执行卸载" ;; esac ;; *) bad "选 6+yes 未触发卸载: $t6y" ;; esac
t6n="$(menu_action '6
no')"; case "$t6n" in *DO_UNINSTALL_CALLED*) bad "选 6 输入 no 竟然还卸载了" ;; *) case "$t6n" in *MENU_RETURNED*) bad "取消卸载后不该继续安装" ;; *) ok "菜单 6) 卸载 → 未确认则取消，不做任何改动" ;; esac ;; esac
t7info="$(menu_action 7)"; case "$t7info" in *DO_SHOW_INFO_CALLED*) case "$t7info" in *MENU_RETURNED*) bad "选 7 不该继续走安装" ;; *) ok "菜单 7) 查看登录信息 → 展示并退出（不走安装）" ;; esac ;; *) bad "选 7 未触发登录信息展示: $t7info" ;; esac
t1="$(menu_action 1)"; case "$t1" in *MENU_RETURNED*) ok "菜单 1) 仍正常进入安装流程" ;; *) bad "选 1 未回到安装流程: $t1" ;; esac
t9="$(menu_action '9
9
9')"; case "$t9" in *MENU_RETURNED*) ok "乱填 3 次 → 按默认正式版继续安装" ;; *) bad "乱填后未回到安装流程: $t9" ;; esac

# 管道模式（curl | sudo bash）下 stdin 是脚本自身，菜单必须改走 /dev/tty —— 用 script 造 pty 模拟真实场景
if command -v script >/dev/null 2>&1; then
    probe="$(mktemp)"
    {
        echo "source $TMPF"
        echo 'ACTION=install; VERSION_TAG=""; BETA=0; YES=0'
        echo 'menu_can_read && echo "MENU_SRC=$MENU_SRC"'
        echo 'interactive_channel_menu >/dev/null 2>&1'
        echo 'echo "BETA=$BETA VERSION_TAG=$VERSION_TAG"'
    } > "$probe"
    out=$(printf '2\n' | env -i PATH=/tmp/fakebin_menu:/usr/bin HOME=/root TERM=dumb script -qec "cat $probe | bash" /dev/null 2>&1 || true)
    case "$out" in
        *MENU_SRC=tty*) case "$out" in
                            *"BETA=1"*) ok "管道模式：菜单走 /dev/tty 读到输入（pty 模拟，非 stdin）" ;;
                            *) bad "管道模式读到了 tty 但选项未生效: $out" ;;
                        esac ;;
        *) bad "管道模式菜单没走 /dev/tty: $out" ;;
    esac
    rm -f "$probe"
else
    echo "  （无 script 命令，跳过 pty 用例）"
fi
rm -rf /tmp/fakebin_menu

echo "== do_upgrade：正式版 2.1.33 选测试版 = 升级（不是跳过） =="
# 用户实测场景：机器上装的是正式版，菜单选「安装测试版」应升级过去而不是被防降级拦住
mkdir -p /tmp/fwupg-cur /tmp/fwupg-tmp
echo 'CURRENT_VERSION = "2.1.33"' > /tmp/fwupg-cur/panel.py
head -n -1 "$SCRIPT" | sed 's|readonly APP_DIR="/usr/local/lib/fwpanel"|readonly APP_DIR="/tmp/fwupg-cur"|' > /tmp/install_funcs_ug.sh
mkdir -p /tmp/fwupg-cwd        # 受控工作目录：升级不得在 CWD 造垃圾文件
( cd /tmp/fwupg-cwd && bash -c '
source /tmp/install_funcs_ug.sh
VERSION_TAG=""; BETA=1; SRC_TAG="v9.9.9"
curl() {   # 只让 panel.py 下载成功（内容 3.2.13），其余文件下载失败走 warn 分支
  if [[ "$*" == *"/panel.py"* && "$*" == *"-o"* ]]; then
    printf "#!/usr/bin/env python3\nCURRENT_VERSION = \"3.2.13\"\n" > "$(echo "$*" | grep -oP "(?<=-o )\S+")"
    return 0
  fi
  return 1
}
mktemp() { echo /tmp/fwupg-tmp; }
systemctl() { return 0; }
out=$(do_upgrade 2>&1)
echo "$out" | grep -q "升级 v2.1.33 → v3.2.13" && echo "  ✓ 正式版 → 测试版 走「升级」（v2.1.33 → v3.2.13）" || { echo "  ✗ 未升级: $out"; exit 1; }
grep -q "3.2.13" /tmp/fwupg-cur/panel.py && echo "  ✓ 磁盘 panel.py 已变成 3.2.13" || { echo "  ✗ 磁盘未更新"; exit 1; }
ls /tmp/fwupg-cur/panel.py.bak.* >/dev/null 2>&1 && echo "  ✓ 升级前已备份旧版本（可回滚）" || { echo "  ✗ 没有备份"; exit 1; }
[ -e bash ] && { echo "  ✗ CWD 里被写入了垃圾文件 bash"; exit 1; } || echo "  ✓ 管道模式不会在 CWD 造出名为 bash 的垃圾文件（\$0 非实体文件时跳过）"
' )
rm -rf /tmp/fwupg-cur /tmp/fwupg-tmp /tmp/fwupg-cwd /tmp/install_funcs_ug.sh

echo "== 首次安装：自定义凭据询问（yes 自定义 / no 随机） =="
# FW_MENU=1 让 prompt_read 从 stdin 读；真实场景由 menu_can_read 决定 /dev/tty 或 stdin
rm -rf /tmp/fakebin_cred && mkdir -p /tmp/fakebin_cred
ln -sf "$(command -v bash)" /tmp/fakebin_cred/bash
cred_run() {  # $1=输入（多行）
    printf '%s\n' "$1" | env -i PATH=/tmp/fakebin_cred FW_MENU=1 HOME=/tmp bash -c '
        source '"$TMPF"'
        ACTION=install; YES=0; PANEL_USER=""; PANEL_PASS=""; MENU_SRC=""
        ask_custom_credentials >/dev/null 2>&1
        printf "USER=[%s] PASS=[%s]" "$PANEL_USER" "$PANEL_PASS"'
}
cred_rc() {   # 同上，但只返回退出码（错误路径用）
    printf '%s\n' "$1" | env -i PATH=/tmp/fakebin_cred FW_MENU=1 HOME=/tmp bash -c '
        source '"$TMPF"'
        ACTION=install; YES=0; PANEL_USER=""; PANEL_PASS=""; MENU_SRC=""
        ask_custom_credentials' >/dev/null 2>&1
}
[ "$(cred_run '')" = "USER=[] PASS=[]" ] && ok "直接回车 → 不自行设定（走随机）" || bad "回车应答后仍写了凭据"
[ "$(cred_run 'no')" = "USER=[] PASS=[]" ] && ok "选 no → 随机生成" || bad "选 no 竟然自行设定"
[ "$(cred_run 'yes
admin
admin
MyPass1234
MyPass1234')" = "USER=[admin] PASS=[MyPass1234]" ] && ok "选 yes → 用户名+密码各两次确认后生效" || bad "yes 路径凭据未生效"
[ "$(cred_run 'y
adm_1
adm_1
longpassword
longpassword')" = "USER=[adm_1] PASS=[longpassword]" ] && ok "y 也认；下划线用户名可用" || bad "y 路径异常"
[ "$(cred_run 'yes
admin
adminx
admin
admin
pw12345678
pw12345678')" = "USER=[admin] PASS=[pw12345678]" ] && ok "用户名两次不一致 → 重问后可成功" || bad "用户名不一致未重问"
[ "$(cred_run 'yes
a
admin
admin
short
pw12345678
pw12345678')" = "USER=[admin] PASS=[pw12345678]" ] && ok "用户名过短 → 重问；密码过短也重问" || bad "非法值未重问"
for setup in 'YES=1' 'PANEL_USER=envuser' 'PANEL_PASS=EnvPass123' 'ACTION=check'; do
    got=$(printf 'yes\nadmin\nadmin\nMyPass1234\nMyPass1234\n' | env -i PATH=/tmp/fakebin_cred FW_MENU=1 HOME=/tmp FW_SETUP="$setup" bash -c '
        source '"$TMPF"'
        ACTION=install; YES=0; PANEL_USER=""; PANEL_PASS=""; MENU_SRC=""
        eval "$FW_SETUP"
        ask_custom_credentials >/dev/null 2>&1
        printf "USER=[%s] PASS=[%s]" "$PANEL_USER" "$PANEL_PASS"' 2>/dev/null)
    case "$setup" in
        YES=1)                 [ "$got" = "USER=[] PASS=[]" ] && ok "-y 时跳过凭据询问" || bad "-y 时仍在问: $got" ;;
        PANEL_USER=envuser)    [ "$got" = "USER=[envuser] PASS=[]" ] && ok "--user 已给时不再询问" || bad "--user 时异常: $got" ;;
        PANEL_PASS=EnvPass123) [ "$got" = "USER=[] PASS=[EnvPass123]" ] && ok "--password 已给时不再询问" || bad "--password 时异常: $got" ;;
        ACTION=check)          [ "$got" = "USER=[] PASS=[]" ] && ok "非安装动作（体检等）不询问" || bad "非安装动作仍在问: $got" ;;
    esac
done
cred_rc 'yes
a
b
c
d
e
f' && bad "用户名错 3 次竟然成功退出" || ok "用户名错 3 次 → 报错退出"

# 走 /dev/tty + 密码不回显（script 造 pty；故意不设 FW_MENU，验证真实交互路径）
# ⚠ 密码必须「隔一会儿再送」：把整段输入一次性塞进 pty 时，输入在 read -s 生效前就已被终端回显，
#   那是测试方法的假象，不是代码问题
if command -v script >/dev/null 2>&1; then
    probe="$(mktemp)"
    { echo "source $TMPF"
      echo 'ACTION=install; YES=0; PANEL_USER=""; PANEL_PASS=""; MENU_SRC=""'
      echo 'ask_custom_credentials >/dev/null 2>&1'
      echo 'echo "USER=[$PANEL_USER] PASS=[$PANEL_PASS] MENU_SRC=$MENU_SRC"'; } > "$probe"
    out=$({ printf 'yes\nadmin\nadmin\n'; sleep 1.5; printf 'Secret12345\n'; sleep 1.5; printf 'Secret12345\n'; } \
        | env -i PATH=/tmp/fakebin_menu:/usr/bin HOME=/root TERM=dumb script -qec "cat $probe | bash" /dev/null 2>&1 || true)
    case "$out" in
        *"MENU_SRC=tty"*) case "$out" in
                              *"PASS=[Secret12345]"*) ok "pty 真实交互：走 /dev/tty 且凭据生效" ;;
                              *) bad "pty 凭据未生效: $out" ;;
                          esac ;;
        *) bad "pty 场景未走 /dev/tty: $out" ;;
    esac
    n=$(printf '%s' "$out" | grep -o "Secret12345" | wc -l)
    [ "$n" -eq 1 ] && ok "pty 真实交互：密码输入不回显（全文只出现 1 次=脚本自身回显）" \
        || bad "密码被回显（出现 $n 次，应为 1）"
    rm -f "$probe"
fi

rm -rf /tmp/fakebin_cred

echo "== 菜单 7) 查看登录信息：地址/反代域名/用户名/密码（含缺失凭据记录的情况） =="
rm -rf /tmp/fwinfo && mkdir -p /tmp/fwinfo/etc
cat > /tmp/fwinfo/etc/config.json <<'EOF'
{"port": 17890, "bind": "0.0.0.0", "username": "jackson", "mode": "strict"}
EOF
cat > /tmp/fwinfo/etc/credentials.json <<'EOF'
{"username": "jackson", "password": "MyPanel2026", "updated_at": "2026-09-16 20:30:00"}
EOF
cat > /tmp/fwinfo/etc/proxies.json <<'EOF'
[{"domain": "sg1panel.isusz.com", "target_port": 17890, "ssl": false, "cert_ref": "sg1panel.isusz.com"}]
EOF
head -n -1 "$SCRIPT" | sed 's|readonly ETC_DIR="/etc/fwpanel"|readonly ETC_DIR="/tmp/fwinfo/etc"|' > /tmp/fwinfo/install_info.sh
infoline() {  # $1=要匹配的片段 $2=说明
    local out="$3"
    case "$out" in *"$1"*) ok "$2" ;; *) bad "$2 —— 输出里没有「$1」: $(printf '%s' "$out" | tail -8)" ;; esac
}
out=$(env -i PATH=/usr/bin:/bin HOME=/root bash -c 'source /tmp/fwinfo/install_info.sh; check_root() { return 0; }; do_show_login_info' 2>&1)
infoline ":17890" "显示面板地址（含端口）" "$out"
infoline "反代地址 : https://sg1panel.isusz.com" "显示反代域名（cert_ref 复用证书 → https）" "$out"
infoline "用户名   : jackson" "显示用户名" "$out"
infoline "密码     : MyPanel2026" "显示密码（来自本机 credentials.json）" "$out"
# 没有凭据记录时必须说清楚（老版本装的机器），并给出可行指引
rm -f /tmp/fwinfo/etc/credentials.json
out2=$(env -i PATH=/usr/bin:/bin HOME=/root bash -c 'source /tmp/fwinfo/install_info.sh; check_root() { return 0; }; do_show_login_info' 2>&1)
infoline "未记录明文" "无凭据记录时说明密码不可反查" "$out2"
infoline "菜单 5) 修改用户名和密码" "无凭据记录时指向菜单 5" "$out2"
# 该功能需要 root：check_root 必须被调用
grep -q "do_show_login_info() {" /tmp/fwinfo/install_info.sh &&     sed -n '/^do_show_login_info()/,/^}/p' /tmp/fwinfo/install_info.sh | head -3 | grep -q "check_root" \
    && ok "查看登录信息前先 check_root（需 root 权限）" || bad "缺少 check_root 保护"
rm -rf /tmp/fwinfo

echo "== 安装摘要文案：管道模式不得印出「sudo bash bash …」 =="
sum_pipe=$(bash -c 'source '"$TMPF"'
    PANEL_BIND=0.0.0.0; PANEL_PORT=17890; PANEL_USER=admin; PANEL_PASS=GzPass2026
    print_summary' 2>&1 || true)
case "$sum_pipe" in
    *"bash bash"*) bad "管道模式摘要印出了不可用的命令（bash bash）" ;;
    *"菜单选 5) 改用户名密码"*) ok "管道模式摘要给出的是可照做的指引（菜单选 5 / 重跑一键命令）" ;;
    *) bad "管道模式摘要缺少改凭据指引: $(printf '%s' "$sum_pipe" | tail -6)" ;;
esac
# 实体脚本模式（$0 是文件）应引用脚本自身路径
sum_file=$(cat > /tmp/fw_sum_probe.sh <<EOF
source $TMPF
PANEL_BIND=0.0.0.0; PANEL_PORT=17890; PANEL_USER=admin; PANEL_PASS=GzPass2026
print_summary
EOF
bash /tmp/fw_sum_probe.sh 2>&1 || true)
case "$sum_file" in
    *"/tmp/fw_sum_probe.sh --change-password"*) ok "实体脚本模式摘要引用 \$0 路径（可照抄执行）" ;;
    *) bad "实体脚本模式摘要异常: $(printf '%s' "$sum_file" | tail -6)" ;;
esac
rm -f /tmp/fw_sum_probe.sh

echo "============================================"
echo "结果: $PASS 通过, $FAIL 失败"
rm -f "$TMPF" /tmp/install_funcs_fw.sh
exit $FAIL
