#!/usr/bin/env bash
# install.sh 函数级单元测试（提取函数源码后 source，不触发 main）
set -u
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/install.sh"
TMPF=$(mktemp)
head -n -1 "$SCRIPT" \
    | sed -e 's|^readonly WRAPPER_PATH="/usr/local/bin/fwp"|readonly WRAPPER_PATH="/tmp/fwtest/bin/fwp"|' \
          -e 's|^readonly APP_DIR="/usr/local/lib/fwpanel"|readonly APP_DIR="/tmp/fwtest/app"|' \
    > "$TMPF"      # 去掉最后一行 main "$@"；并把会落盘的真实路径换成临时路径
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
# curl 必须用「可执行桩 + PATH」，不能用 shell 函数：do_upgrade 的下载现在经过
# run_with_timeout（timeout 是外部命令），函数桩会被绕过而真的联网
mkdir -p /tmp/fakebin_dg
cat > /tmp/fakebin_dg/curl <<'DGCURL'
#!/bin/bash
if [[ "$*" == *"/panel.py"* && "$*" == *"-o"* ]]; then
    printf '#!/usr/bin/env python3\nCURRENT_VERSION = "1.23.19"\n' > "$(echo "$*" | grep -oP '(?<=-o )\S+')"
    exit 0
fi
exit 1
DGCURL
chmod +x /tmp/fakebin_dg/curl
bash -c 'source /tmp/install_funcs_dg.sh
mktemp() { echo /tmp/fwpanel-dg-tmp; }
out=$(PATH=/tmp/fakebin_dg:$PATH do_upgrade 2>&1)
if echo "$out" | grep -q "不降级"; then echo "  ✓ 防降级生效（1.23.20 ≥ 1.23.19 跳过）"; else echo "  ✗ $out"; exit 1; fi'
rm -f /tmp/install_funcs_dg.sh
rm -rf /tmp/fwpanel-dg-cur /tmp/fwpanel-dg-tmp /tmp/fakebin_dg

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
# 乱填只提示重问（不再"连错 3 次就按默认装正式版"——循环菜单里那等于强行安装）；
# 输入耗尽(EOF)后干净退出，BETA 保持默认
chk_menu "x
y
z"                        "BETA=0 VERSION_TAG="
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
# 4/5/6/7 执行完要回到主菜单；8) 退出；1/2/3 进入安装流程
menu_case() {  # $1=输入 → 输出原文（含 stub 调用标记）
    printf '%s\n' "$1" | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp bash -c '
        source '"$TMPF"'
        ACTION=install; VERSION_TAG=""; BETA=0; YES=0; MENU_SRC=""
        do_check() { echo "DO_CHECK_CALLED"; }
        do_change_password() { echo "DO_CHANGE_PW_CALLED"; }
        do_uninstall() { echo "DO_UNINSTALL_CALLED"; }
        do_show_login_info() { echo "DO_SHOW_INFO_CALLED"; }
        do_update_script() { echo "DO_UPDATE_SCRIPT_CALLED"; }
        interactive_channel_menu
        echo "MENU_RETURNED BETA=$BETA VERSION_TAG=$VERSION_TAG"' 2>&1
}
menu_draws() { printf '%s' "$1" | grep -c "请选择要执行的操作" || true; }
menu_has()  { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

out="$(menu_case '4
8')"
menu_has DO_CHECK_CALLED "$out" && [ "$(menu_draws "$out")" -eq 2 ] \
    && ok "4) 体检执行后返回主菜单（菜单重画 2 次）" || bad "4) 未返回菜单: $(printf '%s' "$out" | head -5)"
menu_has MENU_RETURNED "$out" && bad "选 8 退出后不该继续安装" || ok "8) 退出脚本（不再安装）"

out="$(menu_case '5
8')"
menu_has DO_CHANGE_PW_CALLED "$out" && [ "$(menu_draws "$out")" -eq 2 ] \
    && ok "5) 改凭据后返回主菜单" || bad "5) 未返回菜单"
out="$(menu_case '7
8')"
menu_has DO_SHOW_INFO_CALLED "$out" && [ "$(menu_draws "$out")" -eq 2 ] \
    && ok "7) 查看信息后返回主菜单" || bad "7) 未返回菜单"

out="$(menu_case '9
8')"
menu_has DO_UPDATE_SCRIPT_CALLED "$out" && [ "$(menu_draws "$out")" -eq 2 ] \
    && ok "9) 升级脚本执行后返回主菜单（版本没变时不重启菜单）" || bad "9) 未返回菜单"

# 2.34：9 升级脚本 → 缓存拿到新版本时要立刻用新脚本重开菜单（不用再手动敲 fwp）
mkdir -p /tmp/fwtest/app
cat > /tmp/fwtest/fake_new_script.sh <<'EOF_NEW'
#!/usr/bin/env bash
readonly SCRIPT_VERSION="9.9.9"
echo "NEW_SCRIPT_RAN args=[$*]"
EOF_NEW
chmod 0755 /tmp/fwtest/fake_new_script.sh
menu_case_script() {  # do_update_script 会真的把"新脚本"写进缓存
    printf '%s\n' "$1" | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp bash -c '
        source '"$TMPF"'
        ACTION=install; VERSION_TAG=""; BETA=0; YES=0; MENU_SRC=""
        do_update_script() { cat /tmp/fwtest/fake_new_script.sh > "$APP_DIR/$CACHED_SCRIPT_NAME" && return 0; }
        interactive_channel_menu
        echo "MENU_RETURNED"' 2>&1
}
out="$(menu_case_script '9')"
menu_has "NEW_SCRIPT_RAN" "$out" && menu_has "MENU_RETURNED" "$out" && bad "9) 更新后竟然没换脚本" \
    || { menu_has "NEW_SCRIPT_RAN" "$out" && ok "9) 脚本更新后立刻用新脚本重开（无需再敲 fwp）" || bad "9) 没重开新脚本: $(printf '%s' "$out" | tail -3)"; }

out="$(menu_case_script '10
2')"
menu_has "NEW_SCRIPT_RAN args=[--beta]" "$out" && ok "10) 升级脚本+面板：先更新脚本，再以 --beta 跑最新脚本" \
    || bad "10) 未按预期执行: $(printf '%s' "$out" | tail -3)"
out="$(menu_case_script '10
1')"
menu_has "NEW_SCRIPT_RAN args=[]" "$out" && ok "10) 选 1 正式版：不带 --beta 跑最新脚本" \
    || bad "10) 正式版分支异常: $(printf '%s' "$out" | tail -3)"

out="$(menu_case '10
8' 2>/dev/null || true)"
menu_has "请输入 1 - 10" "$out" && ok "菜单提示为「请输入 1 - 10」" || bad "菜单提示未更新"
menu_has "10) 升级脚本+面板" "$out" && ok "菜单里有 10) 升级脚本+面板" || bad "菜单缺少第 10 项"
menu_has "9) 升级脚本" "$out" && ok "第 9 项已改名「升级脚本」" || bad "第 9 项文案未更新"
# 线上最新版比本地脚本新 → 头部直接提示（省得用户自己去想"要不要更新脚本"）
menu_has "脚本有新版" "$out" && ok "脚本落后时菜单直接提示「脚本有新版」" || bad "缺少脚本版本提示"
# 本地脚本已是最新时不该乱提示
out="$(printf '8\n' | env -i PATH=/tmp/fakebin_menu FW_MENU=1 HOME=/tmp bash -c '
    source '"$TMPF"'
    SCRIPT_VERSION="99.0.0"
    ACTION=install; VERSION_TAG=""; BETA=0; YES=0; MENU_SRC=""
    do_show_login_info() { :; }
    interactive_channel_menu' 2>&1 || true)"
menu_has "脚本有新版" "$out" && bad "脚本已最新却仍提示有新版" || ok "脚本已最新时不提示"

echo "== version_gt：脚本版本比较 =="
vg() { ( source "$TMPF"; version_gt "$1" "$2" ) && echo 1 || echo 0; }
[ "$(vg 3.2.34 3.2.33)" = "1" ] && ok "3.2.34 > 3.2.33" || bad "版本比较错(1)"
[ "$(vg 3.2.33 3.2.34)" = "0" ] && ok "3.2.33 不大于 3.2.34" || bad "版本比较错(2)"
[ "$(vg 2.1.33 2.1.9)" = "1" ] && ok "2.1.33 > 2.1.9（不会按字符串比错）" || bad "版本比较错(3)"
[ "$(vg 3.2.34 3.2.34)" = "0" ] && ok "相等不算更新" || bad "版本比较错(4)"
rm -f /tmp/fwtest/fake_new_script.sh
rm -f /tmp/fwtest/app/install.sh    # 别把假缓存留给后面的用例（会造成 9) 意外 exec 新脚本）
out="$(menu_case '6
yes
8')"
menu_has DO_UNINSTALL_CALLED "$out" && [ "$(menu_draws "$out")" -eq 2 ] \
    && ok "6) 确认 yes 后卸载并返回主菜单" || bad "6)+yes 异常"
out="$(menu_case '6
no
8')"
menu_has DO_UNINSTALL_CALLED "$out" && bad "6) 输入 no 竟然还卸载" \
    || { [ "$(menu_draws "$out")" -eq 2 ] && ok "6) 输入 no 取消卸载并返回主菜单" || bad "6) 取消后未返回菜单"; }

out="$(menu_case '1')"
menu_has "MENU_RETURNED BETA=0 VERSION_TAG=" "$out" && ok "1) 进入安装流程（正式版）" || bad "1) 异常: $out"
out="$(menu_case '2')"
menu_has "MENU_RETURNED BETA=1" "$out" && ok "2) 进入安装流程（测试版）" || bad "2) 异常: $out"
out="$(menu_case '')"
menu_has "MENU_RETURNED BETA=0" "$out" && ok "直接回车 = 1 安装正式版" || bad "回车默认异常"
out="$(menu_case '3
3.1.1')"
menu_has "MENU_RETURNED BETA=0 VERSION_TAG=3.1.1" "$out" && ok "3) 指定版本进入安装流程" || bad "3) 异常: $out"
out="$(menu_case '3

1')"
menu_has "MENU_RETURNED BETA=0 VERSION_TAG=" "$out" && ok "3) 版本号直接回车 → 返回主菜单（不再卡死）" || bad "3) 回车返回异常"
out="$(menu_case '9
9
1')"
menu_has "MENU_RETURNED BETA=0" "$out" && [ "$(menu_draws "$out")" -ge 3 ] \
    && ok "乱填只提示重问，不会强制按默认安装（连问 3 次后仍等输入）" || bad "乱填处理异常"

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
mkdir -p /tmp/fwupg-sd         # systemd 单元目录也隔离（FW_SYSTEMD_DIR），不写真 /etc
# curl 桩必须是「可执行文件 + PATH」：do_upgrade 的下载走 run_with_timeout（timeout 是外部命令），
# shell 函数桩会被绕过而真的联网
mkdir -p /tmp/fakebin_ug
cat > /tmp/fakebin_ug/curl <<'UGCURL'
#!/bin/bash
# 只让 panel.py 下载成功（内容 3.2.13），其余文件下载失败走 warn 分支
if [[ "$*" == *"/panel.py"* && "$*" == *"-o"* ]]; then
    printf '#!/usr/bin/env python3\nCURRENT_VERSION = "3.2.13"\n' > "$(echo "$*" | grep -oP '(?<=-o )\S+')"
    exit 0
fi
exit 1
UGCURL
chmod +x /tmp/fakebin_ug/curl
# 用脚本文件而不是 inline bash -c：嵌套多行命令在某些沙箱/终端监控下会被直接 SIGTERM（实测）
cat > /tmp/fwupg-inner.sh <<'UGINNER'
source /tmp/install_funcs_ug.sh
VERSION_TAG=""; BETA=1; SRC_TAG="v9.9.9"
mktemp() { echo /tmp/fwupg-tmp; }
systemctl() { return 0; }
out=$(do_upgrade 2>&1)
echo "$out" | grep -q "升级 v2.1.33 → v3.2.13" && echo "  ✓ 正式版 → 测试版 走「升级」（v2.1.33 → v3.2.13）" || { echo "  ✗ 未升级: $out"; exit 1; }
grep -q "3.2.13" /tmp/fwupg-cur/panel.py && echo "  ✓ 磁盘 panel.py 已变成 3.2.13" || { echo "  ✗ 磁盘未更新"; exit 1; }
ls /tmp/fwupg-cur/panel.py.bak.* >/dev/null 2>&1 && echo "  ✓ 升级前已备份旧版本（可回滚）" || { echo "  ✗ 没有备份"; exit 1; }
[ -e bash ] && { echo "  ✗ CWD 里被写入了垃圾文件 bash"; exit 1; } || echo "  ✓ 管道模式不会在 CWD 造出名为 bash 的垃圾文件（\$0 非实体文件时跳过）"
UGINNER
( cd /tmp/fwupg-cwd && PATH=/tmp/fakebin_ug:$PATH FW_SYSTEMD_DIR=/tmp/fwupg-sd bash /tmp/fwupg-inner.sh )
rm -rf /tmp/fwupg-cur /tmp/fwupg-tmp /tmp/fwupg-cwd /tmp/fwupg-sd /tmp/install_funcs_ug.sh /tmp/fakebin_ug /tmp/fwupg-inner.sh

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

echo "== 菜单 7) 查看登录信息：只显示地址/用户名，密码只能重设（不保存明文） =="
rm -rf /tmp/fwinfo && mkdir -p /tmp/fwinfo/etc
cat > /tmp/fwinfo/etc/config.json <<'EOF'
{"port": 17890, "bind": "0.0.0.0", "username": "jackson", "mode": "strict"}
EOF
cat > /tmp/fwinfo/etc/proxies.json <<'EOF'
[{"domain": "sg1panel.isusz.com", "target_port": 17890, "ssl": false, "cert_ref": "sg1panel.isusz.com"}]
EOF
# 旧版本（v3.2.16/17）留下的明文凭据文件：重跑脚本必须清理掉
cat > /tmp/fwinfo/etc/credentials.json <<'EOF'
{"username": "jackson", "password": "ShouldBeDeleted", "updated_at": "2026-09-16 20:30:00"}
EOF
head -n -1 "$SCRIPT" | sed 's|readonly ETC_DIR="/etc/fwpanel"|readonly ETC_DIR="/tmp/fwinfo/etc"|' > /tmp/fwinfo/install_info.sh
infoline() {  # $1=匹配片段 $2=说明 $3=输出
    local out="$3"
    case "$out" in *"$1"*) ok "$2" ;; *) bad "$2 —— 输出里没有「$1」: $(printf '%s' "$out" | tail -8)" ;; esac
}
# 直接回车：只看信息，返回
out=$(printf '\n' | env -i PATH=/usr/bin:/bin HOME=/root FW_MENU=1 bash -c 'source /tmp/fwinfo/install_info.sh; check_root() { return 0; }; do_show_login_info' 2>&1)
infoline ":17890" "显示面板地址（含端口）" "$out"
infoline "反代地址 : https://sg1panel.isusz.com" "显示反代域名（cert_ref 复用证书 → https）" "$out"
infoline "用户名   : jackson" "显示用户名" "$out"
infoline "不保存明文" "密码栏说明不保存明文、无法反查" "$out"
infoline "按 r 回车" "给出重设入口（等同菜单 5）" "$out"
case "$out" in *ShouldBeDeleted*) bad "竟然把旧版留下的明文密码显示出来了" ;; *) ok "不显示任何明文密码" ;; esac
# 输入 r → 进入重设流程（用 stub 断言分发）
out_r=$(printf 'r\n' | env -i PATH=/usr/bin:/bin HOME=/root FW_MENU=1 bash -c 'source /tmp/fwinfo/install_info.sh; check_root() { return 0; }; do_change_password() { echo "DO_CHANGE_PW_CALLED"; }; do_show_login_info' 2>&1)
case "$out_r" in *DO_CHANGE_PW_CALLED*) ok "输入 r → 直接进入重设流程（不用回菜单）" ;; *) bad "r 入口未生效: $out_r" ;; esac
# 清理旧版遗留的明文凭据文件（函数本身 + 「查看信息」这条真实路径都要清）
cat > /tmp/fwinfo/etc/credentials.json <<'EOF'
{"username": "jackson", "password": "ShouldBeDeleted", "updated_at": "2026-09-16 20:30:00"}
EOF
env -i PATH=/usr/bin:/bin HOME=/root bash -c 'source /tmp/fwinfo/install_info.sh; cleanup_plaintext_credentials' >/dev/null 2>&1
[ -f /tmp/fwinfo/etc/credentials.json ] && bad "旧版明文凭据文件没被清理" || ok "cleanup_plaintext_credentials 会删除旧版遗留文件"
cat > /tmp/fwinfo/etc/credentials.json <<'EOF'
{"username": "jackson", "password": "ShouldBeDeleted", "updated_at": "2026-09-16 20:30:00"}
EOF
printf '\n' | env -i PATH=/usr/bin:/bin HOME=/root FW_MENU=1 bash -c 'source /tmp/fwinfo/install_info.sh; check_root() { return 0; }; do_show_login_info' >/dev/null 2>&1
[ -f /tmp/fwinfo/etc/credentials.json ] && bad "「查看登录信息」路径没有清理旧版明文凭据文件" || ok "「查看登录信息」路径也会清理旧版明文凭据文件"
# 该功能需要 root
sed -n '/^do_show_login_info()/,/^}/p' /tmp/fwinfo/install_info.sh | head -3 | grep -q "check_root" \
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

echo "== 菜单预览查询必须带 4 秒硬超时（网络黑洞时菜单不能被拖住）=="
grep -q "run_with_timeout 4 curl" <(sed -n '/^menu_preview_tag() {/,/^}/p' "$SCRIPT") \
    && ok "menu_preview_tag 用 run_with_timeout 4（不再是 12 秒 × 2 次）" || bad "预览查询缺少硬超时"
grep -q "网络不通会自动跳过" "$SCRIPT" && ok "菜单先给出可见的查询提示（不是黑屏干等）" || bad "菜单没有查询提示"

echo "== 原子落盘：升级时不会让面板读到半截 index.html =="
mkdir -p /tmp/fwatom/dst
python3 - <<'PYEOF'
open("/tmp/fwatom/old.html","w").write("OLD" * 200000)
open("/tmp/fwatom/new.html","w").write("NEW" * 200000)
PYEOF
printf 'old-content\n' > /tmp/fwatom/dst/index.html
atomic_put /tmp/fwatom/new.html /tmp/fwatom/dst/index.html 644
cmp -s /tmp/fwatom/dst/index.html /tmp/fwatom/new.html \
    && ok "atomic_put 完成内容替换" || bad "atomic_put 内容不对"
[ "$(stat -c %a /tmp/fwatom/dst/index.html)" = "644" ] && ok "atomic_put 设置了权限 644" || bad "权限不对"
ls /tmp/fwatom/dst/.index.html.new.* >/dev/null 2>&1 && bad "atomic_put 留下临时文件垃圾" || ok "atomic_put 不留临时文件"
# 关键性质：替换过程中并发读取，只能读到"完整旧版"或"完整新版"，绝不会有半截
( for i in $(seq 1 400); do md5sum /tmp/fwatom/dst/index.html 2>/dev/null | awk '{print $1}'; done > /tmp/fwatom/seen.txt ) &
reader=$!
for i in $(seq 1 12); do atomic_put /tmp/fwatom/new.html /tmp/fwatom/dst/index.html 644; done
wait $reader
old_md5=$(md5sum /tmp/fwatom/old.html | awk '{print $1}')
new_md5=$(md5sum /tmp/fwatom/new.html | awk '{print $1}')
bad_reads=$(grep -vc -e "^$old_md5$" -e "^$new_md5$" /tmp/fwatom/seen.txt || true)
[ "$bad_reads" = "0" ] && ok "并发读取 400 次全部是完整文件（原子替换生效）" \
    || bad "有 $bad_reads 次读到半截文件"
# 对照：原来的 cp 覆盖方式会读到半截（证明这个修复不是想当然）
( for i in $(seq 1 400); do md5sum /tmp/fwatom/dst/index.html 2>/dev/null | awk '{print $1}'; done > /tmp/fwatom/seen_cp.txt ) &
reader=$!
for i in $(seq 1 12); do cp /tmp/fwatom/new.html /tmp/fwatom/dst/index.html; done
wait $reader
cp_bad=$(grep -vc -e "^$old_md5$" -e "^$new_md5$" /tmp/fwatom/seen_cp.txt || true)
echo "    （对照）旧写法 cp 覆盖时读到半截的次数: $cp_bad"
rm -rf /tmp/fwatom

echo "== install.sh 部署静态文件必须走原子替换 =="
grep -q 'cp "$tmpdir/index.html" "$APP_DIR/static/index.html"' "$SCRIPT" \
    && bad "升级路径仍是 cp 直接覆盖（会产生半截文件）" || ok "升级路径已改为原子替换"
grep -q 'install -m 644 "$src_html" "$APP_DIR/static/index.html"' "$SCRIPT" \
    && bad "deploy_files 仍是 install 直接覆盖" || ok "deploy_files 已改为原子替换"
grep -q 'atomic_put "$src_html" "$APP_DIR/static/index.html" 644' "$SCRIPT" \
    && ok "index.html 走 atomic_put" || bad "index.html 没走 atomic_put"

echo "== run_with_timeout：硬超时能杀掉卡死进程（网络黑洞场景）=="
cat > /tmp/fwtest_hang.sh <<'HEOF'
#!/bin/sh
sleep 600
HEOF
chmod +x /tmp/fwtest_hang.sh
t0=$(date +%s)
rc=0; run_with_timeout 2 /tmp/fwtest_hang.sh || rc=$?   # 注意：脚本带着 set -e，失败必须显式接住
t1=$(date +%s)
[ "$rc" = "124" ] && [ $((t1 - t0)) -le 5 ] \
    && ok "卡死命令被硬超时杀掉（rc=124，耗时 $((t1 - t0))s）" || bad "硬超时失效 rc=$rc 耗时 $((t1 - t0))s"
rc=0; out=$(run_with_timeout 5 sh -c 'echo hi; exit 3') || rc=$?
[ "$out" = "hi" ] && [ "$rc" = "3" ] && ok "正常命令透传输出与退出码" || bad "正常命令被影响 out=$out rc=$rc"

echo "== 快捷命令 fwp：缓存脚本 + 生成包装器 =="
rm -rf /tmp/fwtest; mkdir -p /tmp/fwtest/bin /tmp/fwtest/app
# ① 实体脚本方式（$0 是文件）→ 缓存直接复制自身
env -i PATH=/usr/bin:/bin HOME=/tmp bash -c 'source "$0"; install_shortcut' "$TMPF" >/dev/null 2>&1
[ -s /tmp/fwtest/app/install.sh ] && ok "缓存脚本已生成: /tmp/fwtest/app/install.sh" || bad "缓存脚本没生成"
grep -q "SCRIPT_VERSION=" /tmp/fwtest/app/install.sh && ok "缓存内容可识别（含 SCRIPT_VERSION）" || bad "缓存内容异常"
[ -x /tmp/fwtest/bin/fwp ] && ok "包装器已生成且可执行: /tmp/fwtest/bin/fwp" || bad "包装器没生成/不可执行"
sh -n /tmp/fwtest/bin/fwp 2>/dev/null && ok "包装器语法通过（POSIX sh）" || bad "包装器语法错误"
# ⚠ 用户实测 bug 回归：包装器启动时的静默刷新，碰上网络被黑洞（DNS 卡死）就是一片空白 + 永久卡住
if awk '/^if \[ ! -s "\$CACHE" \]/{g=1} /curl|wget/ && !g{print "EARLY:" $0; exit 1}' /tmp/fwtest/bin/fwp >/tmp/fwtest/early.out; then
    ok "显示菜单前绝不联网（缓存缺失时才联网，且有硬超时）"
else bad "包装器在显示菜单前就会联网（网络卡死时会永久卡住）：$(cat /tmp/fwtest/early.out)"; fi
grep -q 'CACHE="/tmp/fwtest/app/install.sh"' /tmp/fwtest/bin/fwp && ok "包装器里缓存路径已正确展开（占位符已替换）" || bad "包装器缓存路径未展开"
grep -q 'exec bash "$CACHE"' /tmp/fwtest/bin/fwp && ok "包装器转交脚本执行（保留参数）" || bad "包装器缺少 exec 逻辑"
grep -q 'id -u' /tmp/fwtest/bin/fwp && ok "非 root 时自动 sudo 提权" || bad "包装器缺提权逻辑"
# 真机抓到过：用 sh -n 校验 bash 脚本，在 Debian/Ubuntu（sh=dash）上永远失败 → 缓存永不刷新
if grep -qF '&& sh -n "$tmp"' /tmp/fwtest/bin/fwp; then bad "包装器用 sh -n 校验缓存（dash 上必然失败）"
else grep -qF 'bash -n "$tmp"' /tmp/fwtest/bin/fwp && ok "缓存校验用 bash -n（不是 sh -n）" || bad "包装器缺少语法校验"; fi

# ①b 菜单里会提示快捷入口（包装器存在时才提示；这里重建一份最小 PATH 的 stub 目录）
rm -rf /tmp/fakebin_fwp && mkdir -p /tmp/fakebin_fwp
for _c in bash sh sed head awk grep cat id uname dirname mktemp tee tail sort tr; do ln -sf "$(command -v "$_c")" "/tmp/fakebin_fwp/$_c"; done
out=$(printf '8\n' | env -i PATH=/tmp/fakebin_fwp FW_MENU=1 HOME=/tmp bash -c 'source "$1"; ACTION=install; VERSION_TAG=""; BETA=0; YES=0; MENU_SRC=""; interactive_channel_menu' bash "$TMPF" 2>&1)
case "$out" in *"快捷入口 : 以后直接输入 fwp"*) ok "菜单会提示 fwp 快捷入口" ;; *) bad "菜单没提示快捷入口" ;; esac

# ② 管道模式：$0 是 "bash" → 按官方地址抓；抓到垃圾内容不得覆盖已有缓存
mkdir -p /tmp/fwtest/fakebin /tmp/fwtest/badbin
cat > /tmp/fwtest/fakebin/curl <<'FEOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
printf '%s' "$FAKE_BODY" > "$out"
FEOF
cat > /tmp/fwtest/badbin/curl <<'FEOF'
#!/bin/sh
exit 1
FEOF
chmod +x /tmp/fwtest/fakebin/curl /tmp/fwtest/badbin/curl
before=$(md5sum /tmp/fwtest/app/install.sh | awk '{print $1}')
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="<html>404 Not Found</html>" \
  bash -c 'source "$1"; install_shortcut' bash "$TMPF" >/dev/null 2>&1
[ "$(md5sum /tmp/fwtest/app/install.sh | awk '{print $1}')" = "$before" ] \
    && ok "错误内容（404 页面）不会覆盖已有缓存" || bad "错误内容把缓存覆盖了"
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="$(cat "$SCRIPT")" \
  bash -c 'source "$1"; install_shortcut' bash "$TMPF" >/dev/null 2>&1
# 缓存应变成"线上原件"（带生产路径），而不再是刚才那份测试副本
grep -q 'readonly WRAPPER_PATH="/usr/local/bin/fwp"' /tmp/fwtest/app/install.sh \
    && ok "管道模式下按官方地址抓到完整脚本并入库" || bad "管道模式抓取入库异常"

# ②b 旧缓存（没有菜单的老脚本，模拟用户机器上那份 v2.1.24）必须给出明确提示，不能让人猜
cp /tmp/fwtest/app/install.sh /tmp/fwtest/app/keep_new.sh
cat > /tmp/fwtest/app/install.sh <<'OLDEOF'
#!/usr/bin/env bash
readonly SCRIPT_VERSION="2.1.24"
usage() { echo "旧脚本用法"; }
case "${1:-}" in --help) usage; exit 0 ;; esac
echo "old-script-ran: $*"
OLDEOF
chmod 755 /tmp/fwtest/app/install.sh
out=$(env -i PATH=/tmp/fwtest/badbin:/usr/bin:/bin HOME=/tmp timeout 20 sh /tmp/fwtest/bin/fwp --help 2>&1)
case "$out" in *"本地脚本是旧版"*) ok "旧版缓存会提示“本地脚本是旧版 + 用 --update-script 更新”" ;;
                *) bad "旧版缓存没有任何提示: $(printf '%s' "$out" | head -3)" ;; esac

# ②c fwp --update-script 自带联网能力：缓存是老脚本也能用（用户实测踩到的坑）
cat > /tmp/fwtest/fakebin/curl <<'FEOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
printf '%s' "$FAKE_BODY" > "$out"
FEOF
chmod +x /tmp/fwtest/fakebin/curl
# 假的 bash 单独放一个目录：不能污染 /tmp/fwtest/fakebin，后面还有测试要用它家的 curl 桩
mkdir -p /tmp/fwtest/fakebash
cat > /tmp/fwtest/fakebash/bash <<'BEOF'
#!/bin/bash
# 冒充“最新脚本被调用”：把收到的参数写下来
echo "SCRIPT_INVOKED_ARGS: $*"
BEOF
chmod +x /tmp/fwtest/fakebash/bash
out=$(env -i PATH=/tmp/fwtest/fakebash:/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp \
      FAKE_BODY="#!/usr/bin/env bash
readonly SCRIPT_VERSION=\"9.9.9\"
echo newest-script" \
      timeout 20 sh /tmp/fwtest/bin/fwp --update-script 2>&1)
grep -q 'SCRIPT_VERSION="9.9.9"' /tmp/fwtest/app/install.sh \
    && ok "fwp --update-script 会把最新脚本写进缓存" || bad "缓存没被更新"
case "$out" in *SCRIPT_INVOKED_ARGS:*--update-script*) ok "更新后交给新脚本执行 --update-script" ;;
                *) bad "没有把 --update-script 交给新脚本: $(printf '%s' "$out" | head -3)" ;; esac
cp /tmp/fwtest/app/keep_new.sh /tmp/fwtest/app/install.sh

# ②d install_shortcut 优先用调用方给的本地副本（免联网；curl 是坏的，只能靠本地副本）
cp "$SCRIPT" /tmp/fwtest/known_new.sh
rm -f /tmp/fwtest/app/install.sh
env -i PATH=/tmp/fwtest/badbin:/usr/bin:/bin HOME=/tmp \
    bash -c 'source "$1"; install_shortcut /tmp/fwtest/known_new.sh' bash "$TMPF" >/tmp/fwtest/sc.out 2>&1 || true
cmp -s /tmp/fwtest/app/install.sh /tmp/fwtest/known_new.sh \
    && ok "install_shortcut 用给定的本地副本建缓存（不依赖网络）" || bad "没采用给定的本地副本"
grep -q "快捷命令已就绪" /tmp/fwtest/sc.out && ok "采用本地副本后照常报告就绪" || bad "本地副本路径没走到就绪分支"

# ②e 非 root 且缓存不可写（root 所有）时，--update-script 必须先提权重跑，
#     否则 mv 会卡在 "overriding mode 0755?" 交互提问上（用户实测踩到）
grep -q 'mv "$tmp" "$CACHE"' /tmp/fwtest/bin/fwp && bad "包装器里还有裸 mv（会弹交互提问）" \
    || ok "包装器里的 mv 一律带 -f（脚本不会弹交互提问）"
mkdir -p /tmp/fwtest/elevbin
cat > /tmp/fwtest/elevbin/sudo <<'SEOF'
#!/bin/sh
echo "SUDO_CALLED: $*"
exit 0
SEOF
chmod +x /tmp/fwtest/elevbin/sudo
chmod 444 /tmp/fwtest/app/install.sh          # 模拟 root 所有、当前用户不可写
out=$(env -i PATH=/tmp/fwtest/elevbin:/usr/bin:/bin HOME=/tmp timeout 20 sh /tmp/fwtest/bin/fwp --update-script 2>&1)
case "$out" in *"SUDO_CALLED: sh /tmp/fwtest/bin/fwp --update-script"*) ok "缓存不可写时自动 sudo 提权重跑（不再卡在 mv 提问）" ;;
                *) bad "没有提权: $(printf '%s' "$out" | head -3)" ;; esac
chmod 644 /tmp/fwtest/app/install.sh

# ③ 包装器实跑：联网失败时回退本地缓存并正常进入脚本（--help 只打印用法，不会安装）
out=$(env -i PATH=/tmp/fwtest/badbin:/usr/bin:/bin HOME=/tmp sh /tmp/fwtest/bin/fwp --help 2>&1)
case "$out" in *用法*|*Usage*) ok "联网失败仍能用本地缓存打开脚本（fwp --help 正常）" ;; *) bad "包装器回退失败: $out" ;; esac

# ③b do_update_script：成功替换缓存；垃圾内容一律拒绝
cat > /tmp/fwtest/bin/newscript.sh <<'NEOF'
#!/usr/bin/env bash
readonly SCRIPT_VERSION="9.9.9"
echo new
NEOF
chmod +x /tmp/fwtest/bin/newscript.sh
cat > /tmp/fwtest/fakebin/curl <<'FEOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
# FAKE_URL_LOG=文件 时把请求的 URL 记下来（用来断言优先取了哪个源）
[ -n "${FAKE_URL_LOG:-}" ] && printf '%s\n' "$url" >> "$FAKE_URL_LOG"
# FAKE_FAIL_RAW=1 时模拟"GitHub 直连不通"，用来验证多源回退
if [ -n "${FAKE_FAIL_RAW:-}" ]; then
    case "$url" in *raw.githubusercontent.com*) exit 22 ;; esac
fi
printf '%s\n' "$FAKE_BODY" > "$out"
FEOF
chmod +x /tmp/fwtest/fakebin/curl
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="$(cat /tmp/fwtest/bin/newscript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script' bash "$TMPF" > /tmp/fwtest/upd.out 2>&1
grep -q 'SCRIPT_VERSION="9.9.9"' /tmp/fwtest/app/install.sh && ok "do_update_script 会把新脚本写入缓存" || bad "缓存未更新"
grep -q "脚本已更新" /tmp/fwtest/upd.out && ok "会提示版本变化（vX → vY）" || bad "没有版本变化提示: $(cat /tmp/fwtest/upd.out)"
before=$(md5sum /tmp/fwtest/app/install.sh | awk '{print $1}')
rc2=0
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="<html>404</html>" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script' bash "$TMPF" > /tmp/fwtest/upd2.out 2>&1 || rc2=$?
[ "$rc2" != "0" ] && ok "校验失败时返回非 0（脚本能感知失败）" || bad "校验失败却返回 0"
[ "$(md5sum /tmp/fwtest/app/install.sh | awk '{print $1}')" = "$before" ] \
    && ok "错误内容不会覆盖缓存" || bad "错误内容把缓存覆盖了"
grep -q "校验失败" /tmp/fwtest/upd2.out && ok "校验失败有明确提示" || bad "校验失败没提示"

# 假 wget：与假 curl 同逻辑（同样只挡 raw）。否则 raw 一失败，真实 wget 会把真脚本下下来，
# "多源回退"用例测到的其实是 wget 同源重试，而不是换源
cat > /tmp/fwtest/fakebin/wget <<'WEOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -O) out="$2"; shift 2 ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
[ -n "${FAKE_URL_LOG:-}" ] && printf '%s\n' "$url" >> "$FAKE_URL_LOG"
if [ -n "${FAKE_FAIL_RAW:-}" ]; then
    case "$url" in *raw.githubusercontent.com*) exit 8 ;; esac
fi
printf '%s\n' "$FAKE_BODY" > "$out"
WEOF
chmod +x /tmp/fwtest/fakebin/wget

# ③c 多源回退：raw 不通时自动换 jsDelivr/ghproxy（国内线路只走 raw 常常拿不到 = 用户实测"按 9 没反应"）
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_FAIL_RAW=1 FAKE_BODY="$(cat /tmp/fwtest/bin/newscript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script' bash "$TMPF" > /tmp/fwtest/upd4.out 2>&1
grep -q 'SCRIPT_VERSION="9.9.9"' /tmp/fwtest/app/install.sh && ok "raw 不通时回退到备用源并成功写入缓存" || bad "多源回退失败: $(tail -2 /tmp/fwtest/upd4.out)"
grep -q "已改用备用源" /tmp/fwtest/upd4.out && ok "换源时有明确提示" || bad "换源没提示"

# ③d 绝不降级：备用源还在发旧内容时，不能把本地脚本换成旧的
before=$(md5sum /tmp/fwtest/app/install.sh | awk '{print $1}')
printf '%s\n' '#!/usr/bin/env bash' 'readonly SCRIPT_VERSION="0.0.1"' > /tmp/fwtest/bin/oldscript.sh
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="$(cat /tmp/fwtest/bin/oldscript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script' bash "$TMPF" > /tmp/fwtest/upd5.out 2>&1 || true
[ "$(md5sum /tmp/fwtest/app/install.sh | awk '{print $1}')" = "$before" ] \
    && ok "下载到较旧版本时保留本地脚本（不降级）" || bad "被降级了"
grep -q "较旧版本" /tmp/fwtest/upd5.out && ok "不降级时说明原因" || bad "缺少不降级说明"

# ③e CDN 未同步：线上已有更新版本、但下载到的还是当前版本 → 必须说清楚，不能只说"已是最新"
cat > /tmp/fwtest/bin/samescript.sh <<'SEOF'
#!/usr/bin/env bash
SEOF
printf 'readonly SCRIPT_VERSION="%s"\n' "$(grep -m1 -o 'SCRIPT_VERSION="[0-9.]*"' "$SCRIPT" | tr -d '"' | cut -d= -f2)" >> /tmp/fwtest/bin/samescript.sh
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="$(cat /tmp/fwtest/bin/samescript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script 9.9.9' bash "$TMPF" > /tmp/fwtest/upd6.out 2>&1
grep -q "线上已发布 v9.9.9" /tmp/fwtest/upd6.out && grep -q "同步有延迟" /tmp/fwtest/upd6.out \
    && ok "下载源未同步时明确提示（不再含糊地说"已是最新"）" || bad "缺少 CDN 未同步提示: $(tail -2 /tmp/fwtest/upd6.out)"
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="$(cat /tmp/fwtest/bin/samescript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script' bash "$TMPF" > /tmp/fwtest/upd7.out 2>&1
grep -q "同步有延迟" /tmp/fwtest/upd7.out && bad "版本真已是线上最新时不该报"延迟"" || ok "确实最新时不说"同步延迟""

# ③g 知道线上新版号时优先按 tag 取（main 的 CDN 刚发版时还没同步，tag 是就绪的）
: > /tmp/fwtest/url.log
cat > /tmp/fwtest/bin/tagscript.sh <<'TEOF'
#!/usr/bin/env bash
readonly SCRIPT_VERSION="9.9.9"
TEOF
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_URL_LOG=/tmp/fwtest/url.log FAKE_BODY="$(cat /tmp/fwtest/bin/tagscript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script 9.9.9' bash "$TMPF" > /tmp/fwtest/upd8.out 2>&1
first_url="$(head -1 /tmp/fwtest/url.log)"
case "$first_url" in
    *"/v9.9.9/"*) ok "知道新版号时优先按 tag 取（避开 main 的 CDN 延迟）：$(printf '%s' "$first_url" | cut -c1-58)..." ;;
    *) bad "没有优先取 tag：$first_url" ;;
esac
grep -q 'SCRIPT_VERSION="9.9.9"' /tmp/fwtest/app/install.sh && ok "tag 源也真的写进了缓存" || bad "tag 源没生效"
# 不知道新版号（命令行直接 --update-script）时仍从 main 起
: > /tmp/fwtest/url.log
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_URL_LOG=/tmp/fwtest/url.log FAKE_BODY="$(cat /tmp/fwtest/bin/tagscript.sh)" \
    bash -c 'source "$1"; check_root() { :; }; menu_preview_tag() { :; }; do_update_script' bash "$TMPF" > /dev/null 2>&1
case "$(head -1 /tmp/fwtest/url.log)" in
    *"/main/"*) ok "查不到新版号时退回 main（有新版号才走 tag）" ;;
    *) bad "无版本信息时没走 main: $(head -1 /tmp/fwtest/url.log)" ;;
esac
rm -f /tmp/fwtest/url.log /tmp/fwtest/bin/tagscript.sh

# ③f 包装器也要多源（缓存缺失时才联网那条路）
grep -q "cdn.jsdelivr.net" /tmp/fwtest/bin/fwp && grep -q "ghproxy.net" /tmp/fwtest/bin/fwp \
    && ok "fwp 包装器拉缓存时也有多源回退" || bad "包装器仍是单源"
# 老版本机器不用重装面板：--update-script 也要顺手把包装器刷新成新版本
rm -f /tmp/fwtest/bin/fwp
env -i PATH=/tmp/fwtest/fakebin:/usr/bin:/bin HOME=/tmp FAKE_BODY="$(cat "$SCRIPT")" \
    bash -c 'source "$1"; check_root() { :; }; do_update_script' bash "$TMPF" >/tmp/fwtest/upd3.out 2>&1 || true
[ -x /tmp/fwtest/bin/fwp ] && ok "--update-script 会重新生成 fwp 包装器（不必重装面板）" || bad "包装器没被刷新"
grep -qF 'exec sudo bash "$CACHE"' /tmp/fwtest/bin/fwp && ok "刷新出来的包装器是内容正确的新版" || bad "刷新出来的包装器内容不对"
cp "$SCRIPT" /tmp/fwtest/app/install.sh

# ④ 卸载时删除快捷命令
env -i PATH=/usr/bin:/bin HOME=/tmp bash -c 'source "$1"; check_root() { :; }; systemctl() { return 1; }; do_uninstall' bash "$TMPF" >/dev/null 2>&1
[ -e /tmp/fwtest/bin/fwp ] && bad "卸载后快捷命令仍在" || ok "卸载会删除快捷命令 fwp"
[ -e /tmp/fwtest/app ] && bad "卸载后程序目录仍在" || ok "卸载会删除程序目录（缓存一并清掉）"
rm -rf /tmp/fwtest /tmp/fakebin_fwp /tmp/fwtest_hang.sh

echo "== gen_initial_rules：已有 rules.json 必须幂等补齐面板端口（v3.2.40 修「重装后端口没放行」） =="
RTMP=$(mktemp -u); rm -f "$RTMP"
printf '%s' '[{"id":"old1","type":"port_allow","proto":"tcp","port":42606,"comment":"旧 SSH 规则","protected":true}]' > "$RTMP"
gen_initial_rules 42606 18935 "$RTMP" >/dev/null 2>&1
PORTS=$(python3 -c "import json;print(','.join(sorted(str(r['port']) for r in json.load(open('$RTMP')))))")
if [ "$PORTS" = "18935,42606" ]; then ok "补齐面板端口且不重复旧 SSH 规则（$PORTS）"; else bad "端口列表异常: $PORTS"; fi
SUM1=$(md5sum "$RTMP" | awk '{print $1}')
gen_initial_rules 42606 18935 "$RTMP" >/dev/null 2>&1
SUM2=$(md5sum "$RTMP" | awk '{print $1}')
if [ "$SUM1" = "$SUM2" ]; then ok "幂等：重复执行不改动规则文件"; else bad "重复执行改动了规则文件"; fi
printf '%s' '{坏掉的 json' > "$RTMP"
gen_initial_rules 42606 18935 "$RTMP" >/dev/null 2>&1
if python3 -c "import json;json.load(open('$RTMP'))" 2>/dev/null; then ok "损坏的 rules.json 已重建为合法 JSON"; else bad "损坏的 rules.json 未重建"; fi
if ls "$RTMP".broken.* >/dev/null 2>&1; then ok "损坏文件已备份（.broken.*）"; else bad "损坏文件未备份"; fi
rm -f "$RTMP" "$RTMP".broken.*

echo "== write_config：已有 config.json 时端口/账号/密码哈希/自定义字段都不被覆盖（v3.2.40） =="
WTMP=$(mktemp -d); mkdir -p "$WTMP/etc" "$WTMP/app"
head -n -1 "$SCRIPT" \
    | sed -e "s|^readonly APP_DIR=\"/usr/local/lib/fwpanel\"|readonly APP_DIR=\"$WTMP/app\"|" \
          -e "s|^readonly ETC_DIR=\"/etc/fwpanel\"|readonly ETC_DIR=\"$WTMP/etc\"|" \
          -e "s|^readonly LOG_FILE=\"/var/log/fwpanel-install.log\"|readonly LOG_FILE=\"$WTMP/install.log\"|" \
    > "$WTMP/install.sh"
cat > "$WTMP/etc/config.json" <<'JSON'
{"username":"huoshen2877","password_hash":"saltXhashY","port":42608,"bind":"0.0.0.0",
 "mode":"strict","ssh_port":42606,"ssh_port_auto":true,"dns_creds":{"cf":{"CF_Token":"T"}},"theme":"vibes-dark"}
JSON
WC_OUT=$(bash -c "
source '$WTMP/install.sh'
PANEL_USER=newuser; PANEL_PASS=NewPass12345; PANEL_PORT=19999; PANEL_BIND=127.0.0.1
write_config >/dev/null 2>&1
python3 -c \"import json;d=json.load(open('$WTMP/etc/config.json'));print(d['username'],d['port'],d['bind'],d['password_hash'],bool(d.get('dns_creds')),d.get('theme'))\"
")
if [ "$WC_OUT" = "huoshen2877 42608 0.0.0.0 saltXhashY True vibes-dark" ]; then
    ok "端口/账号/密码哈希/dns_creds/主题全部保留（未被安装脚本覆盖）"
else
    bad "配置被覆盖: $WC_OUT"
fi
rm -f "$WTMP/etc/config.json"
WC_OUT2=$(bash -c "
source '$WTMP/install.sh'
PANEL_USER=freshuser; PANEL_PASS=FreshPass12345; PANEL_PORT=19999; PANEL_BIND=0.0.0.0
write_config >/dev/null 2>&1
python3 -c \"import json;d=json.load(open('$WTMP/etc/config.json'));print(d['username'],d['port'],len(d['password_hash']) > 10)\"
")
if [ "$WC_OUT2" = "freshuser 19999 True" ]; then ok "无配置时按参数写入新端口与新账号"; else bad "首次安装写入异常: $WC_OUT2"; fi
rm -rf "$WTMP"

echo "== stop_panel_service：孤儿进程必须被真杀（v3.2.40 修「卸载假成功、进程占着端口」） =="
OTMP=$(mktemp -d); mkdir -p "$OTMP/app" "$OTMP/bin"
# 生成被测脚本副本（APP_DIR 指向临时目录）
head -n -1 "$SCRIPT" | sed -e "s|^readonly APP_DIR=\"/usr/local/lib/fwpanel\"|readonly APP_DIR=\"$OTMP/app\"|" > "$OTMP/install.sh"
cat > "$OTMP/app/panel.py" <<'PYBODY'
import time
time.sleep(300)
PYBODY
cat > "$OTMP/bin/systemctl" <<'SHSTUB'
#!/usr/bin/env bash
exit 0      # 模拟「systemctl stop 静默无效」：只信 systemctl 会误判已停止
SHSTUB
chmod +x "$OTMP/bin/systemctl"
cat > "$OTMP/run1.sh" <<'RUNBODY'
source @DIR@/install.sh
python3 '@APP@/panel.py' serve >/dev/null 2>&1 &
p=$!
sleep 1
stop_panel_service >/dev/null 2>&1
rc=$?
if kill -0 $p 2>/dev/null; then echo "ALIVE rc=$rc"; else echo "GONE rc=$rc"; fi
RUNBODY
sed -i -e "s|@APP@|$OTMP/app|g" -e "s|@DIR@|$OTMP|g" "$OTMP/run1.sh"
SP_OUT=$(PATH="$OTMP/bin:$PATH" bash "$OTMP/run1.sh" 2>&1 | tail -1 || true)
if [ "$SP_OUT" = "GONE rc=0" ]; then ok "systemctl 无效时仍把进程杀掉并返回成功"; else bad "孤儿进程未清理: $SP_OUT"; fi

OTMP2=$(mktemp -d); mkdir -p "$OTMP2/app" "$OTMP2/bin"
head -n -1 "$SCRIPT" | sed -e "s|^readonly APP_DIR=\"/usr/local/lib/fwpanel\"|readonly APP_DIR=\"$OTMP2/app\"|" > "$OTMP2/install.sh"
cat > "$OTMP2/app/panel.py" <<'PYBODY'
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(300)
PYBODY
cp "$OTMP/bin/systemctl" "$OTMP2/bin/systemctl"
cat > "$OTMP2/run2.sh" <<'RUNBODY'
source @DIR@/install.sh
python3 '@APP@/panel.py' serve >/dev/null 2>&1 &
p=$!
sleep 1
stop_panel_service >/dev/null 2>&1
rc=$?
if kill -0 $p 2>/dev/null; then echo "ALIVE rc=$rc"; else echo "GONE rc=$rc"; fi
RUNBODY
sed -i -e "s|@APP@|$OTMP2/app|g" -e "s|@DIR@|$OTMP2|g" "$OTMP2/run2.sh"
SP2_OUT=$(PATH="$OTMP2/bin:$PATH" bash "$OTMP2/run2.sh" 2>&1 | tail -1 || true)
if [ "$SP2_OUT" = "GONE rc=0" ]; then ok "忽略 TERM 的顽固进程被 SIGKILL 结束"; else bad "顽固进程未清理: $SP2_OUT"; fi

echo "== start_panel_service：启动前必须清掉已在跑的旧进程（否则新代码/新端口不生效） =="
cat > "$OTMP/run3.sh" <<'RUNBODY'
source @DIR@/install.sh
python3 '@APP@/panel.py' serve >/dev/null 2>&1 &
old=$!
sleep 1
start_panel_service >/dev/null 2>&1
rc=$?
if kill -0 $old 2>/dev/null; then echo "OLD_ALIVE rc=$rc"; else echo "OLD_GONE rc=$rc"; fi
RUNBODY
sed -i -e "s|@APP@|$OTMP/app|g" -e "s|@DIR@|$OTMP|g" "$OTMP/run3.sh"
ST_OUT=$(PATH="$OTMP/bin:$PATH" bash "$OTMP/run3.sh" 2>&1 | tail -1 || true)
if [ "$ST_OUT" = "OLD_GONE rc=0" ]; then ok "旧进程被停掉后重启（新配置才会生效）"; else bad "旧进程仍在: $ST_OUT"; fi

echo "== panel_http_ok：本机 HTTP 自检（真正监听才算通过，安装摘要靠它说真话） =="
HPORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
python3 -m http.server "$HPORT" --bind 127.0.0.1 >/dev/null 2>&1 &
HPID=$!
sleep 1
cat > "$OTMP/httpok.sh" <<'RUNBODY'
source @TMPF@
panel_http_ok "$1" "$2"
RUNBODY
sed -i "s|@TMPF@|$TMPF|g" "$OTMP/httpok.sh"
if bash "$OTMP/httpok.sh" "$HPORT" 2 >/dev/null 2>&1; then ok "监听中的端口返回 200 判定通过"; else bad "监听中的端口未通过自检"; fi
if bash "$OTMP/httpok.sh" 1 1 >/dev/null 2>&1; then bad "未监听端口被误判为可用"; else ok "未监听端口正确判失败"; fi
kill "$HPID" 2>/dev/null || true
rm -rf "$OTMP" "$OTMP2"

echo "== do_upgrade：服务单元缺失（卸载后重装）必须补装并启动服务（v3.2.40） =="
UTMP=$(mktemp -d); mkdir -p "$UTMP/app" "$UTMP/etc"
# 预置「已装旧版」的 panel.py：do_upgrade 的防降级检查要读它（读不到时 grep 退出码 2 会被 set -e 杀掉）
echo 'CURRENT_VERSION = "2.1.33"' > "$UTMP/app/panel.py"
head -n -1 "$SCRIPT" \
    | sed -e "s|^readonly APP_DIR=\"/usr/local/lib/fwpanel\"|readonly APP_DIR=\"$UTMP/app\"|" \
          -e "s|^readonly ETC_DIR=\"/etc/fwpanel\"|readonly ETC_DIR=\"$UTMP/etc\"|" \
          -e "s|^readonly LOG_FILE=\"/var/log/fwpanel-install.log\"|readonly LOG_FILE=\"$UTMP/install.log\"|" \
          -e "s|^readonly SERVICE_NAME=\"fwpanel.service\"|readonly SERVICE_NAME=\"fwpanel_utest.service\"|" \
    > "$UTMP/install.sh"
cat > "$UTMP/inner1.sh" <<'UGI1'
source @UTMP@/install.sh
VERSION_TAG=""; BETA=1
resolve_src_tag() { SRC_TAG=v9.9.9; }
fetch_source() { printf 'CURRENT_VERSION = "9.9.9"\n' > "$1"; return 0; }
install_shortcut() { return 0; }
atomic_put() { mkdir -p "$(dirname "$2")"; cp "$1" "$2"; }
atomic_put_dir() { return 0; }
sshd() { echo 'port 42606'; }
gen_initial_rules() { echo GEN_RULES_CALLED; }
install_service() { echo INSTALL_SERVICE_CALLED; }
do_upgrade
UGI1
sed -i "s|@UTMP@|$UTMP|g" "$UTMP/inner1.sh"
UP_OUT=$(FW_SYSTEMD_DIR="$UTMP/sd" bash "$UTMP/inner1.sh" 2>&1 || true)
case "$UP_OUT" in
    *INSTALL_SERVICE_CALLED*) ok "单元缺失 → 补装服务（不再静默只喊升级完成）" ;;
    *) bad "未补装服务: $(printf '%s' "$UP_OUT" | tail -3 | tr '\n' ' ')" ;;
esac
# 单元存在时走 restart + 自检分支（不再用 enable --now 空操作）
mkdir -p "$UTMP/sd"; touch "$UTMP/sd/fwpanel_utest.service"
# 上面那条用例已把磁盘 panel.py 升到 9.9.9，这里重置成旧版本，否则防降级直接跳过
echo 'CURRENT_VERSION = "2.1.33"' > "$UTMP/app/panel.py"
cat > "$UTMP/inner2.sh" <<'UGI2'
source @UTMP@/install.sh
VERSION_TAG=""; BETA=1
resolve_src_tag() { SRC_TAG=v9.9.9; }
fetch_source() { printf 'CURRENT_VERSION = "9.9.9"\n' > "$1"; return 0; }
install_shortcut() { return 0; }
atomic_put() { mkdir -p "$(dirname "$2")"; cp "$1" "$2"; }
atomic_put_dir() { return 0; }
install_service() { echo INSTALL_SERVICE_UNEXPECTED; }
start_panel_service() { echo START_CALLED; return 0; }
verify_panel_http() { echo VERIFY_CALLED; return 0; }
do_upgrade
UGI2
sed -i "s|@UTMP@|$UTMP|g" "$UTMP/inner2.sh"
UP2_OUT=$(FW_SYSTEMD_DIR="$UTMP/sd" bash "$UTMP/inner2.sh" 2>&1 || true)
case "$UP2_OUT" in
    *START_CALLED*) ok "单元存在 → 显式 restart + 回读自检（替代 enable --now）" ;;
    *) bad "未走 restart 分支: $(printf '%s' "$UP2_OUT" | tail -3 | tr '\n' ' ')" ;;
esac
rm -rf "$UTMP"

echo "== 前端行为测试（node；机器上没有 node 就跳过） =="
NODE_BIN="$(command -v node || command -v /home/saxon/.local/bin/node || true)"
if [ -n "$NODE_BIN" ]; then
    for t in frontend_port_redirect_test.js frontend_bbr_ui_test.js frontend_sys_controls_test.js; do
        if out=$("$NODE_BIN" "$(dirname "$SCRIPT")/test/$t" 2>&1); then
            ok "$t 全部通过"
        else
            bad "$t 失败: $(echo "$out" | tail -4 | tr '\n' ' ')"
        fi
    done
else
    echo "  - 跳过（未安装 node）"
fi

echo "============================================"
echo "结果: $PASS 通过, $FAIL 失败"
rm -f "$TMPF" /tmp/install_funcs_fw.sh
exit $FAIL
