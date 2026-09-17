#!/usr/bin/env bash
# =============================================================================
# fwpanel2 — 简易VPS管理面板2.0 一键安装包（Debian/Ubuntu/Arch/Fedora 多发行版）
# -----------------------------------------------------------------------------
# 零第三方依赖：Python 标准库 + 系统 nftables，不装 firewalld/ufw。
#
# 用法：
#   sudo bash install.sh                         一键安装/升级【最新正式版】（随机端口/用户名/密码一并打印）
#   sudo bash install.sh --beta                  安装/升级【最新测试版】（尝鲜，未充分验证）
#   sudo bash install.sh -p 17890                指定面板端口
#   sudo bash install.sh --bind 127.0.0.1        仅本机访问（默认 0.0.0.0 开放远程）
#   sudo bash install.sh --user admin --password MyPass123  指定凭据
#   sudo bash install.sh --check                 仅体检环境
#   sudo bash install.sh --change-password       重置面板密码（交互式）
#   sudo bash install.sh --uninstall             卸载（停服务+删文件）
#   sudo bash install.sh --purge                 彻底卸载（连配置/规则/站点文件/容器数据/证书一起删）
#
# 环境变量（与参数等效，参数优先）：
#   FW_PORT FW_BIND FW_USER FW_PASS
# =============================================================================

set -Eeuo pipefail

# ------------------------------ 常量 ------------------------------
readonly SCRIPT_NAME="FW-Panel2 VPS管理面板2.0安装包"
readonly SCRIPT_VERSION="3.3.11"
readonly RAW_INSTALL_URL="https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/main/install.sh"
readonly WRAPPER_PATH="${FW_WRAPPER:-/usr/local/bin/fwp}"   # 快捷命令（由本脚本生成/卸载时删除）
readonly CACHED_SCRIPT_NAME="install.sh"            # 缓存到 $APP_DIR 下的脚本副本
readonly LOG_FILE="${FW_LOG_FILE:-/var/log/fwpanel-install.log}"
readonly APP_DIR="${FW_APP_DIR:-/usr/local/lib/fwpanel}"
readonly ETC_DIR="${FW_ETC_DIR:-/etc/fwpanel}"
readonly SERVICE_NAME="fwpanel.service"
# systemd 单元目录（可用 FW_SYSTEMD_DIR 覆盖——测试/沙箱里不希望真写 /etc）
readonly SYSTEMD_DIR="${FW_SYSTEMD_DIR:-/etc/systemd/system}"

# ---- 彻底卸载（--purge）会碰到的路径 ----
# 同样支持 FW_* 覆盖：测试/演练用，生产走默认值（默认值与面板自身的路径常量一一对应）
readonly NFT_TABLE_NAME="inet fwpanel"                          # 面板管理的 nft 表
readonly NGINX_SITES_ENABLED="${FW_NGINX_SITES:-/etc/nginx/sites-enabled}"
readonly NGINX_CONF_D="${FW_NGINX_CONFD:-/etc/nginx/conf.d}"
readonly SITE_ROOT_BASE="${FW_SITE_ROOT:-/var/www}"             # 站点根目录（与面板默认一致）
readonly ACME_WEBROOT="${FW_ACME_WEBROOT:-/var/www/fwpanel-acme}"
readonly LE_DIR="${FW_LE_DIR:-/etc/letsencrypt}"
readonly DOCKER_DATA_BASE="${FW_DOCKER_DATA:-/DockerData}"
readonly COMPOSE_BASE="$DOCKER_DATA_BASE/dockercompose"
readonly APP_DATA_BASE="$DOCKER_DATA_BASE/apps"
readonly NGINX_LOG_DIR="${FW_NGINX_LOG_DIR:-/var/log/nginx}"
readonly BACKUP_ARCHIVE_DIR="${FW_BACKUP_ARCHIVE:-/var/backups/fwpanel}"   # 面板备份包（彻底卸载也保留）
readonly MIN_DEBIAN_VERSION=11
readonly SUPPORTED_DISTROS="debian ubuntu arch fedora centos rocky alma rhel manjaro endeavouros"

# 发行版与包管理器（check_os 中填充）
DISTRO_ID="unknown"
DISTRO_NAME=""
PKG_MGR=""
PY_PKG="python3"

# ------------------------------ 变量 ------------------------------
ACTION="install"
FORCE=0
PANEL_PORT=""
PANEL_BIND=""
PANEL_USER=""
PANEL_PASS=""
OPEN_PORTS=""
VERSION_TAG=""   # 指定安装/升级版本（如 v1.24.42；留空 = 解析最新正式版）
BETA=0           # --beta:安装/升级最新测试版(prerelease)
YES=0            # --yes:跳过交互菜单(无人值守/脚本里用)
SRC_TAG=""       # 解析后的下载源 tag(懒解析)

# ------------------------------ 颜色 ------------------------------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BOLD=""; C_RESET=""
fi

log_info()  { printf '%s[INFO ]%s %s\n' "$C_GREEN" "$C_RESET" "$1" >&2; }
log_warn()  { printf '%s[WARN ]%s %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; }
log_error() { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }

error() { log_error "$1"; exit 1; }

_ERR_TRAP_SHOWN=0
err_trap() {
    local rc=$? cmd="${BASH_COMMAND:-unknown}"
    cmd="${cmd%%$'\n'*}"                                   # 多行命令只显示第一行
    [ "${#cmd}" -le 120 ] || cmd="${cmd:0:117}..."
    # set -E 下同一个失败命令会触发两次（内层命令 + 函数返回），只报一次
    if [ "$_ERR_TRAP_SHOWN" = "0" ]; then
        _ERR_TRAP_SHOWN=1
        case "$rc" in
            127) log_error "脚本异常退出（退出码 127）：找不到命令 —— $cmd" ;;
            126) log_error "脚本异常退出（退出码 126）：命令不可执行 —— $cmd" ;;
            *)   log_error "脚本异常退出（退出码 $rc）—— 失败命令: $cmd" ;;
        esac
        log_error "请查看日志: $LOG_FILE"
    fi
}
trap err_trap ERR

# ============================== 环境检测 ==============================

check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        # root 用户：确保 sudo 可用（便于其他用户提权），缺失则自动安装
        if ! command -v sudo >/dev/null 2>&1; then
            log_warn "未检测到 sudo，自动安装（root 可直接使用，其他用户可借此提权）..."
            install_pkgs "sudo" || log_warn "sudo 安装失败（root 直接使用不受影响）"
        fi
        log_info "权限检查通过（root）"
        return 0
    fi
    # 非 root 用户
    if ! command -v sudo >/dev/null 2>&1; then
        error "当前用户非 root 且未安装 sudo，无法提权安装。请先切换到 root（su -）后重新执行"
    fi
    if [ ! -f "$0" ]; then
        error "检测到管道安装模式（curl | bash）且当前非 root，请改用：curl -sSL <安装地址> | sudo bash"
    fi
    # 有 sudo：自动提权重跑自身（保留原参数）
    log_warn "非 root 用户运行，自动通过 sudo 提权执行 ..."
    exec sudo bash "$0" "${SCRIPT_ARGS[@]}"
}

check_os() {
    [ -r /etc/os-release ] || error "无法读取 /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${NAME:-$DISTRO_ID}"
    case "$DISTRO_ID" in
        debian|ubuntu)            PKG_MGR="apt";    PY_PKG="python3" ;;
        arch|manjaro|endeavouros) PKG_MGR="pacman"; PY_PKG="python"  ;;
        fedora|centos|rocky|alma|rhel) PKG_MGR="dnf"; PY_PKG="python3" ;;
        *)
            [ "$FORCE" = "1" ] && log_warn "未知发行版 $DISTRO_ID（--force 跳过，风险自负）" \
                || error "不支持的系统: $DISTRO_ID（支持: $SUPPORTED_DISTROS，确认兼容可加 --force）"
            ;;
    esac
    log_info "系统: $DISTRO_NAME ($DISTRO_ID)"
    case "$DISTRO_ID" in
        debian)
            local ver="${VERSION_ID:-0}"; ver="${ver%%.*}"
            if [[ "$ver" =~ ^[0-9]+$ ]] && [ "$ver" -lt "$MIN_DEBIAN_VERSION" ]; then
                [ "$FORCE" = "1" ] && log_warn "Debian $ver 低于推荐版本（--force 跳过）" \
                    || error "Debian $ver 版本过低，要求 $MIN_DEBIAN_VERSION 及以上"
            fi
            if [ "$ver" = "13" ]; then log_info "Debian 13 (Trixie) ✓ 完全适配"
            else log_info "Debian $ver（兼容模式）"; fi
            ;;
        ubuntu)                    log_info "Ubuntu ${VERSION_ID:-}（兼容模式）" ;;
        arch|manjaro|endeavouros)  log_info "Arch 系（滚动更新，兼容模式）" ;;
        fedora|centos|rocky|alma|rhel) log_info "$DISTRO_NAME ${VERSION_ID:-}（兼容模式）" ;;
    esac
}

check_arch() {
    case "$(uname -m)" in
        x86_64|aarch64|arm64) log_info "架构: $(uname -m) ✓" ;;
        *) error "不支持的架构: $(uname -m)（仅支持 x86_64 / aarch64）" ;;
    esac
}

check_tools() {
    if command -v python3 >/dev/null 2>&1; then
        local pyver
        pyver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        log_info "Python: $pyver ✓"
    else
        log_warn "未安装 python3，将在安装依赖时自动安装"
    fi
    if command -v nft >/dev/null 2>&1; then
        log_info "nftables: $(nft --version 2>/dev/null | head -1) ✓"
    else
        log_warn "未安装 nftables，将在安装依赖时自动安装"
    fi
}

check_existing() {
    # ⚠ v3.2.40：/etc/fwpanel/config.json 存在也算「已安装」——卸载保留配置后再重装，
    # 旧逻辑只看程序文件与 service 单元，会误判为「首次安装」：重新随机端口、重问账号密码、
    # 覆盖 config.json，装完给出的地址与实际监听的进程对不上（阿基雷机实测）
    if [ -f "$APP_DIR/panel.py" ] || [ -f "$ETC_DIR/config.json" ] || systemctl list-unit-files 2>/dev/null | grep -q "$SERVICE_NAME"; then
        if [ "${1:-}" = "check" ]; then
            log_warn "检测到 fwpanel 已安装（体检模式跳过安装）。"
            log_info "重跑安装脚本可升级到最新正式版: curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/main/install.sh | sudo bash"
            log_info "想尝鲜测试版请在命令后加 --beta"
            exit 0
        fi
        log_info "检测到 fwpanel 已安装，执行升级/重装（保留面板端口、账号、规则与代理）..."
        do_upgrade
        exit 0
    fi
}

do_upgrade() {
    local tmpdir tag
    resolve_src_tag          # 父 shell 解析一次,SRC_TAG 全局缓存
    tmpdir=$(mktemp -d)
    tag="$SRC_TAG"
    if [ -n "$VERSION_TAG" ]; then
        log_info "下载指定版本 $tag ..."
    elif [ "$BETA" = "1" ]; then
        log_info "下载最新测试版...（源: $tag）"
    else
        log_info "下载最新正式版...（源: $tag）"
    fi
    # 三级源回退 + 内容头校验（防镜像返回 HTML 错误页）
    if ! fetch_source "$tmpdir/panel.py" "panel.py"; then
        log_error "下载 panel.py 失败，请检查服务器网络后重试"
        rm -rf "$tmpdir"
        exit 1
    fi
    # 防降级：当前版本 ≥ 下载版本时跳过（例如服务器已是更高版本）；--version 显式指定时允许降级回退
    local cur_ver new_ver
    # ⚠ 取值必须带 || true：卸载后 $APP_DIR/panel.py 不存在 → grep 退出码 2，
    #   在 set -e + pipefail 下会直接把整个升级流程中断（「卸载后重装」实测就是这个坑）
    cur_ver=$(grep -oP 'CURRENT_VERSION\s*=\s*"\K[\d.]+' "$APP_DIR/panel.py" 2>/dev/null | head -1 || true)
    new_ver=$(grep -oP 'CURRENT_VERSION\s*=\s*"\K[\d.]+' "$tmpdir/panel.py" 2>/dev/null | head -1 || true)
    if [ -z "$VERSION_TAG" ] && [ -n "$cur_ver" ] && [ -n "$new_ver" ]; then
        if [ "$(printf '%s\n' "$cur_ver" "$new_ver" | sort -V | tail -1)" = "$cur_ver" ]; then
            if [ "$BETA" = "1" ]; then
                log_info "当前已是最新测试版 v$cur_ver，无需升级"
            else
                log_info "当前版本 v$cur_ver ≥ 正式版 v$new_ver，跳过（不降级）"
                log_info "如当前是测试版并想尝鲜更新，请使用: sudo bash $0 --beta"
            fi
            rm -rf "$tmpdir"
            exit 0
        fi
        log_info "升级 v$cur_ver → v$new_ver"
    elif [ -n "$VERSION_TAG" ] && [ -n "$new_ver" ]; then
        log_info "指定版本安装 v$cur_ver → v$new_ver（允许降级）"
    fi
    fetch_source "$tmpdir/index.html" "static/index.html" || log_warn "下载 index.html 失败（保留现有页面）"
    fetch_source "$tmpdir/github-logo.png" "static/github-logo.png" || true
    fetch_source "$tmpdir/install.sh" "install.sh" || true
    # 字体(思源中文子集 + 0xProto 等宽):缺失时降级系统字体,不影响主功能
    local f
    mkdir -p "$tmpdir/fonts"
    for f in fw-sans-sc-regular.woff2 fw-sans-sc-bold.woff2 0xProto-Regular.woff2 0xProto-Bold.woff2; do
        fetch_source "$tmpdir/fonts/$f" "static/fonts/$f" || log_warn "字体 $f 下载失败(将使用系统字体)"
    done
    # Web 终端 xterm.js（v2.1.19）：下载失败仅终端不可用，主功能不受影响
    mkdir -p "$tmpdir/vendor"
    for f in xterm.js xterm.css xterm-addon-fit.js; do
        fetch_source "$tmpdir/vendor/$f" "static/vendor/$f" || log_warn "终端资源 $f 下载失败(Web 终端不可用)"
    done
    # v3.2.40：程序目录可能整个不存在（卸载时删掉了、配置还留着）→ 先建好目录，
    # 否则下面 install/mv 全部失败、set -e 直接中断升级（用户实测的「卸载后重装又出问题」）
    mkdir -p "$APP_DIR/static"
    # 备份当前版本（保留最近 3 份）；程序文件不存在（刚卸载过）就跳过备份，
    # 且清理旧备份的取值/管道不得中断流程
    local bak
    bak="$APP_DIR/panel.py.bak.$(date +%Y%m%d%H%M%S)"
    if [ -f "$APP_DIR/panel.py" ]; then
        if cp "$APP_DIR/panel.py" "$bak" 2>/dev/null; then
            log_info "已备份旧版本: $bak"
        fi
    fi
    ls -t "$APP_DIR"/panel.py.bak.* 2>/dev/null | tail -n +4 | xargs -r rm -f || true
    # 覆盖安装
    atomic_put "$tmpdir/panel.py" "$APP_DIR/panel.py" 755
    if [ -s "$tmpdir/index.html" ]; then
        mkdir -p "$APP_DIR/static"
        atomic_put "$tmpdir/index.html" "$APP_DIR/static/index.html" 644
    fi
    if [ -s "$tmpdir/github-logo.png" ]; then
        mkdir -p "$APP_DIR/static"
        atomic_put "$tmpdir/github-logo.png" "$APP_DIR/static/github-logo.png" 644
    fi
    if [ -s "$tmpdir/install.sh" ]; then
        # 顺便用刚下载的这份刷新 fwp 脚本缓存（免联网；缓存是旧版就在这里纠正）
        install_shortcut "$tmpdir/install.sh" >/dev/null 2>&1 || log_warn "刷新脚本缓存失败（fwp 可能仍是旧脚本）"
    fi
    if [ -s "$tmpdir/install.sh" ] && [ -f "$0" ]; then
        # 仅当 $0 是实体脚本文件时才就地更新它——管道模式（curl | sudo bash）下 $0 是 "bash"，
        # 无脑 cp 会在当前目录造出一个名为 bash 的垃圾文件
        cp "$tmpdir/install.sh" "$0" 2>/dev/null || true
    fi
    if [ -d "$tmpdir/fonts" ]; then
        mkdir -p "$APP_DIR/static/fonts"
        atomic_put_dir "$tmpdir/fonts" "$APP_DIR/static/fonts"
    fi
    if [ -d "$tmpdir/vendor" ]; then
        mkdir -p "$APP_DIR/static/vendor"
        atomic_put_dir "$tmpdir/vendor" "$APP_DIR/static/vendor"
    fi
    rm -rf "$tmpdir"
    # 语法校验
    if ! python3 -m py_compile "$APP_DIR/panel.py" 2>/dev/null; then
        log_error "新版本语法错误，正在回滚备份..."
        cp "$bak" "$APP_DIR/panel.py" 2>/dev/null
        exit 1
    fi
    # 服务单元可能不存在（卸载保留配置后再重装、或旧版安装方式）→ 按当前配置补装并启动
    if [ ! -f "$SYSTEMD_DIR/$SERVICE_NAME" ]; then
        log_info "未找到 systemd 服务单元，按现有配置补装服务..."
        local _sshp _panelp
        _sshp="$({ sshd -T 2>/dev/null || true; } | awk '/^port /{print $2; exit}' || true)"
        [[ "$_sshp" =~ ^[0-9]{1,5}$ ]] || _sshp=22
        _panelp="$(cfg_field port)"
        if [[ "$_panelp" =~ ^[0-9]{1,5}$ ]]; then
            gen_initial_rules "$_sshp" "$_panelp" "$ETC_DIR/rules.json"
        fi
        install_service
        log_info "升级完成 ✓ 配置/规则已保留；页面请强制刷新（Ctrl+F5）"
        _print_panel_url
        return 0
    fi
    # 重启服务（v3.2.40：显式 restart + 回读校验，取代旧版只看 restart 返回码的逻辑；
    # 旧逻辑对「服务原本就在跑」的情况可能重启不生效，升级后仍是旧代码）
    if ! start_panel_service; then
        log_error "服务未启动成功，请检查: journalctl -u $SERVICE_NAME -n 50 --no-pager"
        exit 1
    fi
    verify_panel_http || true
    log_info "服务已重启（v$(installed_panel_version)）"
    log_info "升级完成 ✓ 配置/规则已保留；页面请强制刷新（Ctrl+F5）"
    _print_panel_url
}

do_check() {
    cleanup_plaintext_credentials    # 任何需要 root 的入口都顺手清掉旧版明文凭据文件（幂等）
    local pv; pv="$(installed_panel_version)"
    echo "================== $SCRIPT_NAME 环境体检 =================="
    echo "  安装脚本 : v$SCRIPT_VERSION"
    if [ -n "$pv" ]; then
        echo "  已装面板 : v$pv"
    fi
    check_os; check_root; check_arch; check_tools; check_existing check
    echo "==========================================================================="
    echo "体检通过。安装/升级请重跑一键命令（或直接回车使用菜单）："
    echo "  curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/main/install.sh | sudo bash"
}

# ============================== 参数解析 ==============================

usage() {
    cat <<EOF
$SCRIPT_NAME（安装脚本 v$SCRIPT_VERSION）—— 简易VPS管理面板2.0（Debian 13 · nftables）

用法:
  sudo bash $0                           交互式菜单：安装正式版/测试版/指定版本、环境体检、改用户名密码、查看登录信息、卸载
  sudo bash $0 -y                        无人值守：跳过菜单与凭据询问，直接装/升【最新正式版】
                                          （首次安装默认询问是否自定义用户名/密码，回车=随机）
  sudo bash $0 --beta                    安装/升级【最新测试版】（尝鲜通道）
  sudo bash $0 -p 17890                  指定面板端口
  sudo bash $0 --bind 127.0.0.1          仅本机访问（默认 0.0.0.0 开放远程）
  sudo bash $0 --user admin --password x  指定登录凭据
  sudo bash $0 --check                   仅体检环境
  sudo bash $0 --version v1.24.42        指定版本安装/升级/回退（如回退到 v1.24.42）
  sudo bash $0 --change-password         重置面板密码（交互式）
  sudo bash $0 --uninstall               卸载（停服务 + 删文件）
  sudo bash $0 --purge               卸载（停服务 + 删文件）
  sudo bash $0 --update-script            升级本地缓存的安装脚本（fwp 用的那份；菜单 9 同效）
  fwp                                    已装面板后可用：直接打开上面的交互式菜单（脚本缓存于 $APP_DIR/$CACHED_SCRIPT_NAME）

选项:
  -p, --port PORT     面板端口（默认随机 17000-19999）
      --bind IP       监听地址（默认 0.0.0.0 开放远程访问）
      --user NAME     登录用户名（默认随机 8 位）
      --password PASS 登录密码，≥8 位（默认随机 16 位强密码）
      --open-port P   安装后立即开放端口给公网（逗号分隔，如 80,443 或 53/udp）
      --beta          安装/升级最新测试版(prerelease)；默认安装最新正式版(Latest)
  -y, --yes           跳过交互菜单（脚本/无人值守用）：直接装最新正式版
      --version V     指定安装/升级到某版本（如 v1.24.42，自动补 v；可回退）
      --force         跳过系统检测
  -h, --help          帮助

环境变量（参数优先）: FW_PORT FW_BIND FW_USER FW_PASS
EOF
}

init_params() {
    PANEL_PORT="${FW_PORT:-}"
    PANEL_BIND="${FW_BIND:-}"
    PANEL_USER="${FW_USER:-}"
    PANEL_PASS="${FW_PASS:-}"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--port)     PANEL_PORT="$2"; shift 2 ;;
            --bind)        PANEL_BIND="$2"; shift 2 ;;
            --user)        PANEL_USER="$2"; shift 2 ;;
            --password)    PANEL_PASS="$2"; shift 2 ;;
            --open-port)   OPEN_PORTS="$2"; shift 2 ;;
            --version)     VERSION_TAG="$2"; shift 2 ;;
            --beta)        BETA=1; shift ;;
            -y|--yes)      YES=1; shift ;;
            --check)       ACTION="check"; shift ;;
            --change-password) ACTION="change-password"; shift ;;
            --update-script) ACTION="update-script"; shift ;;
            -u|--uninstall) ACTION="uninstall"; shift ;;
            --purge)       ACTION="purge"; shift ;;
            --force)       FORCE=1; shift ;;
            -h|--help)     usage; exit 0 ;;
            *) error "未知参数: $1（用 -h 查看帮助）" ;;
        esac
    done
}

gen_password() {
    local pw
    pw="$(head -c 1 /dev/urandom | tr -dc 'A-Z')"
    pw+="$(head -c 1 /dev/urandom | tr -dc 'a-z')"
    pw+="$(head -c 1 /dev/urandom | tr -dc '0-9')"
    pw+="$(head -c 128 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 13)"
    while [ "${#pw}" -lt 16 ]; do pw+="$((RANDOM % 10))"; done
    printf '%s' "${pw:0:16}" | fold -w1 | shuf | tr -d '\n'
}

gen_user() {
    local u
    u="$(head -c 32 /dev/urandom | tr -dc 'a-z0-9' | head -c 8)"
    while [ "${#u}" -lt 8 ]; do
        u+="$((RANDOM % 10))"
    done
    printf '%s' "${u:0:8}"
}

port_in_use() {
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${1}$"
}

# ------------------ 面板进程/服务：状态判定与彻底停止（v3.2.40） ------------------
# 安装/升级/卸载都必须能确认「面板进程是否真的在跑、端口是否真的在听」。
# 旧版只看 systemctl 的返回码与 is-active：遇到孤儿进程（systemd 已不跟踪、进程还活着）
# 就会误判——卸载「成功」却留着进程占端口，安装「成功」却没人监听新端口，
# 于是重装后安装脚本打印的地址打不开（2026-09-17 阿基雷机实测）。
# 注意：全部用 if 判断，不用 `A && B`（set -e 下判定失败会直接退出脚本）。

panel_pids() {   # 运行中的面板进程 PID（按面板程序路径匹配，含 systemd 之外的孤儿进程）
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "$APP_DIR/panel.py" 2>/dev/null || true
    else
        ps -eo pid,args 2>/dev/null | grep -F "$APP_DIR/panel.py" | grep -v grep | awk '{print $1}' || true
    fi
}

port_listening() {   # $1=端口 → 0 = 本机有进程在 LISTEN
    if [ -z "${1:-}" ]; then
        return 1
    fi
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${1}$"
}

panel_http_ok() {   # $1=端口 $2=重试次数(默认15) → 0 = 本机 HTTP 返回 200
    local port="${1:-}" tries="${2:-15}" i=0 code=""
    if [ -z "$port" ]; then
        return 1
    fi
    while [ "$i" -lt "$tries" ]; do
        code="$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://127.0.0.1:${port}/" 2>/dev/null || true)"
        if [ "$code" = "200" ]; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

stop_panel_service() {   # 彻底停止：systemd → TERM → KILL，逐级校验；返回 1 = 仍有进程
    local pids="" i=0
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    while [ "$i" -lt 10 ]; do
        pids="$(panel_pids)"
        if [ -z "$pids" ]; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done
    pids="$(panel_pids)"
    if [ -n "$pids" ]; then
        log_warn "systemd 停止未生效（孤儿进程），强制结束: $pids"
        printf '%s\n' "$pids" | xargs -r kill 2>/dev/null || true
        sleep 2
    fi
    pids="$(panel_pids)"
    if [ -n "$pids" ]; then
        log_warn "TERM 无效，改用 SIGKILL: $pids"
        printf '%s\n' "$pids" | xargs -r kill -9 2>/dev/null || true
        sleep 1
    fi
    pids="$(panel_pids)"
    if [ -n "$pids" ]; then
        log_error "面板进程无法结束（PID: $pids）——请手动执行: kill -9 $pids"
        return 1
    fi
    return 0
}

start_panel_service() {   # 停旧 → restart → 等 active；返回 1 = 没起来（日志已打印）
    local i=0
    if [ -n "$(panel_pids)" ]; then
        log_warn "检测到面板进程已在运行，先停止以便加载新代码/新配置..."
        stop_panel_service || true
    fi
    systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    while [ "$i" -lt 20 ]; do
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    log_error "服务未进入 active 状态，最近日志："
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null | tail -20 || true
    return 1
}

verify_panel_http() {   # 回读校验：config.json 里的端口必须真的能访问；返回 1 = 没通过
    local rport=""
    rport="$(cfg_field port)"
    if panel_http_ok "$rport" 15; then
        log_info "自检通过：面板正在监听 http://127.0.0.1:${rport}（本机 HTTP 200）"
        return 0
    fi
    log_warn "自检未通过：端口 ${rport:-?} 本机未返回 200"
    log_warn "  占用检查: ss -tlnp | grep ${rport:-端口}"
    log_warn "  看日志  : journalctl -u $SERVICE_NAME -n 50 --no-pager"
    return 1
}

resolve_params() {
    [ -n "$PANEL_BIND" ] || PANEL_BIND="0.0.0.0"
    if [ -z "$PANEL_PORT" ]; then
        # 默认随机端口 17000-19999（每次安装不同，安装结束一并打印）
        local p
        while :; do
            p=$((RANDOM % 3000 + 17000))
            port_in_use "$p" || { PANEL_PORT="$p"; break; }
        done
    fi
    [[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] || error "端口必须为数字: $PANEL_PORT"
    port_in_use "$PANEL_PORT" && error "端口 $PANEL_PORT 已被占用，请换一个"
    [ -n "$PANEL_USER" ] || PANEL_USER="$(gen_user)"
    [ -n "$PANEL_PASS" ] || PANEL_PASS="$(gen_password)"
    [ "${#PANEL_PASS}" -ge 8 ] || error "密码至少 8 位"
    [[ "$PANEL_USER" =~ ^[A-Za-z0-9_]{3,32}$ ]] || error "用户名需为 3-32 位字母数字"
}

# ============================== 安装 ==============================

install_deps() {
    # 缺什么装什么（最小化安装可能没有 python3/nftables/curl/wget），按发行版选择包管理器
    local pkgs=()
    if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
        pkgs+=("$PY_PKG")
    fi
    command -v nft >/dev/null 2>&1 || pkgs+=("nftables")
    command -v curl >/dev/null 2>&1 || pkgs+=("curl")
    command -v wget >/dev/null 2>&1 || pkgs+=("wget")
    if [ "${#pkgs[@]}" -gt 0 ]; then
        log_info "安装依赖（$PKG_MGR）: ${pkgs[*]} ..."
        case "$PKG_MGR" in
            apt)
                apt-get update -y
                DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
                ;;
            pacman)
                pacman -Sy --noconfirm "${pkgs[@]}"
                ;;
            dnf)
                dnf install -y "${pkgs[@]}"
                ;;
            *)
                error "未检测到支持的包管理器，请手动安装: ${pkgs[*]}"
                ;;
        esac
    fi
    log_info "依赖就绪（python3 + nftables）"
}

download_file() {
    local dest="$1" url="$2" expect_hex="${3:-}"
    # 硬超时：DNS/线路被黑洞时 curl 自己不会返回（--connect-timeout 覆盖不到 getaddrinfo 卡死）
    run_with_timeout 90 curl -fsSL --connect-timeout 10 --retry 2 -o "$dest" "$url" || return 1
    [ -s "$dest" ] || return 1
    # 内容头校验（hex 前缀）：镜像返回 HTML 错误页时拒绝，防止覆盖真实文件
    if [ -n "$expect_hex" ]; then
        local nbytes=$(( ${#expect_hex} / 2 ))
        local head_hex
        head_hex="$(head -c "$nbytes" "$dest" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        [ "$head_hex" = "$expect_hex" ] || return 1
    fi
    return 0
}

# 下载源 tag：--version 指定 > --beta(最新测试版) > 最新正式版(Latest release)；API 失败回退 main
# ------------------------- GitHub JSON 解析（不依赖 python3） -------------------------
# ⚠ 全新最小系统（Debian netinst / 容器 / 精简云镜像）常常没有 python3，而标签解析发生在
#   install_deps 之前——直接调 python3 会以 127 挂掉整个安装（v3.2.8 真机踩坑：横幅之后
#   只有一行「异常退出（退出码 127）」，退出码还被 2>/dev/null 吞掉看不到原因）。
#   这里一律「有 python3 用它，没有就用 sed/awk」，且永远返回 0，让安装能继续走到装依赖那步。
# ⚠⚠ 另一个坑（v3.2.10 真机 --beta 踩坑）：**必须先把 stdin 读完（drain）再解析**。
#   解析器一旦提前退出（awk 的 exit / head -1），上一条命令（`printf | 解析器` 里的 printf）
#   会被 SIGPIPE 杀掉 → 退出码 141 → set -o pipefail + set -e 直接判整个安装失败；
#   GitHub 的真实响应（20 个 release 带 assets）远大于 64KB 管道缓冲，几乎必现，
#   而几百字节的假数据测不出来。解析统一改成「cat 读完 → here-string 喂给解析器」。
json_tag_latest() {
    # stdin: releases/latest 的 JSON  →  输出 tag_name（失败输出空）
    local data; data="$(cat 2>/dev/null || true)"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("tag_name") or "")
except Exception: pass' <<< "$data" 2>/dev/null || true
        return 0
    fi
    command -v awk >/dev/null 2>&1 || return 0
    awk -v RS='}' '
        match($0, /"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"/) {
            t = substr($0, RSTART, RLENGTH); gsub(/^[^:]*:[[:space:]]*"/, "", t); gsub(/".*$/, "", t); print t; exit
        }
    ' <<< "$data" 2>/dev/null || true
}

json_tag_prerelease() {
    # stdin: releases?per_page=N 的 JSON 列表  →  输出第一个 prerelease=true 的 tag_name
    local data; data="$(cat 2>/dev/null || true)"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys,json
try:
    for r in json.load(sys.stdin):
        if r.get("prerelease") and r.get("tag_name"):
            print(r["tag_name"]); break
except Exception: pass' <<< "$data" 2>/dev/null || true
        return 0
    fi
    command -v awk >/dev/null 2>&1 || return 0
    # 无 python3：按 '}' 切记录滑动扫描——记住最近一个 tag_name，遇到第一个 "prerelease": true 就输出。
    # 这样对 GitHub 的多行美化 JSON 和压缩成单行的 JSON 都成立（assets 内嵌套对象也不含 tag_name）。
    awk -v RS='}' '
        match($0, /"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"/) {
            t = substr($0, RSTART, RLENGTH); gsub(/^[^:]*:[[:space:]]*"/, "", t); gsub(/".*$/, "", t)
        }
        /"prerelease"[[:space:]]*:[[:space:]]*true/ { if (t != "") { print t; exit } }
    ' <<< "$data" 2>/dev/null || true
}

valid_tag() {
    # tag 必须是 v1.2.3 / 1.2.3 这类，防解析残渣当版本号用
    [ -n "${1:-}" ] || return 1
    case "$1" in *[!A-Za-z0-9._-]*) return 1 ;; esac
    return 0
}

resolve_src_tag() {
    [ -n "$SRC_TAG" ] && return 0    # 父 shell 已解析(幂等);命令替换子 shell 里 SRC_TAG 永远为空,不做缓存判断
    if [ -n "$VERSION_TAG" ]; then
        case "$VERSION_TAG" in v*) SRC_TAG="$VERSION_TAG" ;; *) SRC_TAG="v$VERSION_TAG" ;; esac
        return
    fi
    local json tag
    if [ "$BETA" = "1" ]; then
        json="$(run_with_timeout 20 curl -fsSL --connect-timeout 10 --retry 1 "https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=20" 2>/dev/null || true)"
        tag="$(printf '%s' "$json" | json_tag_prerelease)"
        if ! valid_tag "$tag"; then
            error "暂未找到更新的测试版(beta)；如需要请安装最新正式版"
        fi
        SRC_TAG="$tag"
    else
        json="$(run_with_timeout 20 curl -fsSL --connect-timeout 10 --retry 1 "https://api.github.com/repos/jacksonchowspare/fwpanel2/releases/latest" 2>/dev/null || true)"
        tag="$(printf '%s' "$json" | json_tag_latest)"
        if valid_tag "$tag"; then
            SRC_TAG="$tag"
        else
            SRC_TAG="main"
            log_warn "解析最新正式版失败（网络/限流/解析器缺失），回退主线 main（可能包含未转正改动）"
        fi
    fi
}
src_tag() {
    printf '%s' "${SRC_TAG:-main}"
}

# ------------------- 版本显示：始终以「面板版本」为主语 -------------------
# 安装脚本永远从 main 分支取（修 bug 立即对所有通道生效），所以 SCRIPT_VERSION 是**脚本**的版本，
# 不是即将安装的**面板**版本。横幅必须把两者分开写清楚，否则用户会把脚本版本当成面板版本。
target_version() {
    printf '%s' "${SRC_TAG:-main}"
}

tag_release_channel() {
    # $1 = tag  →  正式版 / 测试版 / 空（该 tag 没有 release 或查询失败）
    # 指定版本安装时，用户需要知道这个版本本身是正式版还是测试版（而不是笼统的「指定版本」）。
    # 只查这一个 tag，查不到就由调用方回退成「指定版本」——绝不因为这次查询失败影响安装。
    local tag="$1" data pre
    [ -n "$tag" ] || return 0
    [ "$tag" = "main" ] && return 0
    data="$(run_with_timeout 15 curl -fsSL --connect-timeout 8 --retry 1 \
        "https://api.github.com/repos/jacksonchowspare/fwpanel2/releases/tags/$tag" 2>/dev/null || true)"
    [ -n "$data" ] || return 0
    pre="$(awk -F: '/"prerelease"[[:space:]]*:/ { gsub(/[^a-z]/, "", $2); print $2; exit }' <<< "$data" 2>/dev/null || true)"
    case "$pre" in
        true)  printf '测试版' ;;
        false) printf '正式版' ;;
    esac
}

target_channel_label() {
    if [ -n "$VERSION_TAG" ]; then
        local ch; ch="$(tag_release_channel "$(target_version)")"
        if [ -n "$ch" ]; then printf '%s' "$ch"; else printf '指定版本'; fi
    elif [ "$BETA" = "1" ]; then
        printf '最新测试版'
    else
        printf '最新正式版'
    fi
}

print_banner() {
    local ver label; ver="$(target_version)"
    case "$ver" in
        main)   label="主线 · API 解析失败回退，未转正代码" ;;
        [0-9]*) ver="v$ver"; label="$(target_channel_label)" ;;
        *)      label="$(target_channel_label)" ;;
    esac
    echo "================== $SCRIPT_NAME =================="
    echo "  安装脚本 : v$SCRIPT_VERSION（本脚本自身版本，非面板版本）"
    echo "  目标版本 : 面板 $ver（$label）"
    echo "=================================================="
}

prompt_read() {   # $1=变量名 $2=提示语 $3=1 表示不回显（密码）
    local __v=""
    [ -n "$MENU_SRC" ] || menu_can_read || return 1
    printf '%s' "$2"
    if [ "${3:-}" = "1" ]; then
        case "$MENU_SRC" in
            tty)   IFS= read -rs __v < /dev/tty || true ;;
            stdin) IFS= read -rs __v || true ;;
        esac
        printf '\n'
    else
        case "$MENU_SRC" in
            tty)   IFS= read -r __v < /dev/tty || true ;;
            stdin) IFS= read -r __v || true ;;
        esac
    fi
    printf -v "$1" '%s' "$__v"
    return 0
}

# ------------------------- 首次安装：可自定义登录凭据 -------------------------
# 只在这四个条件同时成立时询问：首次安装（check_existing 判定为未安装）+ 没给 --user/--password
# + 有可读终端 + 没加 -y。非交互场景（systemd/cron/CI/管道无终端/-y）一律静默随机生成，绝不阻塞。
ask_custom_credentials() {
    [ "$ACTION" = "install" ] || return 0
    [ "$YES" = "1" ] && return 0
    if [ -n "$PANEL_USER" ] || [ -n "$PANEL_PASS" ]; then
        return 0                     # 命令行已指定（--user/--password），尊重参数
    fi
    menu_can_read || return 0        # 无终端：直接随机

    local ans="" u1="" u2="" p1="" p2="" tries=0
    echo ""
    echo "  首次安装：面板登录凭据"
    echo "    默认随机生成（安装结束时打印一次，不写入任何文件）"
    prompt_read ans "  是否自行设定用户名和密码？(yes/no，直接回车 = no 随机生成): " || return 0
    case "$ans" in
        y|Y|yes|YES|Yes) ;;
        *) log_info "已选择：随机生成用户名和密码"; return 0 ;;
    esac

    while :; do
        prompt_read u1 "  请输入用户名（3-32 位字母/数字/下划线）: " || return 0
        if [[ "$u1" =~ ^[A-Za-z0-9_]{3,32}$ ]]; then
            prompt_read u2 "  请再次输入用户名: " || return 0
            if [ "$u1" = "$u2" ]; then
                PANEL_USER="$u1"
                break
            fi
            log_warn "两次输入的用户名不一致，请重新输入"
        else
            log_warn "用户名需为 3-32 位字母/数字/下划线，请重新输入"
        fi
        tries=$((tries + 1))
        [ "$tries" -ge 3 ] && error "用户名输入有误（已重试 3 次）；可改用 --user 参数，或重跑后选随机凭据"
    done

    tries=0
    while :; do
        prompt_read p1 "  请输入密码（至少 8 位）: " 1 || return 0
        if [ "${#p1}" -ge 8 ]; then
            prompt_read p2 "  请再次输入密码: " 1 || return 0
            if [ "$p1" = "$p2" ]; then
                PANEL_PASS="$p1"
                break
            fi
            log_warn "两次输入的密码不一致，请重新输入"
        else
            log_warn "密码至少 8 位，请重新输入"
        fi
        tries=$((tries + 1))
        [ "$tries" -ge 3 ] && error "密码输入有误（已重试 3 次）；可改用 --password 参数"
    done
    log_info "已使用你设定的凭据（用户名: $PANEL_USER，密码不回显、安装结束会再打印一次）"
}

installed_panel_version() {
    # 已装面板的真实版本（权威来源是磁盘上的 panel.py，不是脚本常量）
    local p="${1:-$APP_DIR/panel.py}"
    [ -f "$p" ] || return 0
    sed -n 's/^CURRENT_VERSION[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$p" 2>/dev/null | head -n 1 || true
}

# ------------------------- 登录信息查看（不保存明文密码） -------------------------
# 面板只保存 pbkdf2 哈希，明文密码无法反查 —— 所以这里只显示地址/用户名，密码只能“重设”。
# v3.2.16/3.2.17 曾把明文写到 $ETC_DIR/credentials.json；本版本起不再保存，重跑脚本时清理遗留文件。
do_update_script() {
    # 显式升级本地缓存的安装脚本（fwp 用的那份）；菜单 9 / 菜单 10 / --update-script 触发
    # $1 = 已知的线上最新版本（可选；菜单里已经查过就传进来，省一次联网）
    check_root
    local cache="$APP_DIR/$CACHED_SCRIPT_NAME" tmp newv ok="0" src="" known="${1:-}" got="0" tag_srcs="" v
    tmp="$(mktemp)"
    log_info "正在获取最新安装脚本（最多 25 秒，失败不影响本地使用）..."
    # 多源回退：GitHub 直连 → jsDelivr → ghproxy。
    # 只用 raw 一条路时，国内线路拿不到、或刚发版 CDN 还没同步，都会让"升级脚本"看起来没反应
    # （用户实测：按 9 之后重开还是旧脚本）。
    # 知道线上新版号时**直接按 tag 取**：刚发版时 main 的 CDN 往往还没同步
    # （实测：推送 v3.2.36 后 raw/jsDelivr/ghproxy 三家 @main 都还是 3.2.35，@v3.2.36 已经就绪）。
    # tag 地址没有这个延迟，所以先试 tag，再退回 main。
    local tag_srcs=""
    if [ -n "$known" ] && version_gt "$known" "$SCRIPT_VERSION"; then
        tag_srcs="https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/v$known/$CACHED_SCRIPT_NAME
https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel2@v$known/$CACHED_SCRIPT_NAME
https://ghproxy.net/https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/v$known/$CACHED_SCRIPT_NAME"
    fi
    for v in $tag_srcs \
             "$RAW_INSTALL_URL" \
             "https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel2@main/$CACHED_SCRIPT_NAME" \
             "https://ghproxy.net/$RAW_INSTALL_URL"; do
        ok="0"
        if command -v curl >/dev/null 2>&1; then
            run_with_timeout 25 curl -fsSL -o "$tmp" "$v" 2>/dev/null && ok="1"
        fi
        if [ "$ok" != "1" ] && command -v wget >/dev/null 2>&1; then
            run_with_timeout 25 wget -q -O "$tmp" "$v" 2>/dev/null && ok="1"
        fi
        [ "$ok" = "1" ] && got="1"
        if [ "$ok" = "1" ] && [ -s "$tmp" ] && grep -q "SCRIPT_VERSION=" "$tmp" 2>/dev/null \
           && bash -n "$tmp" 2>/dev/null; then
            src="$v"
            break
        fi
        ok="0"
    done
    if [ "$ok" != "1" ] || [ -z "$src" ]; then
        rm -f "$tmp"
        if [ "$got" = "1" ]; then
            # 源连得上但内容不是脚本（404 页面/半截文件）—— 提示要和"完全连不上"区分开
            log_error "下载内容校验失败（错误页面或半截文件），本地缓存未改动。"
        else
            log_error "获取失败（GitHub 直连 / jsDelivr / ghproxy 都没拿到）。本地缓存未改动，fwp 仍可正常使用。"
        fi
        return 1
    fi
    if [ "$src" != "$RAW_INSTALL_URL" ]; then
        log_info "GitHub 直连不通，已改用备用源获取。"
    fi
    newv="$(grep -m1 -o 'SCRIPT_VERSION="[0-9.]*"' "$tmp" | tr -d '"' | cut -d= -f2)"

    # 线上最新版本：菜单里查过就用它，命令行调用时自己查一次（各 4 秒上限，失败不挡事）
    if [ -z "$known" ]; then
        known="$(menu_preview_tag stable)"; known="${known#v}"
        v="$(menu_preview_tag beta)"; v="${v#v}"
        if [ -n "$v" ] && { [ -z "$known" ] || version_gt "$v" "$known"; }; then known="$v"; fi
    fi

    # 绝不降级：备用源/镜像可能还在发旧内容，别把本地好好的脚本换成旧的
    if version_gt "$SCRIPT_VERSION" "$newv"; then
        rm -f "$tmp"
        log_warn "下载到的是较旧版本 v$newv（本地 v$SCRIPT_VERSION），已保留本地脚本。"
        return 1
    fi

    mkdir -p "$APP_DIR"
    chmod 0755 "$tmp"
    mv -f "$tmp" "$cache"
    # 顺手刷新快捷命令本体：老版本机器不必重装面板（不重启服务）就能拿到修好的 fwp
    write_shortcut_wrapper
    if [ "$newv" != "$SCRIPT_VERSION" ]; then
        log_info "脚本已更新：v$SCRIPT_VERSION → v$newv（菜单里选 9 时会立刻用新版重开）"
        return 0
    fi
    # 下载到的版本和本地一样：若线上其实已发布更新的版本，那就是下载源还没同步 —— 说清楚，
    # 别只说一句"已是最新"让用户以为升级失败（用户实测的困惑点）
    if [ -n "$known" ] && version_gt "$known" "$newv"; then
        log_warn "线上已发布 v$known，但各下载源目前给出的还是 v$newv（CDN 同步有延迟）"
        log_warn "→ 等 1-2 分钟再按一次 9；着急的话直接升级面板（菜单 2 / 10）也会顺带刷新脚本"
    else
        log_info "已是最新（脚本 v$SCRIPT_VERSION）"
    fi
    return 0
}

write_shortcut_wrapper() {   # 生成/刷新 $WRAPPER_PATH（缓存路径与地址用占位符展开，避免 heredoc 里转义 $）
# 快捷命令本体：只用本地缓存秒开菜单；缓存缺失才联网（带硬超时），更新脚本走菜单 9
# ⚠ 包装器设计铁律：显示菜单前绝不联网。曾经在启动时静默刷新缓存，结果
#    网络（DNS/线路）被黑洞时 curl 卡死不返回 → 用户输入 fwp 后一片空白、只能 Ctrl+C。
cat > "$WRAPPER_PATH" <<'WRAPPER_EOF'
#!/bin/sh
# fwp —— fwpanel2 安装/管理菜单快捷入口（由 install.sh 自动生成，卸载面板时一并删除）
# 设计：本地有缓存就直接秒开菜单（离线可用）；只有缓存缺失时才联网，且带硬超时 + 明确提示。
CACHE="__CACHE__"
URL="__URL__"

if [ ! -s "$CACHE" ]; then
echo "[fwp] 本地没有脚本缓存，正在获取（最多 10 秒/源，会自动换源）..." >&2
tmp="$(mktemp)"
ok=0
# 多源回退：raw → jsDelivr → ghproxy（国内线路只走 raw 常常拿不到）
for U in "$URL" "https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel2@main/install.sh" "https://ghproxy.net/$URL"; do
    ok=0
    if command -v curl >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then timeout 10 curl -fsSL -o "$tmp" "$U" && ok=1
        else curl -fsSL -m 10 -o "$tmp" "$U" && ok=1; fi
    fi
    if [ "$ok" != "1" ] && command -v wget >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then timeout 10 wget -q -O "$tmp" "$U" && ok=1
        else wget -q -T 10 -O "$tmp" "$U" && ok=1; fi
    fi
    [ "$ok" = "1" ] && [ -s "$tmp" ] && grep -q 'SCRIPT_VERSION=' "$tmp" 2>/dev/null && break
    ok=0
done
if [ "$ok" = "1" ] && [ -s "$tmp" ] && grep -q 'SCRIPT_VERSION=' "$tmp" 2>/dev/null \
   && { ! command -v bash >/dev/null 2>&1 || bash -n "$tmp" 2>/dev/null; }; then
    mkdir -p "$(dirname "$CACHE")" 2>/dev/null || true
    chmod 0755 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$CACHE" || rm -f "$tmp"
else
    rm -f "$tmp"
    echo "[fwp] 获取脚本失败（网络不通或 GitHub 不可达）" >&2
    echo "       请重新执行一键安装命令，或检查网络后重试" >&2
    exit 1
fi
fi

# 显式请求更新脚本：先自己抓最新脚本放进缓存，再交给它跑 --update-script。
# 这样即使本地缓存是"没有菜单、也没有 --update-script"的老脚本（用户实测踩到），这条命令也能用。
case "${1:-}" in
    --update-script|update-script)
        # 缓存是 root 所有的 /usr/local/lib 下的文件：非 root 直接替换会撞上
        # "mv: replace …, overriding mode 0755?" 交互提问（且答 yes 也是 Permission denied）。
        # 所以先自己提权重跑一次，在 root 下完成下载/替换。
        if [ "$(id -u)" != "0" ] && { [ ! -w "$CACHE" ] || [ ! -w "$(dirname "$CACHE")" ]; }; then
            if command -v sudo >/dev/null 2>&1; then
                echo "[fwp] 脚本缓存需要 root 权限，正在通过 sudo 提权..." >&2
                exec sudo sh "$0" --update-script
            fi
            echo "[fwp] 需要 root 权限才能更新 $CACHE，请用：sudo fwp --update-script" >&2
            exit 1
        fi
        echo "[fwp] 正在获取最新安装脚本..." >&2
        tmp="$(mktemp)"
        ok=0
        if command -v curl >/dev/null 2>&1; then
            if command -v timeout >/dev/null 2>&1; then timeout 25 curl -fsSL -o "$tmp" "$URL" && ok=1
            else curl -fsSL -m 25 -o "$tmp" "$URL" && ok=1; fi
        fi
        if [ "$ok" != "1" ] && command -v wget >/dev/null 2>&1; then
            if command -v timeout >/dev/null 2>&1; then timeout 25 wget -q -O "$tmp" "$URL" && ok=1
            else wget -q -T 25 -O "$tmp" "$URL" && ok=1; fi
        fi
        if [ "$ok" = "1" ] && [ -s "$tmp" ] && grep -q 'SCRIPT_VERSION=' "$tmp" 2>/dev/null; then
            mkdir -p "$(dirname "$CACHE")" 2>/dev/null || true
            chmod 0755 "$tmp" 2>/dev/null || true
            mv -f "$tmp" "$CACHE" || rm -f "$tmp"
        else
            rm -f "$tmp"
            echo "[fwp] 下载脚本失败（网络不通或 GitHub 不可达），本地缓存未改动" >&2
            exit 1
        fi
        exec bash "$CACHE" --update-script ;;
esac

# 本地缓存是"没有菜单"的老脚本时给明确提示（否则用户会困惑：为什么 fwp 没有菜单）
if ! grep -q 'interactive_channel_menu' "$CACHE" 2>/dev/null; then
    echo "[fwp] 提示：本地脚本是旧版（没有菜单，也不支持 --update-script）。" >&2
    echo "       运行 sudo fwp --update-script 可更新脚本（会自动联网获取最新版）" >&2
fi

if [ "$(id -u)" -eq 0 ]; then
exec bash "$CACHE" "$@"
fi
if command -v sudo >/dev/null 2>&1; then
echo "[fwp] 需要 root 权限，正在通过 sudo 提权（可能会提示输入密码）" >&2
exec sudo bash "$CACHE" "$@"
fi
echo "[fwp] 需要 root 权限：请用 sudo fwp" >&2
exit 1
WRAPPER_EOF
# 把占位符换成真实路径（避免 heredoc 里到处转义 $）
sed -i -e "s|__CACHE__|$APP_DIR/$CACHED_SCRIPT_NAME|g" -e "s|__URL__|$RAW_INSTALL_URL|g" "$WRAPPER_PATH" 2>/dev/null || true
chmod 0755 "$WRAPPER_PATH" 2>/dev/null || true
}

install_shortcut() {   # $1（可选）= 已知可用的新版脚本地路径（如升级流程刚下载的那份）
    # 生成快捷命令 fwp：以后直接敲 fwp 就能进菜单，不用再翻一键安装命令
    local cache="$APP_DIR/$CACHED_SCRIPT_NAME" tmp ok="0" known="${1:-}" cached_ver=""

    mkdir -p "$APP_DIR" /usr/local/bin 2>/dev/null || true
    tmp="$(mktemp)"

    # ① 首选调用方给的本地副本（免联网；管道升级流程手上就有现成的新版）
    if [ -n "$known" ] && [ -s "$known" ] && grep -q 'SCRIPT_VERSION=' "$known" 2>/dev/null && bash -n "$known" 2>/dev/null; then
        cp "$known" "$tmp" 2>/dev/null && ok="1"
    fi
    # ② 实体脚本方式运行（sudo bash install.sh）：直接把自己复制成缓存
    if [ "$ok" != "1" ] && [ -f "$0" ] && [ "$0" != "$cache" ]; then
        cp "$0" "$tmp" 2>/dev/null && ok="1"
    fi
    # ② 管道方式运行（curl | sudo bash）：$0 是 "bash"，只能按官方地址抓一份
    if [ "$ok" != "1" ]; then
        if command -v curl >/dev/null 2>&1; then
            run_with_timeout 25 curl -fsSL -o "$tmp" "$RAW_INSTALL_URL" 2>/dev/null && ok="1"
        fi
        if [ "$ok" != "1" ] && command -v wget >/dev/null 2>&1; then
            run_with_timeout 25 wget -q -O "$tmp" "$RAW_INSTALL_URL" 2>/dev/null && ok="1"
        fi
    fi

    # 校验后才入库（半截下载/错误页不能覆盖缓存）
    if [ "$ok" = "1" ] && [ -s "$tmp" ] && grep -q "SCRIPT_VERSION=" "$tmp" 2>/dev/null && bash -n "$tmp" 2>/dev/null; then
        chmod 0755 "$tmp"
        mv -f "$tmp" "$cache"
        ok="1"
    else
        rm -f "$tmp"
        ok="0"
        if [ ! -s "$cache" ]; then
            log_warn "未能准备脚本缓存（$cache），fwp 首次运行会尝试联网获取"
        fi
    fi

    write_shortcut_wrapper

    if [ -s "$cache" ] && [ -x "$WRAPPER_PATH" ]; then
        log_info "快捷命令已就绪：以后直接输入 ${C_BOLD}fwp${C_RESET} 即可打开本菜单"
    else
        log_warn "快捷命令未完全就绪（可重跑一键安装命令重试）"
    fi
    # 缓存版本必须与本脚本一致：否则 fwp 打开的是旧脚本（旧版连菜单都没有，用户实测困惑过）
    cached_ver="$(grep -m1 -o 'SCRIPT_VERSION="[0-9.]*"' "$cache" 2>/dev/null | tr -d '"' | cut -d= -f2)"
    if [ -n "$cached_ver" ] && [ "$cached_ver" != "$SCRIPT_VERSION" ]; then
        log_warn "脚本缓存版本不一致：缓存 v$cached_ver / 当前 v$SCRIPT_VERSION"
        log_warn "→ 请运行 ${C_BOLD}fwp --update-script${C_RESET} 更新缓存（否则 fwp 打开的仍是旧脚本）"
    fi
}

run_with_timeout() {   # $1=秒数，其余=要执行的命令；硬超时（能杀掉卡在 DNS/getaddrinfo 的进程）
    local secs="$1"; shift
    [ "$#" -gt 0 ] || return 1
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
        return $?
    fi
    # 极简系统没有 coreutils timeout（Debian/Ubuntu 默认都有）：退化为直接执行，
    # 由各命令自身的超时参数兜底（curl 都带 --connect-timeout）。
    # 不自己造一个假的定时器：早期版本用 sleep+kill 实现，碰上 sleep 缺失的环境会
    # 变成「立刻杀」，反而把正常的下载掐断（实测踩过）。
    "$@"
}


atomic_put() {   # $1=源文件 $2=目标文件 $3=权限（默认 644）
    # 先写同目录临时文件再 mv -f 原子替换。⚠ 别直接 cp 覆盖正在被面板读取的静态文件：
    # cp 是"先截断再写"，升级时正好打开面板就会拿到半截 index.html → 内联脚本语法错误 →
    # 登录页弹"页面加载受阻"（用户实测）。
    local src="$1" dst="$2" mode="${3:-644}" tmp
    [ -s "$src" ] || return 1
    tmp="$(dirname "$dst")/.$(basename "$dst").new.$$"
    install -m "$mode" "$src" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$dst"
}

atomic_put_dir() {   # $1=源目录 $2=目标目录：逐个原子替换（不动源里没有的旧文件）
    local src="$1" dst="$2" f
    [ -d "$src" ] || return 0
    mkdir -p "$dst"
    for f in "$src"/*; do
        [ -f "$f" ] || continue
        atomic_put "$f" "$dst/$(basename "$f")" 644 || log_warn "部署失败: $(basename "$f")"
    done
}

cleanup_plaintext_credentials() {
    if [ -f "$ETC_DIR/credentials.json" ]; then
        rm -f "$ETC_DIR/credentials.json" "$ETC_DIR/credentials.json.tmp" 2>/dev/null || true
        log_warn "已删除旧版本留下的明文凭据文件 $ETC_DIR/credentials.json（新版本不再保存明文密码）"
    fi
}


cfg_field() {   # $1=config.json 字段名 → 输出值（失败输出空）
    python3 - "$ETC_DIR/config.json" "$1" <<'EOF' 2>/dev/null || true
import json, sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))
except Exception:
    pass
EOF
}

do_show_login_info() {
    check_root
    cleanup_plaintext_credentials    # 任何需要 root 的入口都顺手清掉旧版明文凭据文件（幂等）
    [ -f "$ETC_DIR/config.json" ] || error "面板未安装，无法查看登录信息"

    local ip port bind user domain ans
    ip="$({ ip route get 1.1.1.1 2>/dev/null || true; } | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1 || true)"
    [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$ip" ] || ip="<服务器IP>"
    port="$(cfg_field port)"
    bind="$(cfg_field bind)"
    user="$(cfg_field username)"

    echo ""
    echo "  面板地址 : http://${ip}:${port}"
    if [ "$bind" = "127.0.0.1" ]; then
        echo "             （配置为仅本机监听：本机 ssh -L ${port}:127.0.0.1:${port} root@${ip} 后访问 127.0.0.1:${port}）"
    fi
    if [ -f "$ETC_DIR/proxies.json" ]; then
        domain="$(python3 - "$ETC_DIR/proxies.json" "$port" <<'EOF' 2>/dev/null || true
import json, sys
try:
    ps = json.load(open(sys.argv[1]))
except Exception:
    ps = []
port = str(sys.argv[2])
for p in (ps if isinstance(ps, list) else []):
    if str(p.get("target_port")) == port and p.get("domain"):
        scheme = "https" if (p.get("ssl") or p.get("cert_ref")) else "http"
        print(f"{scheme}://{p['domain']}")
EOF
)"
        if [ -n "$domain" ]; then
            echo "  反代地址 : $domain"
        fi
    fi
    echo "  用户名   : ${user:-（未设置）}"
    echo "  密码     : 不保存明文（面板只存 pbkdf2 哈希，无法反查）—— 忘记就重设一个"
    echo ""
    echo "  要现在重设用户名/密码：按 r 回车（等同菜单 5）；直接回车返回。"
    if menu_can_read; then
        printf '  请输入: '
        ans=""
        menu_read ans || ans=""
        case "$ans" in
            r|R)
                echo ""
                do_change_password
                ;;
        esac
    fi
    echo ""
}

# ------------------------- 交互式版本选择菜单 -------------------------
# 只在这三种条件同时成立时出现：无 --beta / --version 参数 + 有可用终端 + 没加 --yes。
# 让用户直接选通道，不用记 --beta / --version。
# ⚠⚠ 管道模式（curl | sudo bash）下 stdin 就是脚本自身，**绝不能 read stdin**——必须走 /dev/tty，
#   否则会把脚本剩余内容当输入吃掉。systemd / cron / CI 里没有控制终端 → 自动跳过菜单，
#   保持原默认行为（装最新正式版），永远不会卡在等输入上。
MENU_SRC=""

menu_can_read() {
    MENU_SRC=""
    if [ -n "${FW_MENU:-}" ]; then MENU_SRC="stdin"; return 0; fi   # 测试/自动化喂输入用
    if { : < /dev/tty; } 2>/dev/null; then MENU_SRC="tty"; return 0; fi
    if [ -f "$0" ] && [ -t 0 ]; then MENU_SRC="stdin"; return 0; fi
    return 1
}

menu_read() {   # $1 = 接收变量名
    local __v=""
    case "$MENU_SRC" in
        tty)   IFS= read -r __v < /dev/tty || true ;;
        stdin) IFS= read -r __v || true ;;
        *)     return 1 ;;
    esac
    printf -v "$1" '%s' "$__v"
}

version_gt() {   # $1 是否比 $2 新（形如 3.2.34；用 sort -V 比较，缺参数按 0 处理）
    [ -n "$1" ] || return 1
    [ -n "$2" ] || return 0
    [ "$1" = "$2" ] && return 1
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

menu_preview_tag() {   # $1 = stable|beta → 该通道当前最新 tag（查不到输出空，不报错）
    # 只用于菜单上的"最新版本"提示，必须快：硬超时 4 秒（网络被黑洞时不超过 4 秒就放弃）
    local json=""
    if [ "$1" = "beta" ]; then
        json="$(run_with_timeout 4 curl -fsSL --connect-timeout 3 --retry 0 "https://api.github.com/repos/jacksonchowspare/fwpanel2/releases?per_page=20" 2>/dev/null || true)"
        printf '%s' "$json" | json_tag_prerelease
    else
        json="$(run_with_timeout 4 curl -fsSL --connect-timeout 3 --retry 0 "https://api.github.com/repos/jacksonchowspare/fwpanel2/releases/latest" 2>/dev/null || true)"
        printf '%s' "$json" | json_tag_latest
    fi
}

version_input_ok() {
    case "$1" in
        "")            return 1 ;;
        *[!0-9.]*)     return 1 ;;   # 只允许数字和点
        *.*)           return 0 ;;   # 形如 3.1.1
        *)             return 1 ;;
    esac
}

interactive_channel_menu() {
    [ "$ACTION" = "install" ] || return 0
    [ -z "$VERSION_TAG" ] || return 0
    [ "$BETA" = "1" ] && return 0
    [ "$YES" = "1" ] && return 0
    menu_can_read || return 0

    local stable beta_tag cur ans ver tries confirm newv2 tchan newest newest_known=""
    # 先打印一行可见反馈：网络不通时这里最多等 4 秒（失败就不再查第二个通道），
    # 免得用户对着黑屏以为卡死了
    log_info "正在查询最新版本…（网络不通会自动跳过）"
    stable="$(menu_preview_tag stable)"
    if [ -n "$stable" ]; then
        beta_tag="$(menu_preview_tag beta)"
    else
        beta_tag=""      # 正式版都查不到 → 基本可以判定不通网，跳过第二次查询
    fi
    cur="$(installed_panel_version)"

    # 头部（含当前版本）只打印一次；选项每轮重画，4/5/6/7 执行完回到这里继续选
    echo ""
    if [ -n "$cur" ]; then
        echo "  当前已装 : 面板 v$cur"
    fi
    echo "  脚本版本 : v$SCRIPT_VERSION"
    # 线上最新版本比本地脚本新 → 直接提示，省得用户每次还要自己敲命令更新脚本
    local newest="" v
    for v in "$stable" "$beta_tag"; do
        [ -z "$v" ] && continue
        v="${v#v}"
        if [ -z "$newest" ] || version_gt "$v" "$newest"; then newest="$v"; fi
    done
    newest_known="$newest"
    if [ -n "$newest" ] && version_gt "$newest" "$SCRIPT_VERSION"; then
        echo -e "  ${C_YELLOW:-}脚本有新版 : v$newest（按 9 升级脚本，或按 10 连面板一起升）${C_RESET:-}"
    fi
    if [ -x "$WRAPPER_PATH" ]; then
        echo "  快捷入口 : 以后直接输入 fwp 就能回到本菜单（9) 可更新脚本）"
    fi
    if [ -n "$cur" ] || [ -x "$WRAPPER_PATH" ]; then
        echo "  ------------------------------------------------------------"
    fi

    while :; do
        echo "  请选择要执行的操作："
        echo ""
        echo "    1) 安装正式版    最新正式版：${stable:-（查询失败，安装时会重试）}"
        echo "    2) 安装测试版    最新测试版：${beta_tag:-（查询失败，安装时会重试）}"
        echo "    3) 安装指定版本  手动输入版本号（不用带 v，例如 3.1.1）"
        echo "    ------------------------------------------------------------"
        echo "    4) 环境体检      只检查系统环境与依赖，不改动任何东西"
        echo "    5) 改用户名密码  交互式修改面板登录用户名和/或密码（回车 = 该项不改）"
        echo "    6) 卸载          停止服务（含孤儿进程）+ 删程序文件（保留 /etc/fwpanel 配置与规则）"
        echo "    7) 彻底卸载      删程序 + 配置/规则 + 站点文件 + 容器数据 + 证书（不可恢复，需输入 DELETE）"
        echo "    8) 退出脚本      不做任何改动直接退出"
        echo "    9) 升级脚本      把 fwp 用的那份脚本更新到最新（更新完立刻用新脚本重开菜单）"
        echo "   10) 升级脚本+面板 先更新脚本，再用最新脚本把面板升到最新（不用敲命令）"
        echo "   11) 查看登录信息  显示面板登录地址和用户名（需 root；密码不保存，只能重设）"
        echo ""

        printf '  请输入 1 - 11 后回车（直接回车 = 1 安装正式版，8 = 退出，11 = 查看登录信息）: '
        ans=""
        menu_read ans || return 0
        case "$ans" in
            ""|1)  echo ""
                   log_info "已选择：安装正式版"
                   return 0 ;;
            2)     echo ""
                   BETA=1
                   log_info "已选择：安装测试版"
                   return 0 ;;
            3)     echo ""
                   tries=0
                   while :; do
                       printf '  请输入版本号（不用带 v，例如 3.1.1，回车返回菜单）: '
                       ver=""
                       menu_read ver || return 0
                       if [ -z "$ver" ]; then
                           break            # 回车 = 返回主菜单
                       fi
                       ver="${ver#v}"; ver="${ver#V}"
                       if version_input_ok "$ver"; then
                           VERSION_TAG="$ver"
                           log_info "已选择：安装指定版本 v$ver"
                           return 0
                       fi
                       tries=$((tries + 1))
                       if [ "$tries" -ge 3 ]; then
                           error "版本号格式不对（应形如 3.1.1，不用带 v）"
                       fi
                       log_warn "版本号格式不对：$ver（应形如 3.1.1，不用带 v）"
                   done
                   echo "" ;;
            4)     echo ""
                   do_check
                   log_info "体检完成（未做任何改动）"
                   echo "" ;;
            5)     echo ""
                   do_change_password
                   log_info "凭据修改流程结束"
                   echo "" ;;
            6)     echo ""
                   printf '  确认卸载 fwpanel？输入 yes 确认，其他内容取消: '
                   confirm=""
                   menu_read confirm || confirm=""
                   case "$confirm" in
                       y|Y|yes|YES|Yes) do_uninstall; log_info "卸载流程结束" ;;
                       *) log_warn "已取消卸载（未做任何改动）" ;;
                   esac
                   echo "" ;;
            7)     echo ""
                   log_warn "彻底卸载会删除：程序、配置与规则、站点文件、容器数据、证书 —— 全部不可恢复"
                   printf '  确认执行？输入 DELETE 确认，其它任何内容取消: '
                   confirm2=""
                   menu_read confirm2 || confirm2=""
                   if [ "$confirm2" = "DELETE" ]; then
                       do_purge
                       log_info "彻底卸载流程结束"
                   else
                       log_warn "已取消彻底卸载（未做任何改动）"
                   fi
                   echo "" ;;
            11)    echo ""
                   do_show_login_info ;;
            8|q|Q|quit|exit)
                   echo ""
                   log_info "已退出，未做任何改动"
                   exit 0 ;;
            9)     echo ""
                   if do_update_script "$newest_known"; then
                       # 读缓存里的版本：文件可能不存在/读不了，一律当空（失败也不能触发 err_trap）
                       newv2="$(sed -n 's/^readonly SCRIPT_VERSION="\([0-9.]*\)".*/\1/p' \
                           "$APP_DIR/$CACHED_SCRIPT_NAME" 2>/dev/null | head -1 || true)"
                       if [ -n "$newv2" ] && [ "$newv2" != "$SCRIPT_VERSION" ]; then
                           log_info "正在用新脚本 v$newv2 重开菜单…"
                           exec bash "$APP_DIR/$CACHED_SCRIPT_NAME"
                       fi
                   fi
                   echo "" ;;
            10)    echo ""
                   if ! do_update_script "$newest_known"; then
                       log_warn "脚本更新失败（网络/GitHub 不可达）。可稍后重试，或继续用当前脚本升级面板。"
                   fi
                   printf '  升级到哪个通道？1) 正式版  2) 测试版（回车 = 2 测试版）: '
                   tchan=""
                   menu_read tchan || tchan=""
                   echo ""
                   if [ "$tchan" = "1" ]; then
                       log_info "正在用最新脚本升级面板（正式版）…"
                       exec bash "$APP_DIR/$CACHED_SCRIPT_NAME"
                   fi
                   log_info "正在用最新脚本升级面板（测试版）…"
                   exec bash "$APP_DIR/$CACHED_SCRIPT_NAME" --beta ;;
            *)     echo ""
                   log_warn "输入无效：$ans（请填 1 - 11，11 = 查看登录信息）" ;;
        esac
    done
}


fetch_source() {
    # 三级源自动回退：GitHub raw → jsDelivr CDN → ghproxy 镜像（国内友好）+ 内容头校验
    local dest="$1" path="$2" tag expect_hex=""
    tag="$(src_tag)"
    case "$path" in
        *.py)   expect_hex="2321" ;;                        # #!
        *.html) expect_hex="3c21444f43545950452068746d6c3e0a3c68746d6c206c616e673d227a682d434e223e" ;;  # <!DOCTYPE html>\n<html lang="zh-CN">
        *.png)  expect_hex="89504e47" ;;                    # \x89PNG
        *.ico)  expect_hex="00000100" ;;                    # ico 头
        *.woff2) expect_hex="774f4632" ;;                   # wOF2
        *.js)   expect_hex="2166756e6374696f6e" ;;          # !function（UMD 库头）
        *.css)  expect_hex="2f2a" ;;                        # /*（样式表注释头）
    esac
    download_file "$dest" "https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/$tag/$path" "$expect_hex" && return 0
    log_warn "GitHub 直连失败，切换 jsDelivr CDN ..."
    download_file "$dest" "https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel2@$tag/$path" "$expect_hex" && return 0
    log_warn "jsDelivr 失败，切换 ghproxy.net 镜像 ..."
    download_file "$dest" "https://ghproxy.net/https://raw.githubusercontent.com/jacksonchowspare/fwpanel2/$tag/$path" "$expect_hex" && return 0
    return 1
}

deploy_files() {
    log_info "部署程序文件到 $APP_DIR ..."
    local script_dir src_py src_html src_ico tmp_src=""
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
    src_py="$script_dir/panel.py"
    src_html="$script_dir/static/index.html"
    src_ico="$script_dir/static/favicon.ico"

    # 管道一键安装（curl | sudo bash）时只有 install.sh 自身，配套文件需自动下载
    if [ ! -f "$src_py" ] || [ ! -f "$src_html" ]; then
        log_warn "未找到配套文件（管道安装模式），自动下载 panel.py / index.html / favicon.ico ..."
        tmp_src="$(mktemp -d)"
        fetch_source "$tmp_src/panel.py" "panel.py" \
            || error "下载 panel.py 失败，请检查网络，或改用 tar 包安装"
        fetch_source "$tmp_src/index.html" "static/index.html" \
            || error "下载 index.html 失败，请检查网络"
        fetch_source "$tmp_src/favicon.ico" "static/favicon.ico" \
            || log_warn "下载 favicon.ico 失败（不影响安装，将使用默认图标）"
        # 字体（思源中文 + 0xProto 等宽）随管道安装一起拉取，缺失时系统字体兜底
        mkdir -p "$tmp_src/static/fonts"
        local _f
        for _f in fw-sans-sc-regular.woff2 fw-sans-sc-bold.woff2 0xProto-Regular.woff2 0xProto-Bold.woff2; do
            fetch_source "$tmp_src/static/fonts/$_f" "static/fonts/$_f" \
                || log_warn "字体 $_f 下载失败（将使用系统字体）"
        done
        # Web 终端 xterm.js（v2.1.19）
        mkdir -p "$tmp_src/static/vendor"
        for _f in xterm.js xterm.css xterm-addon-fit.js; do
            fetch_source "$tmp_src/static/vendor/$_f" "static/vendor/$_f" \
                || log_warn "终端资源 $_f 下载失败（Web 终端不可用）"
        done
        src_py="$tmp_src/panel.py"
        src_html="$tmp_src/index.html"
        src_ico="$tmp_src/favicon.ico"
    fi

    mkdir -p "$APP_DIR/static"
    atomic_put "$src_py" "$APP_DIR/panel.py" 755
    atomic_put "$src_html" "$APP_DIR/static/index.html" 644
    if [ -f "$src_ico" ]; then
        atomic_put "$src_ico" "$APP_DIR/static/favicon.ico" 644
    fi
    # 字体目录:本地(tar/目录)安装直接复制;管道安装已下载到 tmp_src
    local fonts_src="$script_dir/static/fonts"
    if [ -n "$tmp_src" ]; then fonts_src="$tmp_src/static/fonts"; fi
    if [ -d "$fonts_src" ]; then
        mkdir -p "$APP_DIR/static/fonts"
        atomic_put_dir "$fonts_src" "$APP_DIR/static/fonts"
    fi
    # vendor（xterm.js 等）:本地(tar/目录)安装直接复制;管道安装已下载到 tmp_src
    local vendor_src="$script_dir/static/vendor"
    if [ -n "$tmp_src" ]; then vendor_src="$tmp_src/static/vendor"; fi
    if [ -d "$vendor_src" ]; then
        mkdir -p "$APP_DIR/static/vendor"
        atomic_put_dir "$vendor_src" "$APP_DIR/static/vendor"
    fi
    [ -n "$tmp_src" ] && rm -rf "$tmp_src"
    log_info "文件部署完成"
}

write_config() {
    log_info "初始化/更新配置 $ETC_DIR ..."
    mkdir -p "$ETC_DIR"
    # 由 Python 生成密码哈希，明文密码只打印一次，绝不落盘；
    # ssh_port 自动检测系统实际 SSH 端口（防锁死保护跟随真实端口，不固定 22）
    # ⚠ v3.2.40 修复：已有 config.json 时，面板端口/账号/密码哈希/自定义字段（dns_creds 等）
    #   一律沿用。旧版无条件重写——重装或升级后端口随机变、账号被重置、DNS 凭据丢失，
    #   而运行中的服务未必重启，于是「安装完成给出的地址」打不开（阿基雷机实测）。
    local cfg_out ssh_detected pass_kept
    if [ -f "$ETC_DIR/config.json" ]; then
        log_info "检测到已有配置：面板端口/登录账号沿用（改端口请用面板内「系统 → 面板端口」）"
    fi
    cfg_out="$(python3 - "$PANEL_USER" "$PANEL_PASS" "$PANEL_PORT" "$PANEL_BIND" "$ETC_DIR/config.json" <<'EOF'
import sys, json, hashlib, secrets, os, subprocess

user, pwd, port, bind, path = sys.argv[1:6]


def detect_ssh_port():
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.startswith("port "):
                return int(line.split()[1])
    except Exception:
        pass
    return 22


ssh_port = detect_ssh_port()
existing = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            existing = data
    except Exception:
        existing = {}

cfg = dict(existing)          # 保留全部已有字段（dns_creds / ssh_allow_ips / firewall_enabled …）
had_password = bool(cfg.get("password_hash"))
if not cfg.get("username"):
    cfg["username"] = user
if not had_password:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt), 120_000)
    cfg["password_hash"] = f"{salt}${dk.hex()}"
if not cfg.get("port"):
    cfg["port"] = int(port)
if not cfg.get("bind"):
    cfg["bind"] = bind
cfg.setdefault("mode", "strict")     # 默认严格模式（v1.20.0 定稿）
if cfg.get("ssh_port_auto", True):
    cfg["ssh_port"] = ssh_port
    cfg["ssh_port_auto"] = True
else:
    cfg["ssh_port"] = int(cfg.get("ssh_port") or ssh_port)

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
print(ssh_port)
print(cfg["port"])
print(cfg["username"])
print(1 if had_password else 0)
EOF
)"
    local _cfg=()
    mapfile -t _cfg <<< "$cfg_out"
    ssh_detected="${_cfg[0]:-22}"
    PANEL_PORT="${_cfg[1]:-$PANEL_PORT}"
    PANEL_USER="${_cfg[2]:-$PANEL_USER}"
    pass_kept="${_cfg[3]:-0}"
    [[ "$ssh_detected" =~ ^[0-9]{1,5}$ ]] || ssh_detected=22
    if [ "$pass_kept" = "1" ]; then
        PANEL_PASS=""     # 沿用原有密码：本次没有设密码，结尾不能打印（打印了就是假信息）
    fi
    # 初始规则：自动放行实际 SSH 端口 + 面板端口（防锁死，装完即可访问；幂等，不覆盖已有规则）
    gen_initial_rules "$ssh_detected" "$PANEL_PORT" "$ETC_DIR/rules.json"
}

# 生成/补齐初始放行规则：SSH 端口 + 面板端口（均 protected 不可删除，防锁死）
gen_initial_rules() {
    local ssh_port="$1" panel_port="$2" rules_file="$3" added=""
    [[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] || ssh_port=22
    if ! [[ "$panel_port" =~ ^[0-9]{1,5}$ ]]; then
        log_warn "面板端口未知（config.json 无 port 字段），跳过放行规则补齐"
        return 0
    fi
    if [ ! -f "$rules_file" ]; then
        local id1 id2
        id1="$(printf '%04x%04x%04x' $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)))"
        id2="$(printf '%04x%04x%04x' $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)))"
        cat > "$rules_file" <<EOF
[
  {"id": "$id1", "type": "port_allow", "proto": "tcp", "port": $ssh_port, "comment": "SSH保护(安装自动放行)", "protected": true},
  {"id": "$id2", "type": "port_allow", "proto": "tcp", "port": $panel_port, "comment": "面板端口(安装自动放行)", "protected": true}
]
EOF
        chmod 600 "$rules_file"
        log_info "已自动放行 SSH($ssh_port) 与面板端口($panel_port)"
        return 0
    fi
    # 已有 rules.json：幂等补齐（⚠ v3.2.40 修复：旧版直接 return，一旦面板端口变了
    # ——重装、面板内改端口、换机器恢复配置——严格模式（policy drop）下面板端口没有任何
    # 放行规则，公网会被自己的防火墙挡死，安装打印的地址自然也打不开）
    added="$(python3 - "$rules_file" "$ssh_port" "$panel_port" <<'EOF'
import json, os, secrets, sys

path, ssh_port, panel_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    with open(path, encoding="utf-8") as f:
        rules = json.load(f)
    if not isinstance(rules, list):
        raise ValueError("rules.json 不是数组")
except Exception as e:
    bak = "%s.broken.%s" % (path, secrets.token_hex(4))
    try:
        os.replace(path, bak)
        print("规则文件损坏（%s），已备份到 %s 并按初始规则重建" % (e, bak), file=sys.stderr)
    except Exception:
        print("规则文件损坏且备份失败（%s），按初始规则重建" % e, file=sys.stderr)
    rules = []


def ensure_allow(items, port, comment):
    for r in items:
        if not isinstance(r, dict) or r.get("type") != "port_allow":
            continue
        try:
            if int(r.get("port") or 0) == port and r.get("proto") in ("tcp", "both"):
                return False
        except Exception:
            continue
    items.append({"id": secrets.token_hex(6), "type": "port_allow", "proto": "tcp",
                  "port": port, "comment": comment, "protected": True})
    return True


changed = 0
if ensure_allow(rules, ssh_port, "SSH保护(安装自动放行)"):
    changed += 1
if ensure_allow(rules, panel_port, "面板端口(安装自动放行)"):
    changed += 1
if changed:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
print(changed)
EOF
)" || added=""
    [[ "$added" =~ ^[0-9]+$ ]] || added=0
    if [ "$added" != "0" ]; then
        log_info "已补齐放行规则（SSH $ssh_port / 面板端口 $panel_port，新增 ${added} 条）"
    else
        log_info "放行规则已存在（SSH $ssh_port / 面板端口 $panel_port），未改动"
    fi
}

install_service() {
    cat > "$SYSTEMD_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=fwpanel Firewall Panel (nftables)
After=network.target

[Service]
Type=simple
# 端口/监听地址以 /etc/fwpanel/config.json 为准（面板内/改配置后重启即生效）
ExecStart=/usr/bin/python3 $APP_DIR/panel.py serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    # ⚠ v3.2.40 修复：原为 `systemctl enable --now`——服务已在运行时它是空操作，
    # 刚部署的代码与刚写入的 config.json 都不会生效，脚本却照样打印「服务已启动」+ 新端口地址
    # （孤儿进程仍占着旧端口 → 地址打不开）。现在显式 restart，并回读校验真实监听端口。
    if ! start_panel_service; then
        error "fwpanel 服务启动失败（详见上方日志）"
    fi
    log_info "服务已启动并设为开机自启（$SERVICE_NAME）"
    verify_panel_http || true

    # 安装时顺带开放端口（--open-port "80,443,53/udp"）
    if [ -n "$OPEN_PORTS" ]; then
        log_info "开放指定端口给公网: $OPEN_PORTS"
        local item
        IFS=',' read -ra items <<< "$OPEN_PORTS"
        for item in "${items[@]}"; do
            python3 "$APP_DIR/panel.py" open-port "$item" || log_warn "端口 $item 开放失败"
        done
    fi
}

_panel_access_hint() {   # $1=面板端口 → 若有启用的反代指向它，输出该域名（公网入口）
    local panel_port="$1"
    [ -n "$panel_port" ] || return 0
    [ -f "$ETC_DIR/proxies.json" ] || return 0
    python3 - "$ETC_DIR/proxies.json" "$panel_port" <<'EOF' 2>/dev/null || true
import json, sys
path, port = sys.argv[1], int(sys.argv[2])
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    data = []
for p in (data if isinstance(data, list) else []):
    if not isinstance(p, dict) or not p.get("enabled", True):
        continue
    try:
        if int(p.get("target_port") or 0) == port:
            print(p.get("domain", ""))
            break
    except Exception:
        continue
EOF
}

_print_panel_url() {   # 升级/重装收尾打印真实地址（取自 config.json，不靠命令行变量）
    local ip rport rbind user
    ip="$({ ip route get 1.1.1.1 2>/dev/null || true; } | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1 || true)"
    if [ -z "$ip" ]; then
        ip="$({ hostname -I 2>/dev/null || true; } | awk '{print $1}' || true)"
    fi
    rport="$(cfg_field port)"
    rbind="$(cfg_field bind)"
    user="$(cfg_field username)"
    echo "------------------------------------------------------------------"
    if [ "$rbind" = "127.0.0.1" ]; then
        echo "  面板地址 : http://127.0.0.1:${rport}  （仅本机；远程: ssh -L ${rport}:127.0.0.1:${rport} <用户>@${ip:-服务器IP}）"
    else
        echo "  面板地址 : http://${ip:-<服务器IP>}:${rport}"
    fi
    if panel_http_ok "$rport" 3; then
        echo "  自检结果 : 本机 http://127.0.0.1:${rport} 返回 200 ✓"
    else
        echo "  自检结果 : 本机访问未返回 200 ✗（看日志: journalctl -u $SERVICE_NAME -n 50 --no-pager）"
    fi
    local pdomain
    pdomain="$(_panel_access_hint "$rport")"
    if [ -n "$pdomain" ]; then
        echo "  公网入口 : https://${pdomain}/  （${rport} 已被反代接管，直接用 IP:端口 访问不通是正常的）"
    fi
    if [ -n "$user" ]; then
        echo "  登录用户 : ${user}（密码沿用原设置，未改动）"
    fi
    echo "  面板版本 : v$(installed_panel_version)"
}

print_summary() {
    local ip pv _pdomain
    ip="$({ ip route get 1.1.1.1 2>/dev/null || true; } | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1 || true)"
    if [ -z "$ip" ]; then
        ip="$({ hostname -I 2>/dev/null || true; } | awk '{print $1}' || true)"
    fi
    [ -n "$ip" ] || ip="<服务器IP>"

    echo ""
    echo "=================================================================="
    echo "${C_GREEN}  🎉 fwpanel2 简易VPS管理面板2.0 安装完成！${C_RESET}"
    echo "=================================================================="
    # 地址一律以 config.json 为准（v3.2.40：重装/升级时端口沿用旧配置，
    # 用命令行变量打印会和真实监听端口错位——用户按地址访问必然打不开）
    local rport rbind
    rport="$(cfg_field port)"
    [[ "$rport" =~ ^[0-9]{1,5}$ ]] || rport="$PANEL_PORT"
    rbind="$(cfg_field bind)"
    [ -n "$rbind" ] || rbind="$PANEL_BIND"
    if [ "$rbind" = "0.0.0.0" ]; then
        echo "  面板地址 : ${C_BOLD}http://${ip}:${rport}${C_RESET}"
    else
        echo "  面板地址 : ${C_BOLD}http://127.0.0.1:${rport}${C_RESET}  （仅本机）"
        echo "  远程访问 : 在本机执行 ssh -L ${rport}:127.0.0.1:${rport} root@${ip}"
        echo "             然后浏览器打开 http://127.0.0.1:${rport}"
    fi
    # 自检结论：地址必须和真实监听端口一致且本机可访问（v3.2.40 —— 不再只喊「安装完成」）
    if panel_http_ok "$rport" 3; then
        echo "  自检结果 : ${C_GREEN}本机 http://127.0.0.1:${rport} 返回 200 ✓${C_RESET}"
    else
        echo "  自检结果 : ${C_RED}本机访问未返回 200 ✗（面板可能没起来）${C_RESET}"
        echo "             看日志: journalctl -u $SERVICE_NAME -n 50 --no-pager"
    fi
    _pdomain="$(_panel_access_hint "$rport")"
    if [ -n "$_pdomain" ]; then
        echo "  公网入口 : https://${_pdomain}/  （${rport} 已被反代接管，直接用 IP:端口 访问不通是正常的）"
    fi
    pv="$(installed_panel_version)"
    if [ -n "$pv" ]; then
        echo "  面板版本 : v$pv"
    fi
    echo "  登录用户 : ${PANEL_USER}"
    if [ -n "$PANEL_PASS" ]; then
        echo "  登录密码 : ${PANEL_PASS}"
        echo "------------------------------------------------------------------"
        echo "  ${C_RED}⚠ 凭据仅显示这一次，不会写入任何文件，请立即记下！${C_RESET}"
    else
        echo "  登录密码 : （沿用原有密码，本次未改动）"
        echo "------------------------------------------------------------------"
        echo "  重装/升级不会重置密码；忘记密码：重跑安装命令 → 菜单 5) 改用户名密码"
    fi
    if [ -x "$WRAPPER_PATH" ]; then
        echo "  快捷入口 : 以后直接输入 ${C_BOLD}fwp${C_RESET} 打开管理菜单（改凭据 / 升级 / 体检 / 查看信息）"
    fi
    if [ -f "$0" ]; then
        echo "  改用户名/密码: sudo bash $0 --change-password"
        echo "  升级 / 换通道: sudo bash $0（加 --beta 装测试版，--version vX.Y.Z 指定版本）"
    else
        # 管道模式（curl | sudo bash）下 $0 是 "bash"，直接引用会印出 "sudo bash bash ..." 这种不可用的命令
        echo "  改用户名/密码: 重跑一键安装命令 → 菜单选 5) 改用户名密码"
        echo "  查看登录地址/用户名: 同一菜单 11) 查看登录信息（需 root；密码只能重设）"
        echo "  升级 / 换通道: 重跑一键安装命令 → 菜单选 1 / 2 / 3（或加 --beta / --version vX.Y.Z）"
    fi
    echo "  面板内可修改密码；SSH(22) 始终放行防锁死"
    echo "  查看日志: journalctl -u fwpanel -f"
    echo "=================================================================="
}

do_install() {
    interactive_channel_menu # 有终端且没指定通道时弹菜单(正式版/测试版/指定版本)
    resolve_src_tag          # 先解析目标版本，横幅才能显示目标面板版本
    print_banner
    check_os; check_root; check_arch; check_tools
    cleanup_plaintext_credentials   # 清理 v3.2.16/17 留下的明文凭据文件（安装与升级都走这里）
    install_shortcut                # 生成 fwp 快捷命令（升级路径也会执行，因为它在 check_existing 之前）
    check_existing
    ask_custom_credentials   # 首次安装才问（升级不走这里）；无终端/-y 静默随机
    resolve_params
    install_deps
    deploy_files
    write_config
    install_service
    print_summary
}

# ============================== 卸载 ==============================

do_uninstall() {
    echo "================== $SCRIPT_NAME 卸载模式 =================="
    check_root
    cleanup_plaintext_credentials    # 任何需要 root 的入口都顺手清掉旧版明文凭据文件（幂等）
    local rport pids
    rport="$(cfg_field port)"

    log_info "停止面板服务（含孤儿进程检测）..."
    if ! stop_panel_service; then
        error "面板进程仍在运行，未继续卸载——请按上面提示手动结束后重试（残留进程占着端口，重装必然失败）"
    fi
    log_info "禁用并移除 systemd 服务..."
    systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DIR/$SERVICE_NAME"
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true

    log_info "删除程序文件 $APP_DIR ..."
    rm -rf "$APP_DIR"
    if [ -e "$WRAPPER_PATH" ]; then
        rm -f "$WRAPPER_PATH"
        log_info "已删除快捷命令 $WRAPPER_PATH"
    fi

    # 卸载彻底性自检：逐项确认「没有残留」，而不是只喊一句卸载完成
    echo "------------------------------------------------------------------"
    pids="$(panel_pids)"
    if [ -n "$pids" ]; then
        log_warn "仍有面板进程残留: $pids"
    else
        echo "  ✓ 无残留面板进程"
    fi
    if [ -f "$APP_DIR/panel.py" ]; then
        log_warn "程序文件仍存在: $APP_DIR/panel.py"
    else
        echo "  ✓ 程序文件已删除（$APP_DIR）"
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q "$SERVICE_NAME"; then
        log_warn "service 单元仍存在: $SYSTEMD_DIR/$SERVICE_NAME"
    else
        echo "  ✓ systemd 服务已移除（$SERVICE_NAME）"
    fi
    if [ -n "$rport" ] && port_listening "$rport"; then
        log_warn "端口 $rport 仍在监听——可能被其他服务占用，重装前请确认"
    fi
    echo "------------------------------------------------------------------"
    log_info "以下内容按设计保留，重装会自动复用（端口/账号/规则都不变）："
    echo "  配置与规则   : $ETC_DIR（面板端口 / 账号哈希 / 防火墙规则 / 反代与证书记录）"
    echo "  防火墙规则表 : table inet fwpanel 仍在内核生效，重装后由面板继续管理"
    echo ""
    echo "  想彻底清空、装一个全新面板（账号需重新设置）："
    echo "    sudo rm -rf $ETC_DIR"
    echo "    sudo nft delete table inet fwpanel"
    echo "------------------------------------------------------------------"
    log_info "卸载完成"
}


# ============================== 彻底卸载（--purge） ==============================
# 与普通卸载的区别：
#   普通卸载（菜单 6 / --uninstall）只删程序文件，配置/规则/数据都留着，重装自动复用；
#   彻底卸载（菜单 7 / --purge）把面板在这台机器上留下的东西一起清掉 —— 全部不可恢复，
#   所以先列「将删除清单 + 大小」，再要求输入 DELETE，且**只碰名单里、形状能认出来的文件**。

_path_size() {   # 人类可读大小；不存在打印 "-"
    if [ -e "$1" ]; then du -sh "$1" 2>/dev/null | cut -f1 || true; else echo "-"; fi
}

_conf_owned_by_panel() {   # 只认面板的命名形状（与 panel.py 的 CONF_ID_RE 对齐，别误删别人的配置）
    local base="$1" id
    base="$(basename "$1")"
    case "$base" in
        fwpanel-default.conf) return 0 ;;
        fwpanel-*.conf|fwsite-*.conf) ;;
        *) return 1 ;;
    esac
    id="${base%.conf}"; id="${id#fwpanel-}"; id="${id#fwsite-}"
    [[ "$id" =~ ^[0-9a-f]{12}$ ]]
}

_panel_conf_files() {   # 面板写的 nginx 配置（反代 fwpanel-<id>.conf / 站点 fwsite-<id>.conf / 兜底守卫）
    local d fn
    for d in "$NGINX_SITES_ENABLED" "$NGINX_CONF_D"; do
        [ -d "$d" ] || continue
        for fn in "$d"/*.conf; do
            [ -f "$fn" ] || continue
            if _conf_owned_by_panel "$fn"; then printf '%s\n' "$fn"; fi
        done
    done
}

_panel_domains() {   # 面板记录里涉及的域名（证书记录 + 站点/反代引用），用于清证书
    python3 - "$ETC_DIR" <<'PYEOF' 2>/dev/null || true
import json, os, sys
etc = sys.argv[1]
doms = set()

def load(name):
    try:
        with open(os.path.join(etc, name)) as f:
            return json.load(f)
    except Exception:
        return None

c = load("certificates.json")
if isinstance(c, dict):
    doms.update(k.strip() for k in c if isinstance(k, str) and k.strip())
for name in ("sites.json", "proxies.json"):
    data = load(name)
    if isinstance(data, dict):
        data = data.get("items") or data.get("sites") or data.get("proxies") or []
    for it in (data or []):
        if not isinstance(it, dict):
            continue
        for k in ("domain", "cert_ref"):
            v = it.get(k)
            if isinstance(v, str) and v.strip():
                doms.add(v.strip())
print("\n".join(sorted(doms)))
PYEOF
}

_panel_site_roots() {   # 只认 sites.json 里、位于站点根目录之下（且不是根目录本身）的路径
    python3 - "$ETC_DIR" "$SITE_ROOT_BASE" <<'PYEOF' 2>/dev/null || true
import json, os, sys
etc, base = sys.argv[1], sys.argv[2].rstrip("/")
try:
    with open(os.path.join(etc, "sites.json")) as f:
        sites = json.load(f)
except Exception:
    sites = []
if not isinstance(sites, list):
    sites = []
roots = []
for s in sites:
    if not isinstance(s, dict):
        continue
    r = str(s.get("root") or "").strip()
    if not r.startswith("/"):
        continue
    r = os.path.normpath(r)
    if r != base and r.startswith(base + "/") and r not in ("/",):
        roots.append(r)
print("\n".join(sorted(set(roots))))
PYEOF
}

_panel_apps() {   # 应用记录里的 id / folder（用于 compose down -v）
    python3 - "$ETC_DIR" <<'PYEOF' 2>/dev/null || true
import json, os, sys
try:
    with open(os.path.join(sys.argv[1], "apps.json")) as f:
        d = json.load(f)
except Exception:
    d = {}
apps = d.get("apps", []) if isinstance(d, dict) else []
for a in apps:
    if isinstance(a, dict):
        print("%s\t%s" % (a.get("id", ""), a.get("folder", "")))
PYEOF
}

_purge_firewall() {
    if ! command -v nft >/dev/null 2>&1; then
        echo "  - 本机没有 nft 命令（跳过）"
        return 0
    fi
    if nft list table $NFT_TABLE_NAME >/dev/null 2>&1; then
        if nft delete table $NFT_TABLE_NAME >/dev/null 2>&1; then
            echo "  ✓ 已删除内核里的 $NFT_TABLE_NAME 表（规则文件随 $ETC_DIR 一起删掉了）"
            log_warn "注意：此后本机不再有面板下发的防火墙规则"
        else
            log_warn "删除 $NFT_TABLE_NAME 表失败，可手工执行：sudo nft delete table $NFT_TABLE_NAME"
        fi
    else
        echo "  - 内核里没有 $NFT_TABLE_NAME 表（跳过）"
    fi
}

_purge_nginx_confs() {
    local files="$1" cnt=0 f
    if [ -z "$files" ]; then
        echo "  - 没有面板写的 nginx 配置（跳过）"
        return 0
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if rm -f "$f" 2>/dev/null; then cnt=$((cnt + 1)); fi
    done <<< "$files"
    echo "  ✓ 已删除 $cnt 个面板写的 nginx 配置（其它配置文件一律没动）"
    if command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1 || true
            echo "  ✓ nginx 配置校验通过并已 reload"
        else
            log_warn "nginx 配置校验未通过（可能是你其它配置的问题）——面板配置已删但没 reload，请自己跑一下：nginx -t"
        fi
    fi
}

_purge_site_roots() {
    local roots="$1" r
    if [ -z "$roots" ]; then
        echo "  - 没有面板记录的站点目录（跳过）"
        return 0
    fi
    while IFS= read -r r; do
        [ -n "$r" ] || continue
        if [ -d "$r" ]; then
            if rm -rf "$r" 2>/dev/null; then echo "  ✓ 已删除站点目录：$r"; else log_warn "删除失败：$r"; fi
        fi
    done <<< "$roots"
    if [ -d "$ACME_WEBROOT" ]; then
        rm -rf "$ACME_WEBROOT" 2>/dev/null && echo "  ✓ 已删除 ACME 校验目录：$ACME_WEBROOT"
    fi
}

_purge_certs() {
    local doms="$1" d
    if [ -z "$doms" ]; then
        echo "  - 面板记录里没有证书域名（跳过）"
        return 0
    fi
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        if command -v certbot >/dev/null 2>&1 \
           && certbot delete --cert-name "$d" --non-interactive --config-dir "$LE_DIR" >/dev/null 2>&1; then
            echo "  ✓ certbot 已删除证书：$d"
        else
            rm -rf "$LE_DIR/live/$d" "$LE_DIR/archive/$d" >/dev/null 2>&1 || true
            rm -f "$LE_DIR/renewal/$d.conf" >/dev/null 2>&1 || true
            if [ ! -e "$LE_DIR/live/$d" ]; then
                echo "  ✓ 已删除证书文件：$d"
            else
                log_warn "删除证书 $d 失败，可手工：sudo certbot delete --cert-name $d"
            fi
        fi
        # 站点访问/错误日志（面板为每个站点单独写的）
        rm -f "$NGINX_LOG_DIR/$d.access.log" "$NGINX_LOG_DIR/$d.error.log" >/dev/null 2>&1 || true
    done <<< "$doms"
}

_purge_docker() {
    local apps="$1" id folder dir
    if [ -n "$apps" ] && command -v docker >/dev/null 2>&1; then
        while IFS=$'\t' read -r id folder; do
            [ -n "$folder" ] || continue
            dir="$COMPOSE_BASE/$folder"
            if [ -f "$dir/docker-compose.yml" ]; then
                if ( cd "$dir" && docker compose down -v --remove-orphans >/dev/null 2>&1 ); then
                    echo "  ✓ 已停止并删除容器与数据卷：$folder"
                else
                    log_warn "应用 $folder 的容器/卷删除失败，可手工：cd $dir && sudo docker compose down -v"
                fi
            fi
        done <<< "$apps"
    else
        echo "  - 没有面板应用记录或本机无 docker（跳过容器清理）"
    fi
    local sub
    for sub in "$APP_DATA_BASE" "$COMPOSE_BASE" "$DOCKER_DATA_BASE/dockerrun" "$DOCKER_DATA_BASE/dockerimage"; do
        if [ -e "$sub" ]; then
            if rm -rf "$sub" 2>/dev/null; then echo "  ✓ 已删除数据目录：$sub"; fi
        fi
    done
    rmdir "$DOCKER_DATA_BASE" >/dev/null 2>&1 && echo "  ✓ 已删除空目录：$DOCKER_DATA_BASE" || true
}

do_purge() {
    echo "================== $SCRIPT_NAME 彻底卸载（含数据，不可恢复） =================="
    check_root
    cleanup_plaintext_credentials    # 顺手清掉旧版明文凭据文件（幂等）

    local rport confs doms roots apps ncerts
    rport="$(cfg_field port 2>/dev/null || true)"
    confs="$(_panel_conf_files)"
    doms="$(_panel_domains)"
    roots="$(_panel_site_roots)"
    apps="$(_panel_apps)"
    ncerts="$(printf '%s' "$doms" | grep -c . || true)"
    local nconfs
    nconfs="$(printf '%s' "$confs" | grep -c . || true)"

    echo ""
    echo "------------------------------------------------------------------"
    echo "  第一步：停服务并删除程序（与普通卸载相同）"
    echo "    程序文件   : $APP_DIR          $(_path_size "$APP_DIR")"
    echo "    快捷命令   : $WRAPPER_PATH"
    echo "    服务单元   : $SYSTEMD_DIR/$SERVICE_NAME"
    echo ""
    echo "  第二步：删除面板的配置与痕迹"
    echo "    配置与规则 : $ETC_DIR          $(_path_size "$ETC_DIR")（账号、防火墙规则、反代与站点、应用记录、任务与流量记录、联邦令牌）"
    echo "    安装日志   : $LOG_FILE         $(_path_size "$LOG_FILE")"
    echo "    备份包     : $BACKUP_ARCHIVE_DIR   $(_path_size "$BACKUP_ARCHIVE_DIR")（**保留**，见末尾说明）"
    printf '    防火墙表   : %s' "$NFT_TABLE_NAME"
    if command -v nft >/dev/null 2>&1 && nft list table $NFT_TABLE_NAME >/dev/null 2>&1; then
        echo "（内核里正在生效，会一并删掉）"
    else
        echo "（内核里当前没有这张表）"
    fi
    if [ "${nconfs:-0}" -gt 0 ]; then
        echo "    nginx 配置 : $nconfs 个"
        printf '%s\n' "$confs" | sed 's/^/      /'
    else
        echo "    nginx 配置 : 无"
    fi
    echo ""
    echo "  第三步：以下内容删了不可恢复，逐项确认 →"
    if [ -n "$roots" ]; then
        echo "    站点文件   :"
        while IFS= read -r r; do [ -n "$r" ] && echo "      $r   $(_path_size "$r")"; done <<< "$roots"
    else
        echo "    站点文件   : 无"
    fi
    [ -d "$ACME_WEBROOT" ] && echo "    ACME 目录  : $ACME_WEBROOT   $(_path_size "$ACME_WEBROOT")"
    if [ "${ncerts:-0}" -gt 0 ]; then
        echo "    证书（$ncerts 个）:"
        printf '%s\n' "$doms" | sed 's/^/      /'
    else
        echo "    证书       : 无"
    fi
    if [ -n "$apps" ]; then
        echo "    Docker 应用容器与数据 :"
        while IFS=$'\t' read -r _a_id _a_folder; do
            [ -n "$_a_folder" ] && echo "      $_a_folder   $(_path_size "$COMPOSE_BASE/$_a_folder") + $(_path_size "$APP_DATA_BASE/$_a_folder")"
        done <<< "$apps"
    else
        echo "    Docker 应用容器与数据 : 无"
        [ -d "$DOCKER_DATA_BASE" ] && echo "      $DOCKER_DATA_BASE   $(_path_size "$DOCKER_DATA_BASE")"
    fi
    echo "------------------------------------------------------------------"

    # 确认（--yes 无人值守时才自动放行）
    if [ "$YES" = "1" ]; then
        log_warn "--yes：已自动确认彻底卸载（无人值守模式）"
    else
        local ans=""
        printf '  确认彻底删除以上全部内容？输入 DELETE 执行，其它任何输入 = 取消: '
        menu_read ans || ans=""
        if [ "$ans" != "DELETE" ]; then
            log_warn "已取消彻底卸载（未做任何改动）"
            return 0
        fi
    fi

    echo ""
    log_info "① 停止面板服务（含孤儿进程检测）..."
    if ! stop_panel_service; then
        error "面板进程仍在运行，未继续——请按上面提示手动结束后重试"
    fi
    log_info "② 删除 systemd 服务与程序文件..."
    systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DIR/$SERVICE_NAME"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -rf "$APP_DIR"
    [ -e "$WRAPPER_PATH" ] && rm -f "$WRAPPER_PATH"

    log_info "③ 删除配置、日志、nginx 配置与防火墙表..."
    _purge_nginx_confs "$confs"
    _purge_firewall
    rm -rf "$ETC_DIR"
    rm -f "$LOG_FILE"

    log_info "④ 清理站点文件、容器数据与证书..."
    if [ "$YES" = "1" ]; then
        # 无人值守：三样都按清单删掉
        _purge_site_roots "$roots"
        _purge_docker "$apps"
        _purge_certs "$doms"
    else
        # 删了不可恢复的三项，逐项再确认一次（默认否）
        if _ask_yn "删除站点文件与 ACME 目录（不可恢复）？"; then
            _purge_site_roots "$roots"
        else
            echo "  - 已保留站点文件"
        fi
        if _ask_yn "删除 Docker 应用容器与其数据（不可恢复）？"; then
            _purge_docker "$apps"
        else
            echo "  - 已保留 Docker 应用与数据"
        fi
        if _ask_yn "删除面板申请/引用的证书（不可恢复）？"; then
            _purge_certs "$doms"
        else
            echo "  - 已保留证书"
        fi
    fi

    # 收尾自检：逐项确认，而不是只喊一句完成
    echo "------------------------------------------------------------------"
    local pids
    pids="$(panel_pids)"
    if [ -n "$pids" ]; then log_warn "仍有面板进程残留: $pids"; else echo "  ✓ 无残留面板进程"; fi
    [ -f "$APP_DIR/panel.py" ] && log_warn "程序文件仍存在: $APP_DIR/panel.py" || echo "  ✓ 程序文件已删除"
    [ -e "$ETC_DIR" ] && log_warn "配置目录仍存在: $ETC_DIR" || echo "  ✓ 配置目录已删除（$ETC_DIR）"
    systemctl list-unit-files 2>/dev/null | grep -q "$SERVICE_NAME" \
        && log_warn "service 单元仍存在" || echo "  ✓ systemd 服务已移除"
    if [ -n "$rport" ] && port_listening "$rport"; then
        log_warn "端口 $rport 仍在监听（可能是别的服务）"
    fi
    echo "------------------------------------------------------------------"
    echo "  以下改动**故意保留**（动它们有风险，需要你自己决定）："
    for _f in /etc/ssh/sshd_config.d/99-fwpanel-port.conf /etc/ssh/sshd_config.d/99-fwpanel-auth.conf \
              /etc/sysctl.d/99-fwpanel-swap.conf /etc/sysctl.d/99-fwpanel-ipv6.conf /etc/sysctl.d/99-fwpanel-bbr.conf; do
        [ -e "$_f" ] && echo "    $_f（删掉会立刻回到系统默认，可能影响你的 SSH 端口/内核参数）"
    done
    if [ -e "$BACKUP_ARCHIVE_DIR" ]; then
        echo "    $BACKUP_ARCHIVE_DIR（面板备份包：故意保留，它是你换机/重装的回退筹码）"
        echo "      要一起删：sudo rm -rf $BACKUP_ARCHIVE_DIR"
    fi
    echo "  重装面板可以直接再来一遍安装命令（会当作全新安装，账号重新设置）"
    echo "------------------------------------------------------------------"
    log_info "彻底卸载完成"
}

_ask_yn() {   # $1=提示；默认否
    local a=""
    printf '  %s [y/N]: ' "$1"
    menu_read a || a=""
    case "$a" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

# ============================== 改密 ==============================

do_change_password() {
    check_root
    cleanup_plaintext_credentials    # 任何需要 root 的入口都顺手清掉旧版明文凭据文件（幂等）
    [ -f "$ETC_DIR/config.json" ] || error "面板未安装，无法修改凭据"
    local sub="reset-account"
    if ! grep -q '"reset-account"' "$APP_DIR/panel.py" 2>/dev/null; then
        # 旧版面板只有 reset-password（只能改密码）
        sub="reset-password"
        log_warn "当前面板版本较旧，本次只能改密码（不支持改用户名）；升级后可改用户名"
    fi
    log_info "交互式修改面板登录凭据（用户名/密码，直接回车 = 该项不改）..."
    # 管道模式（curl | sudo bash）下 stdin 是脚本自身，输入必须走 /dev/tty
    if { : < /dev/tty; } 2>/dev/null; then
        python3 "$APP_DIR/panel.py" "$sub" < /dev/tty
    else
        python3 "$APP_DIR/panel.py" "$sub"
    fi
}


# ============================== 入口 ==============================

main() {
    SCRIPT_ARGS=("$@")
    init_params
    parse_args "$@"
    case "$ACTION" in
        check)   do_check ;;
        uninstall) exec > >(tee -a "$LOG_FILE") 2>&1; do_uninstall ;;
        purge)   exec > >(tee -a "$LOG_FILE") 2>&1; do_purge ;;
        change-password) do_change_password ;;
        update-script) do_update_script ;;
        *)       exec > >(tee -a "$LOG_FILE") 2>&1; do_install ;;
    esac
}

main "$@"
