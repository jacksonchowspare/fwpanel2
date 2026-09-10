# 应用一键部署（WordPress 起）实施计划 — fwpanel2 v3.1.0

**目标**：在面板里"选应用 → 填参数（含容器端口，可自己填）→ 一键部署"，自动完成容器编排、域名反代、证书签发、强制 HTTPS，并能在面板里升级/备份/卸载。

**范围**：一期只做 **WordPress**（把链路跑通），二期加更多模板。明确**不做原生 LNMP**（php-fpm/MariaDB 按站管理）。

**技术栈**：现有零依赖后端（panel.py 标准库）+ 现有单文件前端（static/index.html）+ 已有 Docker/compose 能力 + 已有反代/证书模块。

---

## 一、现状事实（已核对代码，非推测）

| 能力 | 现状 |
| --- | --- |
| Docker | 已支持安装/容器列表/镜像/统计/日志/一键创建/compose 项目的上/停/升级/下 |
| compose 项目位置 | `/DockerData/dockercompose/<folder>/docker-compose.yml`；启动即该目录 `docker compose up -d` |
| 反代模板 | 已带 `Host / X-Real-IP / X-Forwarded-For / X-Forwarded-Proto` + `Upgrade/Connection` + `proxy_http_version 1.1` → **WordPress 识别 HTTPS 没问题** |
| 证书 | HTTP-01（certbot）+ DNS-01（acme.sh）都已跑通，含 DNS 预检、后台长任务、自动续期配置 |
| **缺失 1** | **全项目没有 `client_max_body_size`** → nginx 默认 **1MB**，WordPress 传媒体/装插件必 413 |
| **缺失 2** | 没有"应用"概念：容器、反代条目、证书三者需要人工分别配置 |
| **缺失 3** | 没有应用级备份（站点文件/数据库） |
| 端口校验 | 站点已有校验（1024-65535，排除面板/SSH 端口、端口站冲突），但**不检查**反代目标端口、容器发布端口、系统实际监听端口 |

---

## 二、设计

### 2.1 数据模型

新增 `/etc/fwpanel/apps.json`（权限 600）：

```json
{"apps": [{
  "id": "a1b2c3d4e5f6",
  "template": "wordpress",
  "name": "我的博客",
  "folder": "wp-blog",                 // compose 目录名（/DockerData/dockercompose/wp-blog/）
  "data_dir": "/DockerData/apps/wp-blog",
  "port": 8080,                        // 容器发布端口（只绑 127.0.0.1）
  "domain": "blog.example.com",         // 可空 = 无域名，仅本机/内网访问
  "proxy_id": "7c3aac4cfac6",           // 自动创建的反代条目 id（可空）
  "expose_public": false,               // 无域名时是否允许公网 IP:端口（默认否）
  "created": 1757500000,
  "image_tag": "latest"
}]}
```

数据目录约定（便于备份/迁移，不用 docker 匿名卷）：

```
/DockerData/apps/<folder>/
├── .env                 # 数据库密码等（600，不进 git、不在前端明文回显）
├── compose/docker-compose.yml   （同时软链/复制到 dockercompose/<folder>/ 以复用现有 compose 页）
├── db/                  # MySQL 数据
├── html/                # WordPress 文件（uploads 等）
└── backups/<时间>.tar.gz
```

### 2.2 端口交互（用户点名要的）

向导里的"容器端口"字段设计：

1. **默认值来自模板**（WordPress = 8080），**可以直接改**（1024–65535）。
2. **实时占用检测**：输入框旁给"检测"状态点，失焦后自动查一次，返回占用来源：
   - 面板自身端口 / SSH 保护端口（硬冲突）
   - 其他端口站 / 已有反代目标端口
   - 已有应用的容器端口 / 运行中容器已发布端口
   - 系统实际 LISTEN（`ss -lnt`）
   → 显示 🟢可用 / 🟡被占用但属可回收（如已删除应用的残留）/ 🔴冲突，并说明是谁占用。
3. **一键"用下一个可用端口"**：从默认值向上找第一个空闲端口填入。
4. **提交时后端再校验一次**（防竞态），冲突则明确报错不部署。
5. **端口的作用域说明**（前端文案）：容器端口**只绑 127.0.0.1**，不对公网开放；对外统一走 80/443 的域名反代。**没有域名**时默认也不放行公网——若要 `IP:端口` 直接访问，必须显式勾选 `expose_public`（会联动放行防火墙）。

### 2.3 一键联动（部署完成自动做）

```
拉镜像 → 写 .env + compose → docker compose up -d → 等容器健康
  → （有域名时）创建反代条目 127.0.0.1:<port>（复用 ProxyStore.add）
  → 放行 80/443（复用 ensure_proxy_entry_ports）
  → DNS 预检（复用 site_dns_precheck）→ 失败则提示但不回滚部署
  → 后台签发证书（复用 issue_cert）→ 启用强制 HTTPS
  → 网站列表里显示为「应用站」（复用 proxy 合并视图 + source 标签）
```

面板自身域名/证书保护规则**直接复用**（应用不许占用面板域名的证书）。

### 2.4 生命周期

- **升级**：拉新镜像 + `compose up -d`（重建容器，数据卷不动）
- **启停**：`compose stop/start`
- **卸载**：默认**保留数据**，另给"同时删除数据"勾选（勾了才删 `data_dir` 并 drop 数据库）
- **备份**：一期做"一键备份"= `mysqldump` + `tar` 数据目录 → `backups/<时间>.tar.gz`；cron 定时备份放二期
- **还原**：二期（一期手工解包）

### 2.5 必须补的底座

1. `client_max_body_size` 可配（反代/站点级别，默认 **32M**）——否则 WordPress 传图必踩 413；要写进 nginx 模板 + 前端可改
2. 反代对应用站的长超时（后台操作/上传慢）：应用反代默认 `proxy_read_timeout 300s`
3. 端口占用汇总 helper：`used_ports_summary()`（供 2.2 的检测与"下一个可用端口"）
4. 容器名/目录名冲突检测（folder 已存在时提示改用或复用）

---

## 三、分任务清单（TDD，每个任务一次提交）

> 路径约定：后端 `/home/saxon/fwpanel2/panel.py`，前端 `static/index.html`，测试 `test/test_panel.py`（unittest），实机测试机 VM-115。

### 阶段 A：底座
- **A1** 端口占用汇总 `used_ports_summary()` + 单测（fake proxies/sites/容器 + ss 输出桩）
- **A2** 端口可用性校验 `app_port_check(port)`（面板/SSH/站点/反代目标/容器/系统监听）+ `next_free_port(base)` + 单测
- **A3** `client_max_body_size` 进入 nginx 渲染模板（反代 + 站点），默认 32M，可空=不写 + 单测断言配置文本

### 阶段 B：应用模板与存储
- **B1** `APP_TEMPLATES = {"wordpress": {...}}`（镜像、默认端口、env 生成、卷、备份命令、说明）+ 单测：渲染出的 compose 含端口映射 `127.0.0.1:<port>:80`、卷指向 `data_dir`
- **B2** `AppStore`（apps.json 读写、增删改、id 生成）+ 单测
- **B3** 模板 → `.env` + compose 文件落盘（`data_dir`、`dockercompose/<folder>/`）+ 单测（文件内容与权限 600）

### 阶段 C：部署/生命周期 API
- **C1** `POST /api/apps` 部署（长任务：拉镜像→compose up→等健康）+ 单测（DRY_RUN 路径 + 参数校验）
- **C2** 部署后联动：建反代（有域名时）+ 放行 80/443 + DNS 预检 + 异步签证书 + 单测（mock 各步骤，断言调用顺序与失败降级）
- **C3** `POST /api/apps/<id> {action: start|stop|upgrade}` + 单测
- **C4** `DELETE /api/apps/<id>?purge=1`（默认保数据）+ 单测
- **C5** `POST /api/apps/<id>/backup`（mysqldump + tar）+ 单测（命令拼接、备份文件存在）
- **C6** `GET /api/apps`（列表 + 容器状态 + 证书状态 + 数据占用）；并入 `GET /api/sites` 视图（标"应用站"）

### 阶段 D：前端
- **D1** 新增「应用」tab（或网站 tab 入口，见待定 Q1）+ 应用卡片（状态/端口/域名/访问地址/按钮组）
- **D2** 部署向导 4 步：选应用 → 填参数（端口可填 + 实时检测 + "下一个可用端口"按钮 + 域名可选 + 管理员账号）→ 部署进度（复用任务轮询）→ 结果页（访问地址、数据库账号密码一次性展示+复制、下一步提示）
- **D3** 卡片操作：打开/升级/启停/备份/卸载（卸载二次确认含"是否删数据"）
- **D4** 反代/站点面板里给"上传大小(client_max_body_size)"可编辑项，默认 32M
- **D5** 主题一致性自检（沿用变量化主题，不新增资源文件）

### 阶段 E：测试与发布
- **E1** 单测补全（目标 ≥ 当前 246 例 → 约 270+ 例全绿）
- **E2** 真浏览器 UI 回归（`test/ui_check_playwright.js`）新增断言：应用 tab 渲染、向导端口检测字段可用、部署按钮可点
- **E3** VM-115 实机全流程：装 Docker → 部署 WordPress → 访问（IP:端口 与 域名反代两种）→ **上传 >1MB 图片**（验证 client_max_body_size）→ 升级 → 一键备份 → 卸载（保数据 / 删数据）
- **E4** 发布 v3.1.0 beta（tag + asset + release notes + 三台机器升级）；v2 线不动

---

## 四、验证清单（完成的定义）

- [ ] 端口字段可手填、实时显示占用来源、一键取下一个可用端口；后端二次校验
- [ ] WordPress 一键部署后可直接打开安装向导（域名反代 + 真证书 + 强制 HTTPS）
- [ ] 上传 ≥10MB 文件不 413（`client_max_body_size` 生效）
- [ ] 站点列表能看到"应用站"，点开能到反代模块编辑
- [ ] 升级/启停/备份/卸载（保数据与删数据两种）全部实机通过
- [ ] 全量单测 + 真浏览器 UI 回归全绿；三台机器升级到 v3.1.0 beta 且面板正常

---

## 五、风险与待定

**风险**
1. 镜像拉取慢/失败（国内链路）→ 长任务 + 明确日志 + 重试提示；必要时支持自定义镜像加速地址
2. 端口竞态（检测通过但提交瞬间被占）→ 后端提交时再校验
3. `docker compose` 版本差异（v1 `docker-compose` vs v2 插件）→ 沿用现有 compose 调用的探测逻辑
4. 容器名/folder 冲突 → 提交前查重并提示
5. LE 配额（每域名每周有限额）→ 失败不反复重试；文案说明
6. WordPress 首次安装需人工填站点信息 → 结果页给直达链接与说明（不做静默预装，避免破坏官方流程）

**待定（需用户拍板）→ 已定（2026-09-11）**

- **Q1 界面位置：独立「应用」tab** ✓（与"网站"并列）
- **Q2 无域名时默认不暴露公网** ✓（要用 `IP:端口` 访问需显式勾选，勾选后联动放行防火墙）
- **Q3 卸载默认保留数据** ✓，另给"同时删除数据"勾选项，勾了才删目录 + drop 数据库
- **Q4 一期模板：WordPress / Typecho / Nextcloud / Vaultwarden 四个** ✓
- **Q5 一期只做"一键备份"** ✓；远程备份（七牛云等对象存储）留到二期再议

### 四个模板的技术前提（已核对镜像与依赖）

| 模板 | 镜像 | 端口默认 | 上传默认 | 特殊要求 |
| --- | --- | --- | --- | --- |
| WordPress | `wordpress:latest` + `mysql:8.0` | 8080 | 32M | 域名可选 |
| Typecho | `joyqi/typecho:nightly-php8.2-apache`（作者官方 nightly，只有 nightly 标签）+ `mariadb` | 8081 | 32M | **向导开放"镜像可改"**兜底 |
| Nextcloud | `nextcloud:stable-apache` + `mariadb` | 8082 | **512M** | 需 `NEXTCLOUD_TRUSTED_DOMAINS` / `TRUSTED_PROXIES` / `OVERWRITEPROTOCOL=https`；建议 ≥1G 内存（前端提示） |
| Vaultwarden | `vaultwarden/server:latest` | 8083 | 32M | **必须有域名 + 证书**（浏览器 Web Crypto 需要 HTTPS 安全上下文）；反代条目须开 `websocket=true`（实时同步）；自动生成 `ADMIN_TOKEN` |

（另：反代模板里的 WebSocket 升级头是**按 `websocket` 开关条件输出**的，所以 Vaultwarden 必须由应用向导在创建反代时把该开关打开。）

### 向导新增字段
「镜像（高级，可改）」——默认取模板镜像，允许用户改成自定义镜像/tag（应对 Typecho nightly 这类情况、以及国内加速镜像）。

---

## 六、二期预告（不在本期）

更多模板（Typecho / Nextcloud / Uptime Kuma / Alist / Vaultwarden / Gitea）、cron 定时备份与还原、应用更新提醒、多应用批量操作、应用日志聚合查看。
