#!/usr/bin/env node
/* 应用数据恢复界面（v3.3.14）：逐应用勾选 + 危险项「先清空」二次确认 + 请求体选项
 *
 * 1) bkRestoreAppsRender：按包内应用清单渲染逐应用勾选（默认全勾）、「先清空」默认不勾（标红）、
 *    「恢复后起回容器」默认勾；包内没有应用数据时不渲染（不报错）
 * 2) bkRestoreAppsToggle：勾/取消「应用数据（Docker）」恢复项 → 应用清单显示/隐藏
 * 3) bkRestore：一个应用都没勾 → 拦下不发请求；有勾选 → opts 带 restore_apps/wipe_apps/restart_apps；
 *    勾了「先清空」→ 必须再弹一次红色二次确认，确认后才真正发请求
 *
 * 用法：node test/frontend_backup_apps_test.js   （全通过退出码 0）
 */
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "..", "static", "index.html"), "utf8");

function extract(name) {
    const marker = "function " + name + "(";
    let start = html.indexOf(marker);
    if (start < 0) return null;
    if (html.slice(start - 6, start) === "async ") start -= 6;
    let depth = 0, end = start;
    for (; end < html.length; end++) {
        const c = html[end];
        if (c === "{") depth++;
        else if (c === "}") { depth--; if (depth === 0) { end++; break; } }
    }
    return html.slice(start, end);
}

let failures = 0, passes = 0;
function check(cond, label, extra) {
    if (cond) { passes++; console.log("  ✓ " + label); }
    else { failures++; console.log("  ✗ " + label + (extra === undefined ? "" : "   → " + extra)); }
}

const names = ["bkRestoreAppsRender", "bkRestoreAppsToggle", "bkRestoreAppPicks", "bkItems", "bkRestore"];
const srcs = names.map(extract);
names.forEach((n, i) => { if (!srcs[i]) { console.log("FAIL 找不到 " + n + "()"); process.exit(1); } });

/* ---------------- 假 DOM ---------------- */
const els = {};
function mkEl(id) {
    return { id: id, innerHTML: "", textContent: "", checked: false, style: { display: "" }, className: "" };
}
["bk_r_apps", "bk_prev", "bk_opt_snap", "bk_opt_restart", "bk_opt_apps_restart"].forEach(id => { els[id] = mkEl(id); });
els.bk_opt_snap.checked = true;
els.bk_opt_restart.checked = true;
els.bk_opt_apps_restart.checked = true;

let itemStubs = [];
let appStubs = [];
let wipeStubs = [];

function stubsFrom(innerHTML, key) {
    const out = [];
    const re = /<input\b([^>]*)>/g;
    let m;
    while ((m = re.exec(innerHTML))) {
        const a = m[1];
        const d = {};
        let mm;
        const kv = /([\w-]+)="([^"]*)"/g;
        while ((mm = kv.exec(a))) d[mm[1]] = mm[2];
        if (d["data-" + key] === undefined) continue;
        const ds = {};
        ds[key] = d["data-" + key];
        out.push({ checked: /(^|\s)checked(\s|$)/.test(a), dataset: ds, attrs: a });
    }
    return out;
}

global.document = {
    querySelectorAll: (sel) => {
        if (sel.indexOf("data-bkrapp") >= 0) return appStubs;
        if (sel.indexOf("data-bkrwipe") >= 0) return wipeStubs;
        if (sel.indexOf("data-bkitem") >= 0) return itemStubs;
        return [];
    },
    querySelector: (sel) => {
        const m = /\[data-bkitem="([^"]+)"\]/.exec(sel);
        if (m) return itemStubs.filter(s => s.dataset.bkitem === m[1])[0] || null;
        return null;
    },
};
global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? "" : s);
global.attrEsc = (s) => String(s == null ? "" : s);
global.bkFmt = (n) => (Number(n || 0) / 1048576).toFixed(1) + " MB";

const toasts = [];
global.toast = (m, k) => toasts.push([String(m), k || ""]);
const panes = [];
global.confirmPanel = (msg, onOk, title) => panes.push({ msg: String(msg || ""), onOk: onOk, title: title || "" });
const tasks = [];
global.apiTask = async (m, p, body, cb) => { tasks.push({ m: m, p: p, body: body }); return {}; };
global.bkOpen = () => {};
let loaded = 0;
global.bkLoad = () => { loaded++; };

const PRELUDE = 'let bkSel = "fwpanel-host-v3.3.14.tar.gz";\n';
const F = new Function(PRELUDE + srcs.join("\n") + "\nreturn {render: bkRestoreAppsRender, toggle: bkRestoreAppsToggle, picks: bkRestoreAppPicks, items: bkItems, restore: bkRestore};")();
const S = F;

const PKG_APPS = [
    { folder: "wordpress-8080", name: "WordPress", db: "mysql", bytes: 2097152, dump: true, subs: ["db", "html"] },
    { folder: "vaultwarden-8083", name: "Vaultwarden", db: "sqlite", bytes: 1048576, dump: false, subs: ["data"] },
];

function setupItems(appDataChecked) {
    itemStubs = [
        { checked: true, dataset: { bkitem: "settings" } },
        { checked: appDataChecked, dataset: { bkitem: "app_files" } },
    ];
}

console.log("== 渲染应用清单 ==");
S.render({ apps: PKG_APPS });
const box = els.bk_r_apps;
const boxHtml = box.innerHTML;
check(boxHtml.indexOf('data-bkrapp="wordpress-8080"') >= 0, "渲染出第一个应用");
check(boxHtml.indexOf('data-bkrapp="vaultwarden-8083"') >= 0, "渲染出第二个应用");
check(boxHtml.indexOf("mysql") >= 0 && boxHtml.indexOf("sqlite") >= 0, "显示数据库类型");
check(boxHtml.indexOf("含数据库导出") >= 0, "标出包内含数据库导出");
check((boxHtml.match(/data-bkrapp="[^"]+"[^>]*checked/g) || []).length === 2, "默认全勾选",
      (boxHtml.match(/data-bkrapp="[^"]+"[^>]*checked/g) || []).length);
check((boxHtml.match(/data-bkrwipe="[^"]+"/g) || []).length === 2, "每个应用都有「先清空」勾选项");
check(!/data-bkrwipe="[^"]+"[^>]*checked/.test(boxHtml), "「先清空」默认不勾（危险项）");
check(boxHtml.indexOf("危险") < 0 && boxHtml.indexOf('data-bkrwipe') >= 0, "「先清空」存在且默认关");
check(boxHtml.indexOf('id="bk_opt_apps_restart"') >= 0 && /id="bk_opt_apps_restart"[^>]*checked/.test(boxHtml),
      "「恢复后起回容器」默认勾选");
check(boxHtml.indexOf("应用记录") >= 0, "提示还需勾选「应用记录」");
appStubs = stubsFrom(boxHtml, "bkrapp");
wipeStubs = stubsFrom(boxHtml, "bkrwipe");
check(appStubs.length === 2 && wipeStubs.length === 2, "解析出的勾选框数量正确",
      appStubs.length + "/" + wipeStubs.length);

console.log("== 恢复项勾选联动 ==");
setupItems(true);
S.toggle();
check(box.style.display === "", "勾了「应用数据（Docker）」→ 应用清单显示");
setupItems(false);
S.toggle();
check(box.style.display === "none", "取消勾选 → 应用清单隐藏");

console.log("== 一个应用都没勾 → 拦下 ==");
setupItems(true);
appStubs.forEach(s => { s.checked = false; });
toasts.length = 0; panes.length = 0; tasks.length = 0;
S.restore();
check(tasks.length === 0, "不发恢复请求");
check(toasts.length === 1 && /至少要勾一个应用/.test(toasts[0][0]), "给出明确提示", JSON.stringify(toasts));

console.log("== 正常恢复：opts 要带逐应用选项 ==");
setupItems(true);
appStubs.forEach(s => { s.checked = true; });
wipeStubs.forEach(s => { s.checked = false; });
toasts.length = 0; panes.length = 0; tasks.length = 0;
S.restore();
check(panes.length === 1, "弹一次确认框");
check(panes[0].msg.indexOf("应用数据：") >= 0 && panes[0].msg.indexOf("wordpress-8080") >= 0,
      "确认框列出要恢复的应用");
check(panes[0].msg.indexOf("先清空") < 0, "没勾「先清空」时不提清空");
panes[0].onOk();
check(tasks.length === 1 && tasks[0].p === "/api/backup/restore", "才真正发恢复请求");
const o1 = tasks[0].body.opts;
check(JSON.stringify(o1.restore_apps) === JSON.stringify(["wordpress-8080", "vaultwarden-8083"]),
      "opts.restore_apps = 勾选的应用", JSON.stringify(o1));
check(JSON.stringify(o1.wipe_apps) === "[]", "opts.wipe_apps = 空（默认不清空）");
check(o1.restart_apps === true, "opts.restart_apps 跟随勾选框");
check(tasks[0].body.items.app_files === true, "items 里带上 app_files 恢复项");

console.log("== 危险项「先清空」→ 必须二次确认 ==");
setupItems(true);
appStubs.forEach(s => { s.checked = false; });
appStubs[0].checked = true;
wipeStubs[0].checked = true;
toasts.length = 0; panes.length = 0; tasks.length = 0;
S.restore();
check(panes.length === 1 && panes[0].msg.indexOf("先清空") >= 0, "第一次确认框就写明要清空");
panes[0].onOk();
check(tasks.length === 0, "第一层确认后还不能发请求");
check(panes.length === 2, "必须再弹一次二次确认");
check(panes[1].title.indexOf("清空") >= 0, "二次确认标题点明清空", panes[1].title);
check(panes[1].msg.indexOf("wordpress-8080") >= 0, "二次确认列出具体应用");
panes[1].onOk();
check(tasks.length === 1, "二次确认后才发请求");
check(JSON.stringify(tasks[0].body.opts.wipe_apps) === JSON.stringify(["wordpress-8080"]),
      "opts.wipe_apps 带上要清空的应用", JSON.stringify(tasks[0].body.opts));

console.log("== 包内没有应用数据（旧包）也不该崩 ==");
S.render({ apps: [] });
check(els.bk_r_apps.innerHTML === "" && els.bk_r_apps.style.display === "none", "不渲染、隐藏");
setupItems(true);
appStubs = []; wipeStubs = [];
toasts.length = 0; panes.length = 0; tasks.length = 0;
S.restore();
check(tasks.length === 0 && toasts.length === 1, "拦下并提示（不发请求）");

console.log((failures === 0 ? "\n全部通过 ✓" : "\n失败 " + failures + " 项 ✗") + "（" + passes + " 通过）");
process.exit(failures === 0 ? 0 : 1);
