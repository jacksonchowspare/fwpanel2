#!/usr/bin/env node
/* 改端口后自动跳转的前端行为测试（v3.2.25）
 *
 * 背景：系统页的「修改面板端口」按钮改完不跳转（走 sysRun 只弹提示），
 * 带跳转逻辑的 setPanelPort() 反而没有按钮绑定。现在两个入口统一走
 * afterPanelPortChange()：轮询探测新端口，服务起来才跳，超时有兜底。
 *
 * 从 static/index.html 现场抽取该函数，在假浏览器环境里真跑四个场景：
 *   1) 直连 IP 改端口：探测失败几次后服务就绪 → 跳到新端口
 *   2) 服务一直起不来 → 30 秒上限后仍然强制跳转（不让用户卡在死页面）
 *   3) 反代域名访问（地址栏无端口）→ 原地刷新，不跳到带端口地址
 *   4) 端口没变化 → 不探测也不跳转
 *
 * 用法：node test/frontend_port_redirect_test.js   （全通过退出码 0）
 */
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "..", "static", "index.html"), "utf8");
const marker = "function afterPanelPortChange(";
const start = html.indexOf(marker);
if (start < 0) {
    console.log("FAIL 找不到 afterPanelPortChange()");
    process.exit(1);
}
// 花括号配平，抽出函数完整体
let depth = 0, end = start;
for (; end < html.length; end++) {
    const c = html[end];
    if (c === "{") depth++;
    else if (c === "}") {
        depth--;
        if (depth === 0) { end++; break; }
    }
}
const fnSrc = html.slice(start, end);

/* ---------------- 假浏览器环境 ---------------- */
const realSetImmediate = setImmediate;
let timers = [], time = 0, calls = { toasts: [], nav: [], probes: [] };

global.setTimeout = (fn, ms) => { timers.push({ fn, at: time + (ms || 0) }); return timers.length; };
global.clearTimeout = () => {};
global.toast = (m, k) => calls.toasts.push([String(m), k || ""]);

const loc = { protocol: "http:", hostname: "203.0.113.9", port: "17890" };
Object.defineProperty(loc, "href", {
    get() { return "http://203.0.113.9" + (loc.port ? ":" + loc.port : "") + "/"; },
    set(v) { calls.nav.push(v); },
});
global.location = loc;

let probeFailTimes = 0;
global.fetch = (url) => {
    calls.probes.push(url);
    if (probeFailTimes > 0 && probeFailTimes-- > 0) return Promise.reject(new Error("ECONNREFUSED"));
    return Promise.resolve({});
};

const realDateNow = Date.now;
Date.now = () => time;

async function runTimers(max = 600000) {
    let guard = 0;
    while (timers.length && guard++ < 5000) {
        timers.sort((a, b) => a.at - b.at);
        const t = timers.shift();
        if (t.at > max) break;
        time = t.at;
        t.fn();
        await new Promise((r) => realSetImmediate(r));
        await new Promise((r) => realSetImmediate(r));
    }
}
function reset() { timers = []; time = 0; calls = { toasts: [], nav: [], probes: [] }; }

let failed = 0;
function done(name, cond, extra) {
    console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : "  <<< " + JSON.stringify(extra)));
    if (!cond) failed++;
}

/* ---------------- 跑场景 ---------------- */
eval(fnSrc);

(async () => {
    // 1) 直连：探测失败 2 次后服务起来 → 跳新端口
    reset(); loc.port = "17890"; probeFailTimes = 2;
    afterPanelPortChange(18001);
    await runTimers();
    done("直连：新端口就绪后跳到新地址",
        calls.nav.length === 1 && calls.nav[0] === "http://203.0.113.9:18001",
        { nav: calls.nav, probes: calls.probes.length });
    done("直连：探测的是新端口且重试过",
        calls.probes.length >= 3 && calls.probes.every((u) => u === "http://203.0.113.9:18001/"),
        { probes: calls.probes });
    done("直连：过程中有可见提示", calls.toasts.some((t) => /服务已就绪|正在跳转/.test(t[0])), calls.toasts);

    // 2) 服务一直起不来 → 超时兜底也要跳
    reset(); loc.port = "17890"; probeFailTimes = 1e9;
    afterPanelPortChange(18002);
    await runTimers();
    done("超时兜底：30 秒后强制跳转",
        calls.nav.length === 1 && calls.nav[0] === "http://203.0.113.9:18002", { nav: calls.nav });
    done("超时兜底：有超时提示", calls.toasts.some((t) => /超时/.test(t[0])), calls.toasts);

    // 3) 反代域名访问 → 原地刷新
    reset(); loc.port = ""; probeFailTimes = 0;
    afterPanelPortChange(18003);
    await runTimers();
    done("反代：原地刷新而不是跳端口",
        calls.nav.length === 1 && calls.nav[0] === "http://203.0.113.9/", { nav: calls.nav });
    done("反代：探测的是当前地址（不带端口）", calls.probes.every((u) => !/:\d+/.test(u)), calls.probes);

    // 4) 端口没变 → 什么都不做
    reset(); loc.port = "17890"; probeFailTimes = 0;
    afterPanelPortChange(17890);
    await runTimers();
    done("端口未变化：不跳转不探测",
        calls.nav.length === 0 && calls.probes.length === 0, { nav: calls.nav, probes: calls.probes });

    console.log(failed ? `\n${failed} 项失败` : "\n全部通过");
    Date.now = realDateNow;
    process.exit(failed ? 1 : 0);
})();
