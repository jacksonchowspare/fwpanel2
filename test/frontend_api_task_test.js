#!/usr/bin/env node
/*
 * 长任务轮询 apiTask 的终止条件回归（v3.3.23）
 *
 * 背景（用户报障「配置 Docker 存储目录点了没反应，面板像卡死」）：
 *   apiTask 轮询 /api/tasks/<id>，旧实现只认 status==="ok" 与 "error" 两种终态，
 *   其余一律 continue 继续轮询，而且**没有总超时**。于是：
 *     ① 任务记录不存在/被清理（404「任务不存在或已过期」）→ 无限轮询：界面永不提示、永不结束 = 看着像卡死；
 *     ② 任何未知终态（后端若返回 interrupted / 别的状态）→ 同样无限轮询；
 *     ③ 任务记录丢了但接口正常返回时，用户要等到天荒地老也没有任何反馈。
 *   修法：404 类错误立即报错（提示记录已丢失/请刷新重试）、任何非 running 状态都视为终态、
 *   外加 30 分钟兜底总超时。后端「面板重启把遗留 running 标成 error」已有单测覆盖（test_reload_marks_stale_running_as_error）。
 *
 * 用法：node frontend_api_task_test.js [index.html]
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const file = process.argv[2] || path.join(__dirname, "..", "static", "index.html");
const html = fs.readFileSync(file, "utf8");
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const js = scripts.sort((a, b) => b.length - a.length)[0];

function extractFn(name) {
  const re = new RegExp("(?:async\\s+)?function\\s+" + name + "\\s*\\(");
  const m = re.exec(js);
  if (!m) return null;
  let depth = 0, started = false;
  for (let j = m.index; j < js.length; j++) {
    if (js[j] === "{") { depth++; started = true; }
    else if (js[j] === "}") { depth--; if (started && depth === 0) return js.slice(m.index, j + 1); }
  }
  return null;
}

let pass = 0, fail = 0;
function check(cond, label, extra) {
  if (cond) { pass++; console.log("  ✓ " + label); }
  else { fail++; console.log("  ✗ " + label + (extra ? "  → " + extra : "")); }
}

const src = extractFn("apiTask");
if (!src) { console.log("提取 apiTask 失败"); process.exit(2); }

function mkSandbox(apiImpl, dateNow) {
  const sb = { console, setTimeout, clearTimeout, Promise, Error, JSON, Math, Date,
               api: apiImpl, apiTask: null };
  if (dateNow) sb.Date = { now: dateNow };
  const ctx = vm.createContext(sb);
  vm.runInContext(src, ctx);
  return ctx;
}

const POST_REPLY = { task: "T1", ok: true, msg: "任务已开始" };
const t = (status, extra) => Object.assign({ action: "docker/data-root", status, ok: status === "ok",
                                             msg: status === "ok" ? "镜像存储已指向 /DockerData/dockerimage" : "执行中...",
                                             done: status !== "running", log: [] }, extra || {});

// 看门狗：旧实现在「任务记录丢失」那条会无限轮询，不设上限会把这个测试挂死（变异验证需要它能自己退出）
const __watchdog = setTimeout(() => {
  console.log("\n✗ 测试未在 60 秒内结束 —— 极可能是 apiTask 陷入了无限轮询（旧实现的症状）");
  console.log("结果: " + pass + " 通过, " + (fail + 1) + " 失败");
  process.exit(1);
}, 60000);

(async () => {
  console.log("== 1) 服务端同步完成（无 task 字段）→ 直接返回原响应 ==");
  {
    const ctx = mkSandbox(async () => ({ ok: true, msg: "同步完成" }));
    const r = await vm.runInContext("apiTask('POST','/api/x',{})", ctx);
    check(r && r.msg === "同步完成", "同步路径原样返回", JSON.stringify(r));
  }

  console.log("== 2) running → running → ok → 正常返回 ==");
  {
    let n = 0;
    const ctx = mkSandbox(async (m, p) => {
      if (p.endsWith("/api/docker/data-root")) return POST_REPLY;
      n++;
      return n < 3 ? t("running") : t("ok");
    });
    const r = await vm.runInContext("apiTask('POST','/api/docker/data-root',{})", ctx);
    check(r.ok === true && /镜像存储/.test(r.msg), "轮询到 ok 后返回 ok/msg", JSON.stringify(r));
  }

  console.log("== 3) error → 抛错且带 msg ==");
  {
    const ctx = mkSandbox(async (m, p) => p.endsWith("/data-root") ? POST_REPLY : t("error", { msg: "配置失败: 模拟" }));
    let err = null;
    try { await vm.runInContext("apiTask('POST','/api/docker/data-root',{})", ctx); } catch (e) { err = e; }
    check(err && /配置失败/.test(err.message), "error 立刻抛出原 msg", err && err.message);
  }

  console.log("== 4) 未知终态（interrupted 等）不能无限轮询 ==");
  {
    const ctx = mkSandbox(async (m, p) => p.endsWith("/data-root") ? POST_REPLY
      : t("interrupted", { done: true, msg: "任务被面板重启中断（未完成），请重新执行一次" }));
    const t0 = Date.now();
    let err = null;
    try { await vm.runInContext("apiTask('POST','/api/docker/data-root',{})", ctx); } catch (e) { err = e; }
    const dt = (Date.now() - t0) / 1000;
    check(err && /中断/.test(err.message), "未知终态视为失败并抛出", err && err.message);
    check(dt < 6, "一轮轮询后即结束（未死循环）", dt + "s");
  }

  console.log("== 5) 任务记录丢失（404「任务不存在或已过期」）→ 立即报错，不无限轮询 ==");
  {
    let polls = 0;
    const ctx = mkSandbox(async (m, p) => {
      if (p.endsWith("/data-root")) return POST_REPLY;
      polls++;
      const e = new Error("任务不存在或已过期");
      throw e;
    });
    const t0 = Date.now();
    let err = null;
    try { await vm.runInContext("apiTask('POST','/api/docker/data-root',{})", ctx); } catch (e) { err = e; }
    const dt = (Date.now() - t0) / 1000;
    check(err && /丢失/.test(err.message), "提示任务记录已丢失/请刷新重试", err && err.message);
    check(polls === 1, "只轮询一次就放弃（旧实现会一直转）", "轮询次数=" + polls);
    check(dt < 6, "耗时正常", dt + "s");
  }

  console.log("== 6) 兜底总超时（任务永远 running）==");
  {
    let now = 1e12;
    const ctx = mkSandbox(async (m, p) => p.endsWith("/data-root") ? POST_REPLY : t("running"), () => now);
    // 每次 Date.now() 前进 5 分钟 → 几轮内必然越过 30 分钟上限
    vm.runInContext("var __advance = null;", ctx);
    const realNow = () => { now += 5 * 60 * 1000; return now; };
    const ctx2 = mkSandbox(async (m, p) => p.endsWith("/data-root") ? POST_REPLY : t("running"), realNow);
    let err = null;
    try { await vm.runInContext("apiTask('POST','/api/docker/data-root',{})", ctx2); } catch (e) { err = e; }
    check(err && /超时/.test(err.message), "超时后报错而不是永远转圈", err && err.message);
  }

  clearTimeout(__watchdog);
  console.log("\n结果: " + pass + " 通过, " + fail + " 失败");
  process.exit(fail ? 1 : 0);
})();
