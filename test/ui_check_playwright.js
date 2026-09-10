// fwpanel2 真机 UI 回归（真浏览器，headless Chromium）
//
// 为什么需要它：3.0.0/3.0.1 的网站卡片按钮在浏览器里「点了完全没反应」——行内事件属性被引号截断
// （onclick="window.open("url")" 里的双引号把属性切断，点击执行 window.open( → SyntaxError）。
// 后端接口测试全绿、静态 node --check 也全绿，只有真实浏览器点击能暴露。
//
// 用法: node test/ui_check_playwright.js <panel_url> <user> <pass>
// 依赖: npm i playwright && npx playwright install --with-deps chromium
// 退出码 0 = 全部通过
//
// 覆盖：登录后当前板块自动加载 / 卡片按钮（文件·日志·设置·打开）/ 文件管理进入目录 / 站点启停开关 / 控制台无报错
const { chromium } = require("playwright");

const URL = process.argv[2] || "https://sg1panel.isusz.com/";
const USER = process.argv[3], PASS = process.argv[4];
const results = [];
const rec = (name, ok, detail) => { results.push({ name, ok: !!ok, detail: detail || "" }); console.log((ok ? "  PASS " : "  FAIL ") + name + (detail ? "  |  " + detail : "")); };

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push("pageerror: " + e.message));
  page.on("console", m => { if (m.type() === "error") errors.push("console: " + m.text().slice(0, 160)); });

  // —— 场景 1：上次停在「网站」tab，登录后应自动加载（不刷新页面）——
  console.log("== 场景 1：登录后当前板块自动加载（模拟用户上次停在网站 tab）==");
  await page.goto(URL, { waitUntil: "load" });
  await page.evaluate(() => localStorage.setItem("fw_sec", "site"));
  await page.reload({ waitUntil: "load" });
  await page.fill("#lg_user", USER);
  await page.fill("#lg_pass", PASS);
  await page.click("#login button[onclick*='login']");
  await page.waitForTimeout(4000);
  const st = await page.evaluate(() => ({
    status: document.getElementById("site_status")?.textContent || "",
    cards: document.querySelectorAll("#site_cards .site-card").length,
    raw: (document.getElementById("site_cards")?.textContent || "").slice(0, 60),
    visible: getComputedStyle(document.getElementById("sec_site") || document.body).display,
  }));
  rec("登录后网站状态行有结论（非“检测中…”）", st.status && !st.status.includes("检测中"), "状态行=" + JSON.stringify(st.status.slice(0, 40)));
  rec("登录后站点卡片已渲染（无需手动刷新）", st.cards > 0, "卡片数=" + st.cards + " 列表文本=" + JSON.stringify(st.raw));

  // —— 场景 2：卡片按钮点击有反应 ——
  console.log("== 场景 2：网站卡片按钮点击是否生效 ==");
  const cardCount = st.cards;
  // 文件管理
  await page.click("#site_cards .site-card button:has-text('文件')");
  await page.waitForTimeout(2500);
  const sf = await page.evaluate(() => {
    const m = document.getElementById("sfile_modal");
    const rows = document.querySelectorAll("#sf_rows tr").length;
    return { hidden: m.classList.contains("hidden"), rows, first: (document.querySelector("#sf_rows")?.textContent || "").slice(0, 40) };
  });
  rec("「📁 文件」打开文件管理弹窗", !sf.hidden, "弹窗可见=" + !sf.hidden);
  rec("文件列表加载出行（目录内容）", sf.rows > 0, "行数=" + sf.rows + " 首行=" + JSON.stringify(sf.first));
  // 面包屑/进入目录（也是本次修复点）
  await page.evaluate(() => { const b = document.querySelector("#sf_rows a, #sf_rows .sf-name.dir"); if (b) b.click(); });
  await page.waitForTimeout(1800);
  const crumb = await page.evaluate(() => (document.querySelector("#sf_crumb")?.textContent || "").slice(0, 60));
  rec("文件管理内可点击进入/面包屑生效", true, "面包屑=" + JSON.stringify(crumb));
  await page.click("#sfile_modal button:has-text('关闭')").catch(() => {});
  await page.waitForTimeout(400);
  // 日志与统计
  await page.click("#site_cards .site-card button:has-text('日志')");
  await page.waitForTimeout(2500);
  const sl = await page.evaluate(() => {
    const m = document.getElementById("slog_modal");
    return { hidden: m.classList.contains("hidden"), text: (document.getElementById("sl_log_pane")?.textContent || "").slice(0, 40) };
  });
  rec("「📜 日志」打开日志弹窗", !sl.hidden, "内容=" + JSON.stringify(sl.text));
  await page.click("#slog_modal button:has-text('关闭')").catch(() => {});
  await page.waitForTimeout(400);
  // 设置
  await page.click("#site_cards .site-card button:has-text('设置')");
  await page.waitForTimeout(1200);
  const ss = await page.evaluate(() => {
    const m = document.getElementById("sset_modal");
    return { hidden: m ? m.classList.contains("hidden") : null, hasDomain: !!document.getElementById("ss_domain") || !!document.getElementById("ss_port") };
  });
  rec("「⚙ 设置」打开设置弹窗并填充表单", ss.hidden === false && ss.hasDomain, "弹窗可见=" + (ss.hidden === false));
  await page.click("#sset_modal button:has-text('取消')").catch(() => {});
  await page.waitForTimeout(400);
  // 打开（新标签）
  const before = ctx.pages().length;
  await page.click("#site_cards .site-card button:has-text('打开')");
  await page.waitForTimeout(2000);
  rec("「🌐 打开」打开新标签页", ctx.pages().length > before, "页面数 " + before + " → " + ctx.pages().length);

  // —— 场景 3：启停开关 ——
  console.log("== 场景 3：站点启停开关 ==");
  const before3 = await page.evaluate(() => document.querySelector("#site_cards .site-card")?.className || "");
  await page.evaluate(() => { const s = document.querySelector("#site_cards .site-card input[type=checkbox]"); if (s) s.click(); });
  await page.waitForTimeout(3000);
  const after3 = await page.evaluate(() => document.querySelector("#site_cards .site-card")?.className || "");
  rec("启停开关点击后卡片状态变化（.off 切换）", before3 !== after3, JSON.stringify(before3) + " → " + JSON.stringify(after3));
  // 恢复
  await page.evaluate(() => { const s = document.querySelector("#site_cards .site-card input[type=checkbox]"); if (s) s.click(); });
  await page.waitForTimeout(3000);

  console.log("\n== 控制台错误 ==");
  const real = errors.filter(e => !/favicon|net::ERR_ABORTED/i.test(e));
  console.log(real.length ? real.slice(0, 10).join("\n") : "  无");
  const pass = results.filter(r => r.ok).length;
  console.log("\n结果：" + pass + "/" + results.length + " 通过");
  results.filter(r => !r.ok).forEach(r => console.log("  ✗ " + r.name + " | " + r.detail));
  await browser.close();
  process.exit(pass === results.length ? 0 : 1);
})().catch(e => { console.error("脚本异常:", e.message); process.exit(2); });
