// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.
//
// Playwright headless-Chromium end-to-end test for wasmlogin.
//   - login page renders
//   - submit creds + WM selection → redirect into the chosen desktop
//   - logout → back at the login page
// Screenshots captured under /tmp/wasmlogin-*.png.

const { chromium } = require('playwright');

const PORTAL = process.env.PORTAL_URL || 'http://localhost:9001';

function assertEq(got, want, label) {
  if (got !== want) {
    throw new Error(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  }
}

function assertContains(haystack, needle, label) {
  if (!haystack.includes(needle)) {
    throw new Error(`${label}: ${JSON.stringify(haystack)} missing ${JSON.stringify(needle)}`);
  }
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  // ---- 1. login page ----
  await page.goto(PORTAL + '/');
  await page.waitForSelector('form');
  const title = await page.title();
  assertEq(title, 'WASMDESK — Sign in', 'login page title');
  const heading = await page.textContent('.title');
  assertEq(heading.trim(), 'WASMDESK', 'card heading');
  const opts = await page.$$eval('select[name=wm] option', os => os.map(o => o.value));
  assertEq(JSON.stringify(opts), JSON.stringify(['wasmaqua', 'wasmbox']), 'WM options');
  await page.screenshot({ path: '/tmp/wasmlogin-login.png', fullPage: true });

  // ---- 2. sign in with wasmaqua ----
  await page.fill('input[name=user]', 'alice');
  await page.fill('input[name=password]', 'x');
  await page.selectOption('select[name=wm]', 'wasmaqua');
  await Promise.all([
    page.waitForURL('**/wasmaqua/'),
    page.click('button[type=submit]'),
  ]);
  const urlAfter = page.url();
  assertEq(urlAfter, PORTAL + '/wasmaqua/', 'post-login URL');
  const body = await page.textContent('body');
  assertContains(body, 'OK wasmaqua', 'post-login body');
  await page.screenshot({ path: '/tmp/wasmlogin-post-login.png', fullPage: true });

  // ---- 3. cookie was set ----
  const cookies = await ctx.cookies();
  const sess = cookies.find(c => c.name === 'wasmdesk_session');
  if (!sess || sess.value.length < 10) {
    throw new Error('session cookie not set: ' + JSON.stringify(cookies));
  }

  // ---- 4. revisiting root with a valid session → bounce into wasmaqua ----
  await page.goto(PORTAL + '/');
  await page.waitForURL('**/wasmaqua/');
  assertEq(page.url(), PORTAL + '/wasmaqua/', 'authed root redirect');

  // ---- 5. logout via POST form ----
  await page.goto(PORTAL + '/');                       // back to authed view
  await page.evaluate(async (PORTAL) => {
    const f = document.createElement('form');
    f.method = 'POST';
    f.action = '/logout';
    document.body.appendChild(f);
    f.submit();
  }, PORTAL);
  await page.waitForSelector('form input[name=user]');
  assertEq(page.url(), PORTAL + '/', 'post-logout URL');
  await page.screenshot({ path: '/tmp/wasmlogin-post-logout.png', fullPage: true });

  // ---- 6. /wasmbox/ without a session bounces to / ----
  await page.goto(PORTAL + '/wasmbox/');
  await page.waitForSelector('form input[name=user]');
  assertEq(page.url(), PORTAL + '/', 'unauth /wasmbox bounced');

  await browser.close();
  console.log('OK wasmlogin e2e: login + WM dispatch + logout verified');
  process.exit(0);
})().catch(err => {
  console.error('FAIL', err);
  process.exit(1);
});
