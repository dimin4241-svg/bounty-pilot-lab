'use strict';
/* Isolated researcher-owned browser fixture observation.
 * No arbitrary JS from a plan is evaluated. Page JS still executes within
 * Chromium, so run only against disposable trusted 127.0.0.1 fixtures.
 * Every request outside the exact loopback origin is aborted before dispatch.
 */
const fs = require('fs');
const path = require('path');
const root = process.argv[2];
const configPath = process.argv[3];
const outPath = process.argv[4];
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const u = new URL(config.origin);
if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' ||
    String(u.port) !== config.origin.split(':').at(-1) ||
    !/^#[A-Za-z][A-Za-z0-9_-]{0,79}$/.test(config.scalar_selector) ||
    ![config.owner_path, config.outsider_path].every(x =>
        typeof x === 'string' && /^\/[A-Za-z0-9_./-]{1,240}$/.test(x) &&
        !x.includes('..') && !x.includes('//'))) {
  throw Error('invalid owned local browser plan');
}
// Resolve the operator-supplied trusted module, not the target fixture's
// potentially malicious node_modules directory.
const {chromium} = require(path.join(root, 'playwright'));
let browser = null;
let blocked = 0;
async function visit(p) {
  const context = await browser.newContext({
    acceptDownloads:false, serviceWorkers:'block',
    ignoreHTTPSErrors:false, permissions:[], javaScriptEnabled:true
  });
  await context.route('**/*', route => {
    let candidate;
    try { candidate = new URL(route.request().url()); }
    catch (_) { blocked++; return route.abort(); }
    if (candidate.origin !== config.origin || candidate.protocol !== 'http:') {
      blocked++;
      return route.abort();
    }
    return route.continue();
  });
  const page = await context.newPage();
  try {
    const response = await page.goto(config.origin + p, {
      waitUntil:'domcontentloaded', timeout:10000
    });
    if (!response || new URL(page.url()).origin !== config.origin)
      throw Error('fixture navigation ended outside exact owned origin');
    const locator = page.locator(config.scalar_selector).first();
    if (await locator.count() !== 1) {
      return {present:false, scalar:null, http_status:response.status()};
    }
    const raw = await locator.getAttribute('data-bp-scalar');
    const scalar = typeof raw === 'string' && /^-?\d{1,10}$/.test(raw)
      ? Number(raw) : null;
    return {present:raw !== null, scalar, http_status:response.status()};
  } finally {
    await context.close();
  }
}
(async () => {
  try {
    browser = await chromium.launch({headless:true});
    const owner = await visit(config.owner_path);
    const outsider = await visit(config.outsider_path);
    fs.writeFileSync(outPath, JSON.stringify({
      schema_version:1, mode:'local-browser-isolated-contexts',
      owner, outsider, blocked_external_requests:blocked
    }));
  } finally {
    if (browser) await browser.close();
  }
})().catch(() => { process.exitCode = 1; });
