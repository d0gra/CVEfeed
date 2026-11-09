/**
 * Spending less of someone else's rate budget.
 *
 * Three guards, all added after GitHub suspended the account this deployment
 * was authenticating as:
 *   - a breaker, so a register that is refusing stops being asked;
 *   - a crawler rule, so walking the sitemap costs no upstream requests;
 *   - an anonymous rule, so a 60/hour budget goes to the refresh rather than
 *     to single-record lookups.
 *
 *   node test/budget.mjs
 */
import assert from 'node:assert/strict';

process.env.MONGODB_URI = '';

const { mayCall, record, cooldownRemaining, resetBreakers, FAILURES_BEFORE_OPEN, COOLDOWN_MS } =
  await import('../src/lib/breaker.js');
const { isBot } = await import('../src/lib/bots.js');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

/* ---------- the breaker ---------- */

resetBreakers();
check('an untouched source may be called', mayCall('github') === true);

for (let i = 0; i < FAILURES_BEFORE_OPEN - 1; i += 1) record('github', false);
check(`${FAILURES_BEFORE_OPEN - 1} failures is not enough to stop`, mayCall('github') === true);

record('github', false);
check(`${FAILURES_BEFORE_OPEN} consecutive failures closes the door`, mayCall('github') === false);
check('  ...and says for how long', cooldownRemaining('github') > 0 && cooldownRemaining('github') <= COOLDOWN_MS / 1000);
check('  ...for that source only', mayCall('nvd') === true);

const later = Date.now() + COOLDOWN_MS + 1000;
check('after the cooldown, one probe is let through', mayCall('github', later) === true);
check('  ...and only one', mayCall('github', later) === false);

record('github', false, later);
check('a failed probe closes it again', mayCall('github', later + 1000) === false);

const muchLater = later + COOLDOWN_MS + 1000;
assert.equal(mayCall('github', muchLater), true);
record('github', true, muchLater);
check('a success reopens it', mayCall('github', muchLater) === true);
check('  ...and clears the cooldown', cooldownRemaining('github', muchLater) === 0);

resetBreakers();
record('kev', false);
record('kev', true);
record('kev', false);
record('kev', false);
check('failures must be consecutive to count', mayCall('kev') === true);

/* ---------- crawlers ---------- */

const crawlers = [
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
  'Mozilla/5.0 (compatible; SemrushBot/7~bl)',
  'python-requests/2.31.0',
  'curl/8.4.0',
  'Go-http-client/2.0',
  'facebookexternalhit/1.1',
  'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0',
];
for (const ua of crawlers) check(`crawler: ${ua.slice(0, 38)}`, isBot(ua) === true);

const people = [
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
];
for (const ua of people) check(`reader: ${ua.slice(0, 38)}`, isBot(ua) === false);
check('a missing User-Agent is not assumed to be a crawler', isBot(undefined) === false && isBot('') === false);

/* ---------- the anonymous rule ---------- */

const github = (await import('../src/sources/github.js')).default;
check('github declares the variable that lifts its budget', github.meta.authEnv === 'GITHUB_TOKEN');
check('  ...and that lookups need it', github.meta.lookupNeedsAuth === true);

const kev = (await import('../src/sources/kev.js')).default;
check('a source with no credential is not held to that rule', !kev.meta.lookupNeedsAuth);

console.log(`\n${pass} passed, ${fail} failed`);
assert.equal(fail, 0);
