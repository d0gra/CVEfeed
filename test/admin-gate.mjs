/**
 * The admin dashboard's gate.
 *
 * /admin/mcp ships no data and is not itself gated - like /moderate, it is
 * unlisted rather than secret. Everything under /admin/api is gated, and the
 * properties worth holding to are:
 *
 *   - no token, no data, on every route including the mutating ones;
 *   - a verification that CANNOT BE COMPLETED denies rather than admits. The
 *     gate asks Supabase whether a session is still an admin's, and an
 *     unreachable Supabase must fail closed;
 *   - the secret key, which bypasses RLS, never reaches the page.
 *
 * Hermetic: Supabase is pointed at a dead port, so nothing here leaves the
 * machine.
 *
 *   node test/admin-gate.mjs
 */
process.env.MONGODB_URI = '';
process.env.SUPABASE_URL = 'http://127.0.0.1:1';
process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_for_the_suite_only';
process.env.SUPABASE_SECRET_KEY = 'sb_secret_for_the_suite_only';

import assert from 'node:assert/strict';

const config = (await import('../src/config.js')).default;
const { createApp } = await import('../src/server.js');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

const server = createApp().listen(0);
await new Promise((resolve) => server.once('listening', resolve));
const base = `http://127.0.0.1:${server.address().port}`;

const call = (path, init = {}) => fetch(`${base}${path}`, init);

/* ---------- the page ---------- */

{
  const res = await call('/admin/mcp');
  const html = await res.text();
  check('the dashboard renders', res.status === 200, `got ${res.status}`);
  check('it is not cached', res.headers.get('cache-control') === 'no-store');
  check('it is not indexed', res.headers.get('x-robots-tag') === 'noindex');
  check('it offers a sign-in', html.includes('id="ad-signin"'));
  // The one value that must never be in a page: it bypasses RLS entirely.
  check('the secret key is not in the page', !html.includes(config.supabaseSecretKey));
  check('the publishable key is', html.includes(config.supabasePublishableKey));
}

/* ---------- the gate ---------- */

const guarded = [
  ['GET', '/admin/api/gateway', undefined],
  ['GET', '/admin/api/host', undefined],
  ['POST', '/admin/api/keys', JSON.stringify({ label: 'x', ratePerHour: 10 })],
  ['PATCH', '/admin/api/keys/00000000-0000-4000-8000-000000000000', JSON.stringify({ disabled: true })],
];

for (const [method, path, body] of guarded) {
  const res = await call(path, {
    method,
    body,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
  });
  check(`${method} ${path} refuses an unauthenticated caller`, res.status === 401, `got ${res.status}`);
}

{
  // A token shaped like a real one, but Supabase is unreachable. The gate must
  // not fall open because it could not ask.
  const res = await call('/admin/api/gateway', { headers: { Authorization: 'Bearer eyJhbGciOiJFUzI1NiJ9.x.y' } });
  const body = await res.json();
  check('an unverifiable token is refused, not admitted', res.status === 401, `got ${res.status}`);
  check('and it says why', /could not reach|not valid|not an administrator/i.test(body.error ?? ''), body.error);
}

{
  const res = await call('/admin/api/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer eyJhbGciOiJFUzI1NiJ9.x.y' },
    body: JSON.stringify({ label: 'should not exist', ratePerHour: 600 }),
  });
  check('an unverifiable token cannot mint a key', res.status === 401, `got ${res.status}`);
}

/* ---------- unconfigured ---------- */

{
  const real = config.supabaseSecretKey;
  config.supabaseSecretKey = '';
  const res = await call('/admin/api/gateway', { headers: { Authorization: 'Bearer anything' } });
  config.supabaseSecretKey = real;
  check('unconfigured reports disabled rather than open', res.status === 404, `got ${res.status}`);
}

/* ---------- not crawled ---------- */

{
  const robots = await (await call('/robots.txt')).text();
  check('robots.txt keeps crawlers out of /admin/', robots.includes('Disallow: /admin/'));
  check('robots.txt keeps crawlers out of /oauth/', robots.includes('Disallow: /oauth/'));
}

server.close();
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
