/**
 * The signed-in account: /account/api/*, /signin and the gated /mcp page.
 *
 * Anyone with a GitHub account can sign up, so the property that matters is
 * not just "no token, no data" but "your token, only your data". That needs a
 * second user to try it, so this runs against a small fake Supabase - Auth's
 * /user endpoint and the handful of PostgREST calls the account makes - on a
 * local port. Nothing leaves the machine.
 *
 *   node test/account-gate.mjs
 */
import http from 'node:http';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

/* ---------- a fake Supabase, just big enough ---------- */

const USERS = {
  'token-alice': { id: 'aaaaaaaa-0000-4000-8000-000000000001', email: 'alice@example.test', app_metadata: {} },
  'token-bob': { id: 'bbbbbbbb-0000-4000-8000-000000000002', email: 'bob@example.test', app_metadata: {} },
};
const keys = []; // { id, owner, label, key_prefix, key_hash, disabled_at, ... }
let nextId = 1;

const fake = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://fake');
  let body = '';
  for await (const chunk of req) body += chunk;
  const json = (status, value) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(value));
  };
  const eq = (name) => url.searchParams.get(name)?.replace(/^eq\./, '');

  if (url.pathname === '/auth/v1/user') {
    const token = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
    return USERS[token] ? json(200, USERS[token]) : json(401, { msg: 'invalid JWT' });
  }
  if (url.pathname === '/rest/v1/rpc/mcp_user_quota') {
    return json(200, [{ tier: 'new', rate_per_hour: 60, deps_per_hour: 10, web_per_hour: 5 }]);
  }
  if (url.pathname === '/rest/v1/rpc/mcp_quota_status') {
    const reset = new Date(Date.now() + 30 * 60_000).toISOString();
    return json(200, [
      { bucket: 'calls', used: 3, reset_at: reset },
      { bucket: 'deps', used: 0, reset_at: reset },
      { bucket: 'web', used: 1, reset_at: reset },
    ]);
  }
  if (url.pathname === '/rest/v1/mcp_keys_public') {
    const owner = eq('owner');
    const activeOnly = url.searchParams.get('active') === 'is.true';
    const rows = keys
      .filter((k) => k.owner === owner && (!activeOnly || !k.disabled_at))
      .map(({ key_hash, ...k }) => ({ ...k, active: !k.disabled_at }));
    return json(200, rows);
  }
  if (url.pathname === '/rest/v1/mcp_keys' && req.method === 'POST') {
    const [row] = JSON.parse(body);
    const stored = { id: `00000000-0000-4000-8000-${String(nextId++).padStart(12, '0')}`, disabled_at: null, ...row };
    keys.push(stored);
    return json(201, [stored]);
  }
  if (url.pathname === '/rest/v1/mcp_keys' && req.method === 'PATCH') {
    // The owner filter is the authorisation: a row must match id AND owner.
    const id = eq('id');
    const owner = eq('owner');
    const hit = keys.filter((k) => k.id === id && (owner === undefined || k.owner === owner));
    for (const k of hit) Object.assign(k, JSON.parse(body));
    return json(200, hit);
  }
  json(404, { message: `fake supabase has no ${req.method} ${url.pathname}` });
});
await new Promise((resolve) => fake.listen(0, '127.0.0.1', resolve));

process.env.MONGODB_URI = '';
process.env.SUPABASE_URL = `http://127.0.0.1:${fake.address().port}`;
process.env.SUPABASE_SECRET_KEY = 'sb_secret_for_the_suite_only';
process.env.MCP_GATEWAY_URL = 'https://example-project.supabase.co/functions/v1/mcp';

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
const as = (token, path, init = {}) =>
  fetch(`${base}${path}`, {
    ...init,
    headers: {
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

/* ---------- no token, no data ---------- */

for (const [method, path, body] of [
  ['GET', '/account/api/me'],
  ['POST', '/account/api/keys', '{}'],
  ['PATCH', '/account/api/keys/x', '{"disabled":true}'],
]) {
  const res = await as(null, path, { method, body });
  check(`${method} ${path} refuses an unauthenticated caller`, res.status === 401, `got ${res.status}`);
}
{
  const res = await as('token-nobody', '/account/api/me');
  check('a token Supabase does not recognise is refused', res.status === 401, `got ${res.status}`);
}

/* ---------- your token, your account ---------- */

{
  const res = await as('token-alice', '/account/api/me');
  const me = await res.json();
  check('a signed-in user reads their account', res.status === 200, `got ${res.status}`);
  check('it shows the new-account tier', me.tier === 'new');
  check('budgets carry what is left', me.budgets?.calls?.remaining === 57 && me.budgets?.web?.remaining === 4,
    JSON.stringify(me.budgets?.calls));
  check('and when each resets', Boolean(me.budgets?.calls?.resetAt));
}

let aliceKey;
{
  const res = await as('token-alice', '/account/api/keys', { method: 'POST', body: JSON.stringify({ label: 'ci' }) });
  const created = await res.json();
  aliceKey = created.id;
  check('a user can mint a key', res.status === 201 && /^cvf_live_[0-9a-f]{48}$/.test(created.key ?? ''), `got ${res.status}`);
  check('the stored row is owned by them', keys.find((k) => k.id === aliceKey)?.owner === USERS['token-alice'].id);
  check('only a hash is stored, never the key', !JSON.stringify(keys).includes(created.key));
}
{
  const res = await as('token-bob', `/account/api/keys/${aliceKey}`, { method: 'PATCH', body: '{"disabled":true}' });
  check("another user cannot revoke someone else's key", res.status === 404, `got ${res.status}`);
  check('and the key is untouched', !keys.find((k) => k.id === aliceKey).disabled_at);
}
{
  const res = await as('token-bob', '/account/api/me');
  const me = await res.json();
  check("another user does not see someone else's keys", Array.isArray(me.keys) && me.keys.length === 0);
}
{
  const res = await as('token-alice', `/account/api/keys/${aliceKey}`, { method: 'PATCH', body: '{"disabled":true}' });
  check('the owner can revoke their own key', res.status === 200, `got ${res.status}`);
}
{
  const res = await as('token-alice', `/account/api/keys/${aliceKey}`, { method: 'PATCH', body: '{"ratePerHour":100000}' });
  check('a user cannot raise their own limit', res.status === 400, `got ${res.status}`);
}
{
  for (let i = 0; i < 3; i++) {
    await as('token-alice', '/account/api/keys', { method: 'POST', body: JSON.stringify({ label: `k${i}` }) });
  }
  const res = await as('token-alice', '/account/api/keys', { method: 'POST', body: '{}' });
  check('keys are capped per person', res.status === 409, `got ${res.status}`);
}

/* ---------- the pages ---------- */

{
  const res = await fetch(`${base}/signin`);
  const html = await res.text();
  check('/signin renders', res.status === 200, `got ${res.status}`);
  check('/signin offers GitHub', html.includes('Continue with GitHub'));
  check('/signin has no email sign-in', !/type="email"|magic link|\/otp/i.test(html));
  check('/signin never carries the secret key', !html.includes(config.supabaseSecretKey));
}
{
  const res = await fetch(`${base}/mcp`, { headers: { Accept: 'text/html' } });
  const html = await res.text();
  const hiddenStart = html.indexOf('id="signed-in" hidden');
  const firstButton = html.indexOf('class="install-btn" href="vscode:');
  check('/mcp leads signed-out visitors to sign in', html.includes('Sign in with GitHub to connect'));
  check('/mcp keeps the install buttons inside the signed-in view', hiddenStart > -1 && firstButton > hiddenStart);
  check('/mcp never carries the secret key', !html.includes(config.supabaseSecretKey));
}
{
  const robots = await (await fetch(`${base}/robots.txt`)).text();
  check('robots.txt keeps crawlers off /signin', robots.includes('Disallow: /signin'));
}

/* ---------- the open-redirect guard in session.js ---------- */

{
  const sandbox = {
    window: { location: { hash: '', origin: 'https://cve.zerocrew.in', pathname: '/mcp', search: '' } },
    document: { querySelector: () => null },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    history: { replaceState() {} },
    URLSearchParams,
  };
  vm.runInNewContext(readFileSync(new URL('../public/assets/session.js', import.meta.url), 'utf8'), sandbox);
  const safeNext = sandbox.window.CvefeedSession.safeNext;
  check('?next= cannot leave the site (//host)', safeNext('//evil.example/x') === '/mcp');
  check('?next= cannot leave the site (absolute URL)', safeNext('https://evil.example/') === '/mcp');
  check('?next= keeps a same-site path', safeNext('/admin/mcp') === '/admin/mcp');
}

/* ---------- one sign-in serves every tab ---------- */

{
  // An MCP client opens the consent page in a fresh tab every time. With the
  // session kept per tab, that was a GitHub round trip on every authorization.
  const store = () => {
    const m = new Map();
    return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), m };
  };
  const shared = store();
  const tab = (hash, own = store()) => {
    const sandbox = {
      window: { location: { hash, origin: 'https://cve.zerocrew.in', pathname: '/oauth/consent', search: '?authorization_id=x' } },
      document: { querySelector: () => null },
      sessionStorage: own,
      localStorage: shared,
      history: { replaceState() {} },
      URLSearchParams,
    };
    vm.runInNewContext(readFileSync(new URL('../public/assets/session.js', import.meta.url), 'utf8'), sandbox);
    return sandbox.window.CvefeedSession;
  };
  tab('#access_token=tok-1&expires_in=3600');
  check('a new tab is already signed in', tab('').getToken() === 'tok-1');
  tab('').signOut();
  check('signing out clears it for every tab', tab('').getToken() === null);

  const old = store();
  old.setItem('cvefeed.sb.token', JSON.stringify({ token: 'tok-old', expiresAt: Date.now() + 600000 }));
  check('a tab signed in before the change keeps its session', tab('', old).getToken() === 'tok-old');
  check('...and it moves to shared storage', shared.getItem('cvefeed.sb.token') !== null && old.getItem('cvefeed.sb.token') === null);

  shared.setItem('cvefeed.sb.token', JSON.stringify({ token: 'tok-dead', expiresAt: Date.now() - 1000 }));
  check('an expired token is not used', tab('').getToken() === null);
}

server.close();
fake.close();
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
