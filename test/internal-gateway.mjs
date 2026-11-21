/**
 * The gateway seam: /internal/mcp-tools and /internal/mcp-tool.
 *
 * These are the routes the Supabase MCP gateway calls on a cache miss, and
 * they cover the two things the public /mcp endpoint got wrong:
 *
 *   - It had no authentication at all. Here a request must carry a signature
 *     that is current, matches, and was made for this exact path - so a body
 *     signed for one route cannot be replayed against another.
 *   - It capped every body at 64kb, so check_dependencies - the tool whose
 *     own description says to paste a lockfile whole - answered an ordinary
 *     200kb package-lock.json with a 502 blaming the upstream feed.
 *
 * Hermetic by design: every case here is settled before the feed is touched,
 * so the suite never reaches for a register or a cluster.
 *
 *   node test/internal-gateway.mjs
 */
process.env.MONGODB_URI = '';
process.env.GATEWAY_SECRET = 'test-secret-for-the-suite-only';

import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

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

/** The scheme internal.js verifies: timestamp, method and path, then body. */
function sign(method, path, body = '', { at = Date.now(), secret = config.gatewaySecret } = {}) {
  const ts = Math.floor(at / 1000);
  const signature = createHmac('sha256', secret)
    .update(`${ts}.${method}.${path}.`)
    .update(Buffer.from(body))
    .digest('hex');
  return { 'x-cvefeed-timestamp': String(ts), 'x-cvefeed-signature': signature };
}

const call = (path, { method = 'GET', body, headers = {} } = {}) =>
  fetch(`${base}${path}`, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body,
  });

/* ---------- the guard ---------- */

{
  const res = await call('/internal/mcp-tools');
  check('an unsigned request is refused', res.status === 401, `got ${res.status}`);
}

{
  const headers = sign('GET', '/internal/mcp-tools', '', { secret: 'the-wrong-secret' });
  const res = await call('/internal/mcp-tools', { headers });
  check('a signature made with the wrong secret is refused', res.status === 401, `got ${res.status}`);
}

{
  // Beyond the window, so a captured request cannot be replayed indefinitely.
  const stale = Date.now() - (config.gatewaySkewMs + 60_000);
  const res = await call('/internal/mcp-tools', { headers: sign('GET', '/internal/mcp-tools', '', { at: stale }) });
  check('an expired timestamp is refused', res.status === 401, `got ${res.status}`);
}

{
  // The signature covers the path, so one made for the manifest route is not
  // a licence to call a tool.
  const body = JSON.stringify({ name: 'feed_status', arguments: {} });
  const headers = sign('POST', '/internal/mcp-tools', body);
  const res = await call('/internal/mcp-tool', { method: 'POST', body, headers });
  check('a signature made for another path is refused', res.status === 401, `got ${res.status}`);
}

{
  // Absent means off, not open - the convention the moderation and refresh
  // endpoints already follow.
  const real = config.gatewaySecret;
  config.gatewaySecret = '';
  const res = await call('/internal/mcp-tools', { headers: sign('GET', '/internal/mcp-tools', '', { secret: real }) });
  config.gatewaySecret = real;
  check('the endpoint 404s when GATEWAY_SECRET is unset', res.status === 404, `got ${res.status}`);
}

/* ---------- the manifest ---------- */

let manifest;
{
  const res = await call('/internal/mcp-tools', { headers: sign('GET', '/internal/mcp-tools') });
  check('a correctly signed request is served', res.status === 200, `got ${res.status}`);
  manifest = await res.json();
  check('the manifest carries every tool', manifest.tools?.length === 6, `got ${manifest.tools?.length}`);
  check('the manifest is versioned by content hash', /^[0-9a-f]{16}$/.test(manifest.version ?? ''), manifest.version);
  check(
    'every tool keeps a name, a description and an object schema',
    manifest.tools.every((t) => t.name && t.description?.length > 40 && t.inputSchema?.type === 'object'),
  );
  check(
    'the untrusted-data advisory is still attached to the dependency tool',
    /lockfile/i.test(manifest.tools.find((t) => t.name === 'check_dependencies')?.description ?? ''),
  );
}

/* ---------- the tool call ---------- */

{
  const body = JSON.stringify({ name: 'drop_everything', arguments: {} });
  const res = await call('/internal/mcp-tool', {
    method: 'POST',
    body,
    headers: sign('POST', '/internal/mcp-tool', body),
  });
  const payload = await res.json();
  check('an unknown tool is rejected', res.status === 400, `got ${res.status}`);
  check('the rejection names the tools that do exist', Array.isArray(payload.tools) && payload.tools.length === 6);
}

{
  const body = JSON.stringify({ name: 'feed_status', arguments: ['not', 'an', 'object'] });
  const res = await call('/internal/mcp-tool', {
    method: 'POST',
    body,
    headers: sign('POST', '/internal/mcp-tool', body),
  });
  check('arguments that are not an object are rejected', res.status === 400, `got ${res.status}`);
}

{
  // The regression that matters. An unknown tool name is used deliberately so
  // the body is fully read, signed over and parsed, and the handler reached,
  // without the feed or OSV being touched. Refused at 64kb this would come
  // back 413, or as the old endpoint's 502 "request entity too large".
  const manifestText = JSON.stringify({
    lockfileVersion: 3,
    packages: Object.fromEntries(
      Array.from({ length: 4000 }, (_, i) => [`node_modules/package-number-${i}`, { version: '1.0.0' }]),
    ),
  });
  const body = JSON.stringify({ name: 'not_a_tool', arguments: { manifest: manifestText } });
  check('the test body really is larger than the global cap', body.length > 150_000, `${body.length} bytes`);

  const res = await call('/internal/mcp-tool', {
    method: 'POST',
    body,
    headers: sign('POST', '/internal/mcp-tool', body),
  });
  const text = await res.text();
  check('a 200kb lockfile-sized body is read, not refused', res.status === 400, `got ${res.status}`);
  check('nothing reports the body as too large', !/entity too large/i.test(text));
  check('nothing is blamed on the upstream feed', !/Upstream feed error/i.test(text));
}

server.close();
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
