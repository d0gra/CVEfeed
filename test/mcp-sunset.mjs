/**
 * Retiring this app's own /mcp, without cutting anyone off by surprise.
 *
 * The endpoint moved to a Supabase edge function that authenticates and meters
 * callers. An agent configured a year ago should not meet a 404: while
 * MCP_GATEWAY_URL is set it keeps answering and every response says where to
 * go, and only once MCP_LEGACY_UNTIL has passed does it refuse - with the new
 * address in the refusal.
 *
 * `initialize` is used throughout because it touches no data, so none of this
 * reaches a register or a cluster.
 *
 *   node test/mcp-sunset.mjs
 */
process.env.MONGODB_URI = '';

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

const GATEWAY = 'https://example-project.supabase.co/functions/v1/mcp';

const initialize = () =>
  fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }),
  });

/* ---------- unset: a self-hosted copy serves its own endpoint ---------- */

config.mcpGatewayUrl = '';
config.mcpLegacyUntil = '';
{
  const res = await initialize();
  const body = await res.json();
  check('with no gateway configured it answers as before', res.status === 200, `got ${res.status}`);
  check('and says nothing about a move', res.headers.get('deprecation') === null);
  check('and the instructions are unchanged', !/HAS MOVED/.test(body.result?.instructions ?? ''));
}

/* ---------- set, no date: answers, but says where to go ---------- */

config.mcpGatewayUrl = GATEWAY;
{
  const res = await initialize();
  const body = await res.json();
  check('with a gateway configured it still answers', res.status === 200, `got ${res.status}`);
  check('it marks itself deprecated', res.headers.get('deprecation') === 'true');
  check('it links to the successor', (res.headers.get('link') ?? '').includes(GATEWAY));
  const instructions = body.result?.instructions ?? '';
  check('the instructions carry the new address', instructions.includes(GATEWAY));
  check('and say authentication is needed', /API key|OAuth/.test(instructions));
  check('no sunset is promised without a date', res.headers.get('sunset') === null);
}

/* ---------- a future date: answers, and names the day ---------- */

config.mcpLegacyUntil = new Date(Date.now() + 90 * 86_400_000).toISOString();
{
  const res = await initialize();
  const body = await res.json();
  check('before the sunset date it answers', res.status === 200, `got ${res.status}`);
  check('and advertises the date', Boolean(res.headers.get('sunset')), res.headers.get('sunset') ?? '');
  check('and the instructions state it', /stops answering on \d{4}-\d{2}-\d{2}/.test(body.result?.instructions ?? ''));
}

/* ---------- past the date: gone, and says where ---------- */

config.mcpLegacyUntil = new Date(Date.now() - 86_400_000).toISOString();
{
  const res = await initialize();
  const body = await res.json();
  check('past the sunset date it is gone', res.status === 410, `got ${res.status}`);
  check('it still links to the successor', (res.headers.get('link') ?? '').includes(GATEWAY));
  const message = body.error?.message ?? '';
  check('the refusal is valid JSON-RPC', body.jsonrpc === '2.0' && typeof body.error?.code === 'number');
  check('and names the new endpoint', message.includes(GATEWAY), message.slice(0, 70));
  check('and explains what is now required', /API key|OAuth/.test(message));
}

/* ---------- the page a human gets is unaffected ---------- */

{
  const res = await fetch(`${base}/mcp`, { headers: { Accept: 'text/html' } });
  check('GET /mcp still serves the page for a browser', res.status === 200, `got ${res.status}`);
  const html = await res.text();
  check('and the page names the gateway, not itself', html.includes(GATEWAY));
}

server.close();
console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
