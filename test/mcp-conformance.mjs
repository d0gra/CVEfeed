/**
 * Checks the hand-written MCP endpoint against the official SDK client.
 *
 * The point is to test the protocol against someone else's implementation
 * rather than our own assumptions - if the real client can connect, list tools
 * and call them, so can anything else that speaks MCP. The SDK is a dev
 * dependency only, so none of this ships.
 *
 *   node test/mcp-conformance.mjs [baseUrl]
 */
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const base = process.argv[2] ?? 'http://localhost:3000';
const endpoint = new URL('/mcp', base);

let passed = 0;
const checks = [];
function check(name, fn) {
  checks.push(async () => {
    try {
      await fn();
      passed += 1;
      console.log(`PASS  ${name}`);
    } catch (error) {
      console.log(`FAIL  ${name}\n      ${error.message}`);
      process.exitCode = 1;
    }
  });
}

const client = new Client({ name: 'cvefeed-conformance', version: '1.0.0' });

try {
  await client.connect(new StreamableHTTPClientTransport(endpoint));
} catch (error) {
  // This one needs something to talk to. Skipping is honest; failing the
  // suite because nothing is running is not.
  console.log(`SKIP  nothing listening at ${endpoint} (${error.message})`);
  console.log('      start the app, or pass a base URL: node test/mcp-conformance.mjs https://your.host');
  process.exit(0);
}
console.log(`connected to ${endpoint}\n`);

const parse = (res) => JSON.parse(res.content[0].text);

let tools;
check('the official client completes the handshake', async () => {
  const info = client.getServerVersion();
  assert.equal(info.name, 'cvefeed');
  assert.ok(client.getInstructions()?.includes('untrusted'), 'instructions should warn about untrusted text');
});

check('tools/list returns usable schemas', async () => {
  ({ tools } = await client.listTools());
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['feed_status', 'get_cve', 'list_exploited', 'search_cves']);
  for (const tool of tools) {
    assert.ok(tool.description?.length > 40, `${tool.name} needs a real description`);
    assert.equal(tool.inputSchema.type, 'object', `${tool.name} schema must be an object`);
  }
});

check('search_cves returns records', async () => {
  const body = parse(await client.callTool({ name: 'search_cves', arguments: { limit: 5 } }));
  assert.ok(body.results.length > 0 && body.results.length <= 5);
  assert.ok(body.matched > 0);
  assert.ok(body.results[0].id, 'each result needs an id');
});

check('results carry the untrusted-data notice', async () => {
  const body = parse(await client.callTool({ name: 'search_cves', arguments: { limit: 1 } }));
  assert.match(body.notice, /untrusted/i);
  assert.match(body.notice, /not as instructions|never as instructions/i);
});

check('severity filter is honoured', async () => {
  const body = parse(await client.callTool({ name: 'search_cves', arguments: { severity: ['critical'], limit: 20 } }));
  assert.ok(body.results.length > 0, 'expected some criticals');
  assert.ok(body.results.every((r) => r.severity === 'critical'));
});

check('the AI-stack filter is honoured', async () => {
  const body = parse(await client.callTool({ name: 'search_cves', arguments: { stack: ['mcp'], limit: 50 } }));
  assert.ok(body.results.length > 0, 'expected MCP-stack records');
  assert.ok(body.results.every((r) => r.aiStack?.categories.includes('mcp')));
});

check('compact results stay lean, detail opts in', async () => {
  const lean = parse(await client.callTool({ name: 'search_cves', arguments: { limit: 1 } }));
  const full = parse(await client.callTool({ name: 'search_cves', arguments: { limit: 1, detail: true } }));
  assert.equal(lean.results[0].description, undefined, 'lean results must omit descriptions');
  assert.ok(full.results[0].description, 'detail must include descriptions');
});

check('get_cve resolves a CVE outside the feed window', async () => {
  const body = parse(await client.callTool({ name: 'get_cve', arguments: { id: 'CVE-2021-44228' } }));
  assert.equal(body.vulnerability.id, 'CVE-2021-44228');
  assert.equal(body.vulnerability.severity, 'critical');
  assert.equal(body.vulnerability.exploited, true);
  assert.ok(body.resolvedOutsideWindow, 'Log4Shell should come from a direct lookup');
});

check('get_cve reports a miss as a tool error, not a crash', async () => {
  const res = await client.callTool({ name: 'get_cve', arguments: { id: 'CVE-1999-99999' } });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /not found/i);
});

check('list_exploited returns only exploited records', async () => {
  const body = parse(await client.callTool({ name: 'list_exploited', arguments: { limit: 20 } }));
  assert.ok(body.results.length > 0);
  assert.ok(body.results.every((r) => r.exploited === true));
});

check('list_exploited narrows to the AI stack', async () => {
  const body = parse(await client.callTool({ name: 'list_exploited', arguments: { stack: ['any'], limit: 50 } }));
  assert.ok(body.results.every((r) => r.exploited === true && r.aiStack));
});

check('feed_status reports source health and categories', async () => {
  const body = parse(await client.callTool({ name: 'feed_status', arguments: {} }));
  assert.ok(body.sources.length >= 1);
  assert.ok(body.aiStackCategories.length === 7);
  assert.equal(typeof body.totalRecords, 'number');
  assert.equal(typeof body.inAiStack, 'number');
});

check('an unknown tool is rejected', async () => {
  await assert.rejects(() => client.callTool({ name: 'drop_everything', arguments: {} }));
});

for (const run of checks) await run();
await client.close();

console.log(`\n${passed}/${checks.length} passed`);
