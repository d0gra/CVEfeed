/**
 * The suggestion layer.
 *
 * Runs without a database on purpose: the curated layer exists precisely so
 * the typeahead keeps working when Atlas is down, and testing it offline is
 * the same thing as testing that promise.
 *
 *   node test/suggest.mjs
 */
import assert from 'node:assert/strict';

// Cleared before the module under test is loaded, and loaded with a DYNAMIC
// import for exactly that reason: `import` declarations are hoisted, so a
// static one would be evaluated before this assignment and config would read
// the real connection string from the environment. The first version of this
// file did that, connected to Atlas, and hung the suite - the same mistake
// that took the entry point down under Passenger.
process.env.MONGODB_URI = '';

const { packageHintFor, suggestFor } = await import('../src/lib/suggest.js');

let passed = 0;
let failed = 0;
const check = async (name, fn) => {
  try {
    await fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL  ${name}\n      ${error.message}`);
  }
};

await check('a prefix finds a curated project with no database', async () => {
  const rows = await suggestFor('vl');
  assert.ok(rows.length > 0, 'expected suggestions from the curated layer alone');
  assert.ok(rows.some((r) => r.value.toLowerCase() === 'vllm'));
});

await check('matching is case-insensitive', async () => {
  const lower = await suggestFor('vllm');
  const upper = await suggestFor('VLLM');
  assert.deepEqual(upper.map((r) => r.value), lower.map((r) => r.value));
});

await check('an exact name sorts above a mere prefix', async () => {
  const rows = await suggestFor('ray');
  assert.ok(rows.length > 0);
  // Whatever else matches, something equal to the term must come first.
  const exact = rows.findIndex((r) => r.value.toLowerCase() === 'ray');
  if (exact !== -1) assert.equal(exact, 0, `expected the exact match first, got ${rows[0].value}`);
});

await check('each suggestion declares what kind of thing it is', async () => {
  const rows = await suggestFor('ml');
  for (const row of rows) {
    assert.ok(['package', 'vendor', 'product', 'subject'].includes(row.kind), `bad kind ${row.kind}`);
    assert.ok(row.value && row.label);
  }
});

await check('the limit is honoured', async () => {
  const rows = await suggestFor('a', { limit: 3 });
  assert.ok(rows.length <= 3);
});

await check('a term too short to be useful returns nothing', async () => {
  assert.deepEqual(await suggestFor('v'), []);
  assert.deepEqual(await suggestFor(''), []);
  assert.deepEqual(await suggestFor(null), []);
});

await check('a package name is reported as a package', async () => {
  const hint = await packageHintFor('vllm');
  assert.ok(hint, 'vllm is a package in the curated taxonomy');
  assert.equal(hint.term, 'vllm');
  assert.ok(Array.isArray(hint.ecosystems));
});

await check('a vendor is not offered a version check', async () => {
  // The whole point of the kind distinction: offering to version-check
  // "Microsoft" against a package registry would be nonsense.
  assert.equal(await packageHintFor('microsoft'), null);
  assert.equal(await packageHintFor('internet explorer'), null);
  assert.equal(await packageHintFor('definitely-not-a-package-xyz'), null);
});

await check('the hint is case-insensitive and trims', async () => {
  assert.ok(await packageHintFor('  VLLM  '));
});

console.log(`\n${passed}/${passed + failed} passed`);
if (failed) process.exitCode = 1;
