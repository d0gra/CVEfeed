/**
 * The name-derivation layer, and the merge that feeds it.
 *
 * Pure and offline on purpose. This is where most of the vendor/software
 * search logic actually lives - what counts as a name, what must never become
 * one, and how two sources describing the same CVE combine - so it is the part
 * worth testing hardest and the part that needs no database to test.
 *
 *   node test/terms.mjs
 */
import assert from 'node:assert/strict';
import { MAX_TERMS, buildSearchTerms, normalizePackage, normalizeTerm } from '../src/lib/terms.js';
import { finalize, mergeAll } from '../src/merge.js';

let passed = 0;
let failed = 0;
const check = (name, fn) => {
  try {
    fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL  ${name}\n      ${error.message}`);
  }
};

/* ---------- normalizeTerm ---------- */

check('a name folds to lowercase with whitespace collapsed', () => {
  assert.equal(normalizeTerm('  Red   Hat '), 'red hat');
  assert.equal(normalizeTerm('vLLM'), 'vllm');
});

check('punctuation is preserved, because package names are punctuation', () => {
  // Stripping it would merge log4j-core with "log4j core" and destroy scoped
  // npm names, which are exactly the strings this exists to match.
  assert.equal(normalizeTerm('@scope/pkg'), '@scope/pkg');
  assert.equal(normalizeTerm('log4j-core'), 'log4j-core');
  assert.equal(normalizeTerm('github.com/gin-gonic/gin'), 'github.com/gin-gonic/gin');
});

check('terms too short or too long are refused', () => {
  assert.equal(normalizeTerm('a'), null);
  assert.equal(normalizeTerm(''), null);
  assert.equal(normalizeTerm(null), null);
  assert.equal(normalizeTerm('x'.repeat(81)), null);
  assert.equal(normalizeTerm('ab'), 'ab');
});

/* ---------- buildSearchTerms ---------- */

check('package names become terms', () => {
  const terms = buildSearchTerms({ packages: [{ name: 'lodash', ecosystem: 'npm' }] });
  assert.deepEqual(terms, ['lodash']);
});

check('ecosystem words never become terms', () => {
  // The bug this guards: GitHub writes the ecosystem where a vendor belongs,
  // so "npm" and "pip" are among the most common vendor values in the corpus.
  // A search for "npm" must not return every JavaScript advisory.
  const terms = buildSearchTerms({
    vendors: ['npm', 'pip', 'rust', 'PyPI', 'crates.io', 'Go', 'Microsoft'],
    products: ['composer'],
  });
  assert.deepEqual(terms, ['microsoft'], `got ${JSON.stringify(terms)}`);
});

check('a Maven coordinate also yields its bare artifact', () => {
  const terms = buildSearchTerms({
    packages: [{ name: 'org.apache.logging.log4j:log4j-core', ecosystem: 'Maven' }],
  });
  assert.ok(terms.includes('org.apache.logging.log4j:log4j-core'));
  assert.ok(terms.includes('log4j-core'), 'people type the artifact, not the group');
});

check('vendors, products and stack subjects all contribute', () => {
  const terms = buildSearchTerms({
    vendors: ['Microsoft'],
    products: ['Internet Explorer'],
    stack: { subjects: ['vLLM'] },
  });
  assert.deepEqual(terms.sort(), ['internet explorer', 'microsoft', 'vllm']);
});

check('the legacy comma-joined product string is split', () => {
  // A record whose adapter has not been updated yet still has only this, and
  // should gain terms on its next touch rather than after a second deploy.
  const terms = buildSearchTerms({ product: 'mlflow, authlib, litellm' });
  assert.deepEqual(terms.sort(), ['authlib', 'litellm', 'mlflow']);
});

check('duplicates collapse across sources', () => {
  const terms = buildSearchTerms({
    packages: [{ name: 'lodash', ecosystem: 'npm' }],
    products: ['lodash', 'LODASH'],
    product: 'lodash',
  });
  assert.deepEqual(terms, ['lodash']);
});

check('the term count is capped', () => {
  // One advisory can list hundreds of affected packages; the index should not
  // carry the long tail nobody searches for.
  const packages = Array.from({ length: 200 }, (_, i) => ({ name: `pkg-${i}`, ecosystem: 'npm' }));
  const terms = buildSearchTerms({ packages });
  assert.equal(terms.length, MAX_TERMS);
});

check('a record that knows nothing about itself yields nothing', () => {
  assert.deepEqual(buildSearchTerms({}), []);
  assert.deepEqual(buildSearchTerms(), []);
});

/* ---------- normalizePackage ---------- */

check('ecosystems are mapped to the spelling the dependency check uses', () => {
  // Otherwise a name found by search and a name sent to OSV mean different
  // registries depending on which half of the app you are in.
  assert.deepEqual(normalizePackage({ name: 'zip', ecosystem: 'rust' }), { name: 'zip', ecosystem: 'crates.io' });
  assert.deepEqual(normalizePackage({ name: 'django', ecosystem: 'pip' }), { name: 'django', ecosystem: 'PyPI' });
  assert.deepEqual(normalizePackage({ name: 'lodash', ecosystem: 'npm' }), { name: 'lodash', ecosystem: 'npm' });
});

check('an unknown ecosystem is kept rather than dropped', () => {
  // A new registry should degrade to "still searchable", not vanish.
  assert.deepEqual(normalizePackage({ name: 'thing', ecosystem: 'Conda' }), { name: 'thing', ecosystem: 'Conda' });
  assert.equal(normalizePackage({ name: '' }), null);
});

/* ---------- merge ---------- */

const item = (over) => ({
  id: 'CVE-2026-9001',
  cveId: 'CVE-2026-9001',
  title: 'A flaw',
  description: 'A flaw in something.',
  severity: 'high',
  score: 8.1,
  published: '2026-10-01T00:00:00.000Z',
  modified: '2026-10-01T00:00:00.000Z',
  cwes: [],
  tags: [],
  references: [],
  relatedCves: [],
  ...over,
});

const mergeOf = (...groups) =>
  finalize([...mergeAll(groups).values()][0]);

check('name arrays union across sources instead of first-source-wins', () => {
  // vendor/product use ??= in mergeInto, which keeps only whichever source was
  // read first. For these arrays that would silently discard half the names.
  const record = mergeOf(
    { meta: { id: 'kev', name: 'CISA KEV' }, items: [item({ vendors: ['Microsoft'], products: ['Windows'] })] },
    { meta: { id: 'euvd', name: 'EUVD' }, items: [item({ vendors: ['Microsoft', 'Contoso'], products: ['Office'] })] },
  );
  assert.deepEqual(record.vendors, ['Contoso', 'Microsoft']);
  assert.deepEqual(record.products, ['Office', 'Windows']);
});

check('packages dedupe on the coordinate, not the name', () => {
  // npm `zip` and crates.io `zip` are unrelated software by unrelated authors.
  const record = mergeOf({
    meta: { id: 'github', name: 'GitHub' },
    items: [
      item({ packages: [{ name: 'zip', ecosystem: 'npm' }] }),
      item({ packages: [{ name: 'zip', ecosystem: 'crates.io' }, { name: 'zip', ecosystem: 'npm' }] }),
    ],
  });
  assert.equal(record.packages.length, 2, JSON.stringify(record.packages));
  assert.deepEqual(record.ecosystems.sort(), ['crates.io', 'npm']);
});

check('finalize derives searchTerms from everything merged', () => {
  const record = mergeOf(
    { meta: { id: 'github', name: 'GitHub' }, items: [item({ packages: [{ name: 'litellm', ecosystem: 'pip' }] })] },
    { meta: { id: 'kev', name: 'CISA KEV' }, items: [item({ vendors: ['BerriAI'] })] },
  );
  assert.ok(record.searchTerms.includes('litellm'));
  assert.ok(record.searchTerms.includes('berriai'));
  // And the ecosystem was canonicalised on the way through.
  assert.equal(record.packages[0].ecosystem, 'PyPI');
});

check('searchTerms picks up the stack subjects finalize itself computes', () => {
  // classifyStack runs inside finalize, so the terms have to be built after
  // it - this asserts the ordering rather than trusting it.
  const record = mergeOf({
    meta: { id: 'github', name: 'GitHub' },
    items: [item({ packages: [{ name: 'vllm', ecosystem: 'pip' }], title: 'vLLM flaw' })],
  });
  assert.ok(record.stack, 'expected the record to classify into the AI stack');
  for (const subject of record.stack.subjects) {
    assert.ok(
      record.searchTerms.includes(subject.toLowerCase()),
      `${subject} is a stack subject but not a search term`,
    );
  }
});

check('a record with no names still finalizes cleanly', () => {
  const record = mergeOf({ meta: { id: 'nvd', name: 'NVD' }, items: [item({})] });
  assert.deepEqual(record.vendors, []);
  assert.deepEqual(record.packages, []);
  assert.deepEqual(record.searchTerms, []);
});

console.log(`\n${passed}/${passed + failed} passed`);
if (failed) process.exitCode = 1;
