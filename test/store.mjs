/**
 * The Atlas-backed store.
 *
 * Runs against a throwaway database, dropped at the end, so it can never
 * disturb real records. Skips entirely without MONGODB_URI, so a checkout
 * with no cluster still has a green suite.
 *
 *   node test/store.mjs
 */
process.env.MONGODB_DB = `cvefeed_test_${Date.now()}`;

import assert from 'node:assert/strict';

if (!process.env.MONGODB_URI) {
  const dotenv = await import('dotenv');
  dotenv.config();
}

if (!process.env.MONGODB_URI) {
  console.log('SKIP  no MONGODB_URI, nothing to test against');
  process.exit(0);
}

const store = await import('../src/store/cveStore.js');
const signals = await import('../src/store/exploitStore.js');
const { getDb, closeMongo } = await import('../src/lib/mongo.js');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

const record = (over = {}) => ({
  key: `cve:${over.cveId}`,
  id: over.cveId,
  cveId: over.cveId,
  kind: 'cve',
  title: over.title ?? 'A test vulnerability in the widget parser',
  description: 'Remote code execution via a crafted widget.',
  severity: 'high',
  severityRank: 3,
  score: 8.8,
  epss: 1.2,
  published: '2026-10-01T00:00:00.000Z',
  modified: '2026-10-02T00:00:00.000Z',
  exploited: false,
  sourceIds: ['nvd'],
  vendor: 'Acme',
  product: 'widget',
  cwes: ['CWE-94'],
  tags: [],
  references: [],
  relatedCves: [],
  sources: [{ id: 'nvd', name: 'NVD' }],
  stack: null,
  ...over,
});

try {
  check('the store reports itself ready', await store.storeReady());

  // --- writing ---
  const docs = [
    record({ cveId: 'CVE-2026-0001' }),
    record({ cveId: 'CVE-2026-0002', severity: 'critical', severityRank: 4, score: 9.8, exploited: true }),
    record({
      cveId: 'CVE-2026-0003',
      title: 'vLLM inference server flaw',
      stack: { categories: ['inference'], categoryNames: ['Inference & serving'], subjects: ['vLLM'], labels: ['vLLM'] },
      exploitation: { maturity: 'proof-of-concept', maturityRank: 3, publicPoc: true, evidence: ['Public PoC'] },
    }),
  ];
  const written = await store.upsertRecords(docs);
  check('records are written', written.ok && written.written === 3, `${written.written} written`);

  // --- reading back ---
  const all = await store.queryRecords({ limit: 50 });
  check('all records come back', all.total === 3, `total=${all.total}`);
  check('  ...with the internal key stripped', all.items.every((i) => i._id === undefined));

  const crit = await store.queryRecords({ severity: 'critical', limit: 50 });
  check('severity filters', crit.total === 1 && crit.items[0].cveId === 'CVE-2026-0002');

  const exploited = await store.queryRecords({ exploited: '1', limit: 50 });
  check('exploited filters', exploited.total === 1);

  const stack = await store.queryRecords({ stack: 'inference', limit: 50 });
  check('the AI-stack facet filters', stack.total === 1 && stack.items[0].cveId === 'CVE-2026-0003');

  const poc = await store.queryRecords({ exploit: 'poc', limit: 50 });
  check('exploit signals filter', poc.total === 1);

  // --- search ---
  const words = await store.queryRecords({ q: 'widget', limit: 50 });
  check('the indexed word search matches', words.total === 3 && words.matchedBy === 'words');

  // The regression that moving to the database introduced: a text index
  // matches whole words, so a term inside one found nothing at all.
  const inside = await store.queryRecords({ q: 'nferenc', limit: 50 });
  check(
    'a term inside a word falls back to a substring match',
    inside.total === 1 && inside.matchedBy === 'substring',
    `total=${inside.total} matchedBy=${inside.matchedBy}`,
  );

  // Project and package names live in stack.subjects, which the text index
  // does not cover at all - and they are what people actually type.
  const subject = await store.queryRecords({ q: 'vLL', limit: 50 });
  check(
    'a project name is found by substring',
    subject.total === 1 && subject.items[0].cveId === 'CVE-2026-0003',
    `total=${subject.total}`,
  );

  const cwe = await store.queryRecords({ q: 'CWE-94', limit: 50 });
  check('a CWE is searchable', cwe.total === 3, `total=${cwe.total}`);

  const nothing = await store.queryRecords({ q: 'zzzznotpresent', limit: 50 });
  check('a term matching nothing still matches nothing', nothing.total === 0);

  // A term off a query string goes into a regular expression, so it has to be
  // escaped - unescaped, this one is a malformed pattern and throws.
  let regexSafe = true;
  try {
    await store.queryRecords({ q: 'c++ (unterminated', limit: 5 });
  } catch {
    regexSafe = false;
  }
  check('a term with regex metacharacters is escaped, not executed', regexSafe);

  const shortTerm = await store.queryRecords({ q: 'zz', limit: 5 });
  check('a term too short to scan for is not retried', shortTerm.matchedBy === 'words');

  const substringStats = await store.aggregateStats({ q: 'nferenc' }, { substring: true });
  check(
    'facet counts can be computed over the substring filter',
    substringStats.total === 1,
    `total=${substringStats.total}`,
  );

  const bogus = await store.queryRecords({ exploit: 'nonsense', limit: 50 });
  check('an unknown signal matches nothing, not everything', bogus.total === 0, `total=${bogus.total}`);

  const sorted = await store.queryRecords({ sort: 'score', limit: 50 });
  check('sorting is applied', sorted.items[0].cveId === 'CVE-2026-0002', `first=${sorted.items[0].cveId}`);

  const paged = await store.queryRecords({ limit: 2, page: 2 });
  check('paging works', paged.items.length === 1 && paged.total === 3);

  const text = await store.queryRecords({ q: 'vLLM', limit: 50 });
  check('free text finds a record', text.total === 1 && text.items[0].cveId === 'CVE-2026-0003', `total=${text.total}`);

  const byId = await store.queryRecords({ q: 'CVE-2026-0002', limit: 50 });
  check('an identifier matches exactly', byId.total === 1);

  // --- stats ---
  const stats = await store.aggregateStats({});
  check('counts are aggregated, not scanned', stats.total === 3, `total=${stats.total}`);
  check('  ...by severity', stats.bySeverity.critical === 1 && stats.bySeverity.high === 2);
  check('  ...by AI-stack category', stats.byStack.inference === 1 && stats.inStack === 1);
  check('  ...and exploit signals', stats.withExploitSignal === 1 && stats.byExploit.publicPoc === 1);
  check('  ...with a mean score', stats.averageScore > 8 && stats.averageScore < 10, `${stats.averageScore}`);

  // --- single record ---
  const one = await store.findRecordById('cve-2026-0001');
  check('a record is found case-insensitively', one?.cveId === 'CVE-2026-0001');
  check('a missing record is null, not an error', (await store.findRecordById('CVE-1999-99999')) === null);

  // --- upsert is idempotent and preserves first sight ---
  const first = (await store.findRecordById('CVE-2026-0001')).firstSeen;
  await store.upsertRecords([record({ cveId: 'CVE-2026-0001', title: 'Renamed' })]);
  const again = await store.findRecordById('CVE-2026-0001');
  check('re-running a refresh updates in place', again.title === 'Renamed' && (await store.aggregateStats({})).total === 3);
  check('  ...and keeps when it was first seen', String(again.firstSeen) === String(first));

  // --- exploit signals round trip ---
  await signals.putSource('metasploit', {
    'CVE-2026-0003': [{ url: 'https://example.com/module', label: 'exploit/test/module' }],
  });
  const got = await signals.getSignals(['CVE-2026-0003', 'CVE-2026-0001']);
  check('signals store and come back by id', got.get('CVE-2026-0003')?.metasploit?.[0]?.url === 'https://example.com/module');
  check('  ...and an id with none is simply absent', !got.has('CVE-2026-0001'));
  // A fourth record, added last on purpose: every assertion above counts
  // records, and inserting this earlier silently changed all of them.
  // --- exact name matching ---
  // A fourth record carrying searchTerms, left off the first three so the
  // existing assertions above keep testing the un-enriched path - which is
  // also the real state of most of the corpus until it is re-ingested.
  await store.upsertRecords([
    record({
      cveId: 'CVE-2026-0004',
      title: 'An unrelated flaw in something else entirely',
      description: 'Nothing here mentions the package by name.',
      vendor: null,
      product: null,
      searchTerms: ['litellm', 'berriai'],
      packages: [{ name: 'litellm', ecosystem: 'PyPI' }],
      vendors: ['BerriAI'],
    }),
  ]);

  const exact = await store.queryRecords({ q: 'litellm', limit: 50 });
  check(
    'an exact name match wins, even when no text mentions it',
    exact.total === 1 && exact.matchedBy === 'exact' && exact.items[0].cveId === 'CVE-2026-0004',
    `total=${exact.total} matchedBy=${exact.matchedBy}`,
  );

  const forced = await store.queryRecords({ q: 'litellm', match: 'words', limit: 50 });
  check(
    'match=words is a real escape hatch from exact-wins',
    forced.matchedBy !== 'exact',
    `matchedBy=${forced.matchedBy}`,
  );

  const caseless = await store.queryRecords({ q: 'LiteLLM', limit: 50 });
  check('exact matching is case-insensitive', caseless.total === 1, `total=${caseless.total}`);

  // The invariant that keeps the facet counts honest: whatever filter
  // produced the rows must also produce the counts.
  const exactStats = await store.aggregateStats({ q: 'litellm' }, { mode: 'exact' });
  check(
    'facet counts can be computed over the exact filter',
    exactStats.total === exact.total,
    `stats=${exactStats.total} rows=${exact.total}`,
  );

  check(
    'the stage order is agreed by one shared rule',
    store.firstMode({ q: 'litellm' }) === 'exact' &&
      store.firstMode({ q: 'litellm', match: 'words' }) === 'words' &&
      store.firstMode({ q: 'CVE-2026-0001' }) === 'words' &&
      store.firstMode({}) === 'words',
  );

  // "it returned the right rows" and "it did not scan the collection" are
  // different claims, and on a free tier only the second one scales.
  const plan = await (await getDb())
    .collection('cves')
    .find(store.buildFilter({ q: 'litellm' }, { mode: 'exact' }))
    .explain('queryPlanner');
  const stage = JSON.stringify(plan?.queryPlanner?.winningPlan ?? {});
  check('the exact stage uses an index rather than scanning', stage.includes('IXSCAN'), stage.slice(0, 90));

  const terms = await store.queryRecords({ q: 'berriai', limit: 50 });
  check('a vendor name is matched exactly too', terms.total === 1 && terms.matchedBy === 'exact');

  // --- hubs ---
  // A second record sharing the vendor, because a hub only exists for a name
  // that appears more than once - a page per one-off would be exactly the
  // thin surface the hubs are meant not to be.
  await store.upsertRecords([
    record({
      cveId: 'CVE-2026-0005',
      title: 'Another BerriAI issue',
      searchTerms: ['litellm', 'berriai'],
      packages: [{ name: 'litellm', ecosystem: 'PyPI' }],
      vendors: ['BerriAI'],
    }),
  ]);

  const byVendor = await store.recordsForName('vendor', 'berriai');
  check(
    'a hub finds its records case-insensitively',
    byVendor.total === 2 && byVendor.items.every((i) => i.vendors.includes('BerriAI')),
    `total=${byVendor.total}`,
  );

  const byPackage = await store.recordsForName('package', 'LiteLLM');
  check('a package hub matches on the coordinate name', byPackage.total === 2, `total=${byPackage.total}`);

  check('an unknown hub name returns nothing, not everything', (await store.recordsForName('vendor', 'nope')).total === 0);
  check('an unknown hub kind is refused', (await store.recordsForName('nonsense', 'x')) === null);

  const hubs = await store.hubNames({ min: 2 });
  check(
    'hub names are listed with their counts',
    hubs.vendors.some((v) => v.value === 'BerriAI' && v.count === 2),
    JSON.stringify(hubs.vendors),
  );
  check(
    'packages are unwound as objects, not as a missing path',
    hubs.packages.some((p) => p.value === 'litellm' && p.count === 2),
    JSON.stringify(hubs.packages),
  );
  check(
    'a name on a single record gets no hub',
    !hubs.vendors.some((v) => v.count < 2),
    JSON.stringify(hubs.vendors.map((v) => v.count)),
  );

  const vocab = await store.aggregateSuggestionVocabulary();
  check(
    'the suggestion vocabulary is aggregated from the corpus',
    vocab.packages.some((p) => p.value === 'litellm' && p.ecosystem === 'PyPI') &&
      vocab.vendors.some((v) => v.value === 'BerriAI'),
    `packages=${vocab.packages.length} vendors=${vocab.vendors.length}`,
  );

} finally {
  const db = await getDb();
  await db?.dropDatabase().catch(() => {});
  await closeMongo();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
