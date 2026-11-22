/**
 * Search answers the question that was typed.
 *
 * Three measured failures, each with a cause confirmed in MongoDB's own $text
 * documentation, and the regression each one gets here:
 *
 *   log4j-core         returned the whole feed: the hyphen splits it into
 *                      "log4j OR core", and "core" is in nearly everything.
 *   apache struts rce  returned 574, Log4j first: words are OR'd, then sorted
 *                      by severity instead of relevance.
 *   remote code execution in jenkins
 *                      returned 8,973, none of them Jenkins.
 *
 * Both search paths are covered - the Mongo filter and the in-memory fallback
 * - because they must answer the same way. Hermetic: no cluster, no network.
 *
 *   node test/search-quality.mjs
 */
process.env.MONGODB_URI = '';

const { significantTerms, termPattern, textSearchString, relevance } = await import('../src/lib/queryTerms.js');
const { buildFilter } = await import('../src/store/cveStore.js');
const { applyFilters } = await import('../src/query.js');
const { editDistance } = await import('../src/lib/suggest.js');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

/* ---------- reading the query ---------- */
{
  const terms = significantTerms('remote code execution in jenkins');
  check('stopwords are dropped', terms.map((t) => t.text).join(' ') === 'remote code execution jenkins');
  const pkg = significantTerms('log4j-core');
  check('a hyphenated name stays one term', pkg.length === 1 && pkg[0].text === 'log4j-core' && pkg[0].packageShaped);
  check('a scoped npm name stays one term', significantTerms('@angular/core')[0]?.text === '@angular/core');
  check('rce means remote code execution too', significantTerms('rce')[0].alternatives.includes('remote code execution'));
  check('a CVE id is not a search word', significantTerms('CVE-2021-44228').length === 0);
  check('a package-shaped term is kept away from $text', textSearchString(pkg) === null);
}

/* ---------- patterns ---------- */
{
  const rce = termPattern(significantTerms('rce')[0]);
  check('"rce" does not match inside "source"', !rce.test('open source library'));
  check('"rce" matches the spelled-out phrase', rce.test('Remote Code Execution in Apache Struts'));
  const core = termPattern(significantTerms('log4j-core')[0]);
  check('"log4j-core" does not match a bare "core"', !core.test('core dump in the kernel'));
  check('"log4j-core" matches the Maven coordinate', core.test('org.apache.logging.log4j:log4j-core'));
}

/* ---------- the Mongo filter ---------- */
const clausesOf = (filter) => filter.$and ?? [];
{
  const f = buildFilter({ q: 'log4j-core' }, { mode: 'words' });
  check('log4j-core: no $text, so nothing splits it', !clausesOf(f).some((c) => c.$text));
  const term = clausesOf(f).find((c) => c.$or);
  check('log4j-core: one required name match', Boolean(term) && term.$or.some((o) => o['packages.name']?.test?.('org.apache.logging.log4j:log4j-core')));
}
{
  const f = buildFilter({ q: 'apache struts rce' }, { mode: 'words' });
  const clauses = clausesOf(f);
  check('apache struts rce: $text kept for recall and ranking', clauses.some((c) => c.$text));
  check('apache struts rce: every term is required', clauses.filter((c) => c.$or).length === 3);
}

/* ---------- the in-memory fallback, on records shaped like the real ones ---------- */
const record = (id, title, description, extra = {}) => ({
  id, cveId: id, title, description, vendor: extra.vendor ?? null, product: extra.product ?? null,
  severity: 'critical', sourceIds: ['nvd'], kind: 'cve', cwes: [], tags: [], score: extra.score ?? 9,
  published: '2026-01-01T00:00:00Z', searchTerms: extra.searchTerms ?? [], packages: extra.packages ?? [],
  vendors: [], products: [], exploited: false,
});
const feed = [
  record('CVE-A', 'Apache Struts OGNL injection leads to remote code execution', 'Struts 2 RCE.', { vendor: 'apache', product: 'struts', score: 8.1 }),
  record('CVE-B', 'Apache Log4j2 JNDI remote code execution', 'Log4Shell.', {
    vendor: 'apache', product: 'log4j', score: 10,
    packages: [{ name: 'org.apache.logging.log4j:log4j-core', ecosystem: 'Maven' }],
    searchTerms: ['org.apache.logging.log4j:log4j-core', 'log4j-core'],
  }),
  record('CVE-C', 'Jenkins script console allows remote code execution', 'Jenkins core.', { vendor: 'jenkins', score: 8.8 }),
  record('CVE-D', 'Linux kernel core dump information leak', 'core', { vendor: 'linux', score: 9.8 }),
];
const ids = (rows) => rows.map((r) => r.id).join(',');
{
  check('memory: log4j-core finds only log4j-core', ids(applyFilters(feed, { q: 'log4j-core' }, { mode: 'words' })) === 'CVE-B');
  check('memory: apache struts rce finds only Struts', ids(applyFilters(feed, { q: 'apache struts rce' }, { mode: 'words' })) === 'CVE-A');
  check('memory: jenkins rce finds only Jenkins', ids(applyFilters(feed, { q: 'remote code execution in jenkins' }, { mode: 'words' })) === 'CVE-C');
}
{
  // Relevance beats severity: the Struts record has the lower CVSS.
  const terms = significantTerms('apache struts rce');
  const score = (r) => relevance(terms, { title: r.title, rest: `${r.description} ${r.vendor} ${r.product}` });
  check('relevance ranks Struts above Log4j for "apache struts rce"', score(feed[0]) > score(feed[1]), `${score(feed[0])} vs ${score(feed[1])}`);
}

/* ---------- typo suggestions ---------- */
check('one edit: lodsh is lodash', editDistance('lodsh', 'lodash', 1) === 1);
check('a swap is one edit: lodsah is lodash', editDistance('lodsah', 'lodash', 1) === 1);
check('jakson-databind is one edit from jackson-databind', editDistance('jakson-databind', 'jackson-databind', 2) === 1);
check('a different word is beyond the ceiling', editDistance('lodash', 'express', 2) > 2);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
