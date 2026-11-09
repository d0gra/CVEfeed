/**
 * /healthz must tell the truth about the registers.
 *
 * It used to report `sources: config.sources` - the ids configured, not the
 * ids that answered - and a flat `status: "ok"`. A source refusing every
 * request for days looked identical to a healthy one, which is how a 403 from
 * GitHub's advisories API sat behind a green check.
 *
 *   node test/health.mjs
 */
import assert from 'node:assert/strict';

// Keep the suite off any live cluster named in .env.
process.env.MONGODB_URI = '';
process.env.SOURCES = 'nvd,kev,github';

const { summarizeSourceHealth } = await import('../src/aggregate.js');
const { anonymousNotes } = await import('../src/lib/credentials.js');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

const cacheOf = (sources) => ({ value: { sources } });
const health = (id, ok, extra = {}) => ({
  id,
  name: id.toUpperCase(),
  ok,
  count: ok ? 100 : 0,
  error: ok ? null : 'HTTP 403 Forbidden for https://api.github.com/advisories - rate limit 0/60 remaining',
  fetchedAt: '2026-11-09T08:30:08.819Z',
  ...extra,
});

// 1. every source answering
const good = summarizeSourceHealth(cacheOf([health('nvd', true), health('kev', true)]));
check('all sources ok reads ok', good.ok === true);
check('  ...with nothing to alert on', good.failing.length === 0);
check('  ...and a count per source', good.counts.nvd === 100 && good.counts.kev === 100);

// 2. one source refusing - the case this exists for
const bad = summarizeSourceHealth(cacheOf([health('nvd', true), health('github', false)]));
check('a failing source is not ok', bad.ok === false);
check('  ...it is named', bad.failing.length === 1 && bad.failing[0].id === 'github');
check('  ...with the upstream reason kept', bad.failing[0].error.includes('rate limit 0/60'));
check('  ...and the time it was tried', bad.failing[0].fetchedAt === '2026-11-09T08:30:08.819Z');
check('  ...while its count is null, not 0', bad.counts.github === null);
check('  ...and the healthy source still reports', bad.counts.nvd === 100);

// 3. a source that answers with nothing is not a failure
const empty = summarizeSourceHealth(cacheOf([health('kev', true, { count: 0 })]));
check('an empty but reachable source stays ok', empty.ok === true && empty.counts.kev === 0);

// 4. before the first refresh, health is unknown - not good
for (const nothing of [{ value: { sources: [] } }, { value: {} }, {}, null, undefined]) {
  const unknown = summarizeSourceHealth(nothing);
  check(
    `no refresh yet reports unknown, not ok  (${JSON.stringify(nothing) ?? 'undefined'})`,
    unknown.ok === null && unknown.unknown === true && unknown.failing.length === 0,
  );
}

// 5. the health is only as current as the snapshot it came from
const dated = summarizeSourceHealth({
  value: { sources: [health('nvd', true)], generatedAt: new Date(Date.now() - 7200_000).toISOString() },
});
check('the snapshot time is reported', typeof dated.checkedAt === 'string');
check('  ...and its age, so a week-old "ok" cannot pass for a fresh one', Math.abs(dated.ageSeconds - 7200) <= 2, `${dated.ageSeconds}s`);
check('an undated snapshot reports a null age, not zero', summarizeSourceHealth(cacheOf([health('nvd', true)])).ageSeconds === null);

// 6. the configured list is still reported, so the old field keeps its meaning
const configured = summarizeSourceHealth(cacheOf([health('nvd', true)])).configured;
check('the configured ids travel with it', Array.isArray(configured) && configured.includes('github'), configured.join(','));

// 7. a source fetched with no credential - the gap between "the token is set"
//    and "the process making the request has it"
const anon = summarizeSourceHealth(
  cacheOf([
    health('nvd', true, { authenticated: true, authEnv: 'NVD_API_KEY' }),
    health('github', false, { authenticated: false, authEnv: 'GITHUB_TOKEN' }),
  ]),
);
check('an anonymous source is listed', anon.unauthenticated.join(',') === 'github');
check('  ...and said so on the failure itself', anon.failing[0].authenticated === false);
check('  ...naming the variable that was missing', anon.failing[0].missing === 'GITHUB_TOKEN');
check('an authenticated source is not listed', !anon.unauthenticated.includes('nvd'));
check(
  'a source needing no credential is not listed',
  summarizeSourceHealth(cacheOf([health('kev', true)])).unauthenticated.length === 0,
);
check(
  'a failing but authenticated source is not blamed on credentials',
  summarizeSourceHealth(cacheOf([health('euvd', false, { authenticated: true })])).failing[0].authenticated === undefined,
);

// 8. an error the source left blank must not read as a success
const silent = summarizeSourceHealth(cacheOf([health('euvd', false, { error: null })]));
check('a failure with no message still fails', silent.ok === false && silent.failing[0].error === 'unknown error');

// 9. the warning the refresh job prints when it fetched something anonymously
const quiet = anonymousNotes([health('kev', true), health('nvd', true, { authenticated: true, authEnv: 'NVD_API_KEY' })]);
check('nothing is said when every source was authenticated', quiet.length === 0);

const noted = anonymousNotes([health('github', true, { authenticated: false, authEnv: 'GITHUB_TOKEN' })], '/srv/app');
check('an anonymous source that worked is a note, not a warning', noted[0].startsWith('note'), noted[0]);
check('  ...naming the variable', noted[0].includes('GITHUB_TOKEN'));
check('  ...and the file dotenv actually reads', noted[1].includes('/srv/app/.env'));

const warned = anonymousNotes(
  [
    health('nvd', true, { authenticated: false, authEnv: 'NVD_API_KEY' }),
    health('github', false, { authenticated: false, authEnv: 'GITHUB_TOKEN' }),
  ],
  '/srv/app',
);
check('anonymous AND refused is a warning', warned[0].startsWith('WARNING  github'), warned[0]);
check('  ...which says what an exhausted budget looks like', warned[0].includes('exhausted anonymous budget'));
check(
  '  ...and is sorted above the source that merely worked',
  warned[1].startsWith('note') && warned[1].includes('nvd'),
  warned[1],
);
check('  ...with the hosting-panel gap spelled out once', warned.filter((l) => l.includes('not cron')).length === 1);

console.log(`\n${pass} passed, ${fail} failed`);
assert.equal(fail, 0);
