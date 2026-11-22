/**
 * research_vulnerability's request and response handling, against a real
 * LangSearch response saved from a live call ("java4shell", count 1).
 *
 * The module under test is the same file the edge function imports; Node runs
 * it through type stripping. What matters: only the phrase is sent, the text
 * is capped, nothing is interpreted, and failures say what failed.
 *
 *   node test/research.mjs
 */
import { readFileSync } from 'node:fs';

const research = await import('../supabase/functions/mcp/research.ts');
const real = JSON.parse(readFileSync(new URL('./fixtures/langsearch-java4shell.json', import.meta.url), 'utf8'));

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

/* ---------- the request ---------- */
{
  const body = research.buildRequest('  java4shell ', 'oneWeek');
  check('only the trimmed phrase is sent', body.query === 'java4shell');
  check('five results, text capped', body.count === 5 && body.contents.text.maxCharacters === 1500);
  check('a known freshness passes through', body.freshness === 'oneWeek');
  check('an unknown freshness falls back to noLimit', research.buildRequest('x', 'whenever').freshness === 'noLimit');
  check('nothing but the four fields leaves the system', Object.keys(body).sort().join() === 'contents,count,freshness,query');
}

/* ---------- the real response ---------- */
{
  const shaped = research.shapeResponse(200, real);
  const [first] = shaped.results;
  check('the real response yields its result', shaped.results.length === 1);
  check('title, url and date come through', first.name.startsWith('Java4Shell (CVE-2026-114938)') && first.url.startsWith('https://dev.to/') && first.datePublished === '2026-11-18T17:00:00.000Z');
  check('the text is there for the model to read', first.text.includes('CVE-2026-114938'));
  check('text is capped even if the provider ignores the cap', first.text.length <= research.MAX_CHARACTERS, `${first.text.length} chars`);
  check('token spend is reported', shaped.outputTokens === 387);
  check('nothing is interpreted - no extracted IDs field', !('cveIds' in shaped) && !('ids' in first));
}
{
  // The real page happened to fit under the cap, so prove the cap with one that does not.
  const long = research.shapeResponse(200, { code: 200, data: { webPages: { value: [{ name: 'x', url: 'https://x.test', text: 'a'.repeat(5000) }] } } });
  check('an oversized page is cut to the cap', long.results[0].text.length === research.MAX_CHARACTERS, `${long.results[0].text.length} chars`);
}

/* ---------- failures ---------- */
{
  let message = '';
  try { research.shapeResponse(400, { code: '400', message: 'count must not exceed 50' }); } catch (e) { message = e.message; }
  check('a 400 reports the provider’s own words', message === 'count must not exceed 50');
  message = '';
  try { research.shapeResponse(200, { code: 500, msg: 'internal' }); } catch (e) { message = e.message; }
  check('a 200 carrying an error code is still a failure', message === 'internal');
  const empty = research.shapeResponse(200, { code: 200, data: { webPages: { value: [] } } });
  check('zero results is an answer, not an error', Array.isArray(empty.results) && empty.results.length === 0);
}

/* ---------- caching ---------- */
check('spelling and spacing share a cache entry', research.cacheKeyFor(' Java4Shell  ') === research.cacheKeyFor('java4shell'));
check('freshness is part of the key', research.cacheKeyFor('x', 'oneDay') !== research.cacheKeyFor('x', 'noLimit'));

/* ---------- the tool definition ---------- */
{
  const tool = research.RESEARCH_TOOL;
  check('the tool is named research_vulnerability', tool.name === 'research_vulnerability');
  check('its description sends the model on to get_cve', /get_cve/.test(tool.description));
  check('its description marks web text untrusted', /untrusted/.test(tool.description));
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
