import { cached, clearCacheKey } from './lib/cache.js';
import { finalize, mergeAll } from './merge.js';
import { enabledSources } from './sources/index.js';
import { lookupBucket } from './lib/ratelimit.js';
import { mayCall, record as recordCall } from './lib/breaker.js';

/**
 * Single-CVE lookup against the sources directly.
 *
 * The feed only holds a recent window, so a search for an older CVE would
 * otherwise come back empty. This asks every source that can answer for one
 * ID and merges the replies with the same rules the feed uses.
 */

const CVE_ID = /^CVE-\d{4}-\d{4,7}$/i;

export const isCveId = (value) => CVE_ID.test(String(value ?? '').trim());

/** Lookups are cached for longer than the feed: an old CVE rarely changes. */
const LOOKUP_TTL_MS = 6 * 60 * 60 * 1000;

/**
 * Sources worth asking for one record right now.
 *
 * Two reasons to leave one out: it needs a credential this process does not
 * have and its anonymous budget belongs to the refresh (see the GitHub source
 * for why), or it has been refusing and its breaker is still open.
 */
function lookupSources(method) {
  return enabledSources().filter((source) => {
    if (typeof source[method] !== 'function') return false;
    const { authEnv, lookupNeedsAuth, id } = source.meta;
    if (lookupNeedsAuth && authEnv && !process.env[authEnv]) return false;
    return mayCall(id);
  });
}

async function collectOne(cveId) {
  // A burst of distinct CVE ids would otherwise fan out one upstream request
  // each - including one against GitHub's thin anonymous budget, shared across
  // the whole host. The bucket caps that; a declined lookup reads as "not
  // found", which is already how an out-of-window miss behaves.
  if (lookupBucket && !lookupBucket.tryTake()) {
    return { item: null, sources: [], lookedUpAt: new Date().toISOString(), throttled: true };
  }

  const sources = lookupSources('lookupById');

  const results = await Promise.all(
    sources.map(async (source) => {
      try {
        const items = await source.lookupById(cveId);
        recordCall(source.meta.id, true);
        return { meta: source.meta, items, error: null };
      } catch (error) {
        // A 404 is an answer, not a failure: most CVEs have no advisory at
        // most registers, and counting those would open every breaker.
        recordCall(source.meta.id, error.status === 404);
        return { meta: source.meta, items: [], error: error.message };
      }
    }),
  );

  const merged = mergeAll(results);
  const wanted = `cve:${cveId.toUpperCase()}`;
  const record = merged.get(wanted);

  return {
    item: record ? { ...finalize(record), outsideWindow: true } : null,
    sources: results.map((r) => ({
      id: r.meta.id,
      name: r.meta.name,
      ok: !r.error,
      count: r.items.length,
      error: r.error,
    })),
    lookedUpAt: new Date().toISOString(),
  };
}

export async function lookupCve(cveId) {
  const normalized = String(cveId).toUpperCase();
  const result = await cached(`lookup-${normalized}`, () => collectOne(normalized), {
    ttlMs: LOOKUP_TTL_MS,
    evictable: true,
  });
  // Don't let a throttled (empty-by-choice) answer stick in the cache.
  if (result.value.throttled) clearCacheKey(`lookup-${normalized}`);
  return result;
}

/* ---------- lookup by software name ---------- */

/**
 * Is this term worth spending an upstream request on?
 *
 * The lookup runs when a search found nothing, so the guard has to separate
 * "a product nobody has asked about" from "a typo" and from someone pasting a
 * sentence. A name is short, is a handful of words, and is not punctuation -
 * anything else would burn the shared rate budget to find nothing.
 */
export function isNameQuery(value) {
  const term = String(value ?? '').trim();
  if (term.length < 3 || term.length > 40) return false;
  if (isCveId(term) || /^(CVE|GHSA|EUVD)-/i.test(term)) return false;
  if (term.split(/\s+/).length > 3) return false;
  // At least one letter, and nothing exotic. Package names keep their
  // punctuation (@scope/pkg, log4j-core, github.com/org/repo).
  return /[a-z]/i.test(term) && /^[\w@./:+-]+(?:\s[\w@./:+-]+){0,2}$/i.test(term);
}

/** Names change less often than the feed, and a miss is worth remembering. */
const NAME_TTL_MS = 12 * 60 * 60 * 1000;

async function collectByName(term) {
  // Shares the bucket with CVE lookups on purpose: both fan out to the same
  // upstream budget, and a spray of distinct search terms is exactly the
  // traffic shape it exists to cap.
  if (lookupBucket && !lookupBucket.tryTake()) {
    return { items: [], sources: [], lookedUpAt: new Date().toISOString(), throttled: true };
  }

  const sources = lookupSources('searchByName');

  const results = await Promise.all(
    sources.map(async (source) => {
      try {
        const items = await source.searchByName(term);
        recordCall(source.meta.id, true);
        return { meta: source.meta, items, error: null };
      } catch (error) {
        recordCall(source.meta.id, error.status === 404);
        return { meta: source.meta, items: [], error: error.message };
      }
    }),
  );

  // Merged with the same rules as the feed, so a record found this way is
  // shaped exactly like one that arrived through a refresh - and marked as
  // outside the window, because it is: it belongs to a search, not to the
  // current listing.
  const merged = mergeAll(results);
  const items = [...merged.values()].map((record) => ({ ...finalize(record), outsideWindow: true }));

  // "We asked and there is nothing" and "we could not ask" are different
  // answers and only one of them is safe to remember. Without this the first
  // rate-limited request pins an empty result in the cache for half a day,
  // and every later search for that name is confidently told nothing exists.
  const answered = results.some((r) => !r.error);

  return {
    items,
    failed: !answered,
    sources: results.map((r) => ({ id: r.meta.id, name: r.meta.name, ok: !r.error, count: r.items.length, error: r.error })),
    lookedUpAt: new Date().toISOString(),
  };
}

/**
 * Everything the registers know about a piece of software, by name.
 *
 * Cached including the misses: a term that found nothing upstream will find
 * nothing again an hour later, and re-asking would spend the budget that the
 * next real lookup needs.
 */
export async function lookupByName(term) {
  const normalized = String(term).trim().toLowerCase();
  const key = `namelookup-${normalized}`;
  const result = await cached(key, () => collectByName(normalized), {
    ttlMs: NAME_TTL_MS,
    evictable: true,
  });
  // Neither a throttled answer nor a failed one is evidence of absence, so
  // neither is allowed to stick: the next search tries again.
  if (result.value.throttled || result.value.failed) clearCacheKey(key);
  return result;
}

export default { lookupCve, isCveId, lookupByName, isNameQuery };
