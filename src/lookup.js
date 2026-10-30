import { cached } from './lib/cache.js';
import { finalize, mergeAll } from './merge.js';
import { enabledSources } from './sources/index.js';

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

async function collectOne(cveId) {
  const sources = enabledSources().filter((source) => typeof source.lookupById === 'function');

  const results = await Promise.all(
    sources.map(async (source) => {
      try {
        return { meta: source.meta, items: await source.lookupById(cveId), error: null };
      } catch (error) {
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

export function lookupCve(cveId) {
  const normalized = String(cveId).toUpperCase();
  return cached(`lookup-${normalized}`, () => collectOne(normalized), { ttlMs: LOOKUP_TTL_MS });
}

export default { lookupCve, isCveId };
