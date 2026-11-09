/**
 * The query layer, shared by every transport.
 *
 * The REST routes and the MCP server must answer the same question the same
 * way, so filtering, sorting, paging and the out-of-window lookup live here
 * rather than in either one of them.
 */
import config from './config.js';
import { comparators, getFeed, readOnly } from './aggregate.js';
import { SEVERITY_ORDER } from './lib/severity.js';
import { isCveId, isNameQuery, lookupByName, lookupCve } from './lookup.js';
import { STACK_CATEGORY_IDS } from './stack.js';
import { attachSignals, MATURITY, pocLinksFor } from './exploits.js';
import { aggregateStats, findRecordById, firstMode, queryRecords, upsertRecords } from './store/cveStore.js';
import { normalizeTerm } from './lib/terms.js';
import { packageHintFor } from './lib/suggest.js';
import { mongoConfigured } from './lib/mongo.js';

const asList = (value) =>
  String(value ?? '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);

const int = (value, fallback) => {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
};

function applyFilters(items, query, { mode = 'words' } = {}) {
  const severities = asList(query.severity).filter((s) => SEVERITY_ORDER.includes(s));
  const sources = asList(query.source);
  const kinds = asList(query.kind);
  const stackRaw = asList(query.stack);
  // Either a named signal (metasploit, poc, ...) or a minimum rung of the
  // maturity ladder, which is what someone triaging usually means.
  const exploitSignals = asList(query.exploit);
  const minMaturity = String(query.maturity ?? '').trim().toLowerCase();
  const minMaturityRank = MATURITY.indexOf(minMaturity);
  const anyStack = stackRaw.includes('any') || stackRaw.includes('all');
  const stacks = stackRaw.filter((s) => STACK_CATEGORY_IDS.includes(s));
  const needle = String(query.q ?? '').trim().toLowerCase();
  // Only when the caller has not explicitly asked for a full-text search.
  const exactTerm = String(query.match ?? '') === 'words' ? null : normalizeTerm(needle);
  // 'exact' narrows to records that carry the term as a name; 'words' is the
  // wider prose match, which includes the exact hits as a subset.
  const exactOnly = mode === 'exact';
  const minScore = Number.parseFloat(query.minScore);
  const days = int(query.days, 0);
  const exploitedOnly = ['1', 'true', 'yes'].includes(String(query.exploited ?? '').toLowerCase());

  const since = days > 0 ? Date.now() - days * 86_400_000 : null;

  return items.filter((item) => {
    if (severities.length && !severities.includes(item.severity)) return false;
    if (sources.length && !item.sourceIds.some((id) => sources.includes(id))) return false;
    if (kinds.length && !kinds.includes(item.kind)) return false;
    if (anyStack && !item.stack) return false;
    if (stacks.length && !item.stack?.categories.some((c) => stacks.includes(c))) return false;
    if (exploitedOnly && !item.exploited) return false;

    if (exploitSignals.length) {
      const x = item.exploitation;
      const matches = exploitSignals.some((signal) => {
        if (signal === 'any') return Boolean(x);
        if (signal === 'weaponized' || signal === 'metasploit') return x?.weaponized === true;
        if (signal === 'exploit' || signal === 'exploitdb') return x?.publicExploit === true;
        if (signal === 'poc') return x?.publicPoc === true;
        if (signal === 'scannable' || signal === 'nuclei') return x?.scannable === true;
        if (signal === 'observed') return x?.observed === true;
        return false;
      });
      if (!matches) return false;
    }

    if (minMaturityRank >= 0) {
      const rank = item.exploitation?.maturityRank ?? 99;
      if (rank > minMaturityRank) return false;
    }
    if (Number.isFinite(minScore) && (item.score ?? -1) < minScore) return false;

    if (since) {
      const stamp = Date.parse(item.published ?? item.modified ?? '');
      if (!Number.isFinite(stamp) || stamp < since) return false;
    }

    if (needle) {
      // The database path matches an exact name before it matches prose, and
      // the memory fallback has to behave the same way or the dashboard would
      // answer differently depending on whether Atlas happens to be up.
      if (exactTerm && item.searchTerms?.includes(exactTerm)) return true;
      if (exactOnly) return false;

      const haystack = [
        item.id,
        item.cveId,
        item.ghsaId,
        item.euvdId,
        item.advisoryId,
        item.title,
        item.description,
        item.vendor,
        item.product,
        item.searchTerms?.join(' '),
        item.vendors?.join(' '),
        item.products?.join(' '),
        item.packages?.map((p) => p.name).join(' '),
        item.cwes.join(' '),
        item.tags.join(' '),
        item.stack?.subjects.join(' '),
        item.stack?.categoryNames.join(' '),
        item.exploitation?.evidence.join(' '),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(needle)) return false;
    }

    return true;
  });
}

function summarize(items) {
  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  const bySource = {};
  const byStack = Object.fromEntries(STACK_CATEGORY_IDS.map((id) => [id, 0]));
  const byExploit = { observed: 0, weaponized: 0, publicExploit: 0, publicPoc: 0, scannable: 0 };
  let withExploitSignal = 0;
  let inStack = 0;
  let stackExploited = 0;
  let exploited = 0;
  let scored = 0;
  let scoreTotal = 0;
  const last24h = Date.now() - 86_400_000;
  let fresh = 0;

  for (const item of items) {
    bySeverity[item.severity] = (bySeverity[item.severity] ?? 0) + 1;
    for (const id of item.sourceIds) bySource[id] = (bySource[id] ?? 0) + 1;
    if (item.stack) {
      inStack += 1;
      if (item.exploited) stackExploited += 1;
      for (const c of item.stack.categories) byStack[c] = (byStack[c] ?? 0) + 1;
    }
    if (item.exploitation) {
      withExploitSignal += 1;
      for (const key of Object.keys(byExploit)) if (item.exploitation[key]) byExploit[key] += 1;
    }
    if (item.exploited) exploited += 1;
    if (Number.isFinite(item.score)) {
      scored += 1;
      scoreTotal += item.score;
    }
    const stamp = Date.parse(item.published ?? '');
    if (Number.isFinite(stamp) && stamp >= last24h) fresh += 1;
  }

  return {
    total: items.length,
    bySeverity,
    bySource,
    byStack,
    inStack,
    stackExploited,
    byExploit,
    withExploitSignal,
    exploited,
    last24h: fresh,
    averageScore: scored ? Number((scoreTotal / scored).toFixed(1)) : null,
  };
}

/**
 * How old the data is - measured from when it was generated, not from when
 * this worker last looked.
 *
 * The two used to be the same thing, because the worker that served a request
 * was also the one that built the feed. Once workers only read, the cache
 * entry's age is just how long ago a worker re-read the summary - under a
 * minute, always - and reporting that would show the feed as fresh forever
 * while the cron job that actually refreshes it had been dead for a day.
 */
export function dataAgeMs(feed) {
  const generated = Date.parse(feed?.value?.generatedAt ?? '');
  return Number.isFinite(generated) ? Date.now() - generated : (feed?.ageMs ?? null);
}

const feedMeta = (feed) => {
  const ageMs = dataAgeMs(feed);
  const external = readOnly();
  return {
  generatedAt: feed.value.generatedAt,
  fromCache: feed.fromCache,
  // Read-only workers judge staleness against the refresh schedule, since the
  // cache entry is always young; builders keep the cache's own judgement.
  stale: external ? ageMs == null || ageMs > config.staleAfterMs : feed.stale,
  // stale + revalidating means the snapshot is old but a refresh is already
  // running; stale on its own means the refresh failed.
  revalidating: external ? false : (feed.revalidating ?? false),
  refresh: external ? 'external' : 'in-process',
  ...(feed.value.neverRefreshed ? { neverRefreshed: true } : {}),
  ageSeconds: ageMs == null ? null : Math.round(ageMs / 1000),
  cacheTtlSeconds: Math.round(config.cacheTtlMs / 1000),
  staleWhileRevalidateSeconds: Math.round(config.staleWhileRevalidateMs / 1000),
  ...(feed.error ? { warning: feed.error } : {}),
  };
};

/**
 * Filter, sort and page the feed, falling back to a direct source lookup when
 * a search names a CVE the current window does not cover.
 */
/**
 * Whether the term names a package, so the dashboard can offer the
 * version-aware check. Decided here rather than on the client, because this
 * is where the vocabulary lives. Best-effort: a failure costs the offer, not
 * the search.
 */
async function hintFor(query) {
  const term = String(query.q ?? '').trim();
  if (!term) return null;
  try {
    return await packageHintFor(term);
  } catch {
    return null;
  }
}

export async function queryFeed(query = {}) {
  let feed = await getFeed();

  // The database answers filtering, sorting, paging and counting. Nothing but
  // this page of records reaches the host.
  if (feed.value.stored) {
    const result = await queryFromStore(feed, query);
    if (result) return withPackageHint(result, await hintFor(query));
    // The store was reachable when this snapshot was written but is not now.
    // Force a refresh; collect() falls back to memory when the database is
    // unreachable, so the request below is served from memory rather than
    // returning an error to the visitor.
    feed = await getFeed({ force: true });
    if (feed.value.stored) {
      // The database recovered between the two calls; try it once more.
      const retry = await queryFromStore(feed, query);
      if (retry) return withPackageHint(retry, await hintFor(query));
    }
  }

  // The same cascade the database path runs, for the same reason: the
  // dashboard must not answer differently depending on whether Atlas is up.
  // An exact name match wins outright; only when nothing carries the term as
  // a name does it fall back to matching prose.
  const pool = feed.value.items ?? [];
  let memoryMatchedBy = 'words';
  let filtered = [];

  if (firstMode(query) === 'exact') {
    filtered = applyFilters(pool, query, { mode: 'exact' });
    if (filtered.length) memoryMatchedBy = 'exact';
  }
  if (!filtered.length) filtered = applyFilters(pool, query, { mode: 'words' });

  const sortKey = String(query.sort ?? 'priority');
  const comparator = comparators[sortKey] ?? comparators.priority;
  const sorted = [...filtered].sort(comparator);

  const limit = Math.min(Math.max(int(query.limit, 50), 1), 500);
  const page = Math.max(int(query.page, 1), 1);
  const start = (page - 1) * limit;

  // The feed only covers a recent window. If someone searched for a specific
  // CVE that is not in it, ask the sources directly rather than returning
  // nothing - this is the most common thing a visitor types.
  let lookup = null;
  const term = String(query.q ?? '').trim();

  // Same name fallback as the database path, so the degraded mode answers the
  // same question rather than a smaller one.
  if (!isCveId(term) && (sorted.length === 0 || (sorted.length < WEAK_MATCH && isNameQuery(term)))) {
    const byName = await nameFallback(query);
    if (byName) {
      const seen = new Set(sorted.map((i) => i.cveId ?? i.id));
      for (const found of byName.items) {
        if (!seen.has(found.cveId ?? found.id)) sorted.push(found);
      }
      lookup = byName.lookup;
      sorted.sort(comparator);
    }
  }

  if (sorted.length === 0 && isCveId(term)) {
    try {
      const found = await lookupCve(term);
      if (found.value.item) {
        lookup = { sources: found.value.sources, lookedUpAt: found.value.lookedUpAt };
        // A looked-up record skipped the feed's enrichment, so it gets it here.
        await attachSignals([found.value.item]);
        await persistLookup(found.value.item);
        sorted.push(found.value.item);
      }
    } catch (error) {
      lookup = { error: error.message };
    }
  }

  return withPackageHint(
    {
    meta: {
      ...feedMeta(feed),
      sort: comparators[sortKey] ? sortKey : 'priority',
      ...(memoryMatchedBy !== 'words' ? { matchedBy: memoryMatchedBy } : {}),
      ...(String(query.q ?? '').trim() ? { q: String(query.q).trim() } : {}),
      total: sorted.length,
      totalUnfiltered: feed.value.items.length,
      page,
      limit,
      pages: Math.max(Math.ceil(sorted.length / limit), 1),
      ...(lookup ? { lookup } : {}),
    },
    stats: summarize(sorted),
    sources: feed.value.sources,
    exploitSources: feed.value.exploitSources ?? [],
    items: sorted.slice(start, start + limit),
    },
    await hintFor(query),
  );
}

/** Attach the package hint to a result's meta, if there is one. */
function withPackageHint(result, hint) {
  if (!hint) return result;
  return { ...result, meta: { ...result.meta, packageHint: hint } };
}

const pocRepos = (item) => (item?.exploitation?.publicPoc ? pocLinksFor(item.cveId) : Promise.resolve([]));

/**
 * Persist a looked-up record so it is never searched upstream again. Stored
 * with outsideWindow:true, it stays out of the browsable window but is found
 * by id - so the next request for it is one database read, not a fan-out to
 * four sources. A no-op without a reachable database.
 */
async function persistLookup(item) {
  if (item) await persistLookups([item]);
}

async function persistLookups(items) {
  if (!mongoConfigured() || !items?.length) return;
  try {
    await upsertRecords(items);
  } catch (error) {
    // Caching the lookup is best-effort; failing it must not fail the
    // request. Logged, because a write that silently never lands means every
    // search for that name pays for the upstream lookup again.
    console.warn(`[cvefeed] could not keep ${items.length} looked-up record(s): ${error.message}`);
  }
}

/**
 * A search that found nothing, answered from the registers instead.
 *
 * The corpus only holds what has been ingested since it started, which for
 * most software is long after its last CVE - so "no results" for a product
 * name usually means "we never fetched that", and reads to the visitor as
 * "nothing is wrong with it". That is the worst possible way for a
 * vulnerability feed to be wrong, so a name that found nothing is looked up
 * once, kept, and answered properly from then on.
 *
 * Always resolves. A throttled or failed lookup leaves the empty result as it
 * was rather than turning a quiet answer into an error.
 */
/**
 * Below this many hits, a name query is checked against the registers.
 *
 * Not only when nothing matched. An exact match on one stored record is
 * high-confidence about relevance and says nothing about completeness - the
 * corpus might hold this morning's DefectDojo advisory and know nothing of
 * the three before it. A handful of incidental substring hits are worth
 * re-asking for the same reason. Bounded by the lookup cache (one fetch per
 * name per 12 hours) and the shared token bucket.
 */
const WEAK_MATCH = 5;

async function nameFallback(query) {
  const term = String(query.q ?? '').trim();
  if (!isNameQuery(term)) return null;

  try {
    const found = await lookupByName(term);
    const items = (found.value.items ?? []).filter((item) => item?.key);
    if (!items.length) return null;

    await attachSignals(items);
    // Kept so the second search for this name is served from the store - in
    // one batch. This used to be one awaited round trip per record, and a
    // name lookup returns up to forty: measured against the cluster that was
    // 1.9 seconds of a worker sitting idle, against 0.1 for the batch.
    await persistLookups(items);

    return {
      items,
      lookup: {
        byName: term,
        sources: found.value.sources?.filter((s) => s.ok && s.count).map((s) => s.name) ?? [],
        lookedUpAt: found.value.lookedUpAt,
      },
    };
  } catch {
    return null;
  }
}

/** The same shape queryFeed has always returned, assembled by the database. */
async function queryFromStore(feed, query) {
  // Computed together, on the assumption the indexed search matches - which is
  // the common case. When it does not and the store falls back to a substring
  // search, the counts have to be recomputed over that same filter, or the
  // facets would describe a result set the visitor is not looking at.
  // Both sides must assume the SAME stage, or the counts silently describe a
  // different filter than the rows even when no recompute is triggered.
  const assumed = firstMode(query);
  let [page, stats] = await Promise.all([queryRecords(query), aggregateStats(query, { mode: assumed })]);

  // The database is unreachable. Return null so the caller can fall back to
  // memory rather than handing the visitor a 500.
  if (!page || !stats) return null;

  // The optimistic call above assumed the first stage would match. Whenever a
  // later stage actually produced the rows, the counts describe a different
  // result set and have to be redone against that stage's filter.
  if (page.matchedBy && page.matchedBy !== assumed) {
    stats = (await aggregateStats(query, { mode: page.matchedBy })) ?? stats;
  }

  let lookup = null;
  const items = [...page.items];
  const term = String(query.q ?? '').trim();

  // A name nobody has searched before: ask the registers, keep what comes
  // back, and answer from it. Only once per term - the lookup is cached,
  // misses included.
  //
  // Nothing found is the obvious trigger. The other one is a weak match: the
  // substring stage is a scan that happily matches a name mentioned in
  // passing inside an unrelated advisory, and a single incidental hit like
  // that would otherwise suppress the lookup and leave the visitor with one
  // wrong answer instead of the real ones.
  if (!isCveId(term) && (page.total === 0 || (page.total < WEAK_MATCH && isNameQuery(term)))) {
    const byName = await nameFallback(query);
    if (byName) {
      const seen = new Set(items.map((i) => i.cveId ?? i.id));
      for (const found of byName.items) {
        if (!seen.has(found.cveId ?? found.id)) items.push(found);
      }
      lookup = byName.lookup;
      // The store returned these already sorted; the fetched ones arrive in
      // whatever order the register gave them, so the merged set has to be
      // sorted again or a 2006 CVE lands above this morning's.
      const comparator = comparators[page.sort] ?? comparators.priority;
      items.sort(comparator);
    }
  }

  if (items.length === 0 && isCveId(term)) {
    try {
      const found = await lookupCve(term);
      if (found.value.item) {
        lookup = { sources: found.value.sources, lookedUpAt: found.value.lookedUpAt };
        await attachSignals([found.value.item]);
        await persistLookup(found.value.item);
        items.push(found.value.item);
      }
    } catch (error) {
      lookup = { error: error.message };
    }
  }

  return {
    meta: {
      ...feedMeta(feed),
      sort: page.sort,
      // How the term was matched, so the dashboard can say so: a substring
      // match means the indexed word search found nothing.
      ...(page.matchedBy && page.matchedBy !== 'words' ? { matchedBy: page.matchedBy } : {}),
      // Echoed so the client can render notes about the term without having
      // to trust its own input box, which may be mid-edit.
      ...(String(query.q ?? '').trim() ? { q: String(query.q).trim() } : {}),
      total: lookup ? items.length : page.total,
      totalUnfiltered: feed.value.fetched ?? stats.total,
      page: page.page,
      limit: page.limit,
      pages: Math.max(Math.ceil((lookup ? items.length : page.total) / page.limit), 1),
      ...(lookup ? { lookup } : {}),
    },
    stats,
    sources: feed.value.sources,
    exploitSources: feed.value.exploitSources ?? [],
    items,
  };
}

/** One record by any of its identifiers, with the same lookup fallback. */
/**
 * @param id        a CVE, GHSA or EUVD id
 * @param allowUpstream  whether a miss may be asked of the registers directly.
 *   False for crawler traffic: the sitemap invites a walk of every CVE that
 *   exists, and answering each miss upstream turns one crawl into hundreds of
 *   thousands of requests nobody is waiting on.
 */
export async function findRecord(id, { allowUpstream = true } = {}) {
  const feed = await getFeed();

  if (feed.value.stored) {
    const stored = await findRecordById(id);
    if (stored) return { item: stored, meta: feedMeta(feed), pocRepos: await pocRepos(stored) };
    return allowUpstream ? lookupFallback(id, feed) : notHere(feed);
  }

  const needle = String(id).toLowerCase();
  const item = feed.value.items.find(
    (candidate) =>
      candidate.id?.toLowerCase() === needle ||
      candidate.cveId?.toLowerCase() === needle ||
      candidate.ghsaId?.toLowerCase() === needle ||
      candidate.euvdId?.toLowerCase() === needle ||
      candidate.advisoryId?.toLowerCase() === needle,
  );

  // A single-record view is worth the extra request that turns "a PoC exists"
  // into the repositories themselves; the feed listing is not.
  if (item) return { item, meta: feedMeta(feed), pocRepos: await pocRepos(item) };

  return allowUpstream ? lookupFallback(id, feed) : notHere(feed);
}

/** A miss we chose not to spend an upstream request on. */
const notHere = (feed) => ({
  item: null,
  meta: feedMeta(feed),
  reason: 'Not found in the current feed window.',
});

/** Anything the store has never seen is asked of the registers directly. */
async function lookupFallback(id, feed) {
  if (isCveId(id)) {
    const found = await lookupCve(id);
    if (found.value.item) {
      await attachSignals([found.value.item]);
      await persistLookup(found.value.item);
      return {
        item: found.value.item,
        pocRepos: await pocRepos(found.value.item),
        meta: { ...feedMeta(feed), lookup: { sources: found.value.sources, lookedUpAt: found.value.lookedUpAt } },
      };
    }
    return { item: null, meta: feedMeta(feed), reason: `${id} was not found at any source.` };
  }

  return { item: null, meta: feedMeta(feed), reason: 'Not found in the current feed window.' };
}

export { applyFilters, feedMeta, summarize, int, asList };
