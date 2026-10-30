/**
 * The query layer, shared by every transport.
 *
 * The REST routes and the MCP server must answer the same question the same
 * way, so filtering, sorting, paging and the out-of-window lookup live here
 * rather than in either one of them.
 */
import config from './config.js';
import { comparators, getFeed } from './aggregate.js';
import { SEVERITY_ORDER } from './lib/severity.js';
import { isCveId, lookupCve } from './lookup.js';
import { STACK_CATEGORY_IDS } from './stack.js';
import { attachSignals, MATURITY, pocLinksFor } from './exploits.js';
import { aggregateStats, findRecordById, queryRecords } from './store/cveStore.js';

const asList = (value) =>
  String(value ?? '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);

const int = (value, fallback) => {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
};

function applyFilters(items, query) {
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

const feedMeta = (feed) => ({
  generatedAt: feed.value.generatedAt,
  fromCache: feed.fromCache,
  stale: feed.stale,
  // stale + revalidating means the snapshot is old but a refresh is already
  // running; stale on its own means the refresh failed.
  revalidating: feed.revalidating ?? false,
  ageSeconds: Math.round((feed.ageMs ?? 0) / 1000),
  cacheTtlSeconds: Math.round(config.cacheTtlMs / 1000),
  staleWhileRevalidateSeconds: Math.round(config.staleWhileRevalidateMs / 1000),
  ...(feed.error ? { warning: feed.error } : {}),
});

/**
 * Filter, sort and page the feed, falling back to a direct source lookup when
 * a search names a CVE the current window does not cover.
 */
export async function queryFeed(query = {}) {
  const feed = await getFeed();

  // The database answers filtering, sorting, paging and counting. Nothing but
  // this page of records reaches the host.
  if (feed.value.stored) return queryFromStore(feed, query);

  const filtered = applyFilters(feed.value.items, query);

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
  if (sorted.length === 0 && isCveId(term)) {
    try {
      const found = await lookupCve(term);
      if (found.value.item) {
        lookup = { sources: found.value.sources, lookedUpAt: found.value.lookedUpAt };
        // A looked-up record skipped the feed's enrichment, so it gets it here.
        await attachSignals([found.value.item]);
        sorted.push(found.value.item);
      }
    } catch (error) {
      lookup = { error: error.message };
    }
  }

  return {
    meta: {
      ...feedMeta(feed),
      sort: comparators[sortKey] ? sortKey : 'priority',
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
  };
}

const pocRepos = (item) => (item?.exploitation?.publicPoc ? pocLinksFor(item.cveId) : Promise.resolve([]));

/** The same shape queryFeed has always returned, assembled by the database. */
async function queryFromStore(feed, query) {
  const [page, stats] = await Promise.all([queryRecords(query), aggregateStats(query)]);

  if (!page) {
    // The database went away mid-flight. Say so rather than reporting an
    // empty feed, which would read as "nothing is wrong and nothing exists".
    throw new Error('The vulnerability store is unavailable.');
  }

  let lookup = null;
  const items = [...page.items];
  const term = String(query.q ?? '').trim();

  if (items.length === 0 && isCveId(term)) {
    try {
      const found = await lookupCve(term);
      if (found.value.item) {
        lookup = { sources: found.value.sources, lookedUpAt: found.value.lookedUpAt };
        await attachSignals([found.value.item]);
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
export async function findRecord(id) {
  const feed = await getFeed();

  if (feed.value.stored) {
    const stored = await findRecordById(id);
    if (stored) return { item: stored, meta: feedMeta(feed), pocRepos: await pocRepos(stored) };
    return lookupFallback(id, feed);
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

  return lookupFallback(id, feed);
}

/** Anything the store has never seen is asked of the registers directly. */
async function lookupFallback(id, feed) {
  if (isCveId(id)) {
    const found = await lookupCve(id);
    if (found.value.item) {
      await attachSignals([found.value.item]);
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
