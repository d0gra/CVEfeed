/**
 * The vulnerability records themselves, in Atlas.
 *
 * Previously the whole feed was a JavaScript array held for the life of the
 * process, and every request filtered, sorted and counted it by scanning. That
 * is what a database does, and doing it in the host's memory was a consequence
 * of not having one.
 *
 * Two things follow from moving it. The host holds nothing between requests,
 * and the feed stops being a rolling window that forgets: records accumulate,
 * so a CVE that drops out of the seven-day fetch still has a page.
 */
import { getDb } from '../lib/mongo.js';
import { SEVERITY_ORDER } from '../lib/severity.js';
import { STACK_CATEGORY_IDS } from '../stack.js';

const COLLECTION = 'cves';

let indexesReady = null;

async function collection() {
  const db = await getDb();
  if (!db) return null;
  const col = db.collection(COLLECTION);

  indexesReady ??= Promise.all([
    // Sorts and the recency filter.
    col.createIndex({ published: -1 }),
    col.createIndex({ modified: -1 }),
    // The default view: exploited first, then score, then recency.
    col.createIndex({ exploited: -1, score: -1, published: -1 }),
    col.createIndex({ score: -1 }),
    col.createIndex({ epss: -1 }),
    // Facets.
    col.createIndex({ severity: 1 }),
    col.createIndex({ sourceIds: 1 }),
    col.createIndex({ kind: 1 }),
    col.createIndex({ 'stack.categories': 1 }),
    col.createIndex({ 'exploitation.maturityRank': 1 }),
    // Lookups by any identifier a visitor might paste.
    col.createIndex({ cveId: 1 }),
    col.createIndex({ ghsaId: 1 }, { sparse: true }),
    col.createIndex({ euvdId: 1 }, { sparse: true }),
    col.createIndex({ advisoryId: 1 }, { sparse: true }),
    // Free-text search. A text index matches words rather than substrings,
    // which is a real behaviour change from the old scan - but a substring
    // scan over a growing collection is not something to carry forward.
    col.createIndex(
      { title: 'text', description: 'text', vendor: 'text', product: 'text' },
      { name: 'search', weights: { title: 10, vendor: 4, product: 4, description: 1 } },
    ),
  ]).catch(() => null);

  await indexesReady;
  return col;
}

export async function storeReady() {
  return Boolean(await collection());
}

/** Write a refresh's records. Chunked, unordered, and nothing kept after. */
export async function upsertRecords(items) {
  const col = await collection();
  if (!col || !items?.length) return { written: 0, ok: Boolean(col) };

  const now = new Date();
  let written = 0;
  const CHUNK = 500;

  for (let i = 0; i < items.length; i += CHUNK) {
    const ops = items.slice(i, i + CHUNK).map((item) => {
      const { key, ...rest } = item;
      return {
        updateOne: {
          filter: { _id: key },
          update: {
            // Normalise outsideWindow to a boolean: a feed refresh must clear
            // the flag a prior lookup set, once the CVE enters the window.
            $set: { ...rest, outsideWindow: rest.outsideWindow === true, lastSeen: now },
            // Kept from the first time we ever saw it, so history is real
            // rather than a side effect of when the last refresh ran.
            $setOnInsert: { firstSeen: now },
          },
          upsert: true,
        },
      };
    });

    const result = await col.bulkWrite(ops, { ordered: false });
    written += (result.upsertedCount ?? 0) + (result.modifiedCount ?? 0);
  }

  return { written, ok: true };
}

/* ---------- reading ---------- */

const int = (value, fallback) => {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
};

const asList = (value) =>
  String(value ?? '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);

/** Translate the public query parameters into a Mongo filter. */
/**
 * Escape a user term for use inside a regular expression.
 *
 * Without this, a search for "c++" or "a|b" is a malformed pattern at best and
 * a pathological one at worst - the input comes straight off a query string.
 */
const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The fields worth scanning.
 *
 * This list matches what the old in-memory filter searched, which is the
 * reason the fallback exists at all: the text index covers title, description,
 * vendor and product, so moving the feed into the database quietly dropped
 * `stack.subjects` - the project and package names - and the tags and CWEs
 * along with them. Those are exactly the terms someone types into a search box.
 */
function substringClauses(term) {
  const pattern = new RegExp(escapeRegex(term), 'i');
  return [
    { title: pattern },
    { vendor: pattern },
    { product: pattern },
    { 'stack.subjects': pattern },
    { 'stack.categoryNames': pattern },
    { tags: pattern },
    { cwes: pattern },
    { description: pattern },
  ];
}

/**
 * Whether a substring retry is worth doing for this term.
 *
 * Short terms match almost everything, and an identifier is already matched
 * exactly, so neither gains anything from a scan.
 */
export const canRetryAsSubstring = (query = {}) => {
  const term = String(query.q ?? '').trim();
  return term.length >= 3 && !/^(CVE|GHSA|EUVD)-/i.test(term);
};

export function buildFilter(query = {}, { substring = false } = {}) {
  const and = [];

  const severities = asList(query.severity).filter((s) => SEVERITY_ORDER.includes(s));
  if (severities.length) and.push({ severity: { $in: severities } });

  const sources = asList(query.source);
  if (sources.length) and.push({ sourceIds: { $in: sources } });

  const kinds = asList(query.kind);
  if (kinds.length) and.push({ kind: { $in: kinds } });

  const stackRaw = asList(query.stack);
  if (stackRaw.includes('any') || stackRaw.includes('all')) {
    and.push({ 'stack.categories': { $exists: true, $ne: [] } });
  } else {
    const stacks = stackRaw.filter((s) => STACK_CATEGORY_IDS.includes(s));
    if (stacks.length) and.push({ 'stack.categories': { $in: stacks } });
  }

  if (['1', 'true', 'yes'].includes(String(query.exploited ?? '').toLowerCase())) {
    and.push({ exploited: true });
  }

  const exploitSignals = asList(query.exploit);
  if (exploitSignals.length) {
    const fields = {
      any: 'exploitation',
      observed: 'exploitation.observed',
      weaponized: 'exploitation.weaponized',
      metasploit: 'exploitation.weaponized',
      exploit: 'exploitation.publicExploit',
      exploitdb: 'exploitation.publicExploit',
      poc: 'exploitation.publicPoc',
      scannable: 'exploitation.scannable',
      nuclei: 'exploitation.scannable',
    };
    const clauses = exploitSignals
      .map((s) => fields[s])
      .filter(Boolean)
      .map((field) => ({ [field]: { $exists: true, $ne: null } }));
    // An unrecognised signal matches nothing, so a typo looks wrong rather
    // than looking like no filter at all.
    and.push(clauses.length ? { $or: clauses } : { _id: null });
  }

  const maturity = String(query.maturity ?? '').trim().toLowerCase();
  const MATURITY = ['observed', 'weaponized', 'public-exploit', 'proof-of-concept', 'none'];
  const rank = MATURITY.indexOf(maturity);
  if (rank >= 0) and.push({ 'exploitation.maturityRank': { $lte: rank } });

  const minScore = Number.parseFloat(query.minScore);
  if (Number.isFinite(minScore)) and.push({ score: { $gte: minScore } });

  const days = int(query.days, 0);
  if (days > 0) {
    and.push({ published: { $gte: new Date(Date.now() - days * 86_400_000).toISOString() } });
  }

  const term = String(query.q ?? '').trim();
  if (term) {
    // An identifier is matched exactly; anything else goes to the text index.
    if (/^(CVE|GHSA|EUVD)-/i.test(term)) {
      const upper = term.toUpperCase();
      and.push({
        $or: [{ cveId: upper }, { ghsaId: upper }, { euvdId: upper }, { advisoryId: upper }, { _id: upper }],
      });
    } else if (substring) {
      // The fallback for what a text index cannot do: match inside words.
      // A package name is the case that matters - "lodash" is a whole word in
      // "Prototype Pollution in lodash" but not in "node-lodash", and "log4j"
      // is not a word in "Log4Shell" at all.
      //
      // This is a scan, which is what the rest of this file exists to avoid,
      // so it runs only after the indexed search has come back with nothing,
      // and only for terms long enough to be worth scanning for.
      and.push({ $or: substringClauses(term) });
    } else {
      and.push({ $text: { $search: term } });
    }
  }

  // Records resolved by a direct lookup are kept so they are never searched
  // upstream twice, but they are not part of the current window: they surface
  // only when asked for by id, never in the browsable listing or its counts.
  if (!/^(CVE|GHSA|EUVD)-/i.test(term)) and.push({ outsideWindow: { $ne: true } });

  return and.length ? { $and: and } : {};
}

const SORTS = {
  priority: { exploited: -1, score: -1, published: -1 },
  newest: { published: -1 },
  updated: { modified: -1 },
  score: { score: -1 },
  epss: { epss: -1 },
  severity: { severityRank: -1, score: -1 },
  exploitability: { 'exploitation.maturityRank': 1, epss: -1 },
};

/** One page of records, plus how many matched. */
export async function queryRecords(query = {}) {
  const col = await collection();
  if (!col) return null;

  const sortKey = SORTS[query.sort] ? query.sort : 'priority';
  const limit = Math.min(Math.max(int(query.limit, 50), 1), 500);
  const page = Math.max(int(query.page, 1), 1);

  const run = async (filter) => {
    const [rows, total] = await Promise.all([
      col
        .find(filter)
        .sort(SORTS[sortKey])
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray(),
      col.countDocuments(filter),
    ]);
    return { rows, total };
  };

  let matchedBy = 'words';
  let { rows, total } = await run(buildFilter(query));

  // A word search that found nothing is retried as a substring search. This is
  // the difference between a search box that works the way people expect and
  // one that answers "nothing matches" for "lodash" because the advisory says
  // "lodash" inside a longer token, or for "log4j" because the title says
  // "Log4Shell". The indexed search runs first precisely so the scan is the
  // exception rather than the rule.
  if (total === 0 && canRetryAsSubstring(query)) {
    const retry = await run(buildFilter(query, { substring: true }));
    if (retry.total > 0) {
      ({ rows, total } = retry);
      matchedBy = 'substring';
    }
  }

  // The record's key was stored as _id. Restore it as `key`, because the
  // dashboard matches a clicked row to its data by item.key - without it,
  // store-backed rows carry an empty data-key and never expand.
  const items = rows.map(({ _id, ...rest }) => ({ key: _id, ...rest }));

  return { items, total, page, limit, sort: sortKey, matchedBy };
}

/**
 * The facet counts, as one aggregation.
 *
 * Done in the database for the same reason as everything else here: counting
 * by scanning the collection into the host would put back exactly what moving
 * it was meant to remove.
 */
export async function aggregateStats(query = {}, { substring = false } = {}) {
  const col = await collection();
  if (!col) return null;

  // The counts have to be computed over whichever filter actually produced the
  // list, or the facets would describe a different result set than the rows.
  const filter = buildFilter(query, { substring });
  const [result] = await col
    .aggregate([
      { $match: filter },
      {
        $facet: {
          total: [{ $count: 'n' }],
          bySeverity: [{ $group: { _id: '$severity', n: { $sum: 1 } } }],
          bySource: [{ $unwind: '$sourceIds' }, { $group: { _id: '$sourceIds', n: { $sum: 1 } } }],
          byStack: [
            { $match: { 'stack.categories.0': { $exists: true } } },
            { $unwind: '$stack.categories' },
            { $group: { _id: '$stack.categories', n: { $sum: 1 } } },
          ],
          inStack: [{ $match: { 'stack.categories.0': { $exists: true } } }, { $count: 'n' }],
          stackExploited: [
            { $match: { 'stack.categories.0': { $exists: true }, exploited: true } },
            { $count: 'n' },
          ],
          exploited: [{ $match: { exploited: true } }, { $count: 'n' }],
          withExploitSignal: [{ $match: { exploitation: { $ne: null } } }, { $count: 'n' }],
          byExploit: [
            { $match: { exploitation: { $ne: null } } },
            {
              $group: {
                _id: null,
                observed: { $sum: { $cond: ['$exploitation.observed', 1, 0] } },
                weaponized: { $sum: { $cond: ['$exploitation.weaponized', 1, 0] } },
                publicExploit: { $sum: { $cond: ['$exploitation.publicExploit', 1, 0] } },
                publicPoc: { $sum: { $cond: ['$exploitation.publicPoc', 1, 0] } },
                scannable: { $sum: { $cond: ['$exploitation.scannable', 1, 0] } },
              },
            },
          ],
          last24h: [
            { $match: { published: { $gte: new Date(Date.now() - 86_400_000).toISOString() } } },
            { $count: 'n' },
          ],
          score: [{ $match: { score: { $ne: null } } }, { $group: { _id: null, avg: { $avg: '$score' } } }],
        },
      },
    ])
    .toArray();

  const count = (facet) => result?.[facet]?.[0]?.n ?? 0;
  const pairs = (facet) => Object.fromEntries((result?.[facet] ?? []).map((r) => [r._id, r.n]));

  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  Object.assign(bySeverity, pairs('bySeverity'));

  const byStack = Object.fromEntries(STACK_CATEGORY_IDS.map((id) => [id, 0]));
  Object.assign(byStack, pairs('byStack'));

  const { _id, ...byExploit } = result?.byExploit?.[0] ?? {};

  return {
    total: count('total'),
    bySeverity,
    bySource: pairs('bySource'),
    byStack,
    inStack: count('inStack'),
    stackExploited: count('stackExploited'),
    byExploit: { observed: 0, weaponized: 0, publicExploit: 0, publicPoc: 0, scannable: 0, ...byExploit },
    withExploitSignal: count('withExploitSignal'),
    exploited: count('exploited'),
    last24h: count('last24h'),
    averageScore: result?.score?.[0]?.avg ? Number(result.score[0].avg.toFixed(1)) : null,
  };
}

/** One record by any identifier it is known under. */
export async function findRecordById(id) {
  const col = await collection();
  if (!col) return null;
  const upper = String(id).toUpperCase();
  const doc = await col.findOne({
    $or: [{ cveId: upper }, { ghsaId: upper }, { euvdId: upper }, { advisoryId: upper }, { _id: upper }],
  });
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return { key: _id, ...rest };
}

/**
 * A batch of records by CVE id, projected down to what a dependency sweep
 * needs.
 *
 * The sweep resolves a list of advisories at once and wants severity, score
 * and exploit signals for each; asking one at a time would be one round trip
 * per dependency, which is the shape of request this collection exists to
 * avoid.
 */
export async function findRecordsByIds(cveIds) {
  const col = await collection();
  if (!col) return null;

  const ids = [...new Set((cveIds ?? []).filter(Boolean).map((id) => String(id).toUpperCase()))];
  if (!ids.length) return new Map();

  const out = new Map();
  const CHUNK = 500;

  for (let i = 0; i < ids.length; i += CHUNK) {
    const cursor = col.find(
      { cveId: { $in: ids.slice(i, i + CHUNK) } },
      {
        projection: {
          cveId: 1, title: 1, severity: 1, score: 1, epss: 1, exploited: 1,
          published: 1, modified: 1, url: 1, cwes: 1, vector: 1, stack: 1,
        },
      },
    );
    for await (const { _id, ...rest } of cursor) out.set(rest.cveId, { key: _id, ...rest });
  }

  return out;
}

/** Identifiers only, for the sitemap: the documents themselves are not needed. */
export async function listIdsForSitemap(limit = 5000) {
  const col = await collection();
  if (!col) return [];
  return col
    .find(
      { outsideWindow: { $ne: true } },
      { projection: { _id: 0, cveId: 1, ghsaId: 1, advisoryId: 1, modified: 1, published: 1, exploited: 1 } },
    )
    .sort({ published: -1 })
    .limit(limit)
    .toArray();
}

export const storeCounts = async () => {
  const col = await collection();
  if (!col) return null;
  return { records: await col.estimatedDocumentCount() };
};

export default {
  upsertRecords,
  queryRecords,
  aggregateStats,
  findRecordById,
  findRecordsByIds,
  canRetryAsSubstring,
  listIdsForSitemap,
  storeReady,
  storeCounts,
};
