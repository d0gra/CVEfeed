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
import { normalizeTerm } from '../lib/terms.js';

const COLLECTION = 'cves';

let indexesReady = null;

/**
 * Index problems, kept rather than swallowed.
 *
 * Every createIndex used to sit inside one `Promise.all([...]).catch(() => null)`,
 * which meant a single failure aborted the rest and reported nothing at all -
 * the app booted green on whatever indexes happened to already exist. Each one
 * now fails on its own and says so, and /healthz surfaces the list.
 */
const indexWarnings = [];
export const storeIndexWarnings = () => [...indexWarnings];

const ensureIndex = (col, keys, options = {}) =>
  col.createIndex(keys, options).catch((error) => {
    const name = options.name ?? Object.keys(keys).join('_');
    indexWarnings.push({ index: name, error: error.message });
    console.warn(`[cvefeed] index ${name} was not created: ${error.message}`);
    return null;
  });

/**
 * The text index, checked but never rewritten.
 *
 * MongoDB allows one text index per collection, so changing this one's keys or
 * weights means dropping it first - and between the drop and the create every
 * $text query errors, which is the dashboard's main search path. Worse, the
 * conflict error is exactly the kind that used to be swallowed, so a changed
 * spec would silently keep the old behaviour.
 *
 * So this only looks, and says what it sees. To actually change the spec, do
 * it deliberately against the cluster during a quiet moment:
 *
 *   db.cves.dropIndex('search')
 *   db.cves.createIndex({ ... }, { name: 'search', weights: { ... } })
 */
async function verifyTextIndex(col) {
  try {
    const live = (await col.indexes()).find((i) => i.name === TEXT_INDEX.name);
    if (!live) return;
    const liveWeights = live.weights ?? {};
    const same =
      Object.keys(TEXT_INDEX.weights).length === Object.keys(liveWeights).length &&
      Object.entries(TEXT_INDEX.weights).every(([field, weight]) => liveWeights[field] === weight);
    if (same) return;
    const message =
      `the "${TEXT_INDEX.name}" index on the cluster does not match the spec in cveStore.js ` +
      `(live: ${Object.keys(liveWeights).join(', ')}); it was NOT changed - recreate it by hand`;
    indexWarnings.push({ index: TEXT_INDEX.name, error: message });
    console.warn(`[cvefeed] ${message}`);
  } catch {
    /* a cluster that cannot list indexes has bigger problems than this check */
  }
}

const TEXT_INDEX = {
  name: 'search',
  keys: { title: 'text', description: 'text', vendor: 'text', product: 'text' },
  weights: { title: 10, vendor: 4, product: 4, description: 1 },
};

async function collection() {
  const db = await getDb();
  if (!db) return null;
  const col = db.collection(COLLECTION);

  indexesReady ??= Promise.all([
    // Sorts and the recency filter.
    ensureIndex(col, { published: -1 }),
    ensureIndex(col, { modified: -1 }),
    // The default view: exploited first, then score, then recency.
    ensureIndex(col, { exploited: -1, score: -1, published: -1 }),
    ensureIndex(col, { score: -1 }),
    ensureIndex(col, { epss: -1 }),
    // Facets.
    ensureIndex(col, { severity: 1 }),
    ensureIndex(col, { sourceIds: 1 }),
    ensureIndex(col, { kind: 1 }),
    ensureIndex(col, { 'stack.categories': 1 }),
    ensureIndex(col, { 'exploitation.maturityRank': 1 }),
    // Lookups by any identifier a visitor might paste.
    ensureIndex(col, { cveId: 1 }),
    ensureIndex(col, { ghsaId: 1 }, { sparse: true }),
    ensureIndex(col, { euvdId: 1 }, { sparse: true }),
    ensureIndex(col, { advisoryId: 1 }, { sparse: true }),
    // Free-text search. A text index matches words rather than substrings,
    // which is a real behaviour change from the old scan - but a substring
    // scan over a growing collection is not something to carry forward.
    // The names a record can be found by. Sparse because the field only
    // appears as records are re-ingested, so the index stays proportional to
    // how much of the corpus has actually been enriched.
    ensureIndex(col, { searchTerms: 1 }, { name: 'terms', sparse: true }),
    ensureIndex(col, { vendors: 1 }, { sparse: true }),
    ensureIndex(col, { 'packages.ecosystem': 1 }, { sparse: true }),
    ensureIndex(col, TEXT_INDEX.keys, { name: TEXT_INDEX.name, weights: TEXT_INDEX.weights }),
  ]).then(() => verifyTextIndex(col));

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
/** Anything that is already an exact identifier skips the matching stages. */
const IDENTIFIER = /^(CVE|GHSA|EUVD)-/i;

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
    { searchTerms: pattern },
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
  return term.length >= 3 && !IDENTIFIER.test(term);
};

/**
 * Which matching stage to try first.
 *
 * Shared, and exported, because two callers have to agree on it: queryRecords
 * runs the stages, and queryFromStore decides whether its optimistic facet
 * counts need recomputing. If they disagreed, the visitor would get counts
 * describing a different result set than the rows on screen.
 */
export function firstMode(query = {}) {
  const term = String(query.q ?? '').trim();
  if (!term || IDENTIFIER.test(term)) return 'words';
  // An explicit match=words is the escape hatch from exact-wins; see the note
  // in queryRecords.
  if (String(query.match ?? '') === 'words') return 'words';
  return normalizeTerm(term) ? 'exact' : 'words';
}

/** The stages to try, in order, stopping at the first that matches anything. */
export function stagesFor(query = {}) {
  const first = firstMode(query);
  const stages = first === 'exact' ? ['exact', 'words'] : ['words'];
  if (canRetryAsSubstring(query)) stages.push('substring');
  return stages;
}

export function buildFilter(query = {}, { substring = false, mode } = {}) {
  // `substring: true` predates `mode` and is still passed by callers and
  // tests; it means the same thing.
  const stage = mode ?? (substring ? 'substring' : 'words');
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
    if (IDENTIFIER.test(term)) {
      const upper = term.toUpperCase();
      and.push({
        $or: [{ cveId: upper }, { ghsaId: upper }, { euvdId: upper }, { advisoryId: upper }, { _id: upper }],
      });
    } else if (stage === 'exact') {
      // One indexed equality against the names the record is known by. This
      // is the only stage that can answer "is there anything against THIS
      // software" without scanning.
      and.push({ searchTerms: normalizeTerm(term) });
    } else if (stage === 'substring') {
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
  if (!IDENTIFIER.test(term)) and.push({ outsideWindow: { $ne: true } });

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

  /**
   * Three stages, cheapest and most precise first, stopping at the first that
   * matches anything.
   *
   *   exact     - the term IS a package, vendor or product name. One indexed
   *               equality. This is the stage that makes "litellm" work.
   *   words     - the $text index, over advisory prose.
   *   substring - a scan, for a term inside a word ("log4j" in "Log4Shell").
   *
   * Exact-wins is the point, but it has a cost worth being explicit about: a
   * term with any exact match hides the text matches, so "chrome" stops
   * returning "Chromium sandbox escape". And because records only gain
   * searchTerms as they are re-ingested, a newly enriched record can hide
   * older ones that simply have not been touched yet. That is why `match`
   * exists as an escape hatch and why the dashboard surfaces it whenever this
   * returns 'exact' - without it the hiding would be invisible.
   */
  const stages = stagesFor(query);
  let matchedBy = stages[0];
  let rows = [];
  let total = 0;

  for (const stage of stages) {
    const result = await run(buildFilter(query, { mode: stage }));
    if (result.total > 0 || stage === stages[stages.length - 1]) {
      ({ rows, total } = result);
      matchedBy = stage;
      if (result.total > 0) break;
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
export async function aggregateStats(query = {}, { substring = false, mode } = {}) {
  const col = await collection();
  if (!col) return null;

  // The counts have to be computed over whichever filter actually produced the
  // list, or the facets would describe a different result set than the rows.
  const filter = buildFilter(query, { substring, mode });
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

/**
 * Every name in the corpus, with how often it appears.
 *
 * One aggregation for the whole vocabulary, run rarely and cached, rather
 * than a `^prefix` query per keystroke. The difference matters on a shared
 * free cluster: a handful of visitors typing would otherwise be hundreds of
 * index scans a minute, where this is a few scans a day and a prefix filter
 * in the host's memory. The vocabulary is small enough for that to be the
 * obviously right trade - a few hundred names for a corpus of thousands.
 */
export async function aggregateSuggestionVocabulary({ limit = 2000 } = {}) {
  const col = await collection();
  if (!col) return null;

  const [result] = await col
    .aggregate([
      { $match: { outsideWindow: { $ne: true } } },
      {
        $facet: {
          packages: [
            { $unwind: '$packages' },
            { $group: { _id: { name: '$packages.name', ecosystem: '$packages.ecosystem' }, n: { $sum: 1 } } },
            { $sort: { n: -1 } },
            { $limit: limit },
          ],
          vendors: [
            { $unwind: '$vendors' },
            { $group: { _id: '$vendors', n: { $sum: 1 } } },
            { $sort: { n: -1 } },
            { $limit: limit },
          ],
          products: [
            { $unwind: '$products' },
            { $group: { _id: '$products', n: { $sum: 1 } } },
            { $sort: { n: -1 } },
            { $limit: limit },
          ],
        },
      },
    ])
    .toArray();

  return {
    packages: (result?.packages ?? []).map((r) => ({ value: r._id.name, ecosystem: r._id.ecosystem, count: r.n })),
    vendors: (result?.vendors ?? []).map((r) => ({ value: r._id, count: r.n })),
    products: (result?.products ?? []).map((r) => ({ value: r._id, count: r.n })),
  };
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
  // How much of the corpus has been enriched with names. Coverage grows as
  // records are re-ingested, so this is the number to watch rather than
  // assume - see the backfill note in the README.
  const [records, withSearchTerms] = await Promise.all([
    col.estimatedDocumentCount(),
    col.countDocuments({ searchTerms: { $exists: true, $ne: [] } }),
  ]);
  return { records, withSearchTerms };
};

export default {
  upsertRecords,
  queryRecords,
  aggregateStats,
  findRecordById,
  findRecordsByIds,
  canRetryAsSubstring,
  aggregateSuggestionVocabulary,
  listIdsForSitemap,
  storeReady,
  storeCounts,
};
