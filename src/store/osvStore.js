/**
 * What OSV has already told us, kept in Atlas.
 *
 * A dependency sweep is the one request here that can fan out to hundreds of
 * upstream queries, and the same coordinates come back over and over - the
 * same lockfile re-checked in CI, the same popular packages across different
 * callers' projects. Caching it in the host's memory would be the thing we
 * moved the feed out of memory to avoid, and would be cold after every deploy
 * besides, so it lives in the database with the rest of the data.
 *
 * Two collections, because the two things expire at different rates:
 *
 *   osv_queries - "what is vulnerable in <ecosystem>/<name>@<version>", which
 *     changes whenever a new advisory lands, so it is held for days;
 *   osv_vulns - one advisory's own detail, which barely changes once
 *     published, so it is held for weeks.
 *
 * Both have a TTL index, so Atlas expires them itself and the collections
 * cannot grow without bound on a free tier.
 */
import { getDb } from '../lib/mongo.js';

const QUERIES = 'osv_queries';
const VULNS = 'osv_vulns';

// How long each kind stays usable. The TTL index removes documents at roughly
// twice these, so a document can be present but too old to trust - the reads
// below check the timestamp rather than relying on expiry being prompt.
export const QUERY_TTL_MS = 6 * 3_600_000; // 6 hours
export const VULN_TTL_MS = 14 * 86_400_000; // 14 days

let indexesReady = null;

async function collections() {
  const db = await getDb();
  if (!db) return null;

  const queries = db.collection(QUERIES);
  const vulns = db.collection(VULNS);

  indexesReady ??= Promise.all([
    queries.createIndex({ at: 1 }, { expireAfterSeconds: Math.round((QUERY_TTL_MS * 2) / 1000) }),
    vulns.createIndex({ at: 1 }, { expireAfterSeconds: Math.round((VULN_TTL_MS * 2) / 1000) }),
  ]).catch(() => null);

  await indexesReady;
  return { queries, vulns };
}

export const coordinateKey = ({ ecosystem, name, version }) =>
  `${ecosystem}|${String(name).toLowerCase()}|${version}`;

/**
 * Which of these coordinates we already have an answer for.
 *
 * Returns a Map of key -> array of OSV ids, with misses simply absent. One
 * round trip for the whole sweep; a caller with nothing in the database gets
 * null and asks upstream for everything.
 */
export async function getCachedQueries(keys) {
  const col = await collections();
  if (!col) return null;

  const wanted = [...new Set(keys)];
  if (!wanted.length) return new Map();

  const fresh = new Date(Date.now() - QUERY_TTL_MS);
  const out = new Map();
  const CHUNK = 500;

  for (let i = 0; i < wanted.length; i += CHUNK) {
    const cursor = col.queries.find(
      { _id: { $in: wanted.slice(i, i + CHUNK) }, at: { $gte: fresh } },
      { projection: { ids: 1 } },
    );
    for await (const doc of cursor) out.set(doc._id, doc.ids ?? []);
  }

  return out;
}

/** Record the answers for a batch of coordinates. Best-effort. */
export async function putQueries(entries) {
  const col = await collections();
  if (!col || !entries.length) return false;

  const at = new Date();
  try {
    await col.queries.bulkWrite(
      entries.map(([key, ids]) => ({
        replaceOne: { filter: { _id: key }, replacement: { ids, at }, upsert: true },
      })),
      { ordered: false },
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * The advisory details we already hold, by OSV id.
 *
 * Only the fields the sweep reports are stored, not the raw OSV record - those
 * run to several kilobytes each, most of it references and version ranges we
 * do not use, and storing them would turn a cache into a mirror.
 */
export async function getCachedVulns(ids) {
  const col = await collections();
  if (!col) return null;

  const wanted = [...new Set(ids)];
  if (!wanted.length) return new Map();

  const fresh = new Date(Date.now() - VULN_TTL_MS);
  const out = new Map();
  const CHUNK = 500;

  for (let i = 0; i < wanted.length; i += CHUNK) {
    const cursor = col.vulns.find({ _id: { $in: wanted.slice(i, i + CHUNK) }, at: { $gte: fresh } });
    for await (const { _id, at, ...rest } of cursor) out.set(_id, { id: _id, ...rest });
  }

  return out;
}

/** Store extracted advisory details. Best-effort. */
export async function putVulns(records) {
  const col = await collections();
  if (!col || !records.length) return false;

  const at = new Date();
  try {
    await col.vulns.bulkWrite(
      records.map(({ id, ...rest }) => ({
        replaceOne: { filter: { _id: id }, replacement: { ...rest, at }, upsert: true },
      })),
      { ordered: false },
    );
    return true;
  } catch {
    return false;
  }
}

/** How much is cached, for feed_status. Counts only. */
export async function osvStoreStats() {
  const col = await collections();
  if (!col) return null;
  const [queries, vulns] = await Promise.all([
    col.queries.estimatedDocumentCount(),
    col.vulns.estimatedDocumentCount(),
  ]);
  return { cachedCoordinates: queries, cachedAdvisories: vulns };
}

export default { getCachedQueries, putQueries, getCachedVulns, putVulns, osvStoreStats, coordinateKey };
