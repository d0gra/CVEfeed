/**
 * Community proof-of-concept submissions, in Atlas.
 *
 * Design decisions that matter here:
 *
 *   - Moderation first. A submission is stored with status "pending" and is
 *     NEVER shown publicly until it is approved. Publishing anonymous,
 *     attacker-adjacent code the instant it arrives would be reckless; the
 *     owner reviews first (POC_AUTO_APPROVE exists only for a trusted private
 *     instance and is off by default).
 *   - Text only. The validator guarantees plain text before anything reaches
 *     here; there are no file uploads, so there is nothing to host or scan.
 *   - De-duplication. Each PoC is fingerprinted by a hash of its normalised
 *     body, so the same submission against the same CVE cannot be stored twice.
 *   - Serialised and self-contained. One document holds the whole submission
 *     and its moderation state; nothing about it is computed from a live join.
 */
import crypto from 'node:crypto';
import config from '../config.js';
import { getDb } from '../lib/mongo.js';

const COLLECTION = 'pocs';

let indexesReady = null;

async function collection() {
  const db = await getDb();
  if (!db) return null;
  const col = db.collection(COLLECTION);

  indexesReady ??= Promise.all([
    // The public read: approved PoCs for one CVE, newest first.
    col.createIndex({ cveId: 1, status: 1, submittedAt: -1 }),
    // The moderation queue.
    col.createIndex({ status: 1, submittedAt: 1 }),
    // De-duplication: one body fingerprint per CVE.
    col.createIndex({ cveId: 1, fingerprint: 1 }, { unique: true }),
  ]).catch(() => null);

  await indexesReady;
  return col;
}

export const pocStoreReady = async () => Boolean(await collection());

/** A stable fingerprint of the PoC body, for dedup. */
const fingerprint = (code) =>
  crypto.createHash('sha256').update(code.replace(/\s+/g, ' ').trim().toLowerCase()).digest('hex').slice(0, 32);

/** An opaque per-submitter token, so abuse can be rate-limited without storing an IP. */
const ipTag = (ip) =>
  ip ? crypto.createHash('sha256').update(`${config.captchaSecret || 'cvefeed'}:${ip}`).digest('hex').slice(0, 16) : null;

/**
 * Store a validated submission.
 * Returns { ok, id, status } or { ok:false, reason }.
 */
export async function submitPoc(value, { ip } = {}) {
  const col = await collection();
  if (!col) return { ok: false, reason: 'The submission store is unavailable.' };

  const now = new Date();
  const doc = {
    _id: crypto.randomUUID(),
    cveId: value.cveId,
    title: value.title,
    code: value.code,
    writeup: value.writeup || null,
    affected: value.affected || null,
    author: value.author,
    // Contact is kept private: for the owner to reach the author, never shown.
    contact: value.contact || null,
    license: value.license,
    references: value.references,
    acknowledgements: value.acknowledgements,
    fingerprint: fingerprint(value.code),
    status: config.pocAutoApprove ? 'approved' : 'pending',
    submittedAt: now,
    moderatedAt: config.pocAutoApprove ? now : null,
    submitterTag: ipTag(ip),
  };

  try {
    await col.insertOne(doc);
    return { ok: true, id: doc._id, status: doc.status };
  } catch (error) {
    // The unique index rejects a duplicate body for the same CVE.
    if (error?.code === 11000) return { ok: false, reason: 'This proof of concept has already been submitted for this CVE.' };
    return { ok: false, reason: 'Could not store the submission.' };
  }
}

/** How many a submitter has sent in the last hour, for rate limiting. */
export async function recentSubmissionCount(ip) {
  const col = await collection();
  const tag = ipTag(ip);
  if (!col || !tag) return 0;
  return col.countDocuments({ submitterTag: tag, submittedAt: { $gte: new Date(Date.now() - 3_600_000) } });
}

/** Public: approved PoCs for a CVE. The contact and submitter tag never leave here. */
export async function approvedPocsForCve(cveId) {
  const col = await collection();
  if (!col) return [];
  return col
    .find(
      { cveId: String(cveId).toUpperCase(), status: 'approved' },
      { projection: { contact: 0, submitterTag: 0, fingerprint: 0, acknowledgements: 0 } },
    )
    .sort({ submittedAt: -1 })
    .limit(25)
    .toArray();
}

/** Counts of approved PoCs per CVE, for a set of ids - so lists can show a badge. */
export async function approvedCountsForCves(cveIds) {
  const col = await collection();
  const ids = [...new Set((cveIds ?? []).filter(Boolean).map((i) => String(i).toUpperCase()))];
  if (!col || ids.length === 0) return new Map();
  const rows = await col
    .aggregate([
      { $match: { cveId: { $in: ids }, status: 'approved' } },
      { $group: { _id: '$cveId', n: { $sum: 1 } } },
    ])
    .toArray();
  return new Map(rows.map((r) => [r._id, r.n]));
}

/* ---------- moderation ---------- */

export async function pendingQueue(limit = 50) {
  const col = await collection();
  if (!col) return [];
  return col.find({ status: 'pending' }).sort({ submittedAt: 1 }).limit(limit).toArray();
}

export async function moderatePoc(id, action) {
  const col = await collection();
  if (!col) return { ok: false };
  const status = action === 'approve' ? 'approved' : 'rejected';
  const res = await col.updateOne({ _id: id }, { $set: { status, moderatedAt: new Date() } });
  return { ok: res.matchedCount === 1, status };
}

export const pocStoreStats = async () => {
  const col = await collection();
  if (!col) return null;
  const rows = await col.aggregate([{ $group: { _id: '$status', n: { $sum: 1 } } }]).toArray();
  return Object.fromEntries(rows.map((r) => [r._id, r.n]));
};

export default {
  submitPoc,
  approvedPocsForCve,
  approvedCountsForCves,
  recentSubmissionCount,
  pendingQueue,
  moderatePoc,
  pocStoreReady,
  pocStoreStats,
};
