/**
 * What the last refresh found, for the processes that did not run it.
 *
 * Web workers do not refresh. Fetching five registers and parsing ~27MB of
 * exploit catalogues peaks around 170-270MB, and V8 does not hand that back to
 * the operating system afterwards - so a worker that refreshes once stays that
 * size for the rest of its life. On a host that bills memory and caps
 * processes, that is the single most expensive thing this application can do,
 * and it used to happen inside whichever web worker happened to serve the
 * request that found the data stale.
 *
 * So refreshing belongs to a separate, short-lived process (scripts/refresh.js,
 * run from cron), which writes the records to `cves` as before and the summary
 * of what it found here. Every web worker reads this one small document rather
 * than rebuilding it, and they all agree because there is only one of it.
 *
 * One document per kind - `feed` and `exploits` - a few kilobytes each.
 */
import { getDb } from '../lib/mongo.js';

const COLLECTION = 'meta';

async function collection() {
  const db = await getDb();
  return db ? db.collection(COLLECTION) : null;
}

/** Record what a refresh found. Returns whether it landed. */
export async function putMeta(kind, value) {
  const col = await collection();
  if (!col) return false;
  try {
    await col.replaceOne({ _id: kind }, { ...value, savedAt: new Date() }, { upsert: true });
    return true;
  } catch {
    return false;
  }
}

/** What the last refresh found, or null if there has not been one. */
export async function getMeta(kind) {
  const col = await collection();
  if (!col) return null;
  const doc = await col.findOne({ _id: kind });
  if (!doc) return null;
  const { _id, savedAt, ...rest } = doc;
  return { ...rest, savedAt };
}

export default { putMeta, getMeta };
