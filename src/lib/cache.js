import fs from 'node:fs/promises';
import path from 'node:path';
import config from '../config.js';

/**
 * Tiny TTL cache with an optional JSON snapshot on disk.
 *
 * The snapshot is deliberately a plain file, not a database: it only exists so
 * a cold start serves data immediately and the dashboard keeps working when an
 * upstream feed is unreachable.
 */
const memory = new Map();
const inflight = new Map();
let diskReady = null;

async function ensureDiskDir() {
  if (!config.diskCache) return false;
  diskReady ??= fs
    .mkdir(config.diskCacheDir, { recursive: true })
    .then(() => true)
    .catch(() => false);
  return diskReady;
}

const fileFor = (key) => path.join(config.diskCacheDir, `${key.replace(/[^a-z0-9_-]/gi, '_')}.json`);

async function readDisk(key) {
  if (!(await ensureDiskDir())) return null;
  try {
    const raw = await fs.readFile(fileFor(key), 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.storedAt !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeDisk(key, entry) {
  if (!(await ensureDiskDir())) return;
  const target = fileFor(key);
  const tmp = `${target}.${process.pid}.tmp`;
  try {
    await fs.writeFile(tmp, JSON.stringify(entry), 'utf8');
    await fs.rename(tmp, target);
  } catch {
    await fs.rm(tmp, { force: true }).catch(() => {});
  }
}

/**
 * Refresh a key from upstream, collapsing concurrent callers onto one request.
 *
 * Bookkeeping lives here so both the blocking and the background paths behave
 * identically: memory is only overwritten on success, so a failed refresh
 * leaves the last good value in place for the caller to fall back to.
 */
function refresh(key, producer) {
  const existing = inflight.get(key);
  if (existing) return existing;

  const pending = (async () => {
    const value = await producer();
    const fresh = { value, storedAt: Date.now() };
    memory.set(key, fresh);
    await writeDisk(key, fresh);
    return { ...fresh, fromCache: false, stale: false, revalidating: false, ageMs: 0 };
  })().finally(() => {
    inflight.delete(key);
  });

  inflight.set(key, pending);
  return pending;
}

/**
 * Resolve a value through the cache.
 *
 * Three outcomes, in order of preference:
 *   fresh                      - inside the TTL, returned as is;
 *   stale-while-revalidate     - past the TTL but within the grace window, so
 *                                the old value is returned immediately and the
 *                                refresh continues in the background;
 *   blocking fetch             - too old to serve, or forced. If that fetch
 *                                fails and stale data exists it is served and
 *                                flagged, so one broken feed never empties the
 *                                dashboard.
 */
export async function cached(
  key,
  producer,
  { ttlMs = config.cacheTtlMs, force = false, staleWhileRevalidateMs = config.staleWhileRevalidateMs } = {},
) {
  const now = Date.now();
  let entry = memory.get(key);

  if (!entry) {
    const fromDisk = await readDisk(key);
    if (fromDisk) {
      entry = fromDisk;
      memory.set(key, entry);
    }
  }

  const age = entry ? now - entry.storedAt : Infinity;
  if (entry && !force && age < ttlMs) {
    return { ...entry, fromCache: true, stale: false, revalidating: false, ageMs: age };
  }

  const pending = refresh(key, producer);

  if (entry && !force && age < ttlMs + staleWhileRevalidateMs) {
    // Nobody is awaiting this one, so swallow the rejection here; the next
    // caller retries, and the stale value stays available either way.
    pending.catch(() => {});
    return { ...entry, fromCache: true, stale: true, revalidating: true, ageMs: age };
  }

  try {
    return await pending;
  } catch (error) {
    if (entry) {
      return {
        ...entry,
        fromCache: true,
        stale: true,
        revalidating: false,
        ageMs: Date.now() - entry.storedAt,
        error: error.message,
      };
    }
    throw error;
  }
}

export function peek(key) {
  const entry = memory.get(key);
  if (!entry) return null;
  return { storedAt: entry.storedAt, ageMs: Date.now() - entry.storedAt };
}

export function clearCache() {
  memory.clear();
}
