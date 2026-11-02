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

/**
 * Keys with one entry per entity - a CVE looked up, a PoC listing fetched -
 * in least-recently-used order. A Set keeps insertion order, so deleting and
 * re-adding a key moves it to the back.
 *
 * These are capped because /cve/:id answers for any published CVE, so the
 * number of possible keys is the number of CVEs that exist. Without a cap a
 * crawler walking the sitemap grows both layers until the process dies, and
 * on shared hosting memory runs out long before disk does. The singleton
 * keys - the feed, the exploit index, the KEV catalog - are not in here:
 * they are overwritten in place and never multiply.
 */
const evictable = new Set();

/** Evictable files are marked in their name so a restart can still spot them. */
const EVICTABLE_PREFIX = 'ev_';

async function ensureDiskDir() {
  if (!config.diskCache) return false;
  diskReady ??= fs
    .mkdir(config.diskCacheDir, { recursive: true })
    .then(async () => {
      await pruneDisk();
      return true;
    })
    .catch(() => false);
  return diskReady;
}

const fileFor = (key, isEvictable = false) =>
  path.join(
    config.diskCacheDir,
    `${isEvictable ? EVICTABLE_PREFIX : ''}${key.replace(/[^a-z0-9_-]/gi, '_')}.json`,
  );

/**
 * Drop evictable snapshots left by earlier runs, oldest first.
 *
 * Memory starts empty after a restart, so the LRU below knows nothing about
 * what a previous process wrote; without this sweep those files would never
 * be reclaimed.
 */
async function pruneDisk() {
  try {
    const names = await fs.readdir(config.diskCacheDir);
    const candidates = names.filter(
      // The unprefixed names are what earlier versions wrote. They are caches
      // either way, so they are swept on the same terms.
      (name) => name.startsWith(EVICTABLE_PREFIX) || name.startsWith('lookup-') || name.startsWith('poc-'),
    );
    if (candidates.length <= config.cacheMaxEntries) return;

    const withTimes = await Promise.all(
      candidates.map(async (name) => {
        const file = path.join(config.diskCacheDir, name);
        try {
          return { file, mtime: (await fs.stat(file)).mtimeMs };
        } catch {
          return null;
        }
      }),
    );

    const sorted = withTimes.filter(Boolean).sort((a, b) => a.mtime - b.mtime);
    for (const { file } of sorted.slice(0, sorted.length - config.cacheMaxEntries)) {
      await fs.rm(file, { force: true }).catch(() => {});
    }
  } catch {
    // A cache that cannot be tidied is not a reason to fail a request.
  }
}

/** Forget the least recently used entries once the cap is exceeded. */
async function enforceLimit() {
  while (evictable.size > config.cacheMaxEntries) {
    const oldest = evictable.values().next().value;
    evictable.delete(oldest);
    memory.delete(oldest);
    if (config.diskCache) await fs.rm(fileFor(oldest, true), { force: true }).catch(() => {});
  }
}

async function readDisk(key, isEvictable = false) {
  if (!(await ensureDiskDir())) return null;
  try {
    const raw = await fs.readFile(fileFor(key, isEvictable), 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.storedAt !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeDisk(key, entry, isEvictable = false) {
  if (!(await ensureDiskDir())) return;
  const target = fileFor(key, isEvictable);
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
function refresh(key, producer, isEvictable = false) {
  const existing = inflight.get(key);
  if (existing) return existing;

  const pending = (async () => {
    const value = await producer();
    const fresh = { value, storedAt: Date.now() };
    memory.set(key, fresh);
    if (isEvictable) {
      evictable.delete(key);
      evictable.add(key);
    }
    await writeDisk(key, fresh, isEvictable);
    if (isEvictable) await enforceLimit();
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
  {
    ttlMs = config.cacheTtlMs,
    force = false,
    staleWhileRevalidateMs = config.staleWhileRevalidateMs,
    // True for keys with one entry per entity, which are capped. See the note
    // on `evictable` above for why.
    evictable: isEvictable = false,
  } = {},
) {
  const now = Date.now();
  let entry = memory.get(key);

  if (!entry) {
    const fromDisk = await readDisk(key, isEvictable);
    if (fromDisk) {
      entry = fromDisk;
      memory.set(key, entry);
      if (isEvictable) {
        evictable.add(key);
        await enforceLimit();
      }
    }
  }

  const age = entry ? now - entry.storedAt : Infinity;
  if (entry && !force && age < ttlMs) {
    // A hit is a use, so this key goes to the back of the queue.
    if (isEvictable && evictable.delete(key)) evictable.add(key);
    return { ...entry, fromCache: true, stale: false, revalidating: false, ageMs: age };
  }

  const pending = refresh(key, producer, isEvictable);

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
  return { storedAt: entry.storedAt, ageMs: Date.now() - entry.storedAt, value: entry.value };
}

export function clearCache() {
  memory.clear();
  evictable.clear();
}

/** Forget a single key, in memory and on disk. */
export function clearCacheKey(key) {
  memory.delete(key);
  evictable.delete(key);
  if (config.diskCache) {
    fs.rm(fileFor(key, true), { force: true }).catch(() => {});
    fs.rm(fileFor(key, false), { force: true }).catch(() => {});
  }
}

/** For tests and /healthz: what the cache is actually holding. */
export const cacheStats = () => ({
  entries: memory.size,
  evictable: evictable.size,
  maxEvictable: config.cacheMaxEntries,
});
