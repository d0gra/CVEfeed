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
 * Resolve a value through the cache.
 *
 * On a miss the producer runs. If the producer throws but stale data exists,
 * the stale data is served and flagged, so one broken feed never empties the
 * dashboard.
 */
export async function cached(key, producer, { ttlMs = config.cacheTtlMs, force = false } = {}) {
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
    return { ...entry, fromCache: true, stale: false, ageMs: age };
  }

  // Collapse concurrent misses onto a single upstream request.
  if (entry?.pending) {
    try {
      return await entry.pending;
    } catch {
      /* fall through to the refetch below */
    }
  }

  const pending = (async () => {
    const value = await producer();
    const fresh = { value, storedAt: Date.now() };
    memory.set(key, fresh);
    await writeDisk(key, fresh);
    return { ...fresh, fromCache: false, stale: false, ageMs: 0 };
  })();

  if (entry) memory.set(key, { ...entry, pending });

  try {
    return await pending;
  } catch (error) {
    if (entry) {
      memory.set(key, { value: entry.value, storedAt: entry.storedAt });
      return {
        ...entry,
        pending: undefined,
        fromCache: true,
        stale: true,
        ageMs: age,
        error: error.message,
      };
    }
    memory.delete(key);
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
