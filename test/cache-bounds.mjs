/**
 * The cache must not grow without limit.
 *
 * /cve/:id answers for any published CVE, so the number of possible cache
 * keys is the number of CVEs that exist - around 300,000 - and the sitemap
 * invites crawlers to walk them. Before this bound, 5,000 requests meant
 * 5,000 files and a heap that climbed until the process died.
 *
 *   node test/cache-bounds.mjs
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvefeed-cache-'));
process.env.DISK_CACHE_DIR = dir;
process.env.CACHE_MAX_ENTRIES = '100';
// These cover the in-memory path. Without this the suite would read .env,
// find a live cluster, and write test data into it.
process.env.MONGODB_URI = '';

const { cached, cacheStats, clearCache } = await import('../src/lib/cache.js');

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

const record = (id) => ({ id, description: 'x'.repeat(2000) });
const files = () => fs.readdirSync(dir);

// 1. per-entity entries stay capped however many are requested
for (let i = 1; i <= 2000; i++) {
  await cached(`lookup-CVE-2024-${i}`, async () => record(i), { ttlMs: 60_000, evictable: true });
}
check('2,000 requests leave the cap intact', cacheStats().evictable === 100, `holding ${cacheStats().evictable}`);
check('  ...and the disk matches', files().filter((f) => f.startsWith('ev_')).length === 100, `${files().length} files`);

// 2. eviction is least-recently-used, not arbitrary
clearCache();
for (const f of files()) fs.rmSync(path.join(dir, f));
for (let i = 1; i <= 100; i++) await cached(`k-${i}`, async () => record(i), { ttlMs: 60_000, evictable: true });
await cached('k-1', async () => record(1), { ttlMs: 60_000, evictable: true }); // touch the oldest
for (let i = 101; i <= 150; i++) await cached(`k-${i}`, async () => record(i), { ttlMs: 60_000, evictable: true });
check('a recently used key survives eviction', fs.existsSync(path.join(dir, 'ev_k-1.json')));
check('  ...while an untouched older one does not', !fs.existsSync(path.join(dir, 'ev_k-2.json')));

// 3. singletons are never evicted, however much pressure there is
await cached('feed-merged', async () => ({ items: [1, 2, 3] }), { ttlMs: 60_000 });
for (let i = 200; i <= 500; i++) await cached(`k-${i}`, async () => record(i), { ttlMs: 60_000, evictable: true });
check('the feed snapshot is not evictable', fs.existsSync(path.join(dir, 'feed-merged.json')));

// 4. a previous run's files are swept at startup, not left to accumulate
for (let i = 0; i < 400; i++) fs.writeFileSync(path.join(dir, `ev_stale-${i}.json`), '{"value":1,"storedAt":1}');
const before = files().length;
const { cached: freshCached } = await import('../src/lib/cache.js?boot=2');
await freshCached('warm', async () => 1, { ttlMs: 60_000 });
check('a restart sweeps what an earlier run left', files().length < before, `${before} -> ${files().length} files`);
check('  ...down to the cap, not to nothing', files().filter((f) => f.startsWith('ev_')).length <= 100);

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
