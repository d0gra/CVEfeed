/**
 * Refresh the store, out of process.
 *
 * Fetching and merging is the expensive part of this application: parsing an
 * 11MB Metasploit catalogue and a 10MB CSV peaks far above anything serving a
 * request costs. Doing it inside the web process means the web process is
 * sized for its worst minute rather than its normal one.
 *
 * Run from cron instead, and set REFRESH_INTERVAL_MINUTES=0 on the web app so
 * it only ever reads. The peak then belongs to a process that exits.
 *
 *   node scripts/refresh.js            refresh the feed
 *   node scripts/refresh.js --exploits refresh the exploit signals too
 */
import { getFeed } from '../src/aggregate.js';
import { getExploitIndex } from '../src/exploits.js';
import { closeMongo, mongoConfigured } from '../src/lib/mongo.js';

const started = Date.now();
const peakMb = () => (process.memoryUsage().rss / 1024 / 1024).toFixed(0);

try {
  if (process.argv.includes('--exploits')) {
    const index = await getExploitIndex({ force: true });
    for (const source of index.value.health ?? []) {
      console.log(`  ${source.ok ? 'ok  ' : 'FAIL'}  ${source.id} (${source.count})${source.error ? `: ${source.error}` : ''}`);
    }
    console.log(`exploit signals refreshed in ${Date.now() - started}ms, peak ${peakMb()}MB`);
  }

  const feed = await getFeed({ force: true });
  const failed = feed.value.sources.filter((s) => !s.ok);
  const count = feed.value.stored ? feed.value.written : feed.value.items.length;

  for (const source of feed.value.sources) {
    console.log(`  ${source.ok ? 'ok  ' : 'FAIL'}  ${source.id} (${source.count})${source.error ? `: ${source.error}` : ''}`);
  }
  console.log(
    `${feed.value.stored ? 'wrote' : 'cached'} ${count} records in ${Date.now() - started}ms, peak ${peakMb()}MB` +
      (mongoConfigured() ? '' : ' (no MONGODB_URI, cached locally)'),
  );

  await closeMongo();
  process.exit(failed.length === feed.value.sources.length ? 1 : 0);
} catch (error) {
  console.error('refresh failed:', error.message);
  await closeMongo().catch(() => {});
  process.exit(1);
}
