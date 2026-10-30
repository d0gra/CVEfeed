/**
 * Pre-fetch every feed into the disk cache.
 *
 * Useful as a post-deploy step or a cron entry on hosts that spin the app down
 * when idle, so the first real visitor never waits on upstream feeds.
 */
import { getFeed } from '../src/aggregate.js';

const started = Date.now();

try {
  const feed = await getFeed({ force: true });
  const ok = feed.value.sources.filter((s) => s.ok);
  const failed = feed.value.sources.filter((s) => !s.ok);

  console.log(`warmed ${feed.value.items.length} records in ${Date.now() - started}ms`);
  for (const source of ok) console.log(`  ok    ${source.id} (${source.count})`);
  for (const source of failed) console.log(`  FAIL  ${source.id}: ${source.error}`);

  process.exit(failed.length === feed.value.sources.length ? 1 : 0);
} catch (error) {
  console.error('warm failed:', error.message);
  process.exit(1);
}
