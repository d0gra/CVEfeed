/**
 * Refresh the store, out of process.
 *
 * Fetching and merging is the expensive part of this application: parsing an
 * 11MB Metasploit catalogue and a 10MB CSV peaks far above anything serving a
 * request costs. Doing it inside the web process means the web process is
 * sized for its worst minute rather than its normal one.
 *
 * Run from cron. With a database configured, web workers no longer refresh
 * at all - they read the summary this leaves in the `meta` collection - so
 * this script is what keeps the data current. The peak then belongs to a
 * process that exits, and the memory goes back to the operating system with
 * it rather than staying resident in a worker for the rest of its life.
 *
 *   node scripts/refresh.js                refresh the feed
 *   node scripts/refresh.js --exploits     refresh the exploit signals too
 *   node scripts/refresh.js --require-db   exit early, cheaply, without a database
 */
import { refreshFeed } from '../src/aggregate.js';
import { refreshExploitIndex } from '../src/exploits.js';
import { closeMongo, mongoConfigured } from '../src/lib/mongo.js';
import { anonymousNotes } from '../src/lib/credentials.js';

const started = Date.now();
const peakMb = () => (process.memoryUsage().rss / 1024 / 1024).toFixed(0);

// Refuse to run without a database when asked to. From cron, a refresh with no
// MONGODB_URI is not a smaller refresh but a wasted one: it fetches every
// register and peaks at hundreds of megabytes, then writes nowhere the web
// workers read. That is exactly what happens if the env file cron points at
// goes missing, since dotenv skips a missing file without complaint. This
// turns that into a one-line message and an exit.
if (process.argv.includes('--require-db') && !mongoConfigured()) {
  console.log('refresh skipped: --require-db, but no MONGODB_URI - check the env file cron points at');
  process.exit(2);
}

try {
  if (process.argv.includes('--exploits')) {
    const index = await refreshExploitIndex();
    for (const source of index.value.health ?? []) {
      console.log(`  ${source.ok ? 'ok  ' : 'FAIL'}  ${source.id} (${source.count})${source.error ? `: ${source.error}` : ''}`);
    }
    console.log(`exploit signals refreshed in ${Date.now() - started}ms, peak ${peakMb()}MB`);
  }

  const feed = await refreshFeed();
  const failed = feed.value.sources.filter((s) => !s.ok);
  const count = feed.value.stored ? feed.value.written : feed.value.items.length;

  for (const source of feed.value.sources) {
    const anon = source.authenticated === false ? ' [anonymous]' : '';
    console.log(`  ${source.ok ? 'ok  ' : 'FAIL'}  ${source.id} (${source.count})${anon}${source.error ? `: ${source.error}` : ''}`);
  }

  // A source fetched anonymously is the quiet failure this script exists to
  // make loud. See src/lib/credentials.js for why a token can be set and
  // still absent from the process that does the fetching.
  const notes = anonymousNotes(feed.value.sources);
  if (notes.length) {
    console.warn('');
    for (const line of notes) console.warn(line);
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
