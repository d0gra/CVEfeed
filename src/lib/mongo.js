/**
 * MongoDB connection.
 *
 * The point of the database here is to keep memory off the host. The exploit
 * index is 44,000 entries that are only ever read one CVE at a time, so
 * holding it in the process costs 15MB to answer questions a lookup would
 * answer better. It lives in Atlas instead.
 *
 * Everything here degrades: without MONGODB_URI, or with Atlas unreachable,
 * the app falls back to its in-memory path and works exactly as it did
 * before, just heavier. A database outage should cost memory, not uptime.
 */
import { MongoClient } from 'mongodb';
import config from '../config.js';

let clientPromise = null;
let lastError = null;
let connected = false;
// After a failed connection we stop trying for a cooldown. This is what keeps
// an unreachable Atlas from being a slow, resource-leaking disaster: without
// it, every request and every refresh builds a fresh MongoClient, each of
// which spawns background monitoring threads over a mongodb+srv:// topology,
// and waits the full server-selection timeout. On a host that counts threads
// as processes that climbs until the app is killed.
let retryAfter = 0;
const COOLDOWN_MS = Math.max(10, Number.parseInt(process.env.MONGO_RETRY_COOLDOWN_SECONDS || '', 10) || 60) * 1000;

export const mongoConfigured = () => Boolean(config.mongoUri);

/**
 * The shared client. Connects once and is reused; a failure is remembered and
 * not retried until the cooldown passes, so an outage costs one timeout a
 * minute rather than one per request.
 */
export async function getDb() {
  if (!config.mongoUri) return null;
  // Inside the cooldown after a failure: fall back to memory immediately,
  // without constructing a client or waiting on a timeout.
  if (!clientPromise && Date.now() < retryAfter) return null;

  clientPromise ??= (async () => {
    const client = new MongoClient(config.mongoUri, {
      // The driver defaults to 100 sockets, which is a lot of memory to hold
      // open for an app that makes a handful of queries per request.
      maxPoolSize: config.mongoPoolSize,
      minPoolSize: 0,
      maxIdleTimeMS: 60_000,
      serverSelectionTimeoutMS: config.mongoTimeoutMs,
      connectTimeoutMS: config.mongoTimeoutMs,
      // Monitor less often; this app does not need sub-10s topology awareness,
      // and each heartbeat is work the host is billed for.
      heartbeatFrequencyMS: 30_000,
      // Keep the wire small; the host's bandwidth is as metered as its memory.
      compressors: ['zlib'],
      zlibCompressionLevel: 6,
    });

    try {
      await client.connect();
      connected = true;
      // Clear a prior failure so health does not report a stale error next to
      // a live connection.
      lastError = null;
      retryAfter = 0;
      return client;
    } catch (error) {
      // Close the failed client, or its monitoring threads leak for the life
      // of the process - the root of the "too many processes" problem.
      await client.close().catch(() => {});
      throw error;
    }
  })().catch((error) => {
    lastError = error.message;
    connected = false;
    clientPromise = null;
    retryAfter = Date.now() + COOLDOWN_MS;
    return null;
  });

  const client = await clientPromise;
  return client ? client.db(config.mongoDb) : null;
}

/** Health, for /healthz and the dashboard's source line. */
export const mongoStatus = () => ({
  configured: mongoConfigured(),
  connected,
  error: lastError,
});

export async function closeMongo() {
  if (!clientPromise) return;
  try {
    const client = await clientPromise;
    await client?.close();
  } catch {
    // Shutting down; nothing useful to do about a failure here.
  } finally {
    clientPromise = null;
    connected = false;
  }
}

export default { getDb, mongoConfigured, mongoStatus, closeMongo };
