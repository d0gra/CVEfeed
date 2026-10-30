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

export const mongoConfigured = () => Boolean(config.mongoUri);

/**
 * The shared client. Connects once; a failure is remembered so every request
 * does not sit through the same timeout.
 */
export async function getDb() {
  if (!config.mongoUri) return null;

  clientPromise ??= (async () => {
    const client = new MongoClient(config.mongoUri, {
      // The driver defaults to 100 sockets, which is a lot of memory to hold
      // open for an app that makes a handful of queries per request.
      maxPoolSize: config.mongoPoolSize,
      minPoolSize: 0,
      maxIdleTimeMS: 60_000,
      serverSelectionTimeoutMS: config.mongoTimeoutMs,
      connectTimeoutMS: config.mongoTimeoutMs,
      // Keep the wire small; the host's bandwidth is as metered as its memory.
      compressors: ['zlib'],
      zlibCompressionLevel: 6,
    });

    await client.connect();
    connected = true;
    return client;
  })().catch((error) => {
    lastError = error.message;
    connected = false;
    // Let a later call try again rather than failing for the process's life.
    clientPromise = null;
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
