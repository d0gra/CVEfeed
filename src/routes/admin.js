/**
 * The admin dashboard's API.
 *
 * Two halves, because the system now has two halves. The gateway's own
 * records - keys, quotas, audit trail - come from Supabase. The host's health
 * comes from this process, and most of it was already being measured and
 * exposed nowhere: cacheStats(), cooldownRemaining() and pocStoreStats() were
 * each written and then wired to nothing.
 *
 * Every route here demands a Supabase access token belonging to an account
 * with role=admin in app_metadata. The page itself is not gated - it holds no
 * data, exactly like /moderate - and a token buys nothing until these routes
 * check it.
 */
import { Router, json } from 'express';
import config from '../config.js';
import { adminMcpPage } from '../pages/adminMcp.js';
import { originFor } from '../pages/layout.js';
import { assetVersionValue } from './pages.js';
import { createLimiter } from '../lib/ratelimit.js';
import { cacheStats } from '../lib/cache.js';
import { cooldownRemaining } from '../lib/breaker.js';
import { mongoStatus } from '../lib/mongo.js';
import { feedCacheStatus, summarizeSourceHealth } from '../aggregate.js';
import { dataAgeMs } from '../query.js';
import { storeIndexWarnings } from '../store/cveStore.js';
import { pocStoreStats } from '../store/pocStore.js';
import {
  gatewaySnapshot,
  issueKey,
  listUsers,
  setUserTier,
  supabaseConfigured,
  updateKey,
  verifyAdmin,
} from '../lib/supabaseAdmin.js';

const router = Router();

router.use(createLimiter({ windowMs: config.rateWindowMs, max: config.apiRateMax }));
router.use(json({ limit: '16kb' }));

/**
 * The dashboard itself. Not gated: it ships no data, and every number on it
 * arrives from the routes below, which are. The same arrangement /moderate
 * uses - an unlisted page is not a secret, and the API is what enforces.
 */
router.get('/mcp', (req, res) => {
  const origin = originFor(req);
  res
    .status(200)
    .type('html')
    .set('Cache-Control', 'no-store')
    .set('X-Robots-Tag', 'noindex')
    .send(
      adminMcpPage({
        canonical: `${origin}/admin/mcp`,
        assetVersion: assetVersionValue(),
        supabaseUrl: config.supabaseUrl,
        publishableKey: config.supabasePublishableKey,
      }),
    );
});

/**
 * The gate. Verified against Supabase on every request rather than trusted
 * from a signature, so a revoked session stops working immediately.
 */
async function requireAdmin(req, res, next) {
  if (!supabaseConfigured()) {
    return res.status(404).json({
      error: 'The dashboard is not configured. Set SUPABASE_URL and SUPABASE_SECRET_KEY.',
    });
  }

  const match = /^Bearer\s+(.+)$/i.exec((req.get('authorization') ?? '').trim());
  const verdict = await verifyAdmin(match?.[1]?.trim());
  if (!verdict.ok) {
    // Logged because a failed admin attempt is worth knowing about, and the
    // audit trail for this host lives in its log rather than in Postgres.
    console.warn(`[cvefeed] admin denied from ${req.ip}: ${verdict.reason}`);
    return res.status(401).json({ error: verdict.reason });
  }
  req.adminEmail = verdict.email;
  return next();
}

/** What the gateway has been doing: from Supabase. */
router.get('/api/gateway', requireAdmin, async (_req, res, next) => {
  try {
    res.set('Cache-Control', 'no-store').json(await gatewaySnapshot());
  } catch (error) {
    next(error);
  }
});

/**
 * What this host is doing: from memory, costing nothing. Deliberately never
 * calls getFeed() - a dashboard must not be able to start a refresh.
 */
router.get('/api/host', requireAdmin, async (_req, res) => {
  const cache = feedCacheStatus();
  const ageMs = cache ? dataAgeMs(cache) : null;
  const store = mongoStatus();

  let pocs = null;
  try {
    pocs = await pocStoreStats();
  } catch {
    /* a nicety, not a requirement */
  }

  res.set('Cache-Control', 'no-store').json({
    uptimeSeconds: Math.round(process.uptime()),
    memoryMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
    feed: {
      generatedAt: cache?.value?.generatedAt ?? null,
      ageSeconds: ageMs == null ? null : Math.round(ageMs / 1000),
      neverRefreshed: Boolean(cache?.value?.neverRefreshed),
      staleAfterSeconds: Math.round(config.staleAfterMs / 1000),
    },
    sourceHealth: summarizeSourceHealth(cache),
    // Which registers are in a breaker cooldown, and for how long. Measured
    // since the breaker was written; never reported until now.
    breakers: config.sources
      .map((id) => ({ id, cooldownSeconds: cooldownRemaining(id) }))
      .filter((entry) => entry.cooldownSeconds > 0),
    cache: cacheStats(),
    store,
    indexWarnings: storeIndexWarnings(),
    pocs,
  });
});

/** Who has signed up, and on what terms. */
router.get('/api/users', requireAdmin, async (_req, res, next) => {
  try {
    res.set('Cache-Control', 'no-store').json({ users: await listUsers() });
  } catch (error) {
    next(error);
  }
});

/** Move one account between tiers. */
router.patch('/api/users/:id', requireAdmin, async (req, res) => {
  try {
    const row = await setUserTier(req.params.id, {
      tier: typeof req.body?.tier === 'string' ? req.body.tier : undefined,
      ratePerHour: req.body?.ratePerHour,
      depsPerHour: req.body?.depsPerHour,
      note: typeof req.body?.note === 'string' ? req.body.note : undefined,
    });
    console.log(`[cvefeed] admin ${req.adminEmail ?? 'unknown'} set ${row?.email ?? row?.user_id} to ${row?.tier}`);
    res.set('Cache-Control', 'no-store').json(row);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/** Mint a key. The plaintext is in this response and nowhere else, ever. */
router.post('/api/keys', requireAdmin, async (req, res, next) => {
  try {
    const { key, row } = await issueKey({
      label: req.body?.label,
      ratePerHour: req.body?.ratePerHour,
    });
    console.log(`[cvefeed] admin ${req.adminEmail ?? 'unknown'} issued key ${row?.key_prefix}`);
    res.status(201).set('Cache-Control', 'no-store').json({
      key,
      prefix: row?.key_prefix,
      id: row?.id,
      note: 'Copy this now. It is not stored and cannot be shown again.',
    });
  } catch (error) {
    next(error);
  }
});

/** Revoke, restore, or re-limit one key. */
router.patch('/api/keys/:id', requireAdmin, async (req, res, next) => {
  try {
    const row = await updateKey(req.params.id, {
      disabled: typeof req.body?.disabled === 'boolean' ? req.body.disabled : undefined,
      ratePerHour: req.body?.ratePerHour,
    });
    console.log(`[cvefeed] admin ${req.adminEmail ?? 'unknown'} updated key ${row?.key_prefix}`);
    res.set('Cache-Control', 'no-store').json(row);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

export default router;
