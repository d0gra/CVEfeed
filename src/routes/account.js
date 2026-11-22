/**
 * The signed-in account: who you are, what you may spend, and your keys.
 *
 * Anyone with a GitHub account can sign up, so this is the page a stranger
 * lands on - which is why it is scoped hard. Every route here acts on the
 * caller's own account and nothing else: the owner filter on a key update is
 * the authorisation, not a check bolted on after it.
 *
 * The /mcp page reads this to decide whether to show the install buttons.
 * That decision is presentation. The gateway refusing unauthenticated MCP calls
 * is the enforcement, and it does not consult this file.
 */
import { Router, json } from 'express';
import config from '../config.js';
import { createLimiter } from '../lib/ratelimit.js';
import {
  accountSnapshot,
  activeKeyCount,
  issueKey,
  keyLimitPerUser,
  supabaseConfigured,
  updateKey,
  verifyUser,
} from '../lib/supabaseAdmin.js';

const router = Router();

router.use(createLimiter({ windowMs: config.rateWindowMs, max: config.apiRateMax }));
router.use(json({ limit: '4kb' }));

async function requireUser(req, res, next) {
  if (!supabaseConfigured()) {
    return res.status(404).json({ error: 'Accounts are not configured on this host.' });
  }
  const match = /^Bearer\s+(.+)$/i.exec((req.get('authorization') ?? '').trim());
  const user = await verifyUser(match?.[1]?.trim());
  if (!user.ok) return res.status(401).json({ error: user.reason });
  req.user = user;
  return next();
}

/** Tier, the three budgets with what is left of each, and your keys. */
router.get('/api/me', requireUser, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store').json(await accountSnapshot(req.user));
  } catch (error) {
    res.status(502).json({ error: `The account could not be read: ${error.message}` });
  }
});

/**
 * Mint a key for CI or an agent with no browser.
 *
 * Capped per person, and metered against the person by the gateway rather than
 * against the key - so a key is a second way in to the same allowance, never
 * a way to multiply it.
 */
router.post('/api/keys', requireUser, async (req, res) => {
  try {
    if ((await activeKeyCount(req.user.userId)) >= keyLimitPerUser) {
      return res.status(409).json({
        error: `You already have ${keyLimitPerUser} active keys. Revoke one to create another.`,
      });
    }
    const label = String(req.body?.label ?? '').trim().slice(0, 80) || 'my key';
    const { key, row } = await issueKey({ label, owner: req.user.userId });
    console.log(`[cvefeed] ${req.user.email ?? req.user.userId} created key ${row?.key_prefix}`);
    res.status(201).set('Cache-Control', 'no-store').json({
      key,
      prefix: row?.key_prefix,
      id: row?.id,
      note: 'Copy this now. It is not stored and cannot be shown again.',
    });
  } catch (error) {
    res.status(502).json({ error: `The key could not be created: ${error.message}` });
  }
});

/** Revoke or restore one of your own keys. Limits are not yours to set. */
router.patch('/api/keys/:id', requireUser, async (req, res) => {
  if (typeof req.body?.disabled !== 'boolean') {
    return res.status(400).json({ error: 'Send { "disabled": true } to revoke, or false to restore.' });
  }
  try {
    const row = await updateKey(req.params.id, { disabled: req.body.disabled }, { owner: req.user.userId });
    res.set('Cache-Control', 'no-store').json(row);
  } catch (error) {
    // "No key with that id" is also what someone else's key id produces, by
    // design: the answer does not reveal whether the key exists.
    res.status(404).json({ error: error.message });
  }
});

export default router;
