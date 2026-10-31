/**
 * Rate limiting, without a dependency.
 *
 * Two shapes, for two different jobs:
 *
 *   - a per-IP sliding window, to keep one caller from flooding the API, the
 *     MCP endpoint or the database;
 *   - a single global token bucket for the upstream lookup fan-out, because
 *     that one is not about fairness between callers - it protects a shared
 *     resource (GitHub's 60-requests-an-hour-per-IP anonymous budget, which is
 *     the whole host's, not ours) from being drained by a burst of distinct
 *     CVE ids that the cache cannot absorb.
 *
 * This is in-process, so it resets on restart and does not coordinate across
 * workers. That is the right amount of protection for casual abuse and crawler
 * politeness; a determined attacker is a job for the edge (Cloudflare), and the
 * deployment notes say so.
 */
import config from '../config.js';

/**
 * A fixed-window per-key counter. Simple, and good enough: the worst case is a
 * caller getting up to 2x the limit across a window boundary, which does not
 * matter at these thresholds.
 */
export function createLimiter({ windowMs, max, name = 'rate' }) {
  // max <= 0 disables the limiter entirely.
  if (!max || max <= 0) return (_req, _res, next) => next();

  const hits = new Map(); // key -> { count, resetAt }

  // Sweep expired keys so the map cannot grow without bound under a spray of
  // distinct source IPs.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) if (entry.resetAt <= now) hits.delete(key);
  }, windowMs);
  sweep.unref();

  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || req.socket?.remoteAddress || 'unknown';
    let entry = hits.get(key);

    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(key, entry);
    }

    entry.count += 1;
    const remaining = Math.max(0, max - entry.count);
    res.setHeader('RateLimit-Limit', max);
    res.setHeader('RateLimit-Remaining', remaining);

    if (entry.count > max) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      // MCP speaks JSON-RPC; everything else gets a plain JSON error. Both are
      // 429 so any client backs off.
      if (req.path === '/mcp') {
        return res
          .status(429)
          .json({ jsonrpc: '2.0', id: null, error: { code: -32029, message: `Rate limited. Retry after ${retryAfter}s.` } });
      }
      return res.status(429).json({ error: `Too many requests. Retry after ${retryAfter}s.` });
    }

    next();
  };
}

/**
 * A token bucket for the upstream lookup fan-out.
 *
 * Refills continuously, so it allows a short burst (the capacity) and then a
 * steady trickle (the refill rate) - which matches what a cache miss storm
 * actually looks like, and keeps us comfortably under GitHub's hourly budget
 * even when every lookup spends one request against it.
 */
export class TokenBucket {
  constructor(capacity, refillPerSec) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.tokens = capacity;
    this.last = Date.now();
  }

  tryTake() {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) / 1000) * this.refillPerSec);
    this.last = now;
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

/** The shared bucket guarding the lookup fan-out. Disabled when capacity <= 0. */
export const lookupBucket =
  config.lookupBurst > 0 ? new TokenBucket(config.lookupBurst, config.lookupRefillPerSec) : null;

export default { createLimiter, TokenBucket, lookupBucket };
