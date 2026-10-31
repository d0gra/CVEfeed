import 'dotenv/config';
import path from 'node:path';

const int = (value, fallback) => {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
};

const bool = (value, fallback) => {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
};

const clamp = (n, min, max) => Math.min(max, Math.max(min, n));

export const config = {
  port: int(process.env.PORT, 3000),
  sources: (process.env.SOURCES || 'nvd,kev,github,euvd,cisa')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
  cacheTtlMs: clamp(int(process.env.CACHE_TTL_MINUTES, 20), 1, 1440) * 60_000,
  // How far past the TTL a snapshot may still be served instantly while a
  // refresh runs behind it. This is what spares the first visitor after an
  // idle period the full upstream round trip. 0 disables it and goes back to
  // blocking on every expiry.
  staleWhileRevalidateMs: clamp(int(process.env.STALE_WHILE_REVALIDATE_MINUTES, 360), 0, 10080) * 60_000,
  refreshIntervalMs: clamp(int(process.env.REFRESH_INTERVAL_MINUTES, 20), 0, 1440) * 60_000,
  nvdDays: clamp(int(process.env.NVD_DAYS, 7), 1, 120),
  nvdMaxPages: clamp(int(process.env.NVD_MAX_PAGES, 2), 1, 10),
  nvdApiKey: process.env.NVD_API_KEY || '',
  // KEV-only records older than this are dropped from the feed so the dashboard
  // shows current activity rather than the full historical catalog. 0 keeps all.
  kevDays: clamp(int(process.env.KEV_DAYS, 90), 0, 36500),
  githubToken: process.env.GITHUB_TOKEN || '',
  // Exploit-availability signals. These are large, slow-moving downloads, so
  // they get their own long TTL rather than riding the feed's.
  exploitSources: (process.env.EXPLOIT_SOURCES || 'exploitdb,metasploit,nuclei,poc,vulncheck')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
  exploitTtlMs: clamp(int(process.env.EXPLOIT_TTL_HOURS, 12), 1, 720) * 3_600_000,
  // How long the first build may wait for them before serving without. The
  // feed is more useful on time than complete.
  exploitBudgetMs: clamp(int(process.env.EXPLOIT_BUDGET_SECONDS, 25), 1, 300) * 1000,
  vulncheckToken: process.env.VULNCHECK_TOKEN || '',
  // Inbound rate limiting (per client IP, per minute). 0 disables a limiter.
  rateWindowMs: clamp(int(process.env.RATE_WINDOW_SECONDS, 60), 1, 3600) * 1000,
  apiRateMax: clamp(int(process.env.API_RATE_MAX, 120), 0, 100_000),
  mcpRateMax: clamp(int(process.env.MCP_RATE_MAX, 60), 0, 100_000),
  pageRateMax: clamp(int(process.env.PAGE_RATE_MAX, 240), 0, 100_000),
  // The shared bucket for the upstream lookup fan-out: a burst of this many,
  // then a steady trickle. Sized to stay well under GitHub's 60/hour anon
  // budget even when every lookup spends one request against it. 0 disables.
  lookupBurst: clamp(int(process.env.LOOKUP_BURST, 15), 0, 10_000),
  lookupRefillPerSec: Number.parseFloat(process.env.LOOKUP_REFILL_PER_SEC || '0.2') || 0.2,
  // Per-entity cache entries - one per CVE looked up - are capped, because
  // /cve/:id answers for any published CVE and nothing stops a crawler from
  // walking all 300,000 of them.
  cacheMaxEntries: clamp(int(process.env.CACHE_MAX_ENTRIES, 500), 20, 50_000),
  // Mongo holds what the host should not: entries read one at a time rather
  // than scanned. Unset means the app keeps everything in memory, as before.
  mongoUri: process.env.MONGODB_URI || '',
  mongoDb: process.env.MONGODB_DB || 'cvefeed',
  mongoPoolSize: clamp(int(process.env.MONGODB_POOL_SIZE, 5), 1, 50),
  mongoTimeoutMs: clamp(int(process.env.MONGODB_TIMEOUT_SECONDS, 10), 2, 60) * 1000,
  diskCache: bool(process.env.DISK_CACHE, true),
  diskCacheDir: path.resolve(process.cwd(), process.env.DISK_CACHE_DIR || '.cache'),
  // Canonical origin for links search engines and agents must agree on. Falls
  // back to the request's own host, which is right in development and wrong
  // behind a proxy that terminates TLS, so set it in production.
  siteUrl: (process.env.SITE_URL || '').replace(/\/+$/, ''),
  refreshToken: process.env.REFRESH_TOKEN || '',
  requestTimeoutMs: clamp(int(process.env.REQUEST_TIMEOUT_SECONDS, 25), 5, 120) * 1000,
  userAgent:
    process.env.USER_AGENT ||
    'CVEfeed-Dashboard/1.0 (+https://github.com/; aggregates public vulnerability feeds)',
};

export default config;
