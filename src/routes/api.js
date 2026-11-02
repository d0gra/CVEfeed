import { Router, json } from 'express';
import config from '../config.js';
import { getFeed, refreshFeed } from '../aggregate.js';
import { feedMeta, findRecord, queryFeed, summarize } from '../query.js';
import { enabledSources } from '../sources/index.js';
import { stackFacets } from '../stack.js';
import { EXPLOIT_SOURCE_META, getExploitIndex } from '../exploits.js';
import { validatePocSubmission } from '../lib/validatePoc.js';
import { verifyCaptcha } from '../lib/captcha.js';
import {
  approvedPocsForCve,
  moderatePoc,
  pendingQueue,
  recentSubmissionCount,
  submitPoc,
} from '../store/pocStore.js';
import { isCveId } from '../lookup.js';
import { sweepDependencies } from '../deps.js';
import { suggestFor } from '../lib/suggest.js';
import { MANIFEST_TYPE_IDS, describeManifest, parseManifest } from '../lib/manifests.js';
import { createLimiter } from '../lib/ratelimit.js';

const router = Router();

/** Shape an approved PoC for public display: never leak private fields. */
const publicPoc = (p) => ({
  id: p._id,
  title: p.title,
  code: p.code,
  writeup: p.writeup,
  affected: p.affected,
  author: p.author,
  license: p.license,
  references: p.references,
  submittedAt: p.submittedAt,
});

/**
 * The largest page an outside caller may ask for.
 *
 * The store allows 500, which the server-rendered pages rely on. From outside
 * it was a resource hazard: one request for 500 whole records is ~700KB pulled
 * off a throttled free-tier cluster, and measured at 3.5 seconds of a worker
 * held for it. The rate limit allows 120 a minute per address, so a single
 * script paging through at the maximum could keep several workers busy on its
 * own. 100 still pages the whole corpus in a handful of calls.
 */
const API_MAX_LIMIT = 100;

router.get('/feed', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit ?? '', 10) || 50, 1), API_MAX_LIMIT);
    // `fields` is how internal pages ask for a trimmed record; from outside it
    // is ignored, so the API's shape is not something a query string can change.
    const { fields, ...query } = req.query;
    res.json(await queryFeed({ ...query, limit }));
  } catch (error) {
    next(error);
  }
});

/**
 * Typeahead for the search box.
 *
 * Never errors: an empty list is a correct answer for "nothing matches", and
 * a search box that shows an error while you type is worse than one that
 * shows nothing. Cacheable for a minute - the vocabulary behind it only
 * rebuilds every few hours anyway.
 */
router.get('/suggest', async (req, res) => {
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit ?? '', 10) || 8, 1), 20);
  try {
    const suggestions = await suggestFor(req.query.q, { limit });
    res.set('Cache-Control', 'public, max-age=60').json({ q: String(req.query.q ?? ''), suggestions });
  } catch {
    res.json({ q: String(req.query.q ?? ''), suggestions: [] });
  }
});

router.get('/stats', async (_req, res, next) => {
  try {
    // Routed through queryFeed so it shares the one memory-fallback path: a
    // dead store degrades here exactly as it does for /api/feed.
    const feed = await queryFeed({ limit: 1 });
    res.json({ meta: feed.meta, stats: feed.stats, sources: feed.sources });
  } catch (error) {
    next(error);
  }
});

/** The AI-stack facet definitions, so the dashboard renders from one source. */
router.get('/stack', (_req, res) => {
  res.json({ categories: stackFacets() });
});

/** What each exploit signal means, and whether its source is answering. */
router.get('/exploit-sources', async (_req, res, next) => {
  try {
    const index = await getExploitIndex();
    res.json({
      signals: Object.values(EXPLOIT_SOURCE_META),
      health: index.value.health ?? [],
      builtAt: index.value.builtAt,
      ageSeconds: Math.round((index.ageMs ?? 0) / 1000),
    });
  } catch (error) {
    next(error);
  }
});

router.get('/sources', (_req, res) => {
  res.json({
    sources: enabledSources().map((s) => s.meta),
    configured: config.sources,
  });
});

router.get('/cve/:id', async (req, res, next) => {
  try {
    const found = await findRecord(req.params.id);
    if (!found.item) return res.status(404).json({ error: found.reason });
    res.json({ meta: found.meta, item: found.item, pocRepos: found.pocRepos ?? [] });
  } catch (error) {
    next(error);
  }
});

/** Public: approved community PoCs for a CVE. */
router.get('/cve/:id/pocs', async (req, res, next) => {
  try {
    if (!isCveId(req.params.id)) return res.status(400).json({ error: 'A CVE ID is required.' });
    const pocs = await approvedPocsForCve(req.params.id);
    res.json({ cveId: req.params.id.toUpperCase(), count: pocs.length, pocs: pocs.map(publicPoc) });
  } catch (error) {
    next(error);
  }
});

/**
 * Submit a community PoC. Anonymous, text only, CAPTCHA-gated, rate-limited,
 * and held for review - it is never shown publicly until a moderator approves.
 */
router.post('/cve/:id/pocs', async (req, res, next) => {
  try {
    const body = { ...req.body, cveId: req.body?.cveId || req.params.id };

    // The CAPTCHA is checked first, so a bot cannot even reach validation.
    if (!(await verifyCaptcha(body, req.ip))) {
      return res.status(400).json({ error: 'CAPTCHA check failed. Please try again.' });
    }

    const result = validatePocSubmission(body, config.pocMaxChars);
    if (!result.ok) return res.status(422).json({ error: 'Validation failed.', details: result.errors });

    // Per-submitter hourly cap, on top of the per-IP request limiter.
    if (config.pocSubmitMax > 0 && (await recentSubmissionCount(req.ip)) >= config.pocSubmitMax) {
      return res.status(429).json({ error: `You have reached the hourly submission limit (${config.pocSubmitMax}).` });
    }

    const stored = await submitPoc(result.value, { ip: req.ip });
    if (!stored.ok) return res.status(409).json({ error: stored.reason });

    res.status(201).json({
      submitted: true,
      status: stored.status,
      message:
        stored.status === 'approved'
          ? 'Submitted and published. Thank you.'
          : 'Submitted for review. It will appear once a moderator approves it. Thank you.',
    });
  } catch (error) {
    next(error);
  }
});

/* --- moderation: token-protected --- */

function requireModerator(req, res) {
  if (!config.pocModerationToken) {
    res.status(404).json({ error: 'Moderation endpoint disabled. Set POC_MODERATION_TOKEN to enable.' });
    return false;
  }
  const supplied = req.get('x-moderation-token') ?? req.query.token;
  if (supplied !== config.pocModerationToken) {
    res.status(401).json({ error: 'Invalid moderation token.' });
    return false;
  }
  return true;
}

/**
 * A dependency sweep over HTTP, for callers that are not speaking MCP - CI, a
 * script, curl.
 *
 * Two things are different about this route. It takes a body far larger than
 * anything else here, because a real package-lock.json is hundreds of
 * kilobytes, so it gets its own JSON parser rather than raising the global
 * cap. And it is the only request that can fan out to hundreds of upstream
 * lookups, so it gets its own, much smaller, rate budget.
 */
const depsLimiter = createLimiter({ windowMs: 3_600_000, max: config.depsRateMax });
const depsBody = json({ limit: config.depsMaxManifestBytes });

router.post('/dependencies/check', depsLimiter, depsBody, async (req, res, next) => {
  try {
    const body = req.body ?? {};
    let packages = Array.isArray(body.packages) ? body.packages : [];
    let manifest;

    const text = typeof body.manifest === 'string' ? body.manifest : '';
    if (text.trim()) {
      const parsed = parseManifest(text, { type: body.manifestType, max: config.depsMaxPackages });
      if (parsed.error && !packages.length) {
        return res.status(400).json({ error: parsed.error, manifestTypes: MANIFEST_TYPE_IDS });
      }
      packages = [...packages, ...parsed.packages];
      manifest = describeManifest(parsed, { max: config.depsMaxPackages });
    }

    if (!packages.length) {
      return res.status(400).json({
        error: 'Pass packages as [{ name, ecosystem, version }], or manifest as the text of a lockfile.',
        manifestTypes: MANIFEST_TYPE_IDS,
      });
    }

    const sweep = await sweepDependencies({
      packages,
      onlyExploitable: body.onlyExploitable === true || req.query.onlyExploitable === '1',
      includeClean: body.includeClean === true || req.query.includeClean === '1',
    });

    // A sweep that could not reach OSV is a failed check, not an empty one.
    if (sweep.error && !sweep.packages) return res.status(502).json(sweep);

    res.json({ ...(manifest ? { manifest } : {}), ...sweep });
  } catch (error) {
    next(error);
  }
});

router.get('/pocs/pending', async (req, res, next) => {
  if (!requireModerator(req, res)) return;
  try {
    res.json({ pending: await pendingQueue() });
  } catch (error) {
    next(error);
  }
});

router.post('/pocs/:id/:action(approve|reject)', async (req, res, next) => {
  if (!requireModerator(req, res)) return;
  try {
    const result = await moderatePoc(req.params.id, req.params.action);
    if (!result.ok) return res.status(404).json({ error: 'No such submission.' });
    res.json({ id: req.params.id, status: result.status });
  } catch (error) {
    next(error);
  }
});

router.post('/refresh', async (req, res, next) => {
  if (!config.refreshToken) {
    return res.status(404).json({ error: 'Refresh endpoint disabled. Set REFRESH_TOKEN to enable.' });
  }

  const supplied = req.get('x-refresh-token') ?? req.query.token;
  if (supplied !== config.refreshToken) {
    return res.status(401).json({ error: 'Invalid refresh token.' });
  }

  try {
    // A deliberate, token-gated rebuild, so it does build even on a read-only
    // worker - but in the worker that serves it, which keeps the memory the
    // refresh used. Cron running scripts/refresh.js is the way to refresh
    // without that cost; this is for the occasional hand-triggered run.
    const feed = await refreshFeed();
    res.json({ refreshed: true, meta: feedMeta(feed), sources: feed.value.sources });
  } catch (error) {
    next(error);
  }
});

export default router;
