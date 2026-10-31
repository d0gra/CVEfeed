import { Router } from 'express';
import config from '../config.js';
import { getFeed } from '../aggregate.js';
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

router.get('/feed', async (req, res, next) => {
  try {
    res.json(await queryFeed(req.query));
  } catch (error) {
    next(error);
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
    const feed = await getFeed({ force: true });
    res.json({ refreshed: true, meta: feedMeta(feed), sources: feed.value.sources });
  } catch (error) {
    next(error);
  }
});

export default router;
