import { Router } from 'express';
import config from '../config.js';
import { getFeed } from '../aggregate.js';
import { feedMeta, findRecord, queryFeed, summarize } from '../query.js';
import { enabledSources } from '../sources/index.js';
import { stackFacets } from '../stack.js';

const router = Router();

router.get('/feed', async (req, res, next) => {
  try {
    res.json(await queryFeed(req.query));
  } catch (error) {
    next(error);
  }
});

router.get('/stats', async (_req, res, next) => {
  try {
    const feed = await getFeed();
    res.json({
      meta: feedMeta(feed),
      stats: summarize(feed.value.items),
      sources: feed.value.sources,
    });
  } catch (error) {
    next(error);
  }
});

/** The AI-stack facet definitions, so the dashboard renders from one source. */
router.get('/stack', (_req, res) => {
  res.json({ categories: stackFacets() });
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
    res.json({ meta: found.meta, item: found.item });
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
