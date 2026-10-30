import { Router } from 'express';
import config from '../config.js';
import { comparators, getFeed } from '../aggregate.js';
import { SEVERITY_ORDER } from '../lib/severity.js';
import { enabledSources } from '../sources/index.js';

const router = Router();

const asList = (value) =>
  String(value ?? '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);

const int = (value, fallback) => {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
};

function applyFilters(items, query) {
  const severities = asList(query.severity).filter((s) => SEVERITY_ORDER.includes(s));
  const sources = asList(query.source);
  const kinds = asList(query.kind);
  const needle = String(query.q ?? '').trim().toLowerCase();
  const minScore = Number.parseFloat(query.minScore);
  const days = int(query.days, 0);
  const exploitedOnly = ['1', 'true', 'yes'].includes(String(query.exploited ?? '').toLowerCase());

  const since = days > 0 ? Date.now() - days * 86_400_000 : null;

  return items.filter((item) => {
    if (severities.length && !severities.includes(item.severity)) return false;
    if (sources.length && !item.sourceIds.some((id) => sources.includes(id))) return false;
    if (kinds.length && !kinds.includes(item.kind)) return false;
    if (exploitedOnly && !item.exploited) return false;
    if (Number.isFinite(minScore) && (item.score ?? -1) < minScore) return false;

    if (since) {
      const stamp = Date.parse(item.published ?? item.modified ?? '');
      if (!Number.isFinite(stamp) || stamp < since) return false;
    }

    if (needle) {
      const haystack = [
        item.id,
        item.cveId,
        item.ghsaId,
        item.euvdId,
        item.advisoryId,
        item.title,
        item.description,
        item.vendor,
        item.product,
        item.cwes.join(' '),
        item.tags.join(' '),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(needle)) return false;
    }

    return true;
  });
}

function summarize(items) {
  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  const bySource = {};
  let exploited = 0;
  let scored = 0;
  let scoreTotal = 0;
  const last24h = Date.now() - 86_400_000;
  let fresh = 0;

  for (const item of items) {
    bySeverity[item.severity] = (bySeverity[item.severity] ?? 0) + 1;
    for (const id of item.sourceIds) bySource[id] = (bySource[id] ?? 0) + 1;
    if (item.exploited) exploited += 1;
    if (Number.isFinite(item.score)) {
      scored += 1;
      scoreTotal += item.score;
    }
    const stamp = Date.parse(item.published ?? '');
    if (Number.isFinite(stamp) && stamp >= last24h) fresh += 1;
  }

  return {
    total: items.length,
    bySeverity,
    bySource,
    exploited,
    last24h: fresh,
    averageScore: scored ? Number((scoreTotal / scored).toFixed(1)) : null,
  };
}

const feedMeta = (feed) => ({
  generatedAt: feed.value.generatedAt,
  fromCache: feed.fromCache,
  stale: feed.stale,
  ageSeconds: Math.round((feed.ageMs ?? 0) / 1000),
  cacheTtlSeconds: Math.round(config.cacheTtlMs / 1000),
  ...(feed.error ? { warning: feed.error } : {}),
});

router.get('/feed', async (req, res, next) => {
  try {
    const feed = await getFeed();
    const filtered = applyFilters(feed.value.items, req.query);

    const sortKey = String(req.query.sort ?? 'priority');
    const comparator = comparators[sortKey] ?? comparators.priority;
    const sorted = [...filtered].sort(comparator);

    const limit = Math.min(Math.max(int(req.query.limit, 50), 1), 500);
    const page = Math.max(int(req.query.page, 1), 1);
    const start = (page - 1) * limit;

    res.json({
      meta: {
        ...feedMeta(feed),
        sort: comparators[sortKey] ? sortKey : 'priority',
        total: sorted.length,
        totalUnfiltered: feed.value.items.length,
        page,
        limit,
        pages: Math.max(Math.ceil(sorted.length / limit), 1),
      },
      stats: summarize(sorted),
      sources: feed.value.sources,
      items: sorted.slice(start, start + limit),
    });
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

router.get('/sources', (_req, res) => {
  res.json({
    sources: enabledSources().map((s) => s.meta),
    configured: config.sources,
  });
});

router.get('/cve/:id', async (req, res, next) => {
  try {
    const feed = await getFeed();
    const needle = String(req.params.id).toLowerCase();
    const item = feed.value.items.find(
      (candidate) =>
        candidate.id?.toLowerCase() === needle ||
        candidate.cveId?.toLowerCase() === needle ||
        candidate.ghsaId?.toLowerCase() === needle ||
        candidate.euvdId?.toLowerCase() === needle ||
        candidate.advisoryId?.toLowerCase() === needle,
    );

    if (!item) {
      return res.status(404).json({ error: 'Not found in the current feed window.' });
    }

    res.json({ meta: feedMeta(feed), item });
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
