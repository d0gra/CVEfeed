/**
 * Server-rendered routes: the indexable surface.
 *
 * Everything here answers in complete HTML without JavaScript, carries a
 * canonical URL and sets its own metadata. The dashboard stays a client-side
 * app; these pages are what a crawler, a link preview or a text browser sees.
 */
import { Router } from 'express';
import config from '../config.js';
import { getFeed } from '../aggregate.js';
import { findRecord, queryFeed } from '../query.js';
import { isCveId } from '../lookup.js';
import { STACK_CATEGORIES } from '../stack.js';
import { listIdsForSitemap } from '../store/cveStore.js';
import { originFor } from '../pages/layout.js';
import { cvePage, notFoundPage } from '../pages/cve.js';
import { agentsPage, exploitedPage, stackCategoryPage, stackIndexPage } from '../pages/index.js';

const router = Router();

/** Set by the server once it knows the asset fingerprint. */
let assetVersion = '';
export const setAssetVersion = (value) => {
  assetVersion = value;
};
export const assetVersionValue = () => assetVersion;

const html = (res, markup, status = 200) =>
  res.status(status).type('html').set('Cache-Control', 'public, max-age=300, s-maxage=900').send(markup);

const byNewest = (a, b) => Date.parse(b.published ?? 0) - Date.parse(a.published ?? 0);

router.get('/cve/:id', async (req, res, next) => {
  const raw = String(req.params.id ?? '').trim();
  const id = raw.toUpperCase();
  const origin = originFor(req);
  const canonical = `${origin}/cve/${encodeURIComponent(id)}`;

  // Keep one URL per record: anything but the canonical spelling redirects.
  if (raw !== id) return res.redirect(301, `/cve/${encodeURIComponent(id)}`);

  try {
    const found = await findRecord(id);
    if (!found.item) {
      return html(res, notFoundPage({ id, origin, canonical, assetVersion }), 404);
    }

    const lookedUp = found.meta.lookup?.sources?.filter((s) => s.ok && s.count).map((s) => s.name);
    html(
      res,
      cvePage({
        item: found.item,
        id: found.item.cveId ?? found.item.ghsaId ?? found.item.advisoryId ?? id,
        origin,
        canonical,
        lookedUp: lookedUp?.length ? lookedUp : null,
        assetVersion,
        pocRepos: found.pocRepos ?? [],
      }),
    );
  } catch (error) {
    next(error);
  }
});

router.get('/ai-stack', async (req, res, next) => {
  try {
    const origin = originFor(req);
    const { stats } = await queryFeed({ limit: 1 });
    html(
      res,
      stackIndexPage({
        stats,
        exploited: stats.stackExploited,
        origin,
        canonical: `${origin}/ai-stack`,
        assetVersion,
      }),
    );
  } catch (error) {
    next(error);
  }
});

router.get('/ai-stack/:category', async (req, res, next) => {
  const category = STACK_CATEGORIES.find((c) => c.id === String(req.params.category).toLowerCase());
  // An unknown category is a 404, not a fall-through to the dashboard.
  if (!category) return next('route');

  try {
    const origin = originFor(req);
    const { items } = await queryFeed({ stack: category.id, limit: 200, sort: 'newest' });
    html(
      res,
      stackCategoryPage({
        category,
        items,
        origin,
        canonical: `${origin}/ai-stack/${category.id}`,
        assetVersion,
      }),
    );
  } catch (error) {
    next(error);
  }
});

router.get('/exploited', async (req, res, next) => {
  try {
    const origin = originFor(req);
    const { items } = await queryFeed({ exploited: '1', limit: 200, sort: 'priority' });
    html(
      res,
      exploitedPage({
        items,
        inStack: items.filter((i) => i.stack).length,
        origin,
        canonical: `${origin}/exploited`,
        assetVersion,
      }),
    );
  } catch (error) {
    next(error);
  }
});

/**
 * GET /mcp is the human-facing page; POST /mcp is the protocol. An MCP client
 * asking for an event stream still gets the 405 the transport expects.
 */
export async function agentsPageHandler(req, res, next) {
  if (req.accepts(['html', 'text/event-stream']) !== 'html') return next();
  try {
    const origin = originFor(req);
    const { stats } = await queryFeed({ limit: 1 });
    html(res, agentsPage({ origin, canonical: `${origin}/mcp`, assetVersion, stats }));
  } catch (error) {
    next(error);
  }
}

router.get('/robots.txt', (req, res) => {
  const origin = originFor(req);
  res
    .type('text/plain')
    .set('Cache-Control', 'public, max-age=86400')
    .send(
      [
        'User-agent: *',
        'Allow: /$',
        'Allow: /cve/',
        'Allow: /ai-stack',
        'Allow: /exploited',
        'Allow: /mcp',
        'Allow: /llms.txt',
        '',
        '# Filtered views are the same records in a different order, and the',
        '# query space is unbounded. The canonical pages above carry the content.',
        'Disallow: /*?',
        'Disallow: /api/',
        '',
        `Sitemap: ${origin}/sitemap.xml`,
        '',
      ].join('\n'),
    );
});

router.get('/sitemap.xml', async (req, res, next) => {
  try {
    const origin = originFor(req);
    const feed = await getFeed();

    const urls = [
      { loc: `${origin}/`, priority: '1.0', changefreq: 'hourly' },
      { loc: `${origin}/ai-stack`, priority: '0.9', changefreq: 'daily' },
      { loc: `${origin}/exploited`, priority: '0.9', changefreq: 'daily' },
      { loc: `${origin}/mcp`, priority: '0.8', changefreq: 'weekly' },
      ...STACK_CATEGORIES.map((c) => ({
        loc: `${origin}/ai-stack/${c.id}`,
        priority: '0.7',
        changefreq: 'daily',
      })),
    ];

    // Only records actually in the window: a sitemap should list pages that
    // exist, not every CVE ever issued. Two records can still resolve to the
    // same page, so the set is deduplicated rather than merely sorted.
    const seen = new Set(urls.map((u) => u.loc));
    const records = feed.value.stored
      ? await listIdsForSitemap(5000)
      : [...feed.value.items].sort(byNewest).slice(0, 5000);

    for (const item of records) {
      const id = item.cveId ?? item.ghsaId ?? item.advisoryId ?? item.id;
      if (!id) continue;
      const loc = `${origin}/cve/${encodeURIComponent(String(id).toUpperCase())}`;
      if (seen.has(loc)) continue;
      seen.add(loc);
      urls.push({
        loc,
        lastmod: (item.modified ?? item.published ?? '').slice(0, 10) || undefined,
        priority: item.exploited ? '0.8' : '0.6',
        changefreq: 'weekly',
      });
    }

    const body = urls
      .map(
        (u) =>
          `<url><loc>${u.loc}</loc>${u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : ''}` +
          `<changefreq>${u.changefreq}</changefreq><priority>${u.priority}</priority></url>`,
      )
      .join('');

    res
      .type('application/xml')
      .set('Cache-Control', 'public, max-age=3600')
      .send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${body}</urlset>`);
  } catch (error) {
    next(error);
  }
});

/** Old-style query links people may already have shared. */
router.get('/cve', (req, res) => {
  const id = String(req.query.id ?? '').trim();
  if (isCveId(id)) return res.redirect(301, `/cve/${encodeURIComponent(id.toUpperCase())}`);
  res.redirect(302, '/');
});

export default router;
