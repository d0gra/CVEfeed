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
import { hubNames, listIdsForSitemap, recordsForName } from '../store/cveStore.js';
import { approvedPocsForCve } from '../store/pocStore.js';
import { issueChallenge, turnstileSiteKey, usingTurnstile } from '../lib/captcha.js';
import { originFor } from '../pages/layout.js';
import { cvePage, notFoundPage } from '../pages/cve.js';
import { agentsPage, depsPage, earnPage, exploitedPage, hubIndexPage, hubPage, moderatePage, slugFor, stackCategoryPage, stackIndexPage, termsPage } from '../pages/index.js';

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

/**
 * The dependency check. Static markup plus a client-side post, so the page is
 * indexable and readable with JavaScript off even though the answer is not.
 */
router.get('/dependencies', (req, res) => {
  const origin = originFor(req);
  html(res, depsPage({ origin, canonical: `${origin}/dependencies`, assetVersion }));
});

// The name people reach for; one canonical URL for the page itself.
router.get(['/deps', '/dependency-check'], (_req, res) => res.redirect(301, '/dependencies'));

/**
 * Hubs: one page per vendor, product and package.
 *
 * Cached names rather than a query per request - the index aggregation is the
 * same one the typeahead uses, and a crawler walking several hundred of these
 * should not be several hundred aggregations.
 */
const HUB_PATHS = { vendor: 'vendor', product: 'product', package: 'package' };

for (const [kind, path] of Object.entries(HUB_PATHS)) {
  router.get(`/${path}`, async (req, res, next) => {
    try {
      const names = await hubNames();
      if (!names) return html(res, notFoundPage({ id: path, origin: originFor(req), canonical: '', assetVersion }), 404);
      const origin = originFor(req);
      html(res, hubIndexPage({ kind, names: names[`${kind}s`] ?? [], origin, canonical: `${origin}/${path}`, assetVersion }));
    } catch (error) {
      next(error);
    }
  });

  router.get(`/${path}/:name`, async (req, res, next) => {
    const raw = String(req.params.name ?? '').trim();
    const origin = originFor(req);

    // One URL per name: a hub is reachable only at its lowercase slug.
    const slug = slugFor(decodeURIComponent(raw));
    if (encodeURIComponent(decodeURIComponent(raw)) !== slug) {
      return res.redirect(301, `/${path}/${slug}`);
    }

    try {
      const name = decodeURIComponent(raw);
      const found = await recordsForName(kind, name);
      // A name on one record has nothing to aggregate, so it gets no page
      // rather than a thin one.
      if (!found || found.total < 2) {
        return html(res, notFoundPage({ id: name, origin, canonical: `${origin}/${path}/${slug}`, assetVersion }), 404);
      }

      // The display spelling comes from the records, not from the URL.
      const field = { vendor: 'vendors', product: 'products', package: 'packages' }[kind];
      const display =
        kind === 'package'
          ? found.items[0].packages?.find((p) => p.name.toLowerCase() === name.toLowerCase())?.name ?? name
          : found.items[0][field]?.find((v) => v.toLowerCase() === name.toLowerCase()) ?? name;

      // Cached now, so this is a map lookup rather than a second aggregation.
      const all = await hubNames();
      const related = (all?.[`${kind}s`] ?? [])
        .filter((n) => n.value.toLowerCase() !== name.toLowerCase())
        .slice(0, 24);

      html(
        res,
        hubPage({
          kind,
          name: display,
          items: found.items,
          total: found.total,
          origin,
          canonical: `${origin}/${path}/${slug}`,
          assetVersion,
          related,
        }),
      );
    } catch (error) {
      next(error);
    }
  });
}

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
    const cveId = found.item.cveId ?? found.item.ghsaId ?? found.item.advisoryId ?? id;
    const [communityPocs, challenge] = await Promise.all([approvedPocsForCve(cveId), Promise.resolve(issueChallenge())]);
    html(
      res,
      cvePage({
        item: found.item,
        id: cveId,
        origin,
        canonical,
        lookedUp: lookedUp?.length ? lookedUp : null,
        assetVersion,
        pocRepos: found.pocRepos ?? [],
        communityPocs: communityPocs.map((p) => ({
          title: p.title,
          code: p.code,
          writeup: p.writeup,
          affected: p.affected,
          author: p.author,
          license: p.license,
          references: p.references,
          submittedAt: p.submittedAt,
        })),
        captcha: {
          usingTurnstile: usingTurnstile(),
          turnstileSiteKey: turnstileSiteKey(),
          challenge,
        },
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
    const { items } = await queryFeed({ stack: category.id, limit: 200, sort: 'newest', fields: 'row' });
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
    const { items } = await queryFeed({ exploited: '1', limit: 200, sort: 'priority', fields: 'row' });
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

router.get('/earn', (req, res) => {
  const origin = originFor(req);
  html(res, earnPage({ origin, canonical: `${origin}/earn`, assetVersion }));
});

router.get('/terms', (req, res) => {
  const origin = originFor(req);
  html(res, termsPage({ origin, canonical: `${origin}/terms`, assetVersion }));
});

router.get('/moderate', (req, res) => {
  const origin = originFor(req);
  // Unlisted admin page; the API enforces the token on every action.
  res
    .status(200)
    .type('html')
    .set('Cache-Control', 'no-store')
    .set('X-Robots-Tag', 'noindex')
    .send(moderatePage({ canonical: `${origin}/moderate`, assetVersion, enabled: Boolean(config.pocModerationToken) }));
});

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
        'Allow: /earn',
        'Allow: /terms',
        'Allow: /mcp',
        'Allow: /dependencies',
        // The hubs aggregate, so they are the pages worth crawling first.
        'Allow: /vendor',
        'Allow: /product',
        'Allow: /package',
        'Allow: /llms.txt',
        '',
        '# Filtered views are the same records in a different order, and the',
        '# query space is unbounded. The canonical pages above carry the content.',
        'Disallow: /*?',
        'Disallow: /moderate',
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
      { loc: `${origin}/dependencies`, priority: '0.9', changefreq: 'weekly' },
      { loc: `${origin}/vendor`, priority: '0.8', changefreq: 'daily' },
      { loc: `${origin}/product`, priority: '0.8', changefreq: 'daily' },
      { loc: `${origin}/package`, priority: '0.8', changefreq: 'daily' },
      { loc: `${origin}/mcp`, priority: '0.8', changefreq: 'weekly' },
      { loc: `${origin}/earn`, priority: '0.7', changefreq: 'monthly' },
      { loc: `${origin}/terms`, priority: '0.3', changefreq: 'yearly' },
      ...STACK_CATEGORIES.map((c) => ({
        loc: `${origin}/ai-stack/${c.id}`,
        priority: '0.7',
        changefreq: 'daily',
      })),
    ];

    // Only records actually in the window: a sitemap should list pages that
    // exist, not every CVE ever issued. Two records can still resolve to the
    // same page, so the set is deduplicated rather than merely sorted.
    // One entry per hub. These aggregate, so they are worth more to a crawler
    // than any single record and are listed ahead of them.
    try {
      const names = await hubNames();
      for (const [kind, path] of Object.entries(HUB_PATHS)) {
        for (const entry of names?.[`${kind}s`] ?? []) {
          urls.push({
            loc: `${origin}/${path}/${slugFor(entry.value)}`,
            priority: '0.7',
            changefreq: 'daily',
            lastmod: String(entry.modified ?? '').slice(0, 10) || undefined,
          });
        }
      }
    } catch {
      // A sitemap without hubs is still a valid sitemap.
    }

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
