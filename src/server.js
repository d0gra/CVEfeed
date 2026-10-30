import express from 'express';
import compression from 'compression';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from './config.js';
import api from './routes/api.js';
import { mountMcp } from './mcp.js';
import pages, { agentsPageHandler, assetVersionValue, setAssetVersion } from './routes/pages.js';
import { missingPage, originFor } from './pages/index.js';
import { llmsTxt } from './llms.js';
import { getFeed, feedCacheStatus } from './aggregate.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, '..', 'public');
const assetsDir = path.join(publicDir, 'assets');

/**
 * Stamp the asset URLs with a token derived from the asset mtimes.
 *
 * Static files are served with a long max-age, so without this a deploy would
 * leave visitors on cached CSS/JS until it expired. The token changes whenever
 * an asset changes, and the page itself is always revalidated.
 */
function buildIndexHtml() {
  const html = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');

  let newest = 0;
  try {
    for (const name of fs.readdirSync(assetsDir)) {
      newest = Math.max(newest, fs.statSync(path.join(assetsDir, name)).mtimeMs);
    }
  } catch {
    newest = Date.now();
  }

  const version = Math.round(newest).toString(36);
  // The rendered pages fingerprint their assets from the same stamp.
  setAssetVersion(version);
  return html
    .replaceAll('__ASSET_VERSION__', version)
    // Relative canonicals are legal; absolute ones are what crawlers and link
    // previews agree on, so SITE_URL is stamped in when it is configured.
    .replaceAll('__SITE_URL__', config.siteUrl);
}

export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  // Correct client IPs and protocol behind Hostinger's reverse proxy.
  app.set('trust proxy', true);
  app.use(compression());
  app.use(express.json({ limit: '64kb' }));

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  // Built once at boot; a deploy restarts the process and re-stamps it.
  let indexHtml = buildIndexHtml();
  const sendIndex = (_req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.send(indexHtml);
  };

  if (process.env.NODE_ENV !== 'production') {
    // Pick up edits without a restart while developing.
    app.use((req, _res, next) => {
      if (req.path === '/' || req.path === '/index.html') indexHtml = buildIndexHtml();
      next();
    });
  }

  app.get('/', sendIndex);

  app.get('/healthz', (_req, res) => {
    const cache = feedCacheStatus();
    res.json({
      status: 'ok',
      uptimeSeconds: Math.round(process.uptime()),
      feedCached: Boolean(cache),
      feedAgeSeconds: cache ? Math.round(cache.ageMs / 1000) : null,
      // The thresholds that give the age above its meaning: under the TTL is
      // fresh, under TTL + grace is served instantly while refreshing behind
      // it, and beyond that the next request waits for upstream.
      cacheTtlSeconds: Math.round(config.cacheTtlMs / 1000),
      staleWhileRevalidateSeconds: Math.round(config.staleWhileRevalidateMs / 1000),
      sources: config.sources,
    });
  });

  // A browser asking for /mcp gets the page; an MCP client gets the protocol.
  app.get('/mcp', agentsPageHandler);

  // An MCP endpoint, so the feed is usable as a tool rather than only a page.
  mountMcp(app, '/mcp');

  // Server-rendered pages: what a crawler, a link preview or curl actually sees.
  app.use(pages);

  // The convention agents look for when handed a bare domain.
  app.get('/llms.txt', (_req, res) => {
    res.type('text/plain; charset=utf-8').set('Cache-Control', 'public, max-age=3600').send(llmsTxt());
  });

  app.use('/api', api);

  app.use(
    express.static(publicDir, {
      maxAge: '7d',
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
      },
    }),
  );

  // Unknown paths get a real 404. Serving the dashboard here instead would
  // answer 200 for every address on the domain, which is an unbounded supply
  // of near-duplicate pages for a crawler to find.
  app.use((req, res) => {
    if (req.method === 'GET' && !req.path.startsWith('/api') && req.accepts('html')) {
      return res
        .status(404)
        .type('html')
        .send(
          missingPage({
            canonical: `${originFor(req)}${req.path}`,
            assetVersion: assetVersionValue(),
            path: req.path,
          }),
        );
    }
    res.status(404).json({ error: 'Not found' });
  });

  app.use((error, req, res, next) => {
    // A body the parser could not read is the client's mistake, not an
    // upstream failure, and the MCP endpoint owes it a JSON-RPC parse error
    // rather than the generic 502 below.
    if (error?.type === 'entity.parse.failed' || error instanceof SyntaxError) {
      if (req.path === '/mcp') {
        return res
          .status(400)
          .json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: body is not valid JSON.' } });
      }
      return res.status(400).json({ error: 'Invalid JSON body.' });
    }

    console.error('[cvefeed]', error.message);
    res.status(502).json({
      error: 'Upstream feed error',
      detail: error.message,
    });
  });

  return app;
}

export function start() {
  const app = createApp();

  // A platform that assigns a port does it through PORT. Setting that variable
  // to an empty string - easy to do when a deploy form asks for every key it
  // found in .env.example - silently shadows the assignment, and the app then
  // listens somewhere the proxy is not looking. The symptom is a 502 with
  // nothing wrong in the logs, so the logs had better say something.
  if (process.env.PORT !== undefined && process.env.PORT.trim() === '') {
    console.warn(
      `[cvefeed] PORT is set but empty, so falling back to ${config.port}. If your host assigns ` +
        'a port, remove the PORT variable entirely rather than leaving it blank, or this app ' +
        'will not be reachable.',
    );
  }

  const server = app.listen(config.port, () => {
    console.log(`[cvefeed] listening on http://localhost:${config.port}`);
    console.log(`[cvefeed] sources: ${config.sources.join(', ')}`);
  });

  // Warm the cache so the first visitor does not wait on upstream feeds.
  getFeed().then(
    (feed) => {
      const ok = feed.value.sources.filter((s) => s.ok).length;
      console.log(
        feed.value.stored
          ? `[cvefeed] store ready: ${feed.fromCache ? 'using the existing refresh' : `wrote ${feed.value.written} records`}` +
            ` from ${ok}/${feed.value.sources.length} sources`
          : `[cvefeed] warm cache ready: ${feed.value.items.length} records from ${ok}/${feed.value.sources.length} sources`,
      );
    },
    (error) => console.error('[cvefeed] initial fetch failed:', error.message),
  );

  if (config.refreshIntervalMs > 0) {
    const timer = setInterval(() => {
      getFeed({ force: true }).catch((error) =>
        console.error('[cvefeed] background refresh failed:', error.message),
      );
    }, config.refreshIntervalMs);
    timer.unref();
  }

  const shutdown = (signal) => () => {
    console.log(`[cvefeed] ${signal} received, closing`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 8000).unref();
  };
  process.on('SIGTERM', shutdown('SIGTERM'));
  process.on('SIGINT', shutdown('SIGINT'));

  return server;
}

export default createApp;
