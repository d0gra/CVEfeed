import express from 'express';
import compression from 'compression';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from './config.js';
import api from './routes/api.js';
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

  return html.replaceAll('__ASSET_VERSION__', Math.round(newest).toString(36));
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

  app.use('/api', api);

  app.use(
    express.static(publicDir, {
      maxAge: '7d',
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
      },
    }),
  );

  app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api')) return next();
    sendIndex(req, res);
  });

  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

  app.use((error, _req, res, _next) => {
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

  const server = app.listen(config.port, () => {
    console.log(`[cvefeed] listening on http://localhost:${config.port}`);
    console.log(`[cvefeed] sources: ${config.sources.join(', ')}`);
  });

  // Warm the cache so the first visitor does not wait on upstream feeds.
  getFeed().then(
    (feed) => {
      const ok = feed.value.sources.filter((s) => s.ok).length;
      console.log(
        `[cvefeed] warm cache ready: ${feed.value.items.length} records from ${ok}/${feed.value.sources.length} sources`,
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
