/**
 * The seam the Supabase MCP gateway calls.
 *
 * The protocol, authentication, quotas, response caching and the audit trail
 * all live at the edge now. What stays here is the one thing only this process
 * can do: answer a tool call out of the Mongo corpus, and fan out to the
 * registers for a CVE nobody has asked for yet.
 *
 * Nothing here reshapes a result. `callTool` already applies the trimmed
 * record and the untrusted-data notice, so exporting it rather than rebuilding
 * the REST surface keeps one implementation of the shaping - and means the
 * injection advisory cannot drift between two languages.
 *
 * Reached only on a cache miss, by one trusted caller, so the guard is a
 * shared-secret signature rather than the public rate limiters. With
 * GATEWAY_SECRET unset these routes 404.
 */
import { Router, json } from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import config from '../config.js';
import {
  INSTRUCTIONS,
  SERVER_INFO,
  SUPPORTED_PROTOCOLS,
  TOOLS,
  callTool,
  toolsManifestVersion,
} from '../mcp.js';
import { createLimiter } from '../lib/ratelimit.js';

const router = Router();

const SIGNATURE_HEADER = 'x-cvefeed-signature';
const TIMESTAMP_HEADER = 'x-cvefeed-timestamp';

/**
 * A lockfile pasted into check_dependencies is the whole reason this route
 * parses bodies at a different size to everything else. The public endpoint
 * capped them at 64kb and answered a 200kb package-lock.json with a 502 that
 * blamed the upstream feed, so the headline tool failed on ordinary input.
 *
 * `verify` keeps the raw bytes, because the signature covers what was sent
 * rather than what JSON.parse made of it.
 */
const parseBody = json({
  limit: config.depsMaxManifestBytes,
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  },
});

/**
 * Is this request signed by the gateway?
 *
 * The signature covers the timestamp, the method and the path as well as the
 * body, so a body signed for one route cannot be replayed against another.
 * Replay protection is the timestamp window alone; these calls only read, so a
 * replay inside the window costs a cache lookup rather than a write.
 */
function signatureProblem(req) {
  const provided = String(req.get(SIGNATURE_HEADER) ?? '');
  const timestamp = Number.parseInt(req.get(TIMESTAMP_HEADER) ?? '', 10);

  if (!provided || !Number.isFinite(timestamp)) {
    return 'A signature and a timestamp are required.';
  }
  if (Math.abs(Date.now() - timestamp * 1000) > config.gatewaySkewMs) {
    return 'The signature has expired.';
  }

  const expected = createHmac('sha256', config.gatewaySecret)
    .update(`${timestamp}.${req.method}.${req.baseUrl}${req.path}.`)
    .update(req.rawBody ?? Buffer.alloc(0))
    .digest('hex');

  // timingSafeEqual throws on a length mismatch, so the lengths are compared
  // first. The length of a hex digest is not a secret; its contents are.
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return 'The signature did not match.';
  }
  return null;
}

function requireGateway(req, res, next) {
  if (!config.gatewaySecret) {
    return res.status(404).json({ error: 'Internal endpoint disabled. Set GATEWAY_SECRET to enable.' });
  }
  // A body the parser skipped - the wrong content type, say - would not be
  // covered by the signature, so it is refused rather than silently ignored.
  if (req.method === 'POST' && req.rawBody === undefined) {
    return res.status(415).json({ error: 'Expected a JSON body with Content-Type: application/json.' });
  }

  const problem = signatureProblem(req);
  if (problem) return res.status(401).json({ error: problem });
  return next();
}

router.use(createLimiter({ windowMs: config.rateWindowMs, max: config.internalRateMax }));

/**
 * The tool surface itself, so the gateway answers tools/list from the schemas
 * this process authors and validates arguments against the same ones. The
 * version is a content hash: when a deploy changes a schema, the gateway can
 * tell without comparing the whole array.
 */
router.get('/mcp-tools', requireGateway, (_req, res) => {
  res.set('Cache-Control', 'no-store').json({
    version: toolsManifestVersion(),
    serverInfo: SERVER_INFO,
    protocols: SUPPORTED_PROTOCOLS,
    instructions: INSTRUCTIONS,
    tools: TOOLS,
  });
});

/** One tool call, shaped exactly as the MCP endpoint would have shaped it. */
router.post('/mcp-tool', parseBody, requireGateway, async (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name : '';
  if (!TOOLS.some((tool) => tool.name === name)) {
    return res.status(400).json({
      error: `Unknown tool: ${name || '(none)'}`,
      tools: TOOLS.map((tool) => tool.name),
    });
  }

  const args = req.body?.arguments ?? {};
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    return res.status(400).json({ error: '`arguments` must be an object.' });
  }

  const startedAt = Date.now();
  try {
    const result = await callTool(name, args);
    return res.set('Cache-Control', 'no-store').json({ result, elapsedMs: Date.now() - startedAt });
  } catch (error) {
    // A tool that could not reach its data is an upstream failure, and the
    // gateway records it as one rather than handing an agent a broken result
    // as though it were an answer. Logged here because the old endpoint
    // swallowed tool failures into the response and logged nothing at all.
    console.error(`[cvefeed] internal tool ${name} failed: ${error.message}`);
    return res.status(502).json({ error: error.message, tool: name, elapsedMs: Date.now() - startedAt });
  }
});

export default router;
