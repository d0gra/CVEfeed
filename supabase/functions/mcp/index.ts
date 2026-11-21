/**
 * The CVEfeed MCP gateway.
 *
 * This is the MCP endpoint now. It owns the protocol, authentication, per
 * account quotas, response caching and the audit trail, and reaches the
 * Express app on Hostinger only when it cannot answer from cache.
 *
 * Why the protocol is written out here rather than taken from an SDK
 * -----------------------------------------------------------------
 * This function registers no tools of its own - it forwards them, and the
 * schemas arrive at runtime from /internal/mcp-tools as raw JSON Schema. Every
 * MCP server SDK is built around registering tools at author time with typed
 * schemas, which is precisely the ergonomics there is nothing to gain from
 * here and a layer to fight when the tool list is data. So the JSON-RPC is
 * handled directly, as it is in src/mcp.js, and the arbiter stays what it
 * already was: test/mcp-conformance.mjs, which checks this endpoint against
 * the real MCP SDK *client*. If that passes, the protocol is right.
 *
 * What this fixes about the endpoint it replaces
 * ---------------------------------------------
 *   - Quota is charged per JSON-RPC message, not per request. A batch of ten
 *     tool calls costs ten. The old endpoint ran 500 concurrently for one
 *     token of a 60-a-minute budget.
 *   - A batch is capped, and so is the body - at a size that actually fits a
 *     lockfile, rather than 64kb.
 *   - Arguments are validated against the advertised inputSchema. The old
 *     endpoint published schemas and then trusted the client to honour them.
 *   - Every call is logged. src/mcp.js had no log line in it at all.
 */
import 'jsr:@supabase/functions-js/edge-runtime.d.ts';
import { createClient, type SupabaseClient } from 'npm:@supabase/supabase-js@2';
import Ajv, { type ValidateFunction } from 'npm:ajv@8';
import { withOAuthProtectedResource } from 'npm:@supabase/server@1';
import { createRemoteJWKSet, jwtVerify } from 'npm:jose@5';

/* ---------- configuration ---------- */

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? '';
const SERVICE_KEY =
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? Deno.env.get('SUPABASE_SECRET_KEY') ?? '';
const UPSTREAM = (Deno.env.get('HOSTINGER_TOOL_URL') ?? '').replace(/\/+$/, '');
const GATEWAY_SECRET = Deno.env.get('GATEWAY_SECRET') ?? '';

const JSONRPC = '2.0';
const ERR = { parse: -32700, request: -32600, method: -32601, params: -32602, internal: -32603 };
// The code the Express endpoint already used for a throttle, kept so a client
// that learned it there sees the same thing here.
const ERR_QUOTA = -32029;

const DEFAULT_PROTOCOL = '2025-06-18';
const FALLBACK_PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];

// Large enough for a real package-lock.json, which is the point: the endpoint
// this replaces capped bodies at 64kb and told the caller the upstream feed
// had failed.
const MAX_BODY_BYTES = 2 * 1024 * 1024;
// Batching left the spec in 2025-06-18. It is still answered, but bounded -
// and every message in it is charged.
const MAX_BATCH = 10;
const UPSTREAM_TIMEOUT_MS = 30_000;
const MANIFEST_TTL_MS = 10 * 60_000;

/**
 * Per-tool cache lifetimes, mirroring the TTLs src/lib/cache.js already uses
 * for the same data. Results carry nothing specific to the caller, so one
 * global cache serves everyone - which is what keeps Hostinger's share of the
 * traffic down to the miss rate.
 */
const CACHE_TTL: Record<string, string> = {
  search_cves: '5 minutes',
  list_exploited: '5 minutes',
  feed_status: '1 minute',
  get_cve: '1 hour',
  get_exploits: '1 hour',
  check_dependencies: '6 hours',
};
// A failure is cached briefly rather than not at all. A stream of lookups for
// CVE ids that do not exist would otherwise reach the register fan-out every
// time, which is the exact traffic the upstream token bucket exists to stop.
const ERROR_TTL = '1 minute';

// An OAuth principal has no mcp_keys row to carry a limit, so these are the
// defaults. An admin gets more room because the dashboard reads through this
// same path.
const USER_RATE_PER_HOUR = 600;
const ADMIN_RATE_PER_HOUR = 5000;

/* ---------- small helpers ---------- */

const enc = new TextEncoder();
const hex = (buffer: ArrayBuffer) =>
  [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');

const sha256 = async (input: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(input)));

/** Runs after the response is sent where the platform supports it. */
function background(task: Promise<unknown>): void {
  const runtime = (globalThis as { EdgeRuntime?: { waitUntil?: (p: Promise<unknown>) => void } }).EdgeRuntime;
  if (runtime?.waitUntil) runtime.waitUntil(task.catch(() => {}));
  else void task.catch(() => {});
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type, mcp-protocol-version, accept',
  // Without this a browser client cannot read the challenge and so cannot
  // start the OAuth flow.
  'Access-Control-Expose-Headers': 'www-authenticate, ratelimit-limit, ratelimit-remaining, retry-after',
  'Access-Control-Max-Age': '86400',
};

const rpcResult = (id: unknown, value: unknown) => ({ jsonrpc: JSONRPC, id: id ?? null, result: value });
const rpcError = (id: unknown, code: number, message: string) => ({
  jsonrpc: JSONRPC,
  id: id ?? null,
  error: { code, message },
});
/** A tool-level failure: reported in the result so the agent can see why. */
const toolFailure = (message: string) => ({ content: [{ type: 'text', text: message }], isError: true });

const respond = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS, ...headers },
  });

/** Stable key order, so two spellings of the same arguments share a cache entry. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(',')}}`;
}

/* ---------- upstream ---------- */

/**
 * A signed call to the Express app. The signature covers the timestamp, the
 * method and the path as well as the body, so a body signed for one route
 * cannot be replayed against another.
 */
async function upstream(method: 'GET' | 'POST', route: string, body?: string) {
  if (!UPSTREAM) throw new Error('HOSTINGER_TOOL_URL is not configured.');
  if (!GATEWAY_SECRET) throw new Error('GATEWAY_SECRET is not configured.');

  const target = new URL(`${UPSTREAM}/${route}`);
  const payloadBytes = enc.encode(body ?? '');
  const timestamp = Math.floor(Date.now() / 1000);
  const prefix = enc.encode(`${timestamp}.${method}.${target.pathname}.`);

  const signed = new Uint8Array(prefix.length + payloadBytes.length);
  signed.set(prefix, 0);
  signed.set(payloadBytes, prefix.length);

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(GATEWAY_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const abort = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
  const response = await fetch(target, {
    method,
    signal: abort,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      'x-cvefeed-timestamp': String(timestamp),
      'x-cvefeed-signature': hex(await crypto.subtle.sign('HMAC', key, signed)),
    },
    body,
  });

  const text = await response.text();
  let parsed: Record<string, unknown> = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Upstream returned ${response.status} with an unreadable body.`);
  }
  if (!response.ok) {
    throw new Error(String(parsed.error ?? `Upstream returned ${response.status}.`));
  }
  return parsed;
}

/* ---------- the tool manifest ---------- */

type Tool = { name: string; description: string; inputSchema: Record<string, unknown> };
type Manifest = {
  version: string;
  serverInfo: { name: string; version: string };
  protocols: string[];
  instructions: string;
  tools: Tool[];
};

// ajv v8 is CommonJS. Under Deno's npm interop a default import can resolve to
// the module namespace rather than the constructor, and `new Ajv()` would then
// throw at module scope - which means on every request, not just once.
const AjvConstructor = ((Ajv as unknown as { default?: typeof Ajv }).default ?? Ajv) as typeof Ajv;
const ajv = new AjvConstructor({ allErrors: true, strict: false, useDefaults: false, coerceTypes: false });

/**
 * The project's public signing keys, fetched lazily and cached by jose, so a
 * key rotation needs no deploy. Built on first use rather than at module
 * scope: with SUPABASE_URL unset the URL constructor would throw on every
 * request instead of letting the handler report a misconfiguration.
 */
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
const keySet = () => (jwks ??= createRemoteJWKSet(new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`)));

let manifest: Manifest | null = null;
let manifestFetchedAt = 0;
let validators = new Map<string, ValidateFunction>();

function compile(tools: Tool[]) {
  const next = new Map<string, ValidateFunction>();
  for (const tool of tools) {
    try {
      next.set(tool.name, ajv.compile(tool.inputSchema));
    } catch (error) {
      // A schema Ajv will not compile must not take the tool out of service.
      // It means that one tool goes unvalidated, which is worth saying out
      // loud rather than discovering later from a shape nobody checked.
      console.error(`[gateway] schema for ${tool.name} did not compile: ${(error as Error).message}`);
      next.delete(tool.name);
    }
  }
  validators = next;
}

/**
 * The tool surface, from Hostinger, cached here and in Postgres.
 *
 * The schemas are authored in src/mcp.js and nowhere else, so tools/list and
 * argument validation cannot drift from what actually executes. The stored
 * copy is what lets tools/list keep answering when Hostinger is unreachable.
 */
async function getManifest(db: SupabaseClient): Promise<Manifest | null> {
  if (manifest && Date.now() - manifestFetchedAt < MANIFEST_TTL_MS) return manifest;

  try {
    const fetched = (await upstream('GET', 'mcp-tools')) as unknown as Manifest;
    if (!Array.isArray(fetched?.tools)) throw new Error('Manifest carried no tools.');
    manifest = fetched;
    manifestFetchedAt = Date.now();
    compile(fetched.tools);
    // The whole manifest goes in `tools`, not just the array: the fallback
    // needs the instructions and serverInfo too.
    background(
      db
        .from('mcp_tool_manifest')
        .upsert({ id: true, version: fetched.version, tools: fetched, fetched_at: new Date().toISOString() })
        .then(),
    );
    return manifest;
  } catch (error) {
    const { data } = await db.from('mcp_tool_manifest').select('tools').maybeSingle();
    const stored = data?.tools as Manifest | undefined;
    if (Array.isArray(stored?.tools)) {
      manifest = stored;
      manifestFetchedAt = Date.now();
      compile(stored.tools);
      return manifest;
    }
    console.error(`[gateway] no manifest available: ${(error as Error).message}`);
    return null;
  }
}

/* ---------- authentication ---------- */

type Principal = { id: string; kind: 'key' | 'user'; limit: number };

async function authenticate(
  db: SupabaseClient,
  req: Request,
): Promise<{ principal?: Principal; problem?: string }> {
  const match = /^Bearer\s+(.+)$/i.exec((req.headers.get('authorization') ?? '').trim());
  if (!match) return { problem: 'Authentication required. Present an API key as a bearer token.' };

  const token = match[1].trim();

  if (token.startsWith('cvf_')) {
    const { data, error } = await db.rpc('mcp_authorize_key', { p_key_hash: await sha256(token) });
    if (error) {
      console.error(`[gateway] key lookup failed: ${error.message}`);
      return { problem: 'The key could not be checked. Try again shortly.' };
    }
    const row = (Array.isArray(data) ? data[0] : data) as
      | { principal: string; rate_per_hour: number }
      | undefined;
    if (!row) return { problem: 'That key is not valid, or has been revoked.' };
    return { principal: { id: row.principal, kind: 'key', limit: row.rate_per_hour } };
  }

  // A Supabase Auth access token - from the OAuth 2.1 flow an MCP client runs,
  // or from an ordinary session. Verified against the project JWKS, so it is
  // checked the same way whatever issued it.
  try {
    const { payload } = await jwtVerify(token, keySet(), { issuer: `${SUPABASE_URL}/auth/v1` });
    const subject = typeof payload.sub === 'string' ? payload.sub : '';
    if (!subject) return { problem: 'That token carries no subject.' };

    // app_metadata only. raw_user_meta_data is editable by the user it
    // describes, so it must never decide anything about authorization.
    const claims = (payload.app_metadata ?? {}) as { role?: string };
    const admin = claims.role === 'admin';
    return {
      principal: {
        id: `user:${subject}`,
        kind: 'user',
        limit: admin ? ADMIN_RATE_PER_HOUR : USER_RATE_PER_HOUR,
      },
    };
  } catch (error) {
    return { problem: `That token was not accepted: ${(error as Error).message}` };
  }
}

/* ---------- audit ---------- */

type LogRow = {
  p_principal: string;
  p_principal_kind: string;
  p_outcome: string;
  p_tool?: string | null;
  p_error_code?: string | null;
  p_duration_ms?: number | null;
  p_upstream_ms?: number | null;
  p_cache_hit?: boolean;
  p_bytes_out?: number | null;
  p_args_digest?: string | null;
  p_args_summary?: unknown;
  p_client?: string | null;
  p_ip_hash?: string | null;
};

/**
 * A bounded, non-identifying shape of the arguments.
 *
 * Never the values. A pasted lockfile names a company's private dependencies
 * and a search term says what someone is worried about; neither belongs in an
 * audit log. Ids are the exception, because a CVE number is public.
 */
function summarizeArgs(tool: string, args: Record<string, unknown>): unknown {
  const summary: Record<string, unknown> = {};
  if (tool === 'check_dependencies') {
    summary.package_count = Array.isArray(args.packages) ? args.packages.length : 0;
    summary.has_manifest = typeof args.manifest === 'string';
    summary.manifest_bytes = typeof args.manifest === 'string' ? args.manifest.length : 0;
    summary.only_exploitable = args.onlyExploitable === true;
  } else if (tool === 'get_cve' || tool === 'get_exploits') {
    summary.id = typeof args.id === 'string' ? args.id.slice(0, 40) : null;
  } else {
    if (typeof args.q === 'string') summary.q_length = args.q.length;
    for (const key of ['severity', 'stack', 'exploit', 'maturity', 'sort', 'days', 'limit', 'page', 'minCvss']) {
      if (args[key] !== undefined) summary[key] = args[key];
    }
    if (args.detail !== undefined) summary.detail = args.detail === true;
  }
  return summary;
}

/* ---------- tool dispatch ---------- */

async function runTool(
  db: SupabaseClient,
  tool: string,
  args: Record<string, unknown>,
  log: LogRow,
): Promise<unknown> {
  const validate = validators.get(tool);
  if (validate && !validate(args)) {
    const problems = (validate.errors ?? [])
      .slice(0, 6)
      .map((e) => `${e.instancePath || 'arguments'} ${e.message}`)
      .join('; ');
    log.p_outcome = 'validation_error';
    log.p_error_code = 'schema';
    return toolFailure(
      `Those arguments do not match the schema for ${tool}: ${problems}. ` +
        'Call tools/list for the accepted shape.',
    );
  }

  const cacheKey = await sha256(`${tool}:${canonical(args)}`);
  log.p_args_digest = cacheKey;
  log.p_args_summary = summarizeArgs(tool, args);

  const { data: cached } = await db.rpc('mcp_cache_get', { p_key: cacheKey });
  if (cached) {
    log.p_cache_hit = true;
    log.p_outcome = 'ok';
    log.p_bytes_out = JSON.stringify(cached).length;
    return cached;
  }

  const startedUpstream = Date.now();
  let payload: Record<string, unknown>;
  try {
    payload = await upstream('POST', 'mcp-tool', JSON.stringify({ name: tool, arguments: args }));
  } catch (error) {
    log.p_upstream_ms = Date.now() - startedUpstream;
    log.p_outcome = 'upstream_error';
    log.p_error_code = (error as Error).name === 'TimeoutError' ? 'timeout' : 'upstream';
    return toolFailure(`The feed could not be queried: ${(error as Error).message}`);
  }
  log.p_upstream_ms = Date.now() - startedUpstream;

  const result = payload.result ?? toolFailure('The feed returned nothing.');
  const isError = Boolean((result as { isError?: boolean }).isError);
  log.p_outcome = isError ? 'tool_error' : 'ok';
  log.p_bytes_out = JSON.stringify(result).length;

  background(
    db
      .rpc('mcp_cache_put', {
        p_key: cacheKey,
        p_tool: tool,
        p_payload: result,
        p_ttl: isError ? ERROR_TTL : (CACHE_TTL[tool] ?? '5 minutes'),
      })
      .then(),
  );

  return result;
}

/* ---------- JSON-RPC ---------- */

async function handleMessage(
  db: SupabaseClient,
  principal: Principal,
  message: Record<string, unknown>,
  context: { client: string | null; ipHash: string | null; logs: LogRow[] },
): Promise<unknown | null> {
  const { id, method, params } = message as { id?: unknown; method?: string; params?: Record<string, unknown> };
  const isNotification = id === undefined;

  if (message?.jsonrpc !== JSONRPC || typeof method !== 'string') {
    return isNotification ? null : rpcError(id, ERR.request, 'Invalid JSON-RPC 2.0 request.');
  }

  const startedAt = Date.now();
  const log: LogRow = {
    p_principal: principal.id,
    p_principal_kind: principal.kind,
    p_outcome: 'ok',
    p_tool: method === 'tools/call' ? String(params?.name ?? '') || null : null,
    p_client: context.client,
    p_ip_hash: context.ipHash,
    p_cache_hit: false,
  };
  const finish = (value: unknown) => {
    log.p_duration_ms = Date.now() - startedAt;
    context.logs.push(log);
    return value;
  };

  // Quota is charged per message. A notification asks for no work worth
  // metering, and charging the handshake would break clients under load.
  if (!isNotification && method !== 'initialize' && method !== 'ping') {
    const { data, error } = await db.rpc('mcp_consume_quota', {
      p_principal: principal.id,
      p_limit: principal.limit,
      p_window: '1 hour',
    });
    const verdict = (Array.isArray(data) ? data[0] : data) as
      | { allowed: boolean; remaining: number; reset_at: string }
      | undefined;
    if (error) console.error(`[gateway] quota check failed: ${error.message}`);
    if (verdict && !verdict.allowed) {
      const retryAfter = Math.max(1, Math.round((Date.parse(verdict.reset_at) - Date.now()) / 1000));
      log.p_outcome = 'quota';
      log.p_error_code = 'rate_limited';
      return finish(
        rpcError(id, ERR_QUOTA, `Rate limit of ${principal.limit}/hour reached. Retry after ${retryAfter}s.`),
      );
    }
  }

  switch (method) {
    case 'initialize': {
      const asked = params?.protocolVersion;
      const live = await getManifest(db);
      const protocols = live?.protocols ?? FALLBACK_PROTOCOLS;
      const clientInfo = params?.clientInfo as { name?: string; version?: string } | undefined;
      if (clientInfo?.name) log.p_client = `${clientInfo.name}/${clientInfo.version ?? '?'}`;
      return finish(
        rpcResult(id, {
          protocolVersion: protocols.includes(asked as string) ? asked : DEFAULT_PROTOCOL,
          capabilities: { tools: { listChanged: false } },
          serverInfo: live?.serverInfo ?? { name: 'cvefeed', version: '1.0.0' },
          instructions: live?.instructions,
        }),
      );
    }

    case 'notifications/initialized':
      return null;

    case 'ping':
      return finish(rpcResult(id, {}));

    case 'tools/list': {
      const live = await getManifest(db);
      if (!live) {
        log.p_outcome = 'upstream_error';
        log.p_error_code = 'no_manifest';
        return finish(rpcError(id, ERR.internal, 'The tool list is temporarily unavailable.'));
      }
      return finish(rpcResult(id, { tools: live.tools }));
    }

    case 'tools/call': {
      const live = await getManifest(db);
      const name = String(params?.name ?? '');
      if (!live?.tools.some((tool) => tool.name === name)) {
        log.p_outcome = 'validation_error';
        log.p_error_code = 'unknown_tool';
        return finish(rpcError(id, ERR.params, `Unknown tool: ${name || '(none)'}`));
      }
      const args = (params?.arguments ?? {}) as Record<string, unknown>;
      if (args === null || typeof args !== 'object' || Array.isArray(args)) {
        log.p_outcome = 'validation_error';
        log.p_error_code = 'bad_arguments';
        return finish(rpcError(id, ERR.params, '`arguments` must be an object.'));
      }
      return finish(rpcResult(id, await runTool(db, name, args, log)));
    }

    default:
      if (isNotification) return null;
      log.p_outcome = 'validation_error';
      log.p_error_code = 'unknown_method';
      return finish(rpcError(id, ERR.method, `Unknown method: ${method}`));
  }
}

/* ---------- transport ---------- */

const handler = async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  if (req.method !== 'POST') {
    return respond(
      405,
      rpcError(null, ERR.request, 'This MCP server is stateless; use POST.'),
      { Allow: 'POST, OPTIONS' },
    );
  }

  if (!SUPABASE_URL || !SERVICE_KEY) {
    return respond(500, rpcError(null, ERR.internal, 'The gateway is not configured.'));
  }

  const declared = Number(req.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return respond(413, rpcError(null, ERR.request, `The body limit is ${MAX_BODY_BYTES} bytes.`));
  }

  const raw = await req.text();
  // A chunked request carries no content-length, so the real size is checked
  // here too rather than trusted from a header.
  if (raw.length > MAX_BODY_BYTES) {
    return respond(413, rpcError(null, ERR.request, `The body limit is ${MAX_BODY_BYTES} bytes.`));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return respond(400, rpcError(null, ERR.parse, 'The body is not valid JSON.'));
  }
  if (parsed === null || typeof parsed !== 'object') {
    return respond(400, rpcError(null, ERR.request, 'Expected a JSON-RPC 2.0 message.'));
  }

  const batched = Array.isArray(parsed);
  const messages = (batched ? parsed : [parsed]) as Record<string, unknown>[];
  if (batched && messages.length === 0) {
    return respond(400, rpcError(null, ERR.request, 'Empty batch.'));
  }
  if (messages.length > MAX_BATCH) {
    return respond(
      400,
      rpcError(
        null,
        ERR.request,
        `A batch may carry at most ${MAX_BATCH} messages; this one carried ${messages.length}. ` +
          'Note that batching was removed from the protocol in revision 2025-06-18.',
      ),
    );
  }

  const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

  const forwarded = (req.headers.get('x-forwarded-for') ?? '').split(',')[0].trim();
  const client = req.headers.get('user-agent');
  const ipHash = forwarded ? (await sha256(`${GATEWAY_SECRET}:${forwarded}`)).slice(0, 16) : null;

  const { principal, problem } = await authenticate(db, req);
  if (!principal) {
    background(
      db
        .rpc('mcp_log_call', {
          p_principal: 'anonymous',
          p_principal_kind: 'anonymous',
          p_outcome: 'auth',
          p_error_code: 'unauthenticated',
          p_client: client,
          p_ip_hash: ipHash,
        })
        .then(),
    );
    // Deliberately no WWW-Authenticate of our own. withOAuthProtectedResource
    // adds one carrying resource_metadata="...", which is the only thing that
    // tells a client where the discovery document is - and setting our own
    // suppresses it, leaving an OAuth-capable client with a challenge it
    // cannot act on. Verified against a probe: a 401 carrying a header of ours
    // came back with no pointer; with no header of ours, the pointer is there.
    return respond(401, rpcError(null, ERR.request, problem ?? 'Authentication required.'));
  }

  const logs: LogRow[] = [];
  const replies: unknown[] = [];
  // Sequential on purpose: ten messages must not become ten concurrent
  // upstream fetches, and quota accounting stays deterministic this way.
  for (const message of messages) {
    const reply = await handleMessage(db, principal, message, { client, ipHash, logs });
    if (reply !== null) replies.push(reply);
  }

  background(Promise.all(logs.map((row) => db.rpc('mcp_log_call', row).then())));

  // Nothing but notifications: acknowledge with no body, as the spec requires.
  if (replies.length === 0) return new Response(null, { status: 202, headers: CORS });

  return respond(200, batched ? replies : replies[0]);
};

/**
 * withOAuthProtectedResource answers the RFC 9728 discovery document an MCP
 * client fetches before it can begin an OAuth flow, and decorates our 401s
 * with the resource_metadata pointer that sends it there. Where that document
 * is served is platform-specific - under
 * /.well-known/oauth-protected-resource/functions/v1/mcp rather than at the
 * origin root - which is precisely the part worth taking from Supabase instead
 * of guessing at. Everything else passes straight through to the handler.
 */
Deno.serve(withOAuthProtectedResource(handler));
