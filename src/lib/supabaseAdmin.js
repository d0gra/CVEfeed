/**
 * Reading the MCP gateway's own records, from here.
 *
 * The gateway lives on Supabase and keeps its keys, quotas, cache and audit
 * trail in Postgres there. This module is how the admin dashboard on this host
 * reads them: PostgREST over fetch, with the project's secret key, which never
 * leaves the server.
 *
 * Two deliberate choices
 * ----------------------
 * No supabase-js. Everything needed here is a GET or a PATCH against
 * /rest/v1/<view>, which fetch already does; the client library would be a
 * dependency earning nothing.
 *
 * An admin is verified by ASKING Supabase rather than by checking a signature
 * locally. `GET /auth/v1/user` costs one request and answers the question a
 * local JWT check cannot: whether the session is still good. Deleting a user
 * or revoking a session does not invalidate an already-issued access token, so
 * a cryptographically perfect signature check would keep admitting a token
 * whose owner was removed an hour ago. The round trip buys revocation, and at
 * one admin looking at a dashboard it costs nothing worth saving.
 */
import { createHash, randomBytes } from 'node:crypto';
import config from '../config.js';

const configured = () => Boolean(config.supabaseUrl && config.supabaseSecretKey);

export const supabaseConfigured = configured;

/** PostgREST, as the service role. Bypasses RLS, so it stays on the server. */
async function rest(path, { method = 'GET', body, prefer } = {}) {
  if (!configured()) throw new Error('Supabase is not configured.');

  const response = await fetch(`${config.supabaseUrl}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: config.supabaseSecretKey,
      Authorization: `Bearer ${config.supabaseSecretKey}`,
      'Content-Type': 'application/json',
      ...(prefer ? { Prefer: prefer } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(config.requestTimeoutMs),
  });

  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`Supabase returned ${response.status} with an unreadable body.`);
  }
  if (!response.ok) {
    throw new Error(parsed?.message || parsed?.hint || `Supabase returned ${response.status}.`);
  }
  return parsed;
}

/* ---------- who is asking ---------- */

// A verified answer is held briefly so a page that fires several requests at
// once does not ask several times. Keyed by a digest, never by the token.
const VERIFY_TTL_MS = 60_000;
const seen = new Map(); // digest -> { at, ok, userId, email, admin, reason }

/**
 * Whose access token is this?
 *
 * Asks Supabase rather than checking a signature locally, so a deleted user or
 * a revoked session is refused straight away - a token stays cryptographically
 * valid until it expires whatever has happened to its owner since.
 *
 * `admin` is read from app_metadata, which only the server can write.
 * user_metadata is editable by the user it describes and must never decide it.
 */
export async function verifyUser(token) {
  if (!configured()) return { ok: false, reason: 'Supabase is not configured.' };
  if (!token) return { ok: false, reason: 'A Supabase access token is required.' };

  const digest = createHash('sha256').update(token).digest('hex');
  const cached = seen.get(digest);
  if (cached && Date.now() - cached.at < VERIFY_TTL_MS) return cached.result;

  let result;
  try {
    const response = await fetch(`${config.supabaseUrl}/auth/v1/user`, {
      headers: { apikey: config.supabaseSecretKey, Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });
    if (response.status === 401 || response.status === 403) {
      result = { ok: false, reason: 'That session is no longer valid. Sign in again.' };
    } else if (!response.ok) {
      // Not cached: an Auth outage should not lock someone out for a minute
      // after it ends.
      return { ok: false, reason: `Supabase Auth returned ${response.status}.` };
    } else {
      const user = await response.json();
      result = {
        ok: Boolean(user?.id),
        userId: user?.id ?? null,
        email: user?.email ?? null,
        admin: user?.app_metadata?.role === 'admin',
        ...(user?.id ? {} : { reason: 'Supabase Auth returned no user.' }),
      };
    }
  } catch (error) {
    return { ok: false, reason: `Could not reach Supabase Auth: ${error.message}` };
  }

  // Bound the map so a spray of tokens cannot grow it without limit.
  if (seen.size > 500) seen.clear();
  seen.set(digest, { at: Date.now(), result });
  return result;
}

/** As verifyUser, and the account must carry the admin claim. */
export async function verifyAdmin(token) {
  const user = await verifyUser(token);
  if (!user.ok) return user;
  return user.admin ? user : { ok: false, reason: 'That account is not an administrator.' };
}

/* ---------- observability ---------- */

/** Everything the dashboard shows, in one round of parallel reads. */
export async function gatewaySnapshot() {
  const [overview, tools, principals, errors, keys] = await Promise.all([
    rest('mcp_overview_24h?select=*').catch((error) => ({ error: error.message })),
    rest('mcp_tool_health_24h?select=*').catch(() => []),
    rest('mcp_top_principals_7d?select=*&limit=15').catch(() => []),
    rest('mcp_recent_errors?select=*&limit=25').catch(() => []),
    rest('mcp_keys_public?select=*&order=created_at.desc').catch(() => []),
  ]);

  return {
    overview: Array.isArray(overview) ? (overview[0] ?? null) : overview,
    tools: Array.isArray(tools) ? tools : [],
    principals: Array.isArray(principals) ? principals : [],
    errors: Array.isArray(errors) ? errors : [],
    keys: Array.isArray(keys) ? keys : [],
  };
}

/* ---------- accounts ---------- */

/**
 * Who has signed up, and on what terms.
 *
 * Sign-up is self-service through GitHub, so this list grows without anyone
 * deciding anything. Everyone starts on the new-account tier; this is where
 * someone is moved off it.
 */
export async function listUsers() {
  return (await rest('mcp_users_public?select=*&order=created_at.desc&limit=200').catch(() => [])) ?? [];
}

/** Raise or lower one account. Passing only a tier applies that tier's numbers. */
export async function setUserTier(userId, { tier, ratePerHour, depsPerHour, note }) {
  const rows = await rest('rpc/mcp_set_user_tier', {
    method: 'POST',
    body: {
      p_user_id: userId,
      p_tier: tier ?? null,
      p_rate: ratePerHour === undefined ? null : Number.parseInt(ratePerHour, 10),
      p_deps: depsPerHour === undefined ? null : Number.parseInt(depsPerHour, 10),
      p_note: note ?? null,
    },
  });
  if (!Array.isArray(rows) || !rows.length) throw new Error('No account with that id.');
  return rows[0];
}

/* ---------- key management ---------- */

const KEY_PREFIX = 'cvf_live_';

/**
 * Mint a key.
 *
 * The plaintext is returned once, here, and never stored: only its sha256 and
 * a displayable head go to the database. There is no path that recovers it,
 * which is the point - a leaked backup of mcp_keys authorises nothing.
 */
export async function issueKey({ label, ratePerHour, owner = null }) {
  const key = `${KEY_PREFIX}${randomBytes(24).toString('hex')}`;
  const rows = await rest('mcp_keys', {
    method: 'POST',
    prefer: 'return=representation',
    body: [
      {
        label: String(label || 'unnamed').slice(0, 80),
        // Long enough that a collision against the unique index is not a
        // practical concern, short enough to be a label rather than a secret.
        key_prefix: key.slice(0, KEY_PREFIX.length + 12),
        key_hash: createHash('sha256').update(key).digest('hex'),
        rate_per_hour: Math.min(Math.max(Number.parseInt(ratePerHour, 10) || 600, 1), 100_000),
        // A key a user mints is metered against that user by the gateway, so
        // its own rate_per_hour is informational for owned keys.
        ...(owner ? { owner } : {}),
      },
    ],
  });
  const row = Array.isArray(rows) ? rows[0] : rows;
  // Never echo the hash back, even to its owner.
  if (row) delete row.key_hash;
  return { key, row };
}

/** Revoke, restore, or change the limit on one key. */
export async function updateKey(id, { disabled, ratePerHour }, { owner } = {}) {
  const patch = {};
  if (disabled === true) patch.disabled_at = new Date().toISOString();
  if (disabled === false) patch.disabled_at = null;
  if (ratePerHour !== undefined) {
    patch.rate_per_hour = Math.min(Math.max(Number.parseInt(ratePerHour, 10) || 600, 1), 100_000);
  }
  if (!Object.keys(patch).length) throw new Error('Nothing to change.');

  // With an owner given, the filter itself is the authorisation: a user
  // naming someone else's key id matches no row and changes nothing.
  const scope = owner ? `&owner=eq.${encodeURIComponent(owner)}` : '';
  const rows = await rest(`mcp_keys?id=eq.${encodeURIComponent(id)}${scope}`, {
    method: 'PATCH',
    prefer: 'return=representation',
    body: patch,
  });
  if (!Array.isArray(rows) || !rows.length) throw new Error('No key with that id.');
  // Never echo the hash back, even to an admin.
  const { key_hash: _hash, ...safe } = rows[0];
  return safe;
}

/* ---------- the signed-in account ---------- */

const KEY_LIMIT_PER_USER = 3;
export const keyLimitPerUser = KEY_LIMIT_PER_USER;

/**
 * Everything the account panel shows for one person, in one round.
 *
 * mcp_user_quota provisions the new-account tier on first sight, so someone
 * who has only signed in to the website - never called the MCP endpoint - still
 * sees real limits rather than an empty panel.
 */
export async function accountSnapshot({ userId, email, admin }) {
  const principal = `user:${userId}`;
  const [tierRows, statusRows, keys] = await Promise.all([
    rest('rpc/mcp_user_quota', { method: 'POST', body: { p_user_id: userId, p_email: email } }),
    rest('rpc/mcp_quota_status', { method: 'POST', body: { p_principal: principal } }),
    rest(`mcp_keys_public?owner=eq.${encodeURIComponent(userId)}&order=created_at.desc`).catch(() => []),
  ]);

  const tier = (Array.isArray(tierRows) ? tierRows[0] : tierRows) ?? {};
  // An admin is not held to their quota row: the gateway gives admins their
  // own limits, so the panel must show the numbers that actually apply.
  const limits = admin
    ? { calls: 5000, deps: 500, web: 500 }
    : { calls: tier.rate_per_hour ?? 60, deps: tier.deps_per_hour ?? 10, web: tier.web_per_hour ?? 5 };

  const used = Object.fromEntries((Array.isArray(statusRows) ? statusRows : []).map((row) => [row.bucket, row]));
  const budget = (name) => ({
    limit: limits[name],
    used: used[name]?.used ?? 0,
    remaining: Math.max(limits[name] - (used[name]?.used ?? 0), 0),
    resetAt: used[name]?.reset_at ?? null,
  });

  return {
    email,
    tier: admin ? 'admin' : (tier.tier ?? 'new'),
    budgets: { calls: budget('calls'), deps: budget('deps'), web: budget('web') },
    keys: Array.isArray(keys) ? keys : [],
    keyLimit: KEY_LIMIT_PER_USER,
  };
}

/** How many live keys this person has, for the per-user cap. */
export async function activeKeyCount(userId) {
  const rows = await rest(
    `mcp_keys_public?owner=eq.${encodeURIComponent(userId)}&active=is.true&select=id`,
  ).catch(() => []);
  return Array.isArray(rows) ? rows.length : 0;
}

export default {
  supabaseConfigured,
  verifyUser,
  verifyAdmin,
  accountSnapshot,
  activeKeyCount,
  gatewaySnapshot,
  listUsers,
  setUserTier,
  issueKey,
  updateKey,
};
