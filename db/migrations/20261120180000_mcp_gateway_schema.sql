-- The MCP gateway's own state: who may call, how often, what was cached, and
-- what happened. None of the vulnerability corpus lives here - that stays in
-- Mongo on Hostinger, reached only on a cache miss.
--
-- Every table carries RLS because `public` is reachable through the Data API.
-- The gateway itself connects with the secret key (service_role), which
-- bypasses RLS entirely; the policies below exist so that an admin reading
-- from a browser session gets the same answers and nobody else gets any.

/* ---------- api keys ---------- */

create table public.mcp_keys (
  id            uuid primary key default gen_random_uuid(),
  -- Null for a key that belongs to no Supabase user: a CI runner, a script.
  owner         uuid references auth.users (id) on delete set null,
  label         text not null check (char_length(label) between 1 and 80),
  -- The displayable head of the key, e.g. 'cvf_live_8f2a'. Shown in the admin
  -- UI so a key can be recognised without ever storing the secret.
  key_prefix    text not null unique,
  -- sha256 of the whole key. The plaintext is shown once, at issue time, and
  -- is not recoverable from here.
  key_hash      text not null unique,
  rate_per_hour integer not null default 600 check (rate_per_hour > 0),
  scopes        text[] not null default array['tools:*']::text[],
  -- Revocation is a timestamp, not a delete, so the audit trail keeps its
  -- foreign subject and "when was this turned off?" has an answer.
  disabled_at   timestamptz,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz
);

comment on table public.mcp_keys is
  'Bearer API keys for the MCP gateway. Stores a sha256 hash only; key_hash is never granted to any client role.';

create index mcp_keys_owner_idx on public.mcp_keys (owner) where owner is not null;

/* ---------- quotas ---------- */

-- A fixed window per principal, matching the semantics of the in-process
-- limiter this replaces (src/lib/ratelimit.js): the worst case is a caller
-- getting up to 2x the limit across a window boundary, which does not matter
-- at these thresholds. Unlike that one, this survives a restart and is shared
-- by every edge worker.
create table public.mcp_quota_buckets (
  -- 'key:<uuid>' or 'user:<uuid>', so both auth paths meter identically.
  principal    text not null,
  window_start timestamptz not null,
  calls        integer not null default 0,
  primary key (principal, window_start)
);

comment on table public.mcp_quota_buckets is
  'Fixed-window call counters per principal. Pruned daily; carries no history worth keeping.';

create index mcp_quota_window_idx on public.mcp_quota_buckets (window_start);

/* ---------- response cache ---------- */

-- Tool results carry no per-principal data, so one global cache serves every
-- caller. That is what keeps Hostinger's share of the traffic down to the
-- miss rate, and it is the number worth watching after rollout.
create table public.mcp_cache (
  cache_key  text primary key,
  tool       text not null,
  payload    jsonb not null,
  bytes      integer not null default 0,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  hits       integer not null default 0
);

comment on table public.mcp_cache is
  'Global cache of MCP tool results, keyed by sha256(tool + canonicalised arguments).';

create index mcp_cache_expires_idx on public.mcp_cache (expires_at);

/* ---------- audit trail ---------- */

create table public.mcp_calls (
  id             bigint generated always as identity primary key,
  at             timestamptz not null default now(),
  principal      text not null,
  principal_kind text not null check (principal_kind in ('key', 'user', 'anonymous')),
  tool           text,
  outcome        text not null check (outcome in
                   ('ok', 'tool_error', 'validation_error', 'quota', 'auth', 'upstream_error', 'internal')),
  error_code     text,
  duration_ms    integer,
  -- Time spent waiting on Hostinger. duration_ms minus this is the gateway's
  -- own overhead, which is the thing we can actually fix.
  upstream_ms    integer,
  cache_hit      boolean not null default false,
  bytes_out      integer,
  -- A digest and a bounded summary, never the arguments themselves: a pasted
  -- lockfile names a company's private dependencies and has no business
  -- sitting in an audit log.
  args_digest    text,
  args_summary   jsonb,
  client         text,
  ip_hash        text
);

comment on table public.mcp_calls is
  'One row per MCP message. Retained 30 days, then folded into mcp_usage_daily by mcp_rollup_usage().';
comment on column public.mcp_calls.args_summary is
  'Bounded, non-identifying shape of the arguments (package_count, ecosystems, filters). Never raw argument values.';

create index mcp_calls_at_idx on public.mcp_calls (at desc);
create index mcp_calls_tool_at_idx on public.mcp_calls (tool, at desc);
create index mcp_calls_principal_at_idx on public.mcp_calls (principal, at desc);
create index mcp_calls_errors_idx on public.mcp_calls (at desc) where outcome <> 'ok';

/* ---------- usage rollup ---------- */

-- mcp_calls is pruned at 30 days; this is what survives, so year-on-year
-- questions stay answerable without keeping every row.
create table public.mcp_usage_daily (
  day        date not null,
  principal  text not null,
  tool       text not null,
  calls      integer not null default 0,
  errors     integer not null default 0,
  cache_hits integer not null default 0,
  bytes_out  bigint  not null default 0,
  p95_ms     integer,
  primary key (day, principal, tool)
);

comment on table public.mcp_usage_daily is
  'Permanent daily rollup of mcp_calls, recomputed idempotently by mcp_rollup_usage().';

create index mcp_usage_daily_day_idx on public.mcp_usage_daily (day desc);

/* ---------- tool manifest ---------- */

-- The tool schemas stay authored in src/mcp.js on Hostinger; this is the
-- gateway's cached copy, so tools/list still answers when Hostinger is down
-- and argument validation has something to validate against.
create table public.mcp_tool_manifest (
  id         boolean primary key default true check (id),
  version    text not null,
  tools      jsonb not null,
  fetched_at timestamptz not null default now()
);

comment on table public.mcp_tool_manifest is
  'Single-row cache of the TOOLS array fetched from Hostinger. The CHECK on a boolean PK keeps it to one row.';

/* ---------- row level security ---------- */

alter table public.mcp_keys           enable row level security;
alter table public.mcp_quota_buckets  enable row level security;
alter table public.mcp_cache          enable row level security;
alter table public.mcp_calls          enable row level security;
alter table public.mcp_usage_daily    enable row level security;
alter table public.mcp_tool_manifest  enable row level security;

-- Admin is claimed in app_metadata, which only the server can write.
-- raw_user_meta_data is user-editable and must never decide authorization.
create function public.mcp_is_admin()
returns boolean
language sql
stable
set search_path = ''
as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false);
$$;

comment on function public.mcp_is_admin() is
  'True when the caller presents an admin claim in app_metadata. Never reads user_metadata, which the user can edit.';

grant execute on function public.mcp_is_admin() to authenticated;

-- Readable by an admin browser session. Everything else that touches these
-- tables goes through the secret key, which does not consult RLS.
create policy "admin reads keys" on public.mcp_keys
  for select to authenticated using ((select public.mcp_is_admin()));

create policy "admin reads calls" on public.mcp_calls
  for select to authenticated using ((select public.mcp_is_admin()));

create policy "admin reads usage" on public.mcp_usage_daily
  for select to authenticated using ((select public.mcp_is_admin()));

-- mcp_quota_buckets, mcp_cache and mcp_tool_manifest get no policies at all:
-- they are gateway machinery, and the admin page reads their summaries
-- through the secret key. RLS on with no policy denies every client role.

/* ---------- grants ---------- */

-- Supabase's default privileges hand new public tables to anon and
-- authenticated, so take that back and grant only what is wanted. Being
-- explicit here means the result does not depend on project-level Data API
-- settings.
revoke all on public.mcp_keys          from anon, authenticated;
revoke all on public.mcp_quota_buckets from anon, authenticated;
revoke all on public.mcp_cache         from anon, authenticated;
revoke all on public.mcp_calls         from anon, authenticated;
revoke all on public.mcp_usage_daily   from anon, authenticated;
revoke all on public.mcp_tool_manifest from anon, authenticated;

-- Column-level, deliberately omitting key_hash: an admin can manage keys
-- through the Data API without the hash ever being selectable.
grant select (id, owner, label, key_prefix, rate_per_hour, scopes,
              disabled_at, created_at, last_used_at)
  on public.mcp_keys to authenticated;

grant select on public.mcp_calls       to authenticated;
grant select on public.mcp_usage_daily to authenticated;
