-- The gateway's server-side logic: authorise, meter, cache, log, roll up,
-- prune. The edge function calls these with the secret key, so they are
-- SECURITY INVOKER - service_role already bypasses RLS, and a SECURITY
-- DEFINER function in `public` would be a public endpoint callable by anon.
-- Execute is revoked from PUBLIC at the bottom for the same reason.

/* ---------- authorisation ---------- */

create function public.mcp_authorize_key(p_key_hash text)
returns table (key_id uuid, principal text, rate_per_hour integer, scopes text[])
language sql
stable
set search_path = ''
as $$
  select k.id,
         'key:' || k.id::text,
         k.rate_per_hour,
         k.scopes
    from public.mcp_keys k
   where k.key_hash = p_key_hash
     and k.disabled_at is null;
$$;

comment on function public.mcp_authorize_key(text) is
  'Resolves a sha256 key hash to a principal. Returns no row for an unknown or revoked key.';

/* ---------- quota ---------- */

-- Charged per JSON-RPC message, not per HTTP request: a batch of ten tool
-- calls costs ten. That is the hole in the endpoint this replaces, where one
-- request carrying 500 messages cost a single token.
create function public.mcp_consume_quota(
  p_principal text,
  p_limit     integer,
  p_window    interval default interval '1 hour'
)
returns table (allowed boolean, remaining integer, reset_at timestamptz)
language plpgsql
set search_path = ''
as $$
declare
  v_secs  double precision := extract(epoch from p_window);
  v_start timestamptz;
  v_calls integer;
begin
  -- Fixed windows, so every worker agrees on the boundary without talking to
  -- the others.
  v_start := to_timestamp(floor(extract(epoch from clock_timestamp()) / v_secs) * v_secs);

  insert into public.mcp_quota_buckets as b (principal, window_start, calls)
       values (p_principal, v_start, 1)
  on conflict (principal, window_start)
    do update set calls = b.calls + 1
    returning b.calls into v_calls;

  return query
    select v_calls <= p_limit,
           greatest(p_limit - v_calls, 0),
           v_start + p_window;
end;
$$;

comment on function public.mcp_consume_quota(text, integer, interval) is
  'Atomically increments and tests the caller''s fixed-window counter. Charge once per JSON-RPC message.';

/* ---------- cache ---------- */

create function public.mcp_cache_get(p_key text)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
  v_payload jsonb;
begin
  -- Read and count the hit in one statement, so concurrent workers cannot
  -- lose a count and an expired row can never be served.
  update public.mcp_cache
     set hits = hits + 1
   where cache_key = p_key
     and expires_at > clock_timestamp()
  returning payload into v_payload;

  return v_payload;
end;
$$;

create function public.mcp_cache_put(
  p_key     text,
  p_tool    text,
  p_payload jsonb,
  p_ttl     interval
)
returns void
language sql
set search_path = ''
as $$
  insert into public.mcp_cache (cache_key, tool, payload, bytes, expires_at)
       values (p_key, p_tool, p_payload,
               octet_length(p_payload::text),
               clock_timestamp() + p_ttl)
  on conflict (cache_key) do update
     set payload    = excluded.payload,
         tool       = excluded.tool,
         bytes      = excluded.bytes,
         created_at = clock_timestamp(),
         expires_at = excluded.expires_at,
         hits       = 0;
$$;

/* ---------- audit ---------- */

create function public.mcp_log_call(
  p_principal      text,
  p_principal_kind text,
  p_outcome        text,
  p_tool           text    default null,
  p_error_code     text    default null,
  p_duration_ms    integer default null,
  p_upstream_ms    integer default null,
  p_cache_hit      boolean default false,
  p_bytes_out      integer default null,
  p_args_digest    text    default null,
  p_args_summary   jsonb   default null,
  p_client         text    default null,
  p_ip_hash        text    default null
)
returns void
language plpgsql
set search_path = ''
as $$
begin
  insert into public.mcp_calls
    (principal, principal_kind, tool, outcome, error_code, duration_ms,
     upstream_ms, cache_hit, bytes_out, args_digest, args_summary, client, ip_hash)
  values
    (p_principal, p_principal_kind, p_tool, p_outcome, p_error_code, p_duration_ms,
     p_upstream_ms, p_cache_hit, p_bytes_out, p_args_digest, p_args_summary, p_client, p_ip_hash);

  if p_principal_kind = 'key' and p_principal like 'key:%' then
    -- A malformed principal must not cost us the audit row that is already in.
    begin
      update public.mcp_keys
         set last_used_at = clock_timestamp()
       where id = substring(p_principal from 5)::uuid;
    exception when invalid_text_representation then
      null;
    end;
  end if;
end;
$$;

comment on function public.mcp_log_call is
  'Writes one audit row and touches the key''s last_used_at. Pass a digest and a bounded summary, never raw arguments.';

/* ---------- rollup and prune ---------- */

-- Recomputes whole days from mcp_calls rather than accumulating, so running
-- it twice is harmless and a late-arriving row is still counted. Two days by
-- default, which covers the first run after midnight.
create function public.mcp_rollup_usage(p_days integer default 2)
returns integer
language plpgsql
set search_path = ''
as $$
declare
  v_rows integer;
begin
  with src as (
    select (c.at at time zone 'UTC')::date          as day,
           c.principal,
           coalesce(c.tool, '(none)')               as tool,
           count(*)                                 as calls,
           count(*) filter (where c.outcome <> 'ok') as errors,
           count(*) filter (where c.cache_hit)      as cache_hits,
           coalesce(sum(c.bytes_out), 0)            as bytes_out,
           percentile_disc(0.95) within group (order by c.duration_ms)
             filter (where c.duration_ms is not null) as p95_ms
      from public.mcp_calls c
     where c.at >= date_trunc('day', clock_timestamp())
                   - make_interval(days => greatest(p_days - 1, 0))
     group by 1, 2, 3
  )
  insert into public.mcp_usage_daily
        (day, principal, tool, calls, errors, cache_hits, bytes_out, p95_ms)
  select day, principal, tool, calls, errors, cache_hits, bytes_out, p95_ms
    from src
  on conflict (day, principal, tool) do update
     set calls      = excluded.calls,
         errors     = excluded.errors,
         cache_hits = excluded.cache_hits,
         bytes_out  = excluded.bytes_out,
         p95_ms     = excluded.p95_ms;

  get diagnostics v_rows = row_count;
  return v_rows;
end;
$$;

-- Retention is load-bearing, not hygiene: the free plan allows 500MB of
-- database against 500k edge invocations a month, and an unpruned audit
-- trail would reach a sizeable fraction of that on its own.
create function public.mcp_prune(p_retain_days integer default 30)
returns table (calls_deleted bigint, cache_deleted bigint, buckets_deleted bigint)
language plpgsql
set search_path = ''
as $$
declare
  v_calls   bigint;
  v_cache   bigint;
  v_buckets bigint;
begin
  delete from public.mcp_calls
   where at < clock_timestamp() - make_interval(days => p_retain_days);
  get diagnostics v_calls = row_count;

  delete from public.mcp_cache where expires_at < clock_timestamp();
  get diagnostics v_cache = row_count;

  delete from public.mcp_quota_buckets
   where window_start < clock_timestamp() - interval '2 days';
  get diagnostics v_buckets = row_count;

  return query select v_calls, v_cache, v_buckets;
end;
$$;

/* ---------- admin views ---------- */

-- security_invoker so the reader's own RLS applies. Without it a view runs as
-- its owner and would hand every authenticated user the whole audit trail.

create view public.mcp_keys_public with (security_invoker = true) as
  select k.id, k.owner, k.label, k.key_prefix, k.rate_per_hour, k.scopes,
         k.disabled_at, k.created_at, k.last_used_at,
         (k.disabled_at is null) as active
    from public.mcp_keys k;

comment on view public.mcp_keys_public is
  'Key metadata without key_hash, which no client role is granted on the base table.';

create view public.mcp_overview_24h with (security_invoker = true) as
  select count(*)                                          as calls,
         count(distinct c.principal)                        as principals,
         count(*) filter (where c.outcome <> 'ok')           as errors,
         count(*) filter (where c.cache_hit)                as cache_hits,
         round(100.0 * count(*) filter (where c.cache_hit)
               / greatest(count(*), 1), 1)                  as cache_hit_pct,
         percentile_disc(0.50) within group (order by c.duration_ms)
           filter (where c.duration_ms is not null)         as p50_ms,
         percentile_disc(0.95) within group (order by c.duration_ms)
           filter (where c.duration_ms is not null)         as p95_ms,
         percentile_disc(0.99) within group (order by c.duration_ms)
           filter (where c.duration_ms is not null)         as p99_ms,
         coalesce(sum(c.bytes_out), 0)                      as bytes_out
    from public.mcp_calls c
   where c.at >= now() - interval '24 hours';

create view public.mcp_tool_health_24h with (security_invoker = true) as
  select coalesce(c.tool, '(none)')                        as tool,
         count(*)                                          as calls,
         count(*) filter (where c.outcome <> 'ok')          as errors,
         round(100.0 * count(*) filter (where c.outcome <> 'ok')
               / greatest(count(*), 1), 1)                  as error_pct,
         round(100.0 * count(*) filter (where c.cache_hit)
               / greatest(count(*), 1), 1)                  as cache_hit_pct,
         percentile_disc(0.95) within group (order by c.duration_ms)
           filter (where c.duration_ms is not null)         as p95_ms,
         percentile_disc(0.95) within group (order by c.upstream_ms)
           filter (where c.upstream_ms is not null)         as p95_upstream_ms
    from public.mcp_calls c
   where c.at >= now() - interval '24 hours'
   group by 1
   order by 2 desc;

create view public.mcp_top_principals_7d with (security_invoker = true) as
  select c.principal,
         c.principal_kind,
         count(*)                                          as calls,
         count(*) filter (where c.outcome <> 'ok')          as errors,
         count(*) filter (where c.outcome = 'quota')        as throttled,
         coalesce(sum(c.bytes_out), 0)                     as bytes_out,
         max(c.at)                                         as last_seen
    from public.mcp_calls c
   where c.at >= now() - interval '7 days'
   group by 1, 2
   order by 3 desc
   limit 50;

create view public.mcp_recent_errors with (security_invoker = true) as
  select c.at, c.principal, c.principal_kind, c.tool, c.outcome,
         c.error_code, c.duration_ms, c.args_summary, c.client
    from public.mcp_calls c
   where c.outcome <> 'ok'
   order by c.at desc
   limit 200;

/* ---------- grants ---------- */

-- Only the gateway calls these, and it connects with the secret key. Postgres
-- grants EXECUTE to PUBLIC on every new function, so take it back.
--
-- The signatures are read from the catalogue rather than written out here. A
-- hand-written argument list is one typo away from failing the whole statement,
-- and rots silently the first time a parameter is added.
do $grants$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as sig
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and p.proname in ('mcp_authorize_key', 'mcp_consume_quota', 'mcp_cache_get',
                         'mcp_cache_put', 'mcp_log_call', 'mcp_rollup_usage', 'mcp_prune')
  loop
    execute format('revoke execute on function %s from public, anon, authenticated', fn.sig);
    execute format('grant execute on function %s to service_role', fn.sig);
  end loop;
end
$grants$;

revoke all on
    public.mcp_keys_public,
    public.mcp_overview_24h,
    public.mcp_tool_health_24h,
    public.mcp_top_principals_7d,
    public.mcp_recent_errors
  from anon, authenticated;

grant select on
    public.mcp_keys_public,
    public.mcp_overview_24h,
    public.mcp_tool_health_24h,
    public.mcp_top_principals_7d,
    public.mcp_recent_errors
  to authenticated;
