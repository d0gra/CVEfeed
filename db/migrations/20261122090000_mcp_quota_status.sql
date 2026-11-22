-- Quota you can see, and keys that share their owner's budget.
--
-- Three changes, all in service of the signed-in account page and the
-- `account` tool:
--
--   1. mcp_quota_status reads the current window without spending it. The
--      only quota function so far was mcp_consume_quota, which increments as
--      it reads, so "how much have I used" could not be asked without using
--      some.
--   2. A third budget, web lookups, for research_vulnerability. Each one costs
--      real money with the search provider, so it is the smallest of the three.
--   3. mcp_authorize_key returns the key's owner. A key a user mints for CI is
--      metered against that user, not against itself - otherwise anyone could
--      multiply their allowance by minting keys.

alter table public.mcp_user_quotas
  add column web_per_hour integer not null default 5 check (web_per_hour > 0);

-- The new column has to be in the dashboard's view too. Appending a column is
-- the one change CREATE OR REPLACE VIEW allows.
create or replace view public.mcp_users_public with (security_invoker = true) as
  select q.user_id,
         q.email,
         q.tier,
         q.rate_per_hour,
         q.deps_per_hour,
         q.note,
         q.created_at,
         q.updated_at,
         (select count(*) from public.mcp_calls c
           where c.principal = 'user:' || q.user_id::text
             and c.at >= now() - interval '7 days') as calls_7d,
         q.web_per_hour
    from public.mcp_user_quotas q;

/* ---------- functions whose return shape changes ---------- */

-- A function's result type cannot be altered in place, so these three are
-- dropped and recreated. All of it runs in one transaction, so there is no
-- moment at which the gateway finds them missing.

drop function public.mcp_user_quota(uuid, text);
create function public.mcp_user_quota(p_user_id uuid, p_email text default null)
returns table (tier text, rate_per_hour integer, deps_per_hour integer, web_per_hour integer)
language sql
set search_path = ''
as $$
  insert into public.mcp_user_quotas (user_id, email)
       values (p_user_id, p_email)
  on conflict (user_id) do update
     set email      = coalesce(excluded.email, public.mcp_user_quotas.email),
         updated_at = clock_timestamp()
  returning tier, rate_per_hour, deps_per_hour, web_per_hour;
$$;

drop function public.mcp_set_user_tier(uuid, text, integer, integer, text);
create function public.mcp_set_user_tier(
  p_user_id uuid,
  p_tier    text,
  p_rate    integer default null,
  p_deps    integer default null,
  p_note    text    default null,
  p_web     integer default null
)
returns setof public.mcp_user_quotas
language sql
set search_path = ''
as $$
  update public.mcp_user_quotas
     set tier          = coalesce(p_tier, tier),
         rate_per_hour = coalesce(p_rate,
                           case when p_tier is null    then rate_per_hour
                                when p_tier = 'admin'  then 5000
                                when p_tier = 'raised' then 600
                                else 60 end),
         deps_per_hour = coalesce(p_deps,
                           case when p_tier is null    then deps_per_hour
                                when p_tier = 'admin'  then 500
                                when p_tier = 'raised' then 60
                                else 10 end),
         web_per_hour  = coalesce(p_web,
                           case when p_tier is null    then web_per_hour
                                when p_tier = 'admin'  then 500
                                when p_tier = 'raised' then 50
                                else 5 end),
         note          = coalesce(p_note, note),
         updated_at    = clock_timestamp()
   where user_id = p_user_id
  returning *;
$$;

drop function public.mcp_authorize_key(text);
create function public.mcp_authorize_key(p_key_hash text)
returns table (key_id uuid, principal text, rate_per_hour integer, scopes text[], owner uuid)
language sql
stable
set search_path = ''
as $$
  select k.id,
         'key:' || k.id::text,
         k.rate_per_hour,
         k.scopes,
         k.owner
    from public.mcp_keys k
   where k.key_hash = p_key_hash
     and k.disabled_at is null;
$$;

/**
 * How much of each budget a principal has spent this window. Reads only.
 *
 * The window arithmetic matches mcp_consume_quota exactly - fixed hour-long
 * windows on the epoch - so the two can never disagree about which bucket is
 * current. A bucket with no row yet has spent nothing.
 */
create function public.mcp_quota_status(p_principal text, p_window interval default interval '1 hour')
returns table (bucket text, used integer, reset_at timestamptz)
language sql
set search_path = ''
as $$
  with win as (
    select to_timestamp(floor(extract(epoch from clock_timestamp()) / extract(epoch from p_window))
                        * extract(epoch from p_window)) as start
  ),
  buckets(bucket, principal) as (
    values ('calls', p_principal), ('deps', p_principal || ':deps'), ('web', p_principal || ':web')
  )
  select b.bucket,
         coalesce(q.calls, 0),
         (select start from win) + p_window
    from buckets b
    left join public.mcp_quota_buckets q
           on q.principal = b.principal
          and q.window_start = (select start from win);
$$;

/* ---------- grants ---------- */

do $grants$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as sig
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and p.proname in ('mcp_user_quota', 'mcp_set_user_tier', 'mcp_authorize_key', 'mcp_quota_status')
  loop
    execute format('revoke execute on function %s from public, anon, authenticated', fn.sig);
    execute format('grant execute on function %s to service_role', fn.sig);
  end loop;
end
$grants$;
