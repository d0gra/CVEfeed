-- Self-service sign-up, without handing a stranger the run of the place.
--
-- Anyone can now connect by signing in with GitHub, so a new account appears
-- without an administrator doing anything. The limit therefore cannot live in
-- a constant in the edge function, as it did: it has to be a per-account
-- record that starts modest and can be raised deliberately.
--
-- Two limits, not one. check_dependencies fans out to OSV.dev and a CVE miss
-- fans out to the registers - including GitHub's anonymous budget of 60 an
-- hour, which is the whole host's and not ours - so the expensive tool gets a
-- tighter ceiling than the cheap ones. The existing mcp_consume_quota serves
-- both by metering a second principal key, '<principal>:deps', which needs no
-- new table and no new function.

create table public.mcp_user_quotas (
  user_id       uuid primary key references auth.users (id) on delete cascade,
  tier          text not null default 'new' check (tier in ('new', 'raised', 'admin')),
  rate_per_hour integer not null default 60 check (rate_per_hour > 0),
  -- Deliberately much smaller: this is the budget that reaches third parties.
  deps_per_hour integer not null default 10 check (deps_per_hour > 0),
  -- Denormalised from the JWT on first sight. auth.users is not reachable
  -- through the Data API, and the dashboard needs something more legible than
  -- a uuid to decide whether to raise someone.
  email         text,
  note          text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

comment on table public.mcp_user_quotas is
  'Per-account limits for OAuth principals. A row appears on first authenticated call; the defaults are the new-account tier.';

create index mcp_user_quotas_tier_idx on public.mcp_user_quotas (tier, created_at desc);

alter table public.mcp_user_quotas enable row level security;

-- An admin reads this from a browser session; the gateway reads it with the
-- secret key, which does not consult RLS.
create policy "admin reads user quotas" on public.mcp_user_quotas
  for select to authenticated using ((select public.mcp_is_admin()));

revoke all on public.mcp_user_quotas from anon, authenticated;
grant select on public.mcp_user_quotas to authenticated;

/**
 * The limits for one account, creating the row if this is the first time we
 * have seen them.
 *
 * Upsert rather than a trigger on auth.users: a trigger would couple this
 * schema to the auth schema and need SECURITY DEFINER to cross it, and the
 * gateway already has the user in hand at exactly the moment the row is
 * wanted. The email is refreshed each time so a change at the provider
 * follows through.
 */
create function public.mcp_user_quota(p_user_id uuid, p_email text default null)
returns table (tier text, rate_per_hour integer, deps_per_hour integer)
language sql
set search_path = ''
as $$
  insert into public.mcp_user_quotas (user_id, email)
       values (p_user_id, p_email)
  on conflict (user_id) do update
     set email      = coalesce(excluded.email, public.mcp_user_quotas.email),
         updated_at = clock_timestamp()
  returning tier, rate_per_hour, deps_per_hour;
$$;

comment on function public.mcp_user_quota(uuid, text) is
  'Limits for one OAuth account, provisioning the new-account tier on first sight.';

/** Raise or lower one account. The dashboard's only write here. */
create function public.mcp_set_user_tier(
  p_user_id uuid,
  p_tier    text,
  p_rate    integer default null,
  p_deps    integer default null,
  p_note    text default null
)
returns setof public.mcp_user_quotas
language sql
set search_path = ''
as $$
  update public.mcp_user_quotas
     set tier          = coalesce(p_tier, tier),
         rate_per_hour = coalesce(p_rate,
                           case when p_tier is null     then rate_per_hour
                                when p_tier = 'admin'   then 5000
                                when p_tier = 'raised'  then 600
                                else 60 end),
         deps_per_hour = coalesce(p_deps,
                           case when p_tier is null     then deps_per_hour
                                when p_tier = 'admin'   then 500
                                when p_tier = 'raised'  then 60
                                else 10 end),
         note          = coalesce(p_note, note),
         updated_at    = clock_timestamp()
   where user_id = p_user_id
  returning *;
$$;

/* ---------- grants ---------- */

-- Only the gateway and the dashboard call these, both with the secret key.
do $grants$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as sig
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and p.proname in ('mcp_user_quota', 'mcp_set_user_tier')
  loop
    execute format('revoke execute on function %s from public, anon, authenticated', fn.sig);
    execute format('grant execute on function %s to service_role', fn.sig);
  end loop;
end
$grants$;

/** Everything the dashboard needs about accounts, in one read. */
create view public.mcp_users_public with (security_invoker = true) as
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
             and c.at >= now() - interval '7 days') as calls_7d
    from public.mcp_user_quotas q;

revoke all on public.mcp_users_public from anon, authenticated;
grant select on public.mcp_users_public to authenticated;
