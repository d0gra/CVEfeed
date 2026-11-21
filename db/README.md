# Database migrations

SQL for the Supabase Postgres project (`imphhoxdrcgmjnamstbi`), which backs the
MCP gateway: API keys, quotas, the response cache, the audit trail and the
admin views. The vulnerability corpus is **not** here - that stays in MongoDB
Atlas, reached by the gateway only on a cache miss.

Migrations live here rather than under `supabase/migrations/` so all database
work sits with the rest of the codebase. The Supabase CLI will not find them at
this path, which is deliberate: they are applied over the authenticated
Supabase MCP connection (`apply_migration`), not with `supabase db push`.

Files are `<UTC timestamp>_<snake_case name>.sql` and are applied in filename
order. They are expected to be idempotent where cheap to make so (`if not
exists`, `on conflict`, unschedule-then-schedule).

If you later want `supabase db push` to work, symlink the directory:

    ln -s ../../db/migrations supabase/migrations
