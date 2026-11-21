-- Scheduling, kept in its own migration because it is the one part that
-- depends on the extension being available rather than on our own schema.
create extension if not exists pg_cron;

-- Idempotent: clear any previous incarnation before scheduling, so re-running
-- this migration cannot leave two copies of a job behind.
select cron.unschedule(jobid)
  from cron.job
 where jobname in ('mcp-rollup-hourly', 'mcp-prune-daily');

-- Off the hour, following the house convention for cron offsets, so these do
-- not pile onto whatever else runs at :00.
select cron.schedule('mcp-rollup-hourly', '7 * * * *',  $job$select public.mcp_rollup_usage();$job$);
select cron.schedule('mcp-prune-daily',   '23 3 * * *', $job$select public.mcp_prune();$job$);
