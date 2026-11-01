/**
 * PM2 config for a Hostinger VPS.
 *   npm install -g pm2
 *   pm2 start ecosystem.config.cjs && pm2 save && pm2 startup
 *
 * The two pool settings are about a process cap rather than performance. The
 * host counts threads as processes, and a default Node process on a many-core
 * machine starts around a dozen threads: one main, four for libuv, and one V8
 * platform worker per core up to a limit. Neither pool is doing real work here
 * - this app waits on network, it does not compute - so both are pinned small.
 * Together they take a process from roughly twelve threads to eight.
 */
module.exports = {
  apps: [
    {
      name: 'cvefeed',
      script: 'app.js',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_memory_restart: '400M',
      // Give a drain long enough to finish in-flight requests and close the
      // database client, so a restart never overlaps two full-sized processes.
      kill_timeout: 10000,
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        UV_THREADPOOL_SIZE: '2',
        NODE_OPTIONS: '--v8-pool-size=2',
      },
    },
  ],
};
