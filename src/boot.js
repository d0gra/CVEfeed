/**
 * Runtime sizing, applied before anything else is evaluated.
 *
 * This is a module of its own, imported first by the entry point, for a
 * reason worth writing down. The host counts threads against a process cap,
 * and libuv fixes its pool size from UV_THREADPOOL_SIZE the first time
 * anything uses the pool - a DNS lookup, zlib, a file read - so the variable
 * has to be set before the app is evaluated, not merely before it listens.
 *
 * The obvious way to guarantee that is `await import()` in the entry point,
 * after the assignment. Do not: Passenger loads the entry file with
 * `require()`, and require() of an ES module graph containing top-level await
 * throws ERR_REQUIRE_ASYNC_MODULE. The app then never listens and the host
 * serves 503. That is not hypothetical - it is what happened.
 *
 * A plain side-effect import is both safe and sufficient. ES modules are
 * evaluated depth-first in the order their import declarations appear, so
 * this file's assignment runs to completion before the server module begins
 * evaluating, and nothing here makes the graph asynchronous.
 *
 * Two threads is well under Node's default of four, and right for this app:
 * the only pool work it does is DNS resolution and gzip, neither on a hot
 * path. The matching V8 setting, --v8-pool-size, can only come from the
 * command line, so it stays an environment variable (see .env.example).
 */
process.env.UV_THREADPOOL_SIZE ??= '2';
