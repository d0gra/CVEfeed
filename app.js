/**
 * Entry point.
 *
 * Named app.js on purpose: Hostinger's Node.js hosting (Passenger) looks for
 * this file at the project root by default. `server.js` beside it is the same
 * entry under the name most platform presets expect, so no host needs telling
 * where to start.
 *
 * The threadpool is sized here, before the app is loaded, because the host
 * counts threads against a process limit. Node sizes libuv's pool from
 * UV_THREADPOOL_SIZE the first time anything uses it - a DNS lookup, zlib, a
 * file read - and the size is fixed from then on. A static `import` would be
 * hoisted above this assignment and could trigger exactly that, so the app is
 * pulled in with a dynamic import, which is not hoisted.
 *
 * Four threads is Node's default and more than this app needs: the work that
 * uses the pool here is DNS resolution and gzip, neither of which is on a hot
 * path. Set UV_THREADPOOL_SIZE in the environment to override.
 */
process.env.UV_THREADPOOL_SIZE ??= '2';

const { start } = await import('./src/server.js');

start();
