/**
 * Entry point.
 *
 * Named app.js on purpose: Hostinger's Node.js hosting (Passenger) looks for
 * this file at the project root by default. `server.js` beside it is the same
 * entry under the name most platform presets expect, so no host needs telling
 * where to start.
 *
 * Passenger loads this file with require(), so it must stay loadable that
 * way: no top-level await here or anywhere in the graph it pulls in. The
 * import below is first because it has to run before the server is evaluated
 * - see src/boot.js, which explains what it sets and why the ordering is
 * guaranteed.
 */
import './src/boot.js';
import { start } from './src/server.js';

start();
