/**
 * Entry point.
 *
 * Named app.js on purpose: Hostinger's Node.js hosting (Passenger) looks for
 * this file at the project root by default. `server.js` beside it is the same
 * entry under the name most platform presets expect, so no host needs telling
 * where to start.
 */
import { start } from './src/server.js';

start();
