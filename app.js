/**
 * Entry point.
 *
 * Named app.js on purpose: Hostinger's Node.js hosting (Passenger) looks for
 * this file at the project root by default, so the app needs no extra config.
 */
import { start } from './src/server.js';

start();
