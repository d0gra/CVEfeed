/**
 * Whether this process may rebuild data implicitly - because a request found
 * it stale - or only read what a refresh left behind.
 *
 * Its own module because both the feed and the exploit index need the answer,
 * and the feed already imports the exploit module: defining it in either one
 * would make the two import each other.
 *
 * "Read-only" is about implicit rebuilds only. scripts/refresh.js runs with
 * the same answer and still refreshes, because it calls the explicit
 * refreshFeed / refreshExploitIndex rather than waiting for something to go
 * stale.
 */
import config from '../config.js';
import { mongoConfigured } from './mongo.js';

export const readOnly = () => mongoConfigured() && !config.webRefresh;

export default { readOnly };
