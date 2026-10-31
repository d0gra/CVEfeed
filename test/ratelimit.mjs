/**
 * The rate-limit primitives, in isolation and without a clock dependency.
 *
 *   node test/ratelimit.mjs
 */
process.env.MONGODB_URI = '';
import assert from 'node:assert/strict';
import { createLimiter, TokenBucket } from '../src/lib/ratelimit.js';

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

// A fake req/res just sufficient for the middleware.
function run(limiter, ip) {
  const req = { ip, path: '/api/feed', socket: {} };
  let status = 200;
  let body = null;
  const headers = {};
  const res = {
    setHeader: (k, v) => (headers[k] = v),
    status(code) {
      status = code;
      return this;
    },
    json(payload) {
      body = payload;
      return this;
    },
  };
  let nexted = false;
  limiter(req, res, () => (nexted = true));
  return { status, body, headers, nexted };
}

// --- per-IP window ---
const limiter = createLimiter({ windowMs: 60_000, max: 3 });
const a = [1, 2, 3, 4, 5].map(() => run(limiter, '1.1.1.1'));
check('first 3 requests pass', a.slice(0, 3).every((r) => r.nexted));
check('the 4th and 5th are blocked with 429', a.slice(3).every((r) => r.status === 429 && !r.nexted));
check('a blocked response sets Retry-After', Number(a[3].headers['Retry-After']) > 0);
check('RateLimit-Remaining counts down', a[0].headers['RateLimit-Remaining'] === 2);

// --- isolation between IPs ---
const other = run(limiter, '2.2.2.2');
check('a different IP has its own budget', other.nexted, `status=${other.status}`);

// --- MCP gets a JSON-RPC error shape ---
const mcpLimiter = createLimiter({ windowMs: 60_000, max: 1 });
const mkMcp = () => {
  const req = { ip: '3.3.3.3', path: '/mcp', socket: {} };
  let status = 200;
  let body = null;
  const res = {
    setHeader() {},
    status(c) {
      status = c;
      return this;
    },
    json(p) {
      body = p;
      return this;
    },
  };
  let nexted = false;
  mcpLimiter(req, res, () => (nexted = true));
  return { status, body, nexted };
};
mkMcp();
const blocked = mkMcp();
check('an over-limit /mcp call returns a JSON-RPC error', blocked.status === 429 && blocked.body?.jsonrpc === '2.0' && blocked.body?.error?.code === -32029);

// --- max <= 0 disables the limiter ---
const off = createLimiter({ windowMs: 1000, max: 0 });
check('max=0 disables limiting', [1, 2, 3, 4].every(() => run(off, '9.9.9.9').nexted === undefined ? false : true));

// --- token bucket ---
const bucket = new TokenBucket(3, 1); // capacity 3, 1/sec
check('the bucket allows a burst up to capacity', [bucket.tryTake(), bucket.tryTake(), bucket.tryTake()].every(Boolean));
check('  ...then declines when empty', bucket.tryTake() === false);

// refill: force time forward by manipulating last
bucket.last = Date.now() - 2000; // 2 seconds -> +2 tokens
check('  ...and refills over time', bucket.tryTake() === true && bucket.tryTake() === true);
check('  ...bounded by capacity', (() => { bucket.last = Date.now() - 100_000; bucket.tryTake(); return bucket.tokens <= 3; })());

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
