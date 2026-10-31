/**
 * CAPTCHA for the public submission form.
 *
 * Two modes, picked by configuration:
 *
 *   - Cloudflare Turnstile, when TURNSTILE_SECRET is set. Privacy-respecting,
 *     no cookies or PII, verified server-side. The right choice for a real
 *     deployment, and recommended in the docs.
 *   - A built-in signed challenge otherwise, so the feature works with zero
 *     setup. The expected answer is carried in an HMAC-signed, expiring token
 *     rather than in server memory, so it needs no session store and survives
 *     across the stateless requests a form makes. It is a modest gate - a
 *     determined bot can read arithmetic - but together with the honeypot and
 *     the per-IP submission limit it stops casual spam.
 *
 * Either way the form cannot be posted without passing, and a CAPTCHA is never
 * solved on anyone's behalf here - this issues and checks challenges, it does
 * not defeat them.
 */
import crypto from 'node:crypto';
import config from '../config.js';

const CHALLENGE_TTL_MS = 15 * 60 * 1000;

// A stable secret keeps challenges valid across requests; a random fallback is
// fine, challenges simply reset when the process restarts.
const SECRET = config.captchaSecret || crypto.randomBytes(32).toString('hex');

export const usingTurnstile = () => Boolean(config.turnstileSecret && config.turnstileSiteKey);
export const turnstileSiteKey = () => config.turnstileSiteKey;

const sign = (payload) => crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');

/** A fresh arithmetic challenge and the signed token that encodes its answer. */
export function issueChallenge() {
  const a = 2 + Math.floor(Math.random() * 8);
  const b = 1 + Math.floor(Math.random() * 8);
  const answer = a + b;
  const expires = Date.now() + CHALLENGE_TTL_MS;
  // The token binds the answer to an expiry under HMAC, so it cannot be forged
  // or replayed past its lifetime, and carries no server state.
  const payload = `${expires}.${sign(`${expires}.${answer}`)}`;
  return { question: `What is ${a} + ${b}?`, token: payload, answer };
}

function verifyChallenge(token, answer) {
  const supplied = Number.parseInt(String(answer ?? '').trim(), 10);
  if (!Number.isInteger(supplied)) return false;

  const [expiresStr, mac] = String(token ?? '').split('.');
  const expires = Number.parseInt(expiresStr, 10);
  if (!Number.isFinite(expires) || expires < Date.now()) return false;

  // Recompute the MAC over the expiry and the supplied answer: it matches only
  // if the answer is the one this token was signed for.
  const expected = sign(`${expires}.${supplied}`);
  if (!mac || mac.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected));
}

async function verifyTurnstile(token, ip) {
  if (!token) return false;
  try {
    const body = new URLSearchParams({ secret: config.turnstileSecret, response: String(token) });
    if (ip) body.set('remoteip', ip);
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await res.json();
    return data?.success === true;
  } catch {
    return false;
  }
}

/**
 * Verify whatever the form sent, by the active mode.
 * Returns true only on a genuine pass.
 */
export async function verifyCaptcha(body = {}, ip) {
  if (usingTurnstile()) {
    return verifyTurnstile(body['cf-turnstile-response'], ip);
  }
  return verifyChallenge(body.captchaToken, body.captchaAnswer);
}

export default { issueChallenge, verifyCaptcha, usingTurnstile, turnstileSiteKey };
