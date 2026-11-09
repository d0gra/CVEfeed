/**
 * Stop asking a register that is refusing.
 *
 * Repeating a request that has just been refused is the traffic shape that
 * gets a client blocked: it reads as a client that does not take no for an
 * answer. http.js no longer retries a refusal within one request; this is the
 * same rule across requests. After a few consecutive failures a source is
 * left alone for a cooldown, then given exactly one probe to prove it is
 * back.
 *
 * Deliberately in memory and per process. It is a politeness valve, not a
 * distributed quota: the worst a restart costs is one extra probe.
 */

export const FAILURES_BEFORE_OPEN = 3;
export const COOLDOWN_MS = 15 * 60 * 1000;

const state = new Map(); // id -> { failures, openedAt, probing }

const entry = (id) => {
  let found = state.get(id);
  if (!found) {
    found = { failures: 0, openedAt: 0, probing: false };
    state.set(id, found);
  }
  return found;
};

/**
 * May we call this source right now?
 *
 * Returns false while the cooldown is running. The first call after it
 * expires is allowed through as a probe; a failure re-opens the breaker for
 * another cooldown rather than letting every caller back in at once.
 */
export function mayCall(id, now = Date.now()) {
  const e = entry(id);
  if (!e.openedAt) return true;
  if (now - e.openedAt < COOLDOWN_MS) return false;
  // Cooldown done: let one caller through, keep the rest out until it reports.
  if (e.probing) return false;
  e.probing = true;
  return true;
}

/** How long until this source is tried again, in seconds; 0 when it is open for business. */
export function cooldownRemaining(id, now = Date.now()) {
  const e = entry(id);
  if (!e.openedAt) return 0;
  return Math.max(0, Math.ceil((COOLDOWN_MS - (now - e.openedAt)) / 1000));
}

/** Record how a call went. Three failures in a row close the door for a while. */
export function record(id, ok, now = Date.now()) {
  const e = entry(id);
  e.probing = false;
  if (ok) {
    e.failures = 0;
    e.openedAt = 0;
    return;
  }
  e.failures += 1;
  if (e.failures >= FAILURES_BEFORE_OPEN) e.openedAt = now;
}

/** For tests. */
export function resetBreakers() {
  state.clear();
}

export default { mayCall, record, cooldownRemaining, resetBreakers, FAILURES_BEFORE_OPEN, COOLDOWN_MS };
