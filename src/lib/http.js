import config from '../config.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Transient: worth repeating. Everything else is the request's own fault. */
const isRetryable = (status) => status === 429 || status >= 500;

/** How much of an error body to read before giving up on it. */
const MAX_DETAIL_CHARS = 300;

/**
 * What the upstream actually said. A bare status is not enough to act on: a
 * GitHub 403 is "rate limit exceeded for <ip>" or "resource not accessible",
 * and those are a budget problem and a credentials problem respectively. The
 * body carries that sentence and the x-ratelimit headers carry the numbers,
 * so both travel with the error instead of being dropped at the throw.
 */
async function describe(response, url) {
  // HTTP/2 carries no reason phrase, so statusText is often empty there.
  const status = [response.status, response.statusText].filter(Boolean).join(' ');
  const parts = [`HTTP ${status} for ${url}`];

  const remaining = response.headers.get('x-ratelimit-remaining');
  if (remaining !== null) {
    const limit = response.headers.get('x-ratelimit-limit') ?? '?';
    const reset = Number.parseInt(response.headers.get('x-ratelimit-reset') || '', 10);
    const resetsIn = Number.isFinite(reset)
      ? `, resets in ${Math.max(0, Math.round(reset - Date.now() / 1000))}s`
      : '';
    parts.push(`rate limit ${remaining}/${limit} remaining${resetsIn}`);
  }

  try {
    const body = (await response.text()).slice(0, 2000);
    // Most of these APIs answer errors in JSON with a `message`; the rest get
    // their first line, collapsed, so an HTML error page cannot flood a log.
    let detail = '';
    try {
      const parsed = JSON.parse(body);
      detail = parsed?.message || parsed?.error || parsed?.detail || '';
    } catch {
      detail = body;
    }
    detail = String(detail).replace(/\s+/g, ' ').trim().slice(0, MAX_DETAIL_CHARS);
    if (detail) parts.push(detail);
  } catch {
    // An unreadable body is not worth failing over; the status still stands.
  }

  const error = new Error(parts.join(' - '));
  error.status = response.status;
  error.retryable = isRetryable(response.status);
  return error;
}

/**
 * fetch with a timeout, a descriptive User-Agent and bounded retries.
 *
 * Retries network errors and 429/5xx, honouring Retry-After when present.
 * Nothing else: a 403 or a 404 means repeating the request cannot help, and
 * where the 403 *is* a rate limit, each repeat spends more of the budget that
 * refused it. This used to retry them anyway - the throw sat inside the try,
 * so its own catch swallowed it - which turned every refused request into
 * three.
 */
export async function fetchWithRetry(url, { retries = 2, headers = {}, ...init } = {}) {
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.requestTimeoutMs);
    let armed = true;
    const disarm = () => {
      if (armed) clearTimeout(timer);
      armed = false;
    };

    try {
      const response = await fetch(url, {
        ...init,
        signal: controller.signal,
        headers: {
          'User-Agent': config.userAgent,
          'Accept-Encoding': 'gzip, deflate',
          ...headers,
        },
      });

      if (response.ok) return response;

      // Reading the error body is not what the timeout is guarding.
      disarm();
      const error = await describe(response, url);
      lastError = error;
      if (!error.retryable || attempt === retries) throw error;

      const retryAfter = Number.parseInt(response.headers.get('retry-after') || '', 10);
      await sleep(Number.isFinite(retryAfter) ? Math.min(retryAfter * 1000, 15_000) : 800 * 2 ** attempt);
      continue;
    } catch (error) {
      lastError = error;
      // retryable === false is a status we have decided against repeating;
      // an undefined retryable is a network error or a timeout, which we do.
      if (error.retryable === false || attempt === retries) throw error;
      await sleep(800 * 2 ** attempt);
      continue;
    } finally {
      disarm();
    }
  }

  throw lastError ?? new Error(`Request failed for ${url}`);
}

export async function fetchJson(url, options) {
  const response = await fetchWithRetry(url, {
    ...options,
    headers: { Accept: 'application/json', ...(options?.headers ?? {}) },
  });
  return response.json();
}

export async function fetchText(url, options) {
  const response = await fetchWithRetry(url, options);
  return response.text();
}
