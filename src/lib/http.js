import config from '../config.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * fetch with a timeout, a descriptive User-Agent and bounded retries.
 * Retries on network errors and on 429/5xx, honouring Retry-After when present.
 */
export async function fetchWithRetry(url, { retries = 2, headers = {}, ...init } = {}) {
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.requestTimeoutMs);

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

      // Retry transient upstream problems only.
      if (response.status === 429 || response.status >= 500) {
        lastError = new Error(`HTTP ${response.status} ${response.statusText} for ${url}`);
        const retryAfter = Number.parseInt(response.headers.get('retry-after') || '', 10);
        const waitMs = Number.isFinite(retryAfter)
          ? Math.min(retryAfter * 1000, 15_000)
          : 800 * 2 ** attempt;
        if (attempt < retries) {
          await sleep(waitMs);
          continue;
        }
      }

      throw new Error(`HTTP ${response.status} ${response.statusText} for ${url}`);
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        await sleep(800 * 2 ** attempt);
        continue;
      }
    } finally {
      clearTimeout(timer);
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
