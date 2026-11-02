/**
 * What to offer someone typing in the search box.
 *
 * Two layers, because they fail differently. The curated layer is the ~70
 * projects the AI-stack taxonomy already knows about, held in the process and
 * always available - it works with the database down, which is also what
 * makes it testable offline. The corpus layer is everything the stored
 * records actually name, which is far larger but only exists when Atlas is up.
 *
 * Neither layer is queried per keystroke. The corpus vocabulary is built once
 * and cached, and matching is a prefix filter over an array in memory. On a
 * free shared cluster the alternative - a `^prefix` index scan for every
 * character typed - is the kind of thing that works in development and falls
 * over the moment more than one person uses it.
 */
import { cached } from './cache.js';
import config from '../config.js';
import { normalizeTerm } from './terms.js';
import { subjectSuggestions } from '../stack.js';
import { aggregateSuggestionVocabulary } from '../store/cveStore.js';

// Scoped to the database, for the same reason as the hub names: this cache
// is on disk and would otherwise be shared across every database.
const cacheKey = () => `suggest-vocab-${config.mongoDb}`;
const TTL_MS = Math.max(1, Number.parseInt(process.env.SUGGEST_TTL_HOURS || '', 10) || 6) * 3_600_000;

/** `kind` drives what the dashboard may offer: only a package gets a version check. */
const KIND = { package: 'package', vendor: 'vendor', product: 'product', subject: 'subject' };

/**
 * The curated layer, flattened into suggestion rows.
 *
 * A project contributes its display name and each package it is known by, so
 * typing either "vLLM" or "vllm" finds it. The package rows carry no
 * ecosystem: the taxonomy records names, not registries, and claiming one
 * would be inventing it.
 */
function curatedRows() {
  const rows = [];
  for (const subject of subjectSuggestions()) {
    rows.push({ value: subject.value, label: subject.value, kind: KIND.subject, count: null });
    for (const name of subject.packages) {
      rows.push({ value: name, label: name, kind: KIND.package, ecosystem: null, count: null });
    }
    for (const vendor of subject.vendors) {
      rows.push({ value: vendor, label: vendor, kind: KIND.vendor, count: null });
    }
  }
  return rows;
}

/** The corpus layer. Null when the store is unreachable, never an exception. */
async function corpusRows() {
  try {
    const entry = await cached(
      cacheKey(),
      async () => {
        const vocab = await aggregateSuggestionVocabulary();
        // Throw rather than return null when the store is unreachable. The
        // cache stores whatever the producer returns, so returning null here
        // would pin "no suggestions" in place for the whole TTL - long after
        // the database came back. A rejection is not cached, so the next
        // request tries again.
        if (!vocab) throw new Error('the store is unavailable');
        return vocab;
      },
      { ttlMs: TTL_MS },
    );
    const vocab = entry?.value;
    if (!vocab) return null;
    return [
      ...vocab.packages.map((p) => ({ value: p.value, label: p.value, kind: KIND.package, ecosystem: p.ecosystem, count: p.count })),
      ...vocab.vendors.map((v) => ({ value: v.value, label: v.value, kind: KIND.vendor, count: v.count })),
      ...vocab.products.map((p) => ({ value: p.value, label: p.value, kind: KIND.product, count: p.count })),
    ];
  } catch {
    return null;
  }
}

/**
 * Everything suggestable, curated first so its labels win the dedupe.
 *
 * "vLLM" reads better than the "vllm" the corpus would produce, and the
 * curated entry is the one that knows which project a package belongs to.
 */
async function vocabulary() {
  const corpus = (await corpusRows()) ?? [];
  const merged = new Map();

  for (const row of [...curatedRows(), ...corpus]) {
    const key = `${row.kind}|${String(row.value).toLowerCase()}`;
    const existing = merged.get(key);
    if (existing) {
      // Keep the curated label, take the corpus count.
      if (existing.count == null && row.count != null) existing.count = row.count;
      if (!existing.ecosystem && row.ecosystem) existing.ecosystem = row.ecosystem;
      continue;
    }
    merged.set(key, { ...row });
  }

  return [...merged.values()];
}

const RANK = { package: 0, subject: 1, vendor: 2, product: 3 };

/**
 * Suggestions for a prefix.
 *
 * Prefix rather than substring, deliberately: a substring match on two
 * characters returns noise, and a search box that suggests badly is worse
 * than one that suggests nothing. Names that start with the term come first,
 * then the rest of a word inside the name, so typing "log4j" still surfaces
 * "org.apache.logging.log4j:log4j-core".
 */
export async function suggestFor(prefix, { limit = 8 } = {}) {
  const term = normalizeTerm(prefix);
  if (!term) return [];

  const rows = await vocabulary();
  const scored = [];

  for (const row of rows) {
    const value = String(row.value).toLowerCase();
    let rank;
    if (value === term) rank = 0;
    else if (value.startsWith(term)) rank = 1;
    // A word boundary inside the name - "log4j-core" for "core", scoped npm
    // names, Maven artifacts after the colon.
    else if (new RegExp(`[\\s/:@.-]${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`).test(value)) rank = 2;
    else continue;

    scored.push({ row, rank });
  }

  scored.sort(
    (a, b) =>
      a.rank - b.rank ||
      RANK[a.row.kind] - RANK[b.row.kind] ||
      (b.row.count ?? 0) - (a.row.count ?? 0) ||
      a.row.value.length - b.row.value.length,
  );

  return scored.slice(0, limit).map(({ row }) => ({
    value: row.value,
    label: row.label,
    kind: row.kind,
    ...(row.ecosystem ? { ecosystem: row.ecosystem } : {}),
    ...(row.count != null ? { count: row.count } : {}),
  }));
}

/**
 * Is this term a package name, and which registries is it in?
 *
 * Only package-kind entries count. A vendor ("microsoft") or a product
 * ("Internet Explorer") must return null, because the dependency check works
 * on registry coordinates and offering to version-check Windows would be
 * nonsense.
 */
export async function packageHintFor(term) {
  const wanted = normalizeTerm(term);
  if (!wanted) return null;

  const rows = await vocabulary();
  const ecosystems = new Set();
  let found = false;

  for (const row of rows) {
    if (row.kind !== KIND.package) continue;
    if (String(row.value).toLowerCase() !== wanted) continue;
    found = true;
    if (row.ecosystem) ecosystems.add(row.ecosystem);
  }

  if (!found) return null;
  return { term: wanted, ecosystems: [...ecosystems].sort() };
}

export default { suggestFor, packageHintFor };
