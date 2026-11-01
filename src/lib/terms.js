/**
 * The names a record can be found by.
 *
 * Search over advisory prose cannot answer "is there anything against this
 * software", and the reason is not ranking - it is that the question is about
 * a *name*, and prose only sometimes contains one. Three of the five sources
 * hand us real names (GitHub package coordinates, KEV vendor/product, EUVD
 * vendor/product) and until now every one of them was flattened into a
 * comma-joined string or dropped entirely.
 *
 * This module turns whatever a record knows about itself into one flat,
 * lowercased, deduplicated array, `searchTerms`, which is the single field the
 * search cascade matches on. One field means one multikey index and a plain
 * equality predicate, which is index-backed; the alternative - a
 * case-insensitive anchored regex across three separate arrays - is not.
 *
 * The typed arrays (`vendors`, `products`, `packages`) are kept alongside it,
 * because the distinction matters downstream: a package hit can offer the
 * version-aware dependency check, and a vendor hit must not. "Internet
 * Explorer" is a product, not something to look up in a registry.
 */
import { normalizeEcosystem } from './manifests.js';

/**
 * How many names one record may contribute.
 *
 * A single advisory can list hundreds of affected packages - a framework
 * monorepo, or a vendor shipping one CVE across a product line. Storing all of
 * them would bloat both the document and the multikey index, and the long tail
 * is not what anyone types. The first two dozen are the ones with a search
 * term attached to them.
 */
export const MAX_TERMS = 24;

/** Below this a term matches most of the corpus; above it, nobody typed it. */
const MIN_LENGTH = 2;
const MAX_LENGTH = 80;

/**
 * Fold a name to its matchable form.
 *
 * Deliberately conservative: lowercase and collapse whitespace, nothing more.
 * Stripping punctuation would merge `log4j-core` with `log4j core` and also
 * destroy scoped npm names like `@scope/pkg`, which are exactly the strings
 * this is for.
 */
export function normalizeTerm(value) {
  const text = String(value ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
  if (text.length < MIN_LENGTH || text.length > MAX_LENGTH) return null;
  return text;
}

/**
 * Is this word just the name of a registry?
 *
 * GitHub records their ecosystem where a vendor belongs, so the corpus is full
 * of "pip", "npm" and "rust" masquerading as vendor names. They must not
 * become search terms: a search for "npm" should not return every JavaScript
 * advisory ever published. `normalizeEcosystem` already knows both spellings -
 * GitHub's informal ones and OSV's canonical ones - so one call covers both.
 */
const isEcosystemWord = (value) => Boolean(normalizeEcosystem(value));

/**
 * Every name a finalized record should be findable by.
 *
 * Takes the structured arrays, and also the legacy comma-joined `product`
 * string: a record re-ingested before its source adapter was updated still has
 * only that, and splitting it means such records gain terms on the next touch
 * rather than waiting for a second deploy.
 */
export function buildSearchTerms({ vendors, products, packages, product, stack } = {}) {
  const terms = new Set();

  const add = (value) => {
    if (terms.size >= MAX_TERMS) return;
    const term = normalizeTerm(value);
    if (!term || isEcosystemWord(term)) return;
    terms.add(term);
  };

  // Package coordinates first: they are the most precise thing we have, and
  // the cap should spend itself on them before it reaches prose-derived names.
  for (const entry of packages ?? []) {
    add(entry?.name);
    // Maven and Packagist names are `group:artifact` / `vendor/package`, and
    // people type the artifact alone. Both forms are worth matching.
    const name = String(entry?.name ?? '');
    const tail = name.includes(':') ? name.split(':').pop() : null;
    if (tail) add(tail);
  }

  for (const value of vendors ?? []) add(value);
  for (const value of products ?? []) add(value);

  // The curated AI-stack project names ("vLLM", "Model Context Protocol").
  // Folding them in turns what was a regex scan over prose into an exact hit.
  for (const value of stack?.subjects ?? []) add(value);

  // The pre-existing flattened string, so nothing regresses mid-rollout.
  for (const part of String(product ?? '').split(',')) add(part);

  return [...terms];
}

/**
 * Normalise a package coordinate as the sources hand it over.
 *
 * The ecosystem is mapped to OSV's spelling so a name found here and a name
 * sent to the dependency check mean the same registry - `rust` and
 * `crates.io` must not be two different things depending on which half of the
 * app you are in. An unrecognised ecosystem is kept verbatim rather than
 * dropped, since a new registry should degrade to "still searchable".
 */
export function normalizePackage(entry) {
  const name = String(entry?.name ?? '').trim();
  if (!name) return null;
  const raw = String(entry?.ecosystem ?? '').trim();
  return { name, ecosystem: normalizeEcosystem(raw) ?? raw ?? null };
}

/** The key two coordinates are the same package under. */
export const packageKey = (entry) => `${entry.ecosystem ?? ''}|${entry.name.toLowerCase()}`;

export default { buildSearchTerms, normalizeTerm, normalizePackage, packageKey, MAX_TERMS };
