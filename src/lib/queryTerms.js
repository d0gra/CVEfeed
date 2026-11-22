/**
 * What a search query asks for, read the same way by every search path.
 *
 * MongoDB's $text does three things that made search answer the wrong
 * question, all confirmed in its documentation:
 *
 *   - Space-separated words are OR'd, so "apache struts rce" matched anything
 *     mentioning "apache", and the severity sort put Log4j on top.
 *   - A hyphen inside a word is a delimiter, so "log4j-core" became
 *     "log4j OR core" - and "core" is in nearly every record, which is how a
 *     package name returned the entire feed.
 *   - Results are not ranked by relevance unless asked.
 *
 * So the query is split into significant terms here, and each search path
 * requires every one of them (AND). $text is kept for what it is good at -
 * recall and a relevance score - but it no longer decides what matches.
 *
 * Deliberately small and deterministic. Working out what a nickname means is
 * the model's job, through research_vulnerability; this only reads the words.
 */

/** Words that carry no meaning in a vulnerability search. */
const STOPWORDS = new Set([
  'a', 'an', 'and', 'the', 'of', 'in', 'on', 'for', 'to', 'with', 'by', 'at', 'from', 'is', 'are',
  'vulnerability', 'vulnerabilities', 'vuln', 'vulns', 'cve', 'cves', 'bug', 'bugs', 'issue', 'issues',
  'find', 'show', 'list', 'search', 'any', 'all', 'about', 'what', 'which',
]);

/**
 * Abbreviations people type for what advisories spell out. Each term matches
 * any of its alternatives, so "rce" finds "remote code execution".
 */
const SYNONYMS = {
  rce: ['remote code execution', 'rce'],
  xss: ['cross-site scripting', 'cross site scripting', 'xss'],
  sqli: ['sql injection', 'sqli'],
  ssrf: ['server-side request forgery', 'server side request forgery', 'ssrf'],
  csrf: ['cross-site request forgery', 'cross site request forgery', 'csrf'],
  lpe: ['privilege escalation', 'lpe'],
  dos: ['denial of service', 'dos'],
  xxe: ['xml external entity', 'xxe'],
  lfi: ['local file inclusion', 'path traversal', 'lfi'],
  traversal: ['path traversal', 'directory traversal', 'traversal'],
};

// A package-shaped token: scoped names, Maven coordinates, dotted and
// hyphenated names. These are one name, never several words.
const PACKAGE_SHAPED = /[-./@:]/;
const IDENTIFIER = /^(CVE|GHSA|EUVD)-/i;

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The terms in a query that must all match.
 *
 * Each is `{ text, alternatives, packageShaped }`. Quotes and trailing
 * punctuation are stripped; stopwords and single characters are dropped.
 */
export function significantTerms(query) {
  const raw = String(query ?? '').toLowerCase();
  const terms = [];
  for (const piece of raw.split(/\s+/)) {
    // Strip wrapping quotes and sentence punctuation, keep inner - . / @ :
    const text = piece.replace(/^["'(\[]+|["')\],;!?]+$/g, '');
    if (text.length < 2 || STOPWORDS.has(text) || IDENTIFIER.test(text)) continue;
    const packageShaped = PACKAGE_SHAPED.test(text);
    terms.push({ text, packageShaped, alternatives: packageShaped ? [text] : (SYNONYMS[text] ?? [text]) });
  }
  return terms;
}

/**
 * One case-insensitive pattern per term, matching any of its alternatives.
 *
 * Plain words match on word boundaries, so "rce" does not match "source". A
 * package-shaped term matches as written, boundaries and all, because "@" and
 * "." are not word characters and \b would refuse to anchor on them.
 */
export function termPattern(term) {
  const body = term.alternatives.map(escapeRegex).join('|');
  return new RegExp(term.packageShaped ? `(?:${body})` : `\\b(?:${body})\\b`, 'i');
}

/** The words worth handing to $text for recall and scoring, or null. */
export function textSearchString(terms) {
  const words = terms
    .filter((t) => !t.packageShaped)
    .flatMap((t) => t.alternatives)
    .join(' ')
    .trim();
  return words || null;
}

/**
 * A relevance score for the in-memory path, standing in for $text's.
 *
 * A hit in the title counts three times a hit elsewhere, which roughly matches
 * the text index's own weights (title 10, vendor and product 4, description 1).
 */
export function relevance(terms, { title = '', rest = '' }) {
  let score = 0;
  for (const term of terms) {
    const pattern = termPattern(term);
    if (pattern.test(title)) score += 3;
    if (pattern.test(rest)) score += 1;
  }
  return score;
}

export default { significantTerms, termPattern, textSearchString, relevance };
