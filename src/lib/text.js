const ENTITIES = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  '#39': "'",
};

function decodeEntities(input) {
  return String(input)
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&([a-z]+|#\d+);/gi, (match, name) => ENTITIES[name.toLowerCase()] ?? match);
}

/**
 * Collapse HTML/markdown-ish feed text into a single readable paragraph.
 *
 * Entities are decoded before tags are stripped: some feeds (CISA's RSS) deliver
 * their markup entity-encoded, so stripping first would leave literal tags behind.
 */
export function toPlainText(input, maxLength = 1200) {
  if (!input) return '';

  const text = decodeEntities(input)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<\/(p|div|li|tr|h[1-6])>/gi, ' ')
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/^\s*[#*>\-]{1,4}\s*/gm, '')
    .replace(/[`*_]{1,3}/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength).replace(/\s+\S*$/, '')}…`;
}

/** Feeds that ship no headline get one from the first sentence of the body. */
export function summarizeTitle(description, maxLength = 140) {
  if (!description) return null;
  const sentence = description.split(/(?<=[.!?])\s/)[0] ?? description;
  const trimmed =
    sentence.length > maxLength
      ? `${sentence.slice(0, maxLength).replace(/\s+\S*$/, '')}…`
      : sentence;
  return trimmed.trim() || null;
}

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;

export function extractCveIds(input) {
  if (!input) return [];
  const matches = String(input).toUpperCase().match(CVE_PATTERN);
  return matches ? [...new Set(matches)] : [];
}

/** Parse the varied date shapes feeds emit; returns an ISO string or null. */
export function toIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}
