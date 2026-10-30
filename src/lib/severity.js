export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'none'];

const RANK = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, SEVERITY_ORDER.length - i]));

/** CVSS v3/v4 qualitative rating boundaries. */
export function severityFromScore(score) {
  const n = Number(score);
  if (!Number.isFinite(n) || n <= 0) return 'none';
  if (n >= 9.0) return 'critical';
  if (n >= 7.0) return 'high';
  if (n >= 4.0) return 'medium';
  return 'low';
}

export function normalizeSeverity(label, score) {
  const text = String(label ?? '').toLowerCase().trim();
  if (SEVERITY_ORDER.includes(text)) return text;
  if (text === 'moderate') return 'medium';
  if (text === 'important') return 'high';
  return severityFromScore(score);
}

export const severityRank = (severity) => RANK[severity] ?? 0;
