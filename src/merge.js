import { severityFromScore, severityRank } from './lib/severity.js';

/**
 * Shared record-merging rules.
 *
 * The feed and the single-CVE lookup both combine records that several sources
 * describe, so the rules live here rather than in either caller.
 */

const maxNum = (a, b) => {
  const x = Number.isFinite(Number(a)) ? Number(a) : null;
  const y = Number.isFinite(Number(b)) ? Number(b) : null;
  if (x === null) return y;
  if (y === null) return x;
  return Math.max(x, y);
};

const earliest = (a, b) => (!a ? b : !b ? a : a < b ? a : b);
const latest = (a, b) => (!a ? b : !b ? a : a > b ? a : b);

const isPlaceholderTitle = (title, id) => !title || title === id || /^(CVE|GHSA|EUVD)-/i.test(title);

/** Records describing the same vulnerability share a key; advisories stay distinct. */
export function mergeKey(item) {
  if (item.source === 'cisa') return `advisory:${item.advisoryId ?? item.id}`;
  if (item.cveId) return `cve:${item.cveId.toUpperCase()}`;
  if (item.ghsaId) return `ghsa:${item.ghsaId}`;
  if (item.euvdId) return `euvd:${item.euvdId}`;
  return `${item.source}:${item.id}`;
}

export function seed(item, sourceMeta) {
  return {
    key: mergeKey(item),
    id: item.id,
    cveId: item.cveId ?? null,
    ghsaId: item.ghsaId ?? null,
    euvdId: item.euvdId ?? null,
    advisoryId: item.advisoryId ?? null,
    kind: item.source === 'cisa' ? 'advisory' : 'cve',
    title: item.title,
    description: item.description ?? '',
    score: Number.isFinite(Number(item.score)) ? Number(item.score) : null,
    scoreVersion: item.scoreVersion ?? null,
    vector: item.vector ?? null,
    epss: Number.isFinite(Number(item.epss)) ? Number(item.epss) : null,
    published: item.published ?? null,
    modified: item.modified ?? null,
    vendor: item.vendor ?? null,
    product: item.product ?? null,
    status: item.status ?? null,
    assigner: item.assigner ?? null,
    exploited: Boolean(item.exploited),
    kev: item.kev ?? null,
    url: item.url ?? null,
    sources: [sourceMeta],
    links: { [item.source]: item.url ?? null },
    cweSet: new Set(item.cwes ?? []),
    tagSet: new Set(item.tags ?? []),
    refMap: new Map((item.references ?? []).filter((r) => r?.url).map((r) => [r.url, r])),
    relatedSet: new Set(item.relatedCves ?? []),
  };
}

export function mergeInto(target, item, sourceMeta) {
  target.sources.push(sourceMeta);

  target.score = maxNum(target.score, item.score);
  if (item.score !== null && item.score !== undefined && Number(item.score) === target.score) {
    target.scoreVersion = item.scoreVersion ?? target.scoreVersion;
    target.vector = item.vector ?? target.vector;
  }

  target.epss = maxNum(target.epss, item.epss);
  target.published = earliest(target.published, item.published);
  target.modified = latest(target.modified, item.modified);

  if (isPlaceholderTitle(target.title, target.id) && !isPlaceholderTitle(item.title, item.id)) {
    target.title = item.title;
  }
  if ((item.description?.length ?? 0) > (target.description?.length ?? 0)) {
    target.description = item.description;
  }

  target.cveId ??= item.cveId ?? null;
  target.ghsaId ??= item.ghsaId ?? null;
  target.euvdId ??= item.euvdId ?? null;
  target.vendor ??= item.vendor ?? null;
  target.product ??= item.product ?? null;
  target.status ??= item.status ?? null;
  target.assigner ??= item.assigner ?? null;

  if (item.exploited) target.exploited = true;
  if (item.kev) target.kev = { ...item.kev, ...(target.kev ?? {}) };

  for (const cwe of item.cwes ?? []) target.cweSet.add(cwe);
  for (const tag of item.tags ?? []) target.tagSet.add(tag);
  for (const cve of item.relatedCves ?? []) target.relatedSet.add(cve);
  for (const ref of item.references ?? []) {
    if (ref?.url) target.refMap.set(ref.url, ref);
  }
  target.links[item.source] = item.url ?? target.links[item.source];
}

export function finalize(record) {
  const { cweSet, tagSet, refMap, relatedSet, ...rest } = record;

  // Severity always follows the merged CVSS score; exploitation is separate.
  const severity = severityFromScore(rest.score);

  return {
    ...rest,
    severity,
    severityRank: severityRank(severity),
    cwes: [...cweSet].sort(),
    tags: [...tagSet].sort(),
    references: [...refMap.values()].slice(0, 15),
    relatedCves: [...relatedSet],
    sourceIds: [...new Set(rest.sources.map((s) => s.id))],
    sources: rest.sources.filter((s, i, arr) => arr.findIndex((o) => o.id === s.id) === i),
  };
}

/**
 * Fold per-source result sets into one keyed map of merged records.
 * `results` is [{ meta, items }]; the map is returned unfinalized so callers
 * can still cross-reference records before finalizing.
 */
export function mergeAll(results) {
  const merged = new Map();

  for (const { meta, items } of results) {
    const sourceMeta = { id: meta.id, name: meta.name, homepage: meta.homepage };
    for (const item of items) {
      const key = mergeKey(item);
      const existing = merged.get(key);
      if (existing) mergeInto(existing, item, sourceMeta);
      else merged.set(key, seed(item, sourceMeta));
    }
  }

  return merged;
}
