import { severityFromScore, severityRank } from './lib/severity.js';
import { classifyStack } from './stack.js';
import { buildSearchTerms, normalizePackage, packageKey } from './lib/terms.js';

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

/**
 * Number(null) is 0 and Number('') is 0, so a source that reports "no score"
 * explicitly would otherwise land in the feed as a CVSS of 0.0. Absent and
 * zero are different facts here.
 */
function num(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
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
    score: num(item.score),
    scoreVersion: item.scoreVersion ?? null,
    vector: item.vector ?? null,
    epss: num(item.epss),
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
    // Names union across sources rather than first-source-wins, which is what
    // `vendor`/`product` below do with ??=. Two registers describing the same
    // CVE routinely name different affected software, and keeping only the
    // first one read would discard half of it.
    vendorSet: new Set(item.vendors ?? []),
    productSet: new Set(item.products ?? []),
    // Keyed on the coordinate, not the name: npm `zip` and crates.io `zip`
    // are unrelated software and must stay two entries.
    packageMap: new Map(
      (item.packages ?? []).map(normalizePackage).filter(Boolean).map((p) => [packageKey(p), p]),
    ),
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

  for (const vendor of item.vendors ?? []) target.vendorSet.add(vendor);
  for (const product of item.products ?? []) target.productSet.add(product);
  for (const entry of item.packages ?? []) {
    const pkg = normalizePackage(entry);
    if (pkg) target.packageMap.set(packageKey(pkg), pkg);
  }

  for (const cwe of item.cwes ?? []) target.cweSet.add(cwe);
  for (const tag of item.tags ?? []) target.tagSet.add(tag);
  for (const cve of item.relatedCves ?? []) target.relatedSet.add(cve);
  for (const ref of item.references ?? []) {
    if (ref?.url) target.refMap.set(ref.url, ref);
  }
  target.links[item.source] = item.url ?? target.links[item.source];
}

export function finalize(record) {
  const { cweSet, tagSet, refMap, relatedSet, vendorSet, productSet, packageMap, ...rest } = record;

  // Severity always follows the merged CVSS score; exploitation is separate.
  const severity = severityFromScore(rest.score);

  const stack = classifyStack(rest);

  const vendors = [...vendorSet].filter(Boolean).sort();
  const products = [...productSet].filter(Boolean).sort();
  const packages = [...packageMap.values()];

  return {
    ...rest,
    severity,
    severityRank: severityRank(severity),
    stack,
    vendors,
    products,
    packages,
    ecosystems: [...new Set(packages.map((p) => p.ecosystem).filter(Boolean))].sort(),
    // Built last, because it folds in the stack subjects classifyStack has
    // just derived above.
    searchTerms: buildSearchTerms({ vendors, products, packages, product: rest.product, stack }),
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
