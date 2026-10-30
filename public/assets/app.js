const SEVERITIES = [
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
  { id: 'low', label: 'Low' },
  { id: 'none', label: 'Unscored' },
];

const SOURCE_LABELS = {
  nvd: 'NVD',
  kev: 'CISA KEV',
  github: 'GitHub',
  euvd: 'EUVD',
  cisa: 'CISA Adv.',
};

const el = (id) => document.getElementById(id);

const dom = {
  stats: el('stats'),
  sources: el('sources'),
  feed: el('feed'),
  empty: el('empty'),
  skeletons: el('skeletons'),
  pager: el('pager'),
  results: el('results'),
  resultsCount: el('results-count'),
  resultsNote: el('results-note'),
  q: el('q'),
  clearQ: el('clear-q'),
  sort: el('sort'),
  days: el('days'),
  exploited: el('exploited'),
  severityChips: el('severity-chips'),
  sourceChips: el('source-chips'),
  refresh: el('refresh'),
  reset: el('reset'),
  theme: el('theme-toggle'),
  freshnessText: el('freshness-text'),
  statusDot: el('status-dot'),
};

const state = {
  q: '',
  sort: 'priority',
  days: 0,
  exploited: false,
  severity: new Set(),
  source: new Set(),
  page: 1,
  limit: 50,
};

let lastPayload = null;
let inFlight = null;
const expanded = new Set();

/* ---------- utilities ---------- */

const escapeHtml = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[ch]);

function relativeTime(iso) {
  if (!iso) return 'unknown date';
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return 'unknown date';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return 'just now';
  const units = [
    ['minute', 60], ['hour', 60], ['day', 24], ['month', 30.44], ['year', 12],
  ];
  let value = seconds / 60;
  let unit = 'minute';
  for (let i = 0; i < units.length - 1; i += 1) {
    if (Math.abs(value) < units[i + 1][1]) { unit = units[i][0]; break; }
    value /= units[i + 1][1];
    unit = units[i + 1][0];
  }
  const rounded = Math.round(value);
  return `${rounded} ${unit}${rounded === 1 ? '' : 's'} ago`;
}

const fullDate = (iso) => {
  const t = Date.parse(iso ?? '');
  return Number.isFinite(t)
    ? new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : '—';
};

/* ---------- URL state ---------- */

function readUrl() {
  const p = new URLSearchParams(location.search);
  state.q = p.get('q') ?? '';
  state.sort = p.get('sort') ?? 'priority';
  state.days = Number.parseInt(p.get('days') ?? '0', 10) || 0;
  state.exploited = p.get('exploited') === '1';
  state.page = Math.max(Number.parseInt(p.get('page') ?? '1', 10) || 1, 1);
  state.severity = new Set((p.get('severity') ?? '').split(',').filter(Boolean));
  state.source = new Set((p.get('source') ?? '').split(',').filter(Boolean));
}

function writeUrl() {
  const p = new URLSearchParams();
  if (state.q) p.set('q', state.q);
  if (state.sort !== 'priority') p.set('sort', state.sort);
  if (state.days) p.set('days', String(state.days));
  if (state.exploited) p.set('exploited', '1');
  if (state.severity.size) p.set('severity', [...state.severity].join(','));
  if (state.source.size) p.set('source', [...state.source].join(','));
  if (state.page > 1) p.set('page', String(state.page));
  const qs = p.toString();
  history.replaceState(null, '', qs ? `?${qs}` : location.pathname);
}

/* ---------- rendering ---------- */

function renderSources(sources = []) {
  dom.sources.innerHTML = sources
    .map((s) => {
      const title = s.ok
        ? `${escapeHtml(s.label)} — ${s.count} records in ${s.durationMs}ms`
        : `${escapeHtml(s.label)} — unavailable: ${escapeHtml(s.error ?? 'error')}`;
      return `<span class="src" data-ok="${s.ok}" title="${title}">
        <span class="src-dot"></span><b>${escapeHtml(s.name)}</b>
        ${s.ok ? `<span>${s.count}</span>` : '<span>offline</span>'}
      </span>`;
    })
    .join('');
}

function renderStats(stats) {
  const tiles = [
    { label: 'Tracked', value: stats.total, tone: 'var(--accent)', hint: 'matching filters' },
    { label: 'Exploited', value: stats.exploited, tone: 'var(--exploited)', hint: 'in CISA KEV', filter: 'exploited' },
    { label: 'Critical', value: stats.bySeverity.critical ?? 0, tone: 'var(--critical)', hint: 'CVSS 9.0+', filter: 'critical' },
    { label: 'High', value: stats.bySeverity.high ?? 0, tone: 'var(--high)', hint: 'CVSS 7.0–8.9', filter: 'high' },
    { label: 'New', value: stats.last24h, tone: 'var(--low)', hint: 'last 24 hours' },
    { label: 'Avg CVSS', value: stats.averageScore ?? '—', tone: 'var(--medium)', hint: 'of scored items' },
  ];

  dom.stats.innerHTML = tiles
    .map((t) => {
      const active =
        t.filter === 'exploited' ? state.exploited : t.filter ? state.severity.has(t.filter) : false;
      const interactive = Boolean(t.filter);
      return `<${interactive ? 'button type="button"' : 'div'}
        class="stat${interactive ? ' is-clickable' : ''}"
        style="--tone:${t.tone}"
        ${interactive ? `data-filter="${t.filter}" aria-pressed="${active}"` : ''}>
        <p class="stat-label">${t.label}</p>
        <p class="stat-value">${escapeHtml(t.value)}</p>
        <p class="stat-hint">${t.hint}</p>
      </${interactive ? 'button' : 'div'}>`;
    })
    .join('');
}

function renderChips(stats) {
  dom.severityChips.innerHTML = SEVERITIES.map((s) => {
    const count = stats?.bySeverity?.[s.id] ?? 0;
    return `<button type="button" class="chip" style="--tone:var(--${s.id})"
      data-severity="${s.id}" aria-pressed="${state.severity.has(s.id)}">
      ${s.label}<span class="chip-count">${count}</span>
    </button>`;
  }).join('');

  const sourceIds = Object.keys(SOURCE_LABELS).filter(
    (id) => (lastPayload?.sources ?? []).some((s) => s.id === id),
  );
  dom.sourceChips.innerHTML = sourceIds
    .map((id) => {
      const count = stats?.bySource?.[id] ?? 0;
      return `<button type="button" class="chip" data-source="${id}" aria-pressed="${state.source.has(id)}">
        ${escapeHtml(SOURCE_LABELS[id])}<span class="chip-count">${count}</span>
      </button>`;
    })
    .join('');
}

function metaLine(item) {
  const bits = [];
  bits.push(`<span title="${escapeHtml(fullDate(item.published))}">🕑 ${relativeTime(item.published)}</span>`);
  if (item.vendor) bits.push(`<span>🏷 ${escapeHtml(item.vendor)}</span>`);
  if (item.product) bits.push(`<span>📦 ${escapeHtml(item.product)}</span>`);
  if (item.cwes?.length) bits.push(`<span>⚠ ${escapeHtml(item.cwes.slice(0, 3).join(', '))}</span>`);
  if (item.status) bits.push(`<span>● ${escapeHtml(item.status)}</span>`);
  return bits.join('');
}

function badges(item) {
  const out = [];
  if (item.exploited) out.push('<span class="tag tag-exploited">Exploited</span>');
  if (item.kev?.ransomware) out.push('<span class="tag tag-ransomware">Ransomware</span>');
  if (item.kind === 'advisory') out.push('<span class="tag tag-advisory">Advisory</span>');
  if (Number.isFinite(item.epss) && item.epss >= 1) {
    out.push(`<span class="tag tag-epss">EPSS ${item.epss.toFixed(1)}%</span>`);
  }
  if (item.tags?.includes('cisa-advisory') && item.kind !== 'advisory') {
    out.push('<span class="tag tag-advisory">In CISA advisory</span>');
  }
  return out.join('');
}

function detailHtml(item) {
  const blocks = [];

  if (item.description) {
    blocks.push(`<div class="detail-block"><h4>Description</h4><p>${escapeHtml(item.description)}</p></div>`);
  }

  if (item.kev) {
    const rows = [
      item.kev.dateAdded ? `Added to KEV ${fullDate(item.kev.dateAdded)}` : null,
      item.kev.dueDate ? `Federal remediation due ${fullDate(item.kev.dueDate)}` : null,
      item.kev.ransomware ? 'Known use in ransomware campaigns' : null,
    ].filter(Boolean);
    blocks.push(`<div class="kev-box">
      <h4>⚡ Known exploited vulnerability</h4>
      ${rows.length ? `<p>${rows.map(escapeHtml).join(' · ')}</p>` : ''}
      ${item.kev.requiredAction ? `<p><strong>Required action:</strong> ${escapeHtml(item.kev.requiredAction)}</p>` : ''}
    </div>`);
  }

  const kv = [
    ['CVSS', item.score !== null ? `${item.score} (v${escapeHtml(item.scoreVersion ?? '?')})` : 'Not yet scored'],
    ['EPSS', Number.isFinite(item.epss) ? `${item.epss}% likelihood` : '—'],
    ['Published', fullDate(item.published)],
    ['Last modified', fullDate(item.modified)],
    item.cwes?.length ? ['Weaknesses', escapeHtml(item.cwes.join(', '))] : null,
    item.assigner ? ['Assigner', escapeHtml(item.assigner)] : null,
  ].filter(Boolean);

  blocks.push(`<div class="detail-block"><h4>Assessment</h4><dl class="kv">${kv
    .map(([k, v]) => `<div class="kv-item"><dt>${k}</dt><dd>${v}</dd></div>`)
    .join('')}</dl></div>`);

  if (item.vector) {
    blocks.push(`<div class="detail-block"><h4>CVSS vector</h4><p class="vector">${escapeHtml(item.vector)}</p></div>`);
  }

  const links = Object.entries(item.links ?? {}).filter(([, url]) => url);
  if (links.length) {
    blocks.push(`<div class="detail-block"><h4>Open at source</h4><div class="links-row">${links
      .map(
        ([id, url]) =>
          `<a class="link-btn" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(SOURCE_LABELS[id] ?? id)} ↗</a>`,
      )
      .join('')}</div></div>`);
  }

  const refs = (item.references ?? []).filter((r) => r.url).slice(0, 8);
  if (refs.length) {
    blocks.push(`<div class="detail-block"><h4>References</h4><ul class="ref-list">${refs
      .map(
        (r) =>
          `<li><a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.url)}</a></li>`,
      )
      .join('')}</ul></div>`);
  }

  return blocks.join('');
}

function cardHtml(item) {
  const sev = item.severity ?? 'none';
  const isOpen = expanded.has(item.key);
  const scoreText = item.score !== null && item.score !== undefined ? item.score.toFixed(1) : '—';

  return `<li class="card" data-exploited="${item.exploited}" data-open="${isOpen}" data-key="${escapeHtml(item.key)}">
    <button type="button" class="card-head" aria-expanded="${isOpen}">
      <span class="score" style="--tone:var(--${sev})">
        <span class="score-num">${scoreText}</span>
        <span class="score-sev">${sev === 'none' ? 'n/a' : escapeHtml(sev)}</span>
      </span>
      <span class="card-body">
        <span class="card-id">
          <span class="cve-id">${escapeHtml(item.cveId ?? item.ghsaId ?? item.advisoryId ?? item.id)}</span>
          ${badges(item)}
        </span>
        <h3 class="card-title">${escapeHtml(item.title)}</h3>
        <span class="card-meta">${metaLine(item)}</span>
      </span>
      <span class="src-pills">
        ${(item.sourceIds ?? []).map((id) => `<span class="src-pill">${escapeHtml(SOURCE_LABELS[id] ?? id)}</span>`).join('')}
        <span class="chev">▶</span>
      </span>
    </button>
    ${isOpen ? `<div class="card-detail">${detailHtml(item)}</div>` : ''}
  </li>`;
}

function renderPager(meta) {
  if (meta.pages <= 1) {
    dom.pager.hidden = true;
    return;
  }
  dom.pager.hidden = false;
  dom.pager.innerHTML = `
    <button type="button" class="btn" data-page="${meta.page - 1}" ${meta.page <= 1 ? 'disabled' : ''}>← Prev</button>
    <span class="pager-info">Page ${meta.page} of ${meta.pages}</span>
    <button type="button" class="btn" data-page="${meta.page + 1}" ${meta.page >= meta.pages ? 'disabled' : ''}>Next →</button>`;
}

function renderBanner(meta) {
  document.querySelectorAll('.banner').forEach((n) => n.remove());
  const offline = (lastPayload?.sources ?? []).filter((s) => !s.ok);
  const messages = [];
  if (meta?.stale) messages.push('Showing the last good snapshot — a refresh from upstream failed.');
  if (offline.length) messages.push(`Unavailable right now: ${offline.map((s) => s.name).join(', ')}.`);
  if (!messages.length) return;

  const banner = document.createElement('div');
  banner.className = 'banner';
  banner.dataset.kind = meta?.stale ? 'error' : 'warn';
  banner.textContent = messages.join(' ');
  dom.results.prepend(banner);
}

function renderFeed(payload) {
  const { items, meta, stats } = payload;

  renderStats(stats);
  renderChips(stats);
  renderSources(payload.sources);
  renderBanner(meta);

  dom.skeletons.innerHTML = '';
  dom.feed.innerHTML = items.map(cardHtml).join('');
  dom.empty.hidden = items.length > 0;

  const shown = items.length ? `${(meta.page - 1) * meta.limit + 1}–${(meta.page - 1) * meta.limit + items.length}` : '0';
  const noun = meta.total === 1 ? 'vulnerability' : 'vulnerabilities';
  dom.resultsCount.textContent = `${meta.total.toLocaleString()} ${noun} · showing ${shown}`;
  dom.resultsNote.textContent = `${meta.totalUnfiltered.toLocaleString()} in the current window · sorted by ${meta.sort}`;

  renderPager(meta);
  dom.results.setAttribute('aria-busy', 'false');

  const label = meta.stale ? 'stale' : meta.fromCache ? 'cached' : 'fresh';
  dom.statusDot.dataset.state = meta.stale ? 'stale' : 'ok';
  dom.freshnessText.textContent = `Updated ${relativeTime(meta.generatedAt)} · ${label}`;
}

/* ---------- data ---------- */

function buildQuery() {
  const p = new URLSearchParams();
  if (state.q) p.set('q', state.q);
  p.set('sort', state.sort);
  if (state.days) p.set('days', String(state.days));
  if (state.exploited) p.set('exploited', '1');
  if (state.severity.size) p.set('severity', [...state.severity].join(','));
  if (state.source.size) p.set('source', [...state.source].join(','));
  p.set('page', String(state.page));
  p.set('limit', String(state.limit));
  return p.toString();
}

async function load({ showSkeletons = false } = {}) {
  if (inFlight) inFlight.abort();
  const controller = new AbortController();
  inFlight = controller;

  dom.results.setAttribute('aria-busy', 'true');
  if (showSkeletons) {
    dom.feed.innerHTML = '';
    dom.empty.hidden = true;
    dom.skeletons.innerHTML = '<div class="skel"></div>'.repeat(6);
    dom.statusDot.dataset.state = 'loading';
    dom.freshnessText.textContent = 'Fetching feeds…';
  }

  try {
    const response = await fetch(`/api/feed?${buildQuery()}`, { signal: controller.signal });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail ?? body.error ?? `Request failed (${response.status})`);
    }
    lastPayload = await response.json();
    renderFeed(lastPayload);
  } catch (error) {
    if (error.name === 'AbortError') return;
    dom.skeletons.innerHTML = '';
    dom.statusDot.dataset.state = 'error';
    dom.freshnessText.textContent = 'Feed unavailable';
    dom.resultsCount.textContent = 'Could not load the feed';
    dom.resultsNote.textContent = '';
    dom.feed.innerHTML = '';
    dom.empty.hidden = true;
    document.querySelectorAll('.banner').forEach((n) => n.remove());
    const banner = document.createElement('div');
    banner.className = 'banner';
    banner.dataset.kind = 'error';
    banner.textContent = `${error.message}. The upstream feeds may be rate-limiting; retrying shortly.`;
    dom.results.prepend(banner);
  } finally {
    if (inFlight === controller) inFlight = null;
  }
}

/* ---------- interaction ---------- */

const debounce = (fn, ms) => {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
};

function apply({ resetPage = true } = {}) {
  if (resetPage) state.page = 1;
  writeUrl();
  load();
}

function toggleSet(set, value) {
  if (set.has(value)) set.delete(value);
  else set.add(value);
}

dom.q.addEventListener('input', debounce(() => {
  state.q = dom.q.value.trim();
  dom.clearQ.hidden = !dom.q.value;
  apply();
}, 280));

dom.clearQ.addEventListener('click', () => {
  dom.q.value = '';
  state.q = '';
  dom.clearQ.hidden = true;
  dom.q.focus();
  apply();
});

dom.sort.addEventListener('change', () => { state.sort = dom.sort.value; apply(); });
dom.days.addEventListener('change', () => { state.days = Number(dom.days.value); apply(); });
dom.exploited.addEventListener('change', () => { state.exploited = dom.exploited.checked; apply(); });

dom.severityChips.addEventListener('click', (event) => {
  const chip = event.target.closest('[data-severity]');
  if (!chip) return;
  toggleSet(state.severity, chip.dataset.severity);
  apply();
});

dom.sourceChips.addEventListener('click', (event) => {
  const chip = event.target.closest('[data-source]');
  if (!chip) return;
  toggleSet(state.source, chip.dataset.source);
  apply();
});

dom.stats.addEventListener('click', (event) => {
  const tile = event.target.closest('[data-filter]');
  if (!tile) return;
  const filter = tile.dataset.filter;
  if (filter === 'exploited') {
    state.exploited = !state.exploited;
    dom.exploited.checked = state.exploited;
  } else {
    toggleSet(state.severity, filter);
  }
  apply();
});

dom.feed.addEventListener('click', (event) => {
  const head = event.target.closest('.card-head');
  if (!head) return;
  const card = head.closest('.card');
  const key = card.dataset.key;
  const item = lastPayload?.items.find((candidate) => candidate.key === key);
  if (!item) return;

  if (expanded.has(key)) {
    expanded.delete(key);
    card.dataset.open = 'false';
    head.setAttribute('aria-expanded', 'false');
    card.querySelector('.card-detail')?.remove();
  } else {
    expanded.add(key);
    card.dataset.open = 'true';
    head.setAttribute('aria-expanded', 'true');
    const detail = document.createElement('div');
    detail.className = 'card-detail';
    detail.innerHTML = detailHtml(item);
    card.append(detail);
  }
});

dom.pager.addEventListener('click', (event) => {
  const button = event.target.closest('[data-page]');
  if (!button || button.disabled) return;
  state.page = Number(button.dataset.page);
  writeUrl();
  load({ showSkeletons: true });
  dom.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

dom.refresh.addEventListener('click', async () => {
  dom.refresh.disabled = true;
  await load({ showSkeletons: true });
  dom.refresh.disabled = false;
});

dom.reset.addEventListener('click', () => {
  state.q = '';
  state.sort = 'priority';
  state.days = 0;
  state.exploited = false;
  state.severity.clear();
  state.source.clear();
  syncControls();
  apply();
});

dom.theme.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('cvefeed-theme', next); } catch { /* private mode */ }
});

document.addEventListener('keydown', (event) => {
  if (event.key === '/' && document.activeElement !== dom.q) {
    event.preventDefault();
    dom.q.focus();
  }
  if (event.key === 'Escape' && document.activeElement === dom.q) dom.q.blur();
});

function syncControls() {
  dom.q.value = state.q;
  dom.clearQ.hidden = !state.q;
  dom.sort.value = state.sort;
  dom.days.value = String(state.days);
  dom.exploited.checked = state.exploited;
}

/* ---------- boot ---------- */

try {
  const saved = localStorage.getItem('cvefeed-theme');
  if (saved) document.documentElement.dataset.theme = saved;
} catch { /* private mode */ }

readUrl();
syncControls();
renderChips(null);
load({ showSkeletons: true });

// Keep the relative timestamps honest, and pick up new server-side data.
setInterval(() => {
  if (lastPayload?.meta?.generatedAt) {
    const label = lastPayload.meta.stale ? 'stale' : 'cached';
    dom.freshnessText.textContent = `Updated ${relativeTime(lastPayload.meta.generatedAt)} · ${label}`;
  }
}, 30_000);

setInterval(() => {
  if (document.visibilityState === 'visible' && !inFlight) load();
}, 5 * 60_000);
