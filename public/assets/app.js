const SEVERITIES = [
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'medium', label: 'Medium' },
  { id: 'low', label: 'Low' },
  { id: 'none', label: 'Unscored' },
];

const SEV_SHORT = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'low',
  none: 'n/s',
};

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
        <b>${escapeHtml(s.name)}</b><i>${s.ok ? s.count : 'down'}</i>
      </span>`;
    })
    .join('');
}

function renderStats(stats) {
  const figures = [
    { label: 'Tracked', value: stats.total },
    { label: 'Exploited', value: stats.exploited, filter: 'exploited' },
    { label: 'Critical', value: stats.bySeverity.critical ?? 0, filter: 'critical' },
    { label: 'High', value: stats.bySeverity.high ?? 0, filter: 'high' },
    { label: 'New today', value: stats.last24h },
    {
      label: 'Mean CVSS',
      value: Number.isFinite(stats.averageScore) ? stats.averageScore.toFixed(1) : '—',
    },
  ];

  dom.stats.innerHTML = figures
    .map((f) => {
      const active =
        f.filter === 'exploited' ? state.exploited : f.filter ? state.severity.has(f.filter) : false;
      const tag = f.filter ? 'button' : 'div';
      const attrs = f.filter
        ? ` type="button" data-filter="${f.filter}" aria-pressed="${active}"`
        : '';
      return `<${tag} class="figure"${attrs}>
        <span class="figure-value">${escapeHtml(
          typeof f.value === 'number' ? f.value.toLocaleString() : f.value,
        )}</span>
        <span class="figure-label">${f.label}</span>
      </${tag}>`;
    })
    .join('');
}

function renderChips(stats) {
  dom.severityChips.innerHTML = SEVERITIES.map((sev) => {
    const count = stats?.bySeverity?.[sev.id] ?? 0;
    return `<button type="button" class="chip" style="--tone:var(--${sev.id})"
      data-severity="${sev.id}" data-empty="${count === 0}"
      aria-pressed="${state.severity.has(sev.id)}">${sev.label}<b>${count}</b></button>`;
  }).join('');

  const sourceIds = Object.keys(SOURCE_LABELS).filter(
    (id) => (lastPayload?.sources ?? []).some((s) => s.id === id),
  );
  dom.sourceChips.innerHTML = sourceIds
    .map((id) => {
      const count = stats?.bySource?.[id] ?? 0;
      return `<button type="button" class="chip" data-source="${id}" data-empty="${count === 0}"
        aria-pressed="${state.source.has(id)}">${escapeHtml(SOURCE_LABELS[id])}<b>${count}</b></button>`;
    })
    .join('');
}

function metaLine(item) {
  const bits = [`<span class="id">${escapeHtml(
    item.cveId ?? item.ghsaId ?? item.advisoryId ?? item.id,
  )}</span>`];

  bits.push(...badges(item));
  bits.push(`<span title="${escapeHtml(fullDate(item.published))}">${relativeTime(item.published)}</span>`);

  const subject = [item.vendor, item.product].filter(Boolean).join(' · ');
  if (subject) bits.push(`<span>${escapeHtml(subject)}</span>`);
  if (item.cwes?.length) bits.push(`<span>${escapeHtml(item.cwes.slice(0, 2).join(', '))}</span>`);

  return bits.join('');
}

function badges(item) {
  const out = [];
  if (item.exploited) out.push('<span class="flag">Exploited</span>');
  if (item.kev?.ransomware) out.push('<span class="flag flag-ransom">Ransomware</span>');
  if (item.kind === 'advisory') out.push('<span class="flag flag-quiet">Advisory</span>');
  if (Number.isFinite(item.epss) && item.epss >= 1) {
    out.push(`<span class="flag flag-quiet">EPSS ${item.epss.toFixed(1)}%</span>`);
  }
  if (item.outsideWindow) out.push('<span class="flag flag-quiet">Looked up</span>');
  return out;
}

function detailHtml(item) {
  const blocks = [];

  if (item.description) {
    blocks.push(`<p class="lede">${escapeHtml(item.description)}</p>`);
  }

  if (item.kev) {
    const terms = [
      item.kev.dateAdded ? `Catalogued ${fullDate(item.kev.dateAdded)}` : null,
      item.kev.dueDate ? `Federal deadline ${fullDate(item.kev.dueDate)}` : null,
      item.kev.ransomware ? 'Used in ransomware campaigns' : null,
    ].filter(Boolean);

    blocks.push(`<div class="kev">
      <h4>Known exploited</h4>
      ${terms.length ? `<p class="terms">${terms.map(escapeHtml).join(' · ')}</p>` : ''}
      ${item.kev.requiredAction ? `<p>${escapeHtml(item.kev.requiredAction)}</p>` : ''}
    </div>`);
  }

  const facts = [
    ['CVSS', item.score !== null ? `${item.score} · v${escapeHtml(item.scoreVersion ?? '?')}` : 'Unscored'],
    ['EPSS', Number.isFinite(item.epss) ? `${item.epss}%` : '—'],
    ['Published', fullDate(item.published)],
    ['Updated', fullDate(item.modified)],
    item.cwes?.length ? ['Weakness', escapeHtml(item.cwes.join(', '))] : null,
    item.assigner ? ['Assigner', escapeHtml(item.assigner)] : null,
  ].filter(Boolean);

  blocks.push(`<div class="block"><h4>Assessment</h4><dl class="facts">${facts
    .map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`)
    .join('')}</dl></div>`);

  if (item.vector) {
    blocks.push(`<div class="block"><h4>Vector</h4><p class="vector">${escapeHtml(item.vector)}</p></div>`);
  }

  const links = Object.entries(item.links ?? {}).filter(([, url]) => url);
  if (links.length) {
    blocks.push(`<div class="block"><h4>At the source</h4><div class="outlinks">${links
      .map(
        ([id, url]) =>
          `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
            SOURCE_LABELS[id] ?? id,
          )}</a>`,
      )
      .join('')}</div></div>`);
  }

  const refs = (item.references ?? []).filter((r) => r.url).slice(0, 6);
  if (refs.length) {
    blocks.push(`<div class="block"><h4>References</h4><ul class="refs">${refs
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
  const score = item.score !== null && item.score !== undefined ? item.score.toFixed(1) : '—';

  return `<li class="entry" data-open="${isOpen}" data-key="${escapeHtml(item.key)}">
    <button type="button" class="entry-head" aria-expanded="${isOpen}">
      <span class="mark" style="--tone:var(--${sev === 'none' ? 'unscored' : sev})">
        <span class="mark-score">${score}</span>
        <span class="mark-sev">${escapeHtml(SEV_SHORT[sev] ?? sev)}</span>
      </span>
      <span class="entry-body">
        <h3 class="entry-title">${escapeHtml(item.title)}</h3>
        <span class="entry-meta">${metaLine(item)}</span>
      </span>
      <span class="entry-sources">${(item.sourceIds ?? [])
        .map((id) => escapeHtml(SOURCE_LABELS[id] ?? id))
        .join(' · ')}</span>
    </button>
    ${isOpen ? `<div class="detail">${detailHtml(item)}</div>` : ''}
  </li>`;
}

function renderPager(meta) {
  if (meta.pages <= 1) {
    dom.pager.hidden = true;
    return;
  }
  dom.pager.hidden = false;
  dom.pager.innerHTML = `
    <button type="button" class="quiet" data-page="${meta.page - 1}" ${meta.page <= 1 ? 'disabled' : ''}>← Previous</button>
    <span class="pager-info">${meta.page} / ${meta.pages}</span>
    <button type="button" class="quiet" data-page="${meta.page + 1}" ${meta.page >= meta.pages ? 'disabled' : ''}>Next →</button>`;
}

function renderBanner(meta) {
  document.querySelectorAll('.notice').forEach((n) => n.remove());

  const notes = [];

  // A CVE resolved outside the feed window is worth saying out loud.
  if (meta?.lookup?.sources) {
    const answered = meta.lookup.sources.filter((s) => s.ok && s.count > 0).map((s) => s.name);
    notes.push({
      kind: 'found',
      text: answered.length
        ? `Outside the current window — looked up at ${answered.join(', ')}.`
        : 'Outside the current window — looked up at the source.',
    });
  } else if (meta?.lookup?.error) {
    notes.push({ kind: 'error', text: `Direct lookup failed: ${meta.lookup.error}` });
  }

  if (meta?.stale) {
    notes.push({ kind: 'error', text: 'Showing the last good snapshot — refreshing from upstream failed.' });
  }

  const offline = (lastPayload?.sources ?? []).filter((s) => !s.ok);
  if (offline.length) {
    notes.push({ kind: 'warn', text: `Unavailable: ${offline.map((s) => s.name).join(', ')}.` });
  }

  for (const note of notes.reverse()) {
    const el = document.createElement('div');
    el.className = 'notice';
    el.dataset.kind = note.kind;
    el.textContent = note.text;
    dom.results.prepend(el);
  }
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

  const from = (meta.page - 1) * meta.limit + 1;
  const to = (meta.page - 1) * meta.limit + items.length;
  const noun = meta.total === 1 ? 'disclosure' : 'disclosures';

  dom.resultsCount.textContent = meta.total
    ? `${meta.total.toLocaleString()} ${noun}`
    : 'Nothing matching';
  dom.resultsNote.textContent = meta.total
    ? `Showing ${from}–${to} · ${meta.sort}`
    : `${meta.totalUnfiltered.toLocaleString()} in the window`;

  renderPager(meta);
  dom.results.setAttribute('aria-busy', 'false');

  dom.statusDot.dataset.state = meta.stale ? 'stale' : 'ok';
  dom.freshnessText.textContent = `Updated ${relativeTime(meta.generatedAt)}`;
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
    dom.skeletons.innerHTML = '<div class="skel"></div>'.repeat(7);
    dom.statusDot.dataset.state = 'loading';
    dom.freshnessText.textContent = 'Fetching';
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
    dom.freshnessText.textContent = 'Unavailable';
    dom.resultsCount.textContent = 'Could not load';
    dom.resultsNote.textContent = '';
    dom.feed.innerHTML = '';
    dom.empty.hidden = true;
    document.querySelectorAll('.notice').forEach((n) => n.remove());
    const note = document.createElement('div');
    note.className = 'notice';
    note.dataset.kind = 'error';
    note.textContent = `${error.message}. The upstream registers may be rate-limiting; it will retry.`;
    dom.results.prepend(note);
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
  const head = event.target.closest('.entry-head');
  if (!head) return;
  const card = head.closest('.entry');
  const key = card.dataset.key;
  const item = lastPayload?.items.find((candidate) => candidate.key === key);
  if (!item) return;

  if (expanded.has(key)) {
    expanded.delete(key);
    card.dataset.open = 'false';
    head.setAttribute('aria-expanded', 'false');
    card.querySelector('.detail')?.remove();
  } else {
    expanded.add(key);
    card.dataset.open = 'true';
    head.setAttribute('aria-expanded', 'true');
    const detail = document.createElement('div');
    detail.className = 'detail';
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

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  // The label names the mode the button switches to, not the current one.
  dom.theme.textContent = theme === 'dark' ? 'Light' : 'Dark';
}

dom.theme.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
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
  applyTheme(localStorage.getItem('cvefeed-theme') || 'dark');
} catch {
  applyTheme('dark');
}

readUrl();
syncControls();
renderChips(null);
load({ showSkeletons: true });

// Keep the relative timestamps honest, and pick up new server-side data.
setInterval(() => {
  if (lastPayload?.meta?.generatedAt) {
    dom.freshnessText.textContent = `Updated ${relativeTime(lastPayload.meta.generatedAt)}`;
  }
}, 30_000);

setInterval(() => {
  if (document.visibilityState === 'visible' && !inFlight) load();
}, 5 * 60_000);
