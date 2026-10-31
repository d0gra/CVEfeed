/**
 * The moderation page: review pending community PoCs and approve or reject.
 *
 * Deliberately minimal and unlisted (noindex, not in the nav or sitemap). It
 * holds no secret itself - the token is entered here and sent as a header on
 * each request, and the API enforces it on every action. Without a valid token
 * the page shows nothing but the prompt.
 */
import { escapeHtml, layout } from './layout.js';

export function moderatePage({ canonical, assetVersion, enabled }) {
  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Moderate</span></nav>
    <h1>Review submissions</h1>

    ${
      enabled
        ? `<p class="lede">Pending community proofs of concept. Approve to publish on the CVE page, or
           reject to hide. Nothing here is public until you approve it.</p>

        <div class="mod-auth">
          <label for="mod-token">Moderation token</label>
          <input id="mod-token" type="password" autocomplete="off" placeholder="POC_MODERATION_TOKEN">
          <button type="button" id="mod-load" class="poc-btn">Load pending</button>
        </div>
        <p class="mod-status" id="mod-status" role="status"></p>
        <div id="mod-list"></div>`
        : `<p class="lede">Moderation is disabled. Set <code>POC_MODERATION_TOKEN</code> in the
           environment to enable reviewing and approving submissions.</p>`
    }
  </article>

  <script>
  (function () {
    var tokenEl = document.getElementById('mod-token');
    var status = document.getElementById('mod-status');
    var list = document.getElementById('mod-list');
    if (!tokenEl) return;

    // Prefill from ?token= for convenience, then scrub it from the URL bar.
    var m = location.search.match(/[?&]token=([^&]+)/);
    if (m) { tokenEl.value = decodeURIComponent(m[1]); history.replaceState(null, '', location.pathname); }

    function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }

    function act(id, action, token) {
      return fetch('/api/pocs/' + encodeURIComponent(id) + '/' + action, {
        method: 'POST', headers: { 'x-moderation-token': token },
      }).then(function (r) { return r.ok; });
    }

    function render(pending, token) {
      if (!pending.length) { list.innerHTML = '<p class="aside">Nothing pending.</p>'; return; }
      list.innerHTML = pending.map(function (p) {
        return '<div class="mod-item" data-id="' + esc(p._id) + '">' +
          '<div class="mod-head"><strong>' + esc(p.cveId) + '</strong> · ' + esc(p.title) +
          ' <span class="poc-by">by ' + esc(p.author) + '</span></div>' +
          (p.writeup ? '<p>' + esc(p.writeup) + '</p>' : '') +
          '<pre class="poc-code"><code>' + esc(p.code) + '</code></pre>' +
          (p.contact ? '<p class="aside">Contact: ' + esc(p.contact) + '</p>' : '') +
          '<div class="mod-actions">' +
            '<button class="poc-btn" data-act="approve">Approve</button>' +
            '<button class="quiet" data-act="reject">Reject</button>' +
          '</div></div>';
      }).join('');

      list.querySelectorAll('.mod-item').forEach(function (el) {
        el.querySelectorAll('[data-act]').forEach(function (btn) {
          btn.addEventListener('click', function () {
            act(el.dataset.id, btn.dataset.act, token).then(function (ok) {
              if (ok) { el.remove(); status.textContent = 'Done.'; }
              else { status.textContent = 'Action failed (check the token).'; }
            });
          });
        });
      });
    }

    function load() {
      var token = tokenEl.value.trim();
      if (!token) { status.textContent = 'Enter the moderation token.'; return; }
      status.textContent = 'Loading…';
      fetch('/api/pocs/pending', { headers: { 'x-moderation-token': token } })
        .then(function (r) {
          if (r.status === 401) { status.textContent = 'Invalid token.'; return null; }
          if (!r.ok) { status.textContent = 'Could not load.'; return null; }
          return r.json();
        })
        .then(function (b) { if (b) { status.textContent = ''; render(b.pending || [], token); } })
        .catch(function () { status.textContent = 'Network error.'; });
    }

    document.getElementById('mod-load').addEventListener('click', load);
    if (tokenEl.value) load();
  })();
  </script>`;

  return layout({
    title: 'Moderate submissions | CVE Feed',
    description: 'Review pending community proof-of-concept submissions.',
    canonical,
    body,
    current: '',
    assetVersion,
    noindex: true,
  });
}

export default { moderatePage };
