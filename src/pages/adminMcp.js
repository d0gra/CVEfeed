/**
 * The MCP gateway dashboard.
 *
 * The audit the gateway now keeps is only worth keeping if someone can read
 * it, and the question it exists to answer is "who hammered us at 3am, and
 * which tool was failing while they did it?". That is a page, not a SQL
 * prompt.
 *
 * Unlisted and noindex, like /moderate, and it holds no data of its own: every
 * number arrives from /admin/api/*, which demands a Supabase access token for
 * an account carrying role=admin in app_metadata. Loading this page while
 * signed out shows an email box and nothing else.
 *
 * Principal ids, key labels and client strings all originate outside this
 * process - a label is typed by an admin, but a client name comes from
 * whatever an MCP client chose to call itself. Everything is written with
 * textContent.
 */
import { layout } from './layout.js';
import { sessionHead } from './signin.js';
import { brandIcon } from './brandIcons.js';

export function adminMcpPage({ canonical, assetVersion, supabaseUrl, publishableKey }) {
  const configured = Boolean(supabaseUrl && publishableKey);

  const body = `<article class="doc wide">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Gateway</span></nav>
    <h1>MCP gateway</h1>

    ${
      configured
        ? `<div id="ad-signin" hidden>
          <p class="lede">Sign in to read the gateway's records.</p>
          <button type="button" id="ad-github" class="install-btn signin-btn">${brandIcon('github')}<span>Continue with GitHub</span></button>
        </div>

        <div id="ad-main" hidden>
          <section>
            <h2>Last 24 hours</h2>
            <div class="ad-tiles" id="ad-tiles"></div>
          </section>

          <section>
            <h2>This host</h2>
            <div class="ad-tiles" id="ad-host"></div>
            <p class="ad-note" id="ad-host-notes"></p>
          </section>

          <section>
            <h2>By tool, last 24 hours</h2>
            <div class="ad-table" id="ad-tools"></div>
          </section>

          <section>
            <h2>Busiest callers, last 7 days</h2>
            <div class="ad-table" id="ad-principals"></div>
          </section>

          <section>
            <h2>Recent failures</h2>
            <div class="ad-table" id="ad-errors"></div>
          </section>

          <section>
            <h2>Accounts</h2>
            <p class="ad-note">Anyone can sign up with GitHub. New accounts start at 60 calls an hour
               and 10 dependency checks; raise one when you recognise it. Tiers set quota only &mdash;
               access to this page comes from <code>app_metadata.role</code>, which is not settable here.</p>
            <div class="ad-table" id="ad-users"></div>
          </section>

          <section>
            <h2>API keys</h2>
            <div class="mod-auth">
              <label for="ad-label">Label</label>
              <input id="ad-label" type="text" placeholder="ci runner" maxlength="80">
              <label for="ad-rate">Calls/hour</label>
              <input id="ad-rate" type="number" value="600" min="1" max="100000">
              <button type="button" id="ad-issue" class="poc-btn">Issue a key</button>
            </div>
            <pre class="ad-newkey" id="ad-newkey" hidden></pre>
            <div class="ad-table" id="ad-keys"></div>
          </section>
        </div>

        <p class="mod-status" id="ad-status" role="status"></p>`
        : `<p class="lede">Not configured. Set <code>SUPABASE_URL</code>,
           <code>SUPABASE_PUBLISHABLE_KEY</code> and <code>SUPABASE_SECRET_KEY</code> to enable
           the dashboard.</p>`
    }
  </article>

  ${
    configured
      ? `${sessionHead(supabaseUrl, assetVersion)}
  <script>
  (function () {
    var session = window.CvefeedSession;

    var el = function (id) { return document.getElementById(id); };
    var say = function (m) { el('ad-status').textContent = m || ''; };

    /* session.js has already claimed any session GitHub sent back. */
    function token() { return session.getToken(); }
    function forget() { session.signOut(); }

    function api(path, options) {
      var init = options || {};
      init.headers = Object.assign({ Authorization: 'Bearer ' + token() }, init.headers || {});
      if (init.body) init.headers['Content-Type'] = 'application/json';
      return fetch('/admin/api' + path, init).then(function (response) {
        if (response.status === 401) { forget(); showSignin('That session is not an admin, or has expired.'); return null; }
        return response.json().catch(function () { return {}; }).then(function (payload) {
          if (!response.ok) { say(payload.error || 'That request failed.'); return null; }
          return payload;
        });
      });
    }

    function showSignin(message) {
      el('ad-main').hidden = true;
      el('ad-signin').hidden = false;
      say(message || '');
    }

    /* ---------- rendering ---------- */

    var num = function (v) { return v === null || v === undefined ? '--' : String(v); };
    var when = function (v) {
      if (!v) return '--';
      var d = new Date(v);
      return isNaN(d.getTime()) ? String(v) : d.toLocaleString();
    };

    function tiles(target, entries) {
      var host = el(target);
      host.textContent = '';
      entries.forEach(function (entry) {
        var tile = document.createElement('div');
        tile.className = 'ad-tile';
        var value = document.createElement('strong');
        value.textContent = entry[1];
        var label = document.createElement('span');
        label.textContent = entry[0];
        tile.appendChild(value);
        tile.appendChild(label);
        host.appendChild(tile);
      });
    }

    /* Columns are [heading, accessor]. Values are set as text, never markup:
       a client name is whatever an MCP client called itself. */
    function table(target, columns, rows, empty) {
      var host = el(target);
      host.textContent = '';
      if (!rows || !rows.length) {
        var none = document.createElement('p');
        none.className = 'ad-note';
        none.textContent = empty;
        host.appendChild(none);
        return;
      }
      var tbl = document.createElement('table');
      var thead = document.createElement('thead');
      var hrow = document.createElement('tr');
      columns.forEach(function (col) {
        var th = document.createElement('th');
        th.textContent = col[0];
        hrow.appendChild(th);
      });
      thead.appendChild(hrow);
      tbl.appendChild(thead);
      var tbody = document.createElement('tbody');
      rows.forEach(function (row) {
        var tr = document.createElement('tr');
        columns.forEach(function (col) {
          var td = document.createElement('td');
          var cell = col[1](row, td);
          if (cell !== undefined) td.textContent = cell;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      host.appendChild(tbl);
    }

    function renderGateway(data) {
      var o = data.overview || {};
      tiles('ad-tiles', [
        ['calls', num(o.calls)],
        ['callers', num(o.principals)],
        ['errors', num(o.errors)],
        ['cache hits', o.cache_hit_pct === undefined ? '--' : o.cache_hit_pct + '%'],
        ['p50', num(o.p50_ms) + 'ms'],
        ['p95', num(o.p95_ms) + 'ms'],
        ['p99', num(o.p99_ms) + 'ms']
      ]);

      table('ad-tools', [
        ['tool', function (r) { return r.tool; }],
        ['calls', function (r) { return num(r.calls); }],
        ['errors', function (r) { return num(r.errors) + ' (' + num(r.error_pct) + '%)'; }],
        ['cached', function (r) { return num(r.cache_hit_pct) + '%'; }],
        ['p95', function (r) { return num(r.p95_ms) + 'ms'; }],
        ['p95 upstream', function (r) { return num(r.p95_upstream_ms) + 'ms'; }]
      ], data.tools, 'No tool calls in the last 24 hours.');

      table('ad-principals', [
        ['caller', function (r) { return r.principal; }],
        ['kind', function (r) { return r.principal_kind; }],
        ['calls', function (r) { return num(r.calls); }],
        ['errors', function (r) { return num(r.errors); }],
        ['throttled', function (r) { return num(r.throttled); }],
        ['last seen', function (r) { return when(r.last_seen); }]
      ], data.principals, 'No calls in the last 7 days.');

      table('ad-errors', [
        ['when', function (r) { return when(r.at); }],
        ['caller', function (r) { return r.principal; }],
        ['tool', function (r) { return r.tool || '--'; }],
        ['outcome', function (r) { return r.outcome; }],
        ['code', function (r) { return r.error_code || '--'; }],
        ['took', function (r) { return num(r.duration_ms) + 'ms'; }]
      ], data.errors, 'Nothing has failed. ');

      table('ad-users', [
        ['account', function (r) { return r.email || r.user_id; }],
        ['tier', function (r) { return r.tier; }],
        ['calls/hour', function (r) { return num(r.rate_per_hour); }],
        ['deps/hour', function (r) { return num(r.deps_per_hour); }],
        ['calls (7d)', function (r) { return num(r.calls_7d); }],
        ['joined', function (r) { return when(r.created_at); }],
        ['', function (r, td) {
          /* Labelled by what they do, not by their name. The top tier is
             called 'admin' in the schema and grants nothing but a bigger
             quota - dashboard access comes from app_metadata.role, which is
             a different thing entirely and is not settable from here. */
          var TIERS = { new: '60/hr', raised: '600/hr', admin: '5000/hr' };
          ['new', 'raised', 'admin'].forEach(function (tier) {
            if (tier === r.tier) return;
            var button = document.createElement('button');
            button.type = 'button';
            button.className = 'poc-btn small';
            button.textContent = tier + ' \u00b7 ' + TIERS[tier];
            button.title = 'Set this account to ' + TIERS[tier] + '. Does not grant dashboard access.';
            button.addEventListener('click', function () {
              button.disabled = true;
              api('/users/' + encodeURIComponent(r.user_id), {
                method: 'PATCH',
                body: JSON.stringify({ tier: tier })
              }).then(function (result) { if (result) load(); else button.disabled = false; });
            });
            td.appendChild(button);
          });
          return undefined;
        }]
      ], data.users, 'Nobody has signed in yet.');

      table('ad-keys', [
        ['key', function (r) { return r.key_prefix + '...'; }],
        ['label', function (r) { return r.label; }],
        ['calls/hour', function (r) { return num(r.rate_per_hour); }],
        ['state', function (r) { return r.active ? 'active' : 'revoked'; }],
        ['last used', function (r) { return when(r.last_used_at); }],
        ['', function (r, td) {
          var button = document.createElement('button');
          button.type = 'button';
          button.className = 'poc-btn small';
          button.textContent = r.active ? 'Revoke' : 'Restore';
          button.addEventListener('click', function () {
            button.disabled = true;
            api('/keys/' + encodeURIComponent(r.id), {
              method: 'PATCH',
              body: JSON.stringify({ disabled: r.active })
            }).then(function (result) { if (result) load(); else button.disabled = false; });
          });
          td.appendChild(button);
          return undefined;
        }]
      ], data.keys, 'No keys issued yet.');
    }

    function renderHost(data) {
      var feed = data.feed || {};
      var health = data.sourceHealth || {};
      tiles('ad-host', [
        ['uptime', Math.round((data.uptimeSeconds || 0) / 60) + 'm'],
        ['memory', num(data.memoryMb) + 'MB'],
        ['feed age', feed.ageSeconds === null || feed.ageSeconds === undefined ? 'unknown' : Math.round(feed.ageSeconds / 60) + 'm'],
        ['database', data.store && data.store.connected ? 'connected' : (data.store && data.store.state) || 'unknown'],
        ['cache entries', num(data.cache && data.cache.entries)],
        ['registers ok', health.ok === false ? 'degraded' : health.ok === true ? 'all answering' : 'unknown']
      ]);

      var notes = [];
      if (feed.neverRefreshed) notes.push('No refresh has ever run - schedule scripts/refresh.js.');
      if (data.store && data.store.error) notes.push('Database: ' + data.store.error);
      (data.breakers || []).forEach(function (b) {
        notes.push('Breaker open on ' + b.id + ' for another ' + b.cooldownSeconds + 's.');
      });
      (data.indexWarnings || []).forEach(function (w) {
        notes.push('Index ' + (w.index || '?') + ': ' + (w.error || 'drifted from the source spec'));
      });
      if (data.pocs) {
        var pending = data.pocs.pending || 0;
        if (pending) notes.push(pending + ' community PoC(s) awaiting review at /moderate.');
      }
      el('ad-host-notes').textContent = notes.join('  ');
    }

    function load() {
      say('Loading...');
      Promise.all([api('/gateway'), api('/host'), api('/users')]).then(function (results) {
        if (!results[0] && !results[1]) return;
        el('ad-signin').hidden = true;
        el('ad-main').hidden = false;
        if (results[0]) renderGateway(Object.assign({ users: (results[2] || {}).users || [] }, results[0]));
        if (results[1]) renderHost(results[1]);
        say('');
      });
    }

    el('ad-github').addEventListener('click', function () { session.signIn('/admin/mcp'); });
    el('ad-issue').addEventListener('click', function () {
      el('ad-issue').disabled = true;
      api('/keys', {
        method: 'POST',
        body: JSON.stringify({ label: el('ad-label').value, ratePerHour: el('ad-rate').value })
      }).then(function (result) {
        el('ad-issue').disabled = false;
        if (!result) return;
        var box = el('ad-newkey');
        box.hidden = false;
        /* Shown once. Nothing stores the plaintext, here or in Postgres. */
        box.textContent = result.key + '\\n\\n' + result.note;
        el('ad-label').value = '';
        load();
      });
    });

    if (token()) load();
    else showSignin('');
  })();
  </script>`
      : ''
  }`;

  return layout({
    title: 'MCP gateway - CVE Feed',
    description: 'Administration and observability for the MCP gateway.',
    canonical,
    body,
    noindex: true,
    assetVersion,
  });
}

export default { adminMcpPage };
