/**
 * The page for people deciding whether to point an agent at this feed.
 *
 * Served on GET /mcp by content negotiation: a browser asking for HTML gets
 * this, an MCP client gets the protocol. One URL to give someone, whichever
 * of the two they are.
 *
 * Signed out, it is a pitch and a sign-in button. Signed in with GitHub, it is
 * your account - tier, what you have left of each budget, your keys - and the
 * install buttons. Hiding the buttons is presentation: the URL is public and
 * the gateway refusing unauthenticated calls is the enforcement. But a button
 * that leads straight into a sign-in prompt is a worse first step than signing
 * in here, where you can see what you are getting.
 *
 * How each button installs, per each client's own documentation:
 *
 *   one click  VS Code    vscode:mcp/install?<url-encoded JSON {name, type, url}>
 *              Cursor     cursor://anysphere.cursor-deeplink/mcp/install?name=&config=<base64 {url}>
 *              LM Studio  https://lmstudio.ai/install-mcp?name=&config=<base64 {url}>
 *   command    Claude     claude mcp add --transport http
 *              OpenCode   opencode mcp add --url
 *              OpenClaw   openclaw mcp add --url --transport streamable-http, then login
 *              Codex      codex mcp add --url, then login
 *              Copilot    copilot mcp add --transport http (its own list; VS Code's mcp.json is not read)
 *   config     Hermes     ~/.hermes/config.yaml, mcp_servers with auth: oauth
 *              Zed        settings.json, context_servers with a url and no auth header
 *
 * Every one of them runs the OAuth flow on first use, so the URL is all any of
 * them needs; a key is offered underneath for CI and headless agents.
 */
import { breadcrumbJsonLd, escapeHtml, layout } from './layout.js';
import { brandIcon } from './brandIcons.js';
import { sessionHead } from './signin.js';
import config from '../config.js';

const SERVER_NAME = 'cvefeed';

const TOOLS = [
  ['check_dependencies', 'Paste a lockfile; get the vulnerable packages at their exact versions, ordered by whether exploit code exists.'],
  ['search_cves', 'Filter by severity, CVSS, EPSS, exploitation, exploit maturity, AI-stack component, recency or text.'],
  ['get_cve', 'One advisory in full, with exploit links and community PoCs. Unseen CVEs are fetched live.'],
  ['get_exploits', 'Can this be exploited, and with what: Metasploit, Exploit-DB, Nuclei, PoC repositories.'],
  ['list_exploited', 'What CISA confirms is exploited in the wild, optionally only the AI stack.'],
  ['feed_status', 'What is stored and which sources answered, so an empty result can be read correctly.'],
  ['research_vulnerability', 'Looks up a nickname or anything too new for the registers on the web, so the model can find the CVE IDs.'],
  ['account', 'Who you are signed in as, and what is left of your hourly allowance.'],
];

const base64Json = (value) => encodeURIComponent(Buffer.from(JSON.stringify(value)).toString('base64'));

/** The install buttons, built from the endpoint so they never drift from it. */
function installTargets(endpoint) {
  const vscode = { name: SERVER_NAME, type: 'http', url: endpoint };
  return [
    {
      id: 'vscode', group: 'click', label: 'VS Code',
      href: `vscode:mcp/install?${encodeURIComponent(JSON.stringify(vscode))}`,
      hint: "Opens VS Code to review and install, for VS Code's own Agent mode in Chat.",
    },
    {
      id: 'cursor', group: 'click', label: 'Cursor',
      href: `cursor://anysphere.cursor-deeplink/mcp/install?name=${SERVER_NAME}&config=${base64Json({ url: endpoint })}`,
      hint: 'Opens Cursor to confirm the install.',
    },
    {
      id: 'lmstudio', group: 'click', label: 'LM Studio',
      href: `https://lmstudio.ai/install-mcp?name=${SERVER_NAME}&config=${base64Json({ url: endpoint })}`,
      hint: 'Opens LM Studio (0.3.17 or later) to add the server.',
    },
    {
      id: 'claude', group: 'copy', label: 'Claude',
      copy: `claude mcp add --transport http ${SERVER_NAME} ${endpoint}`,
      hint: 'Copies the Claude Code command. On claude.ai, add the URL under Customize, Connectors.',
    },
    {
      // Its own list, separate from VS Code's: the Copilot CLI agent - in a
      // terminal or as an agent inside VS Code Chat - does not read mcp.json.
      id: 'copilot', group: 'copy', label: 'Copilot CLI',
      copy: `copilot mcp add --transport http ${SERVER_NAME} ${endpoint}`,
      hint: 'Copies the GitHub Copilot CLI command. Also what the Copilot CLI agent in VS Code Chat uses.',
    },
    {
      id: 'opencode', group: 'copy', label: 'OpenCode',
      copy: `opencode mcp add ${SERVER_NAME} --url ${endpoint}`,
      hint: 'Copies the OpenCode command.',
    },
    {
      id: 'openclaw', group: 'copy', label: 'OpenClaw',
      copy: `openclaw mcp add ${SERVER_NAME} --url ${endpoint} --transport streamable-http && openclaw mcp login ${SERVER_NAME}`,
      hint: 'Copies the OpenClaw commands: add the server, then sign in.',
    },
    {
      id: 'codex', group: 'copy', label: 'Codex',
      copy: `codex mcp add ${SERVER_NAME} --url ${endpoint} && codex mcp login ${SERVER_NAME}`,
      hint: 'Copies the Codex commands: add the server, then sign in.',
    },
    {
      id: 'hermes', group: 'copy', label: 'Hermes',
      copy: `mcp_servers:\n  ${SERVER_NAME}:\n    url: "${endpoint}"\n    auth: oauth`,
      hint: 'Copies a block for ~/.hermes/config.yaml.',
    },
    {
      id: 'zed', group: 'copy', label: 'Zed',
      copy: `"context_servers": {\n  "${SERVER_NAME}": { "url": "${endpoint}" }\n}`,
      hint: 'Copies a block for Zed settings.json. Zed signs you in when it first connects.',
    },
  ];
}

function installButton(target) {
  const inner = `${brandIcon(target.id)}<span>${escapeHtml(target.label)}</span>`;
  const title = escapeHtml(target.hint);
  if (target.href) return `<a class="install-btn" href="${escapeHtml(target.href)}" title="${title}">${inner}</a>`;
  return `<button type="button" class="install-btn" data-copy="${escapeHtml(target.copy)}" title="${title}">${inner}</button>`;
}

function installSection(endpoint) {
  const targets = installTargets(endpoint);
  const group = (name) => targets.filter((t) => t.group === name).map(installButton).join('');
  return `<div class="install-group">
        <span class="install-label">One click</span>
        <div class="install-grid">${group('click')}</div>
      </div>
      <div class="install-group">
        <span class="install-label">Copy a command or config</span>
        <div class="install-grid">${group('copy')}</div>
      </div>
      <p class="install-status" id="install-status" role="status"></p>
      <details class="install-help">
        <summary>Installed, but your chat can't see the tools?</summary>
        <p>Each agent keeps its own list of servers. The VS Code button adds this server to
           <strong>VS Code's own</strong> agent: pick <em>Agent</em> in the Chat view's agent menu,
           and the tools show up under the tools icon. If your chat runs the <em>Copilot CLI</em>
           agent instead, it never reads VS Code's list. Run the Copilot CLI command above once, in a
           terminal, and that agent will have it too.</p>
        <p>The first connection opens your browser to sign in. Allow VS Code to open the page,
           sign in with GitHub, then press <em>Allow</em>. After that, the client renews the sign-in
           on its own.</p>
      </details>
      <div class="endpoint">
        <span class="endpoint-label">Or use the URL in any client</span>
        <div class="copy-row">
          <code>${escapeHtml(endpoint)}</code>
          <button type="button" class="copy-btn" data-copy="${escapeHtml(endpoint)}">Copy</button>
        </div>
      </div>`;
}

export function agentsPage({ origin, canonical, assetVersion, stats }) {
  // The endpoint is the gateway once there is one. This page is the thing an
  // agent is pointed at, so it must name the address that actually works.
  const endpoint = config.mcpGatewayUrl || `${origin}/mcp`;
  // Sign-in exists only where there is a gateway and a Supabase project to
  // sign in to. A self-hosted copy has neither, and shows the buttons plainly.
  const gated = Boolean(config.mcpGatewayUrl && config.supabaseUrl);

  const tools = TOOLS.map(
    ([name, line]) => `<li><code>${escapeHtml(name)}</code><span>${escapeHtml(line)}</span></li>`,
  ).join('');

  const connect = gated
    ? `<section class="install">
      <div id="signed-out">
        <a class="install-btn signin-btn" id="signin-link" href="/signin?next=%2Fmcp">
          ${brandIcon('github')}<span>Sign in with GitHub to connect</span>
        </a>
        <p class="aside">Free. New accounts get 60 MCP calls an hour, and you'll see exactly what you
          have left before you install anything.</p>
        <p class="install-status" id="signin-status" role="status"></p>
      </div>

      <div id="signed-in" hidden>
        <div class="account-panel">
          <div class="account-head">
            <span>Signed in as <strong id="acct-email"></strong> &middot; <span id="acct-tier"></span> tier</span>
            <button type="button" class="copy-btn" id="acct-signout">Sign out</button>
          </div>
          <div class="budgets" id="acct-budgets"></div>
        </div>

        ${installSection(endpoint)}

        <details class="key-option" id="keys">
          <summary>No browser? Use an API key</summary>
          <p>For CI or an agent that can't open a browser. A key draws on the same allowance as your
             account; it is a second way in, not a second budget.</p>
          <div class="key-create">
            <input id="key-label" type="text" maxlength="80" placeholder="Label, e.g. ci runner">
            <button type="button" class="copy-btn" id="key-create">Create key</button>
          </div>
          <pre class="ad-newkey" id="key-new" hidden></pre>
          <ul class="key-list" id="key-list"></ul>
          <pre><code>{
  "mcpServers": {
    "${SERVER_NAME}": {
      "type": "http",
      "url": "${escapeHtml(endpoint)}",
      "headers": { "Authorization": "Bearer cvf_live_..." }
    }
  }
}</code></pre>
        </details>
      </div>
    </section>`
    : `<section class="install">
      ${installSection(endpoint)}
      <p class="aside">No account, no API key. Any MCP client works — the endpoint is all it needs.</p>
    </section>`;

  const body = `<article class="doc agents-page">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>For agents</span></nav>

    <h1>Connect your agent</h1>
    <p class="lede">Live vulnerability and exploit intelligence for any MCP client: what landed
    overnight, whether working exploit code exists, and which of your dependencies it hits.
    <strong>${stats?.withExploitSignal ?? 0}</strong> stored records carry a known exploit signal.</p>

    ${connect}

    <section class="block">
      <h2>${TOOLS.length} tools</h2>
      <ul class="tool-list">${tools}</ul>
    </section>

    <section class="callout callout-exploit">
      <h2>Authorised testing only</h2>
      <p>Use this on systems you own or have written permission to test. Advisory text and
      community proofs of concept are untrusted third-party content: every result says so, and
      reference URLs are listed but never fetched. See the <a href="/terms">terms</a>.</p>
    </section>

    <p class="aside agents-foot">No MCP? The same data is plain JSON at
    <a href="/api/feed">/api/feed</a>, described for agents in <a href="/llms.txt">/llms.txt</a>.
    <a href="https://github.com/d0gra/CVEfeed" rel="noopener">Source on GitHub</a>.</p>
  </article>

  ${gated ? sessionHead(config.supabaseUrl, assetVersion) : ''}
  <script>
  (function () {
    var el = function (id) { return document.getElementById(id); };
    var status = el('install-status');

    /* Values come from data attributes the server wrote or from this account's
       own API responses. Everything is set as text, never as markup. */
    function fallback(text) {
      var area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'absolute';
      area.style.left = '-9999px';
      document.body.appendChild(area);
      area.select();
      try { document.execCommand('copy'); } catch (e) { /* nothing more to try */ }
      document.body.removeChild(area);
    }
    function copy(text, button) {
      var done = function () {
        if (button && button.classList.contains('copy-btn')) {
          var before = button.textContent;
          button.textContent = 'Copied';
          setTimeout(function () { button.textContent = before; }, 1600);
        }
        if (status) status.textContent = 'Copied: ' + text.split('\\n')[0] + (text.indexOf('\\n') > -1 ? ' ...' : '');
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
      } else { fallback(text); done(); }
    }
    document.querySelectorAll('[data-copy]').forEach(function (button) {
      button.addEventListener('click', function () { copy(button.getAttribute('data-copy'), button); });
    });

    var session = window.CvefeedSession;
    if (!session || !el('signed-in')) return;

    var LABELS = { calls: 'MCP calls', deps: 'Dependency checks', web: 'Web research' };

    function api(path, init) {
      init = init || {};
      init.headers = Object.assign({ Authorization: 'Bearer ' + session.getToken() }, init.headers || {});
      if (init.body) init.headers['Content-Type'] = 'application/json';
      return fetch('/account/api' + path, init).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (payload) {
          return { ok: response.ok, status: response.status, payload: payload };
        });
      });
    }

    function minutesUntil(iso) {
      var ms = Date.parse(iso) - Date.now();
      return isFinite(ms) && ms > 0 ? Math.ceil(ms / 60000) : 0;
    }

    function renderBudgets(budgets) {
      var host = el('acct-budgets');
      host.textContent = '';
      ['calls', 'deps', 'web'].forEach(function (name) {
        var b = budgets[name];
        if (!b) return;
        var row = document.createElement('div');
        row.className = 'budget';
        var head = document.createElement('div');
        head.className = 'budget-head';
        var label = document.createElement('span');
        label.textContent = LABELS[name];
        var count = document.createElement('span');
        count.textContent = b.remaining + ' of ' + b.limit + ' left this hour';
        head.appendChild(label);
        head.appendChild(count);
        var bar = document.createElement('div');
        bar.className = 'budget-bar';
        var fill = document.createElement('span');
        fill.style.width = Math.min(100, Math.round((b.used / Math.max(b.limit, 1)) * 100)) + '%';
        bar.appendChild(fill);
        row.appendChild(head);
        row.appendChild(bar);
        if (b.used > 0 && b.resetAt) {
          var reset = document.createElement('span');
          reset.className = 'budget-reset';
          reset.textContent = 'Resets in ' + minutesUntil(b.resetAt) + ' min';
          row.appendChild(reset);
        }
        host.appendChild(row);
      });
    }

    function renderKeys(keys) {
      var list = el('key-list');
      list.textContent = '';
      keys.forEach(function (k) {
        var li = document.createElement('li');
        var name = document.createElement('span');
        name.textContent = k.key_prefix + '...  ' + k.label + (k.active ? '' : '  (revoked)');
        li.appendChild(name);
        if (k.active) {
          var revoke = document.createElement('button');
          revoke.type = 'button';
          revoke.className = 'copy-btn';
          revoke.textContent = 'Revoke';
          revoke.addEventListener('click', function () {
            revoke.disabled = true;
            api('/keys/' + encodeURIComponent(k.id), { method: 'PATCH', body: JSON.stringify({ disabled: true }) })
              .then(load);
          });
          li.appendChild(revoke);
        }
        list.appendChild(li);
      });
    }

    function showSignedOut(message) {
      el('signed-in').hidden = true;
      el('signed-out').hidden = false;
      el('signin-status').textContent = message || '';
    }

    function load() {
      return api('/me').then(function (r) {
        if (r.status === 401) { session.signOut(); showSignedOut('Your session has ended. Sign in again.'); return; }
        if (!r.ok) { showSignedOut(r.payload.error || 'Your account could not be loaded.'); return; }
        var me = r.payload;
        el('acct-email').textContent = me.email || 'your GitHub account';
        el('acct-tier').textContent = me.tier;
        renderBudgets(me.budgets || {});
        renderKeys(me.keys || []);
        el('signed-out').hidden = true;
        el('signed-in').hidden = false;
      }).catch(function () { showSignedOut('Could not reach your account.'); });
    }

    el('acct-signout').addEventListener('click', function () { session.signOut(); showSignedOut(''); });
    el('signin-link').addEventListener('click', function (event) { event.preventDefault(); session.signIn('/mcp'); });
    el('key-create').addEventListener('click', function () {
      var button = el('key-create');
      button.disabled = true;
      api('/keys', { method: 'POST', body: JSON.stringify({ label: el('key-label').value }) }).then(function (r) {
        button.disabled = false;
        var box = el('key-new');
        box.hidden = false;
        /* Shown once. Nothing stores the plaintext, here or in Postgres. */
        box.textContent = r.ok ? r.payload.key + '\\n\\n' + r.payload.note : (r.payload.error || 'The key could not be created.');
        if (r.ok) { el('key-label').value = ''; load(); }
      });
    });

    if (session.getToken()) load();
  })();
  </script>`;

  return layout({
    title: 'Connect your agent | CVE Feed',
    description:
      'Add CVE Feed to VS Code, Cursor, Claude, Codex, OpenClaw, Hermes and more: live ' +
      'vulnerability and exploit intelligence over MCP, plus a dependency check by exact version. ' +
      (gated ? 'Free; sign in with GitHub.' : 'No account, no API key.'),
    canonical,
    body,
    current: '/mcp',
    assetVersion,
    jsonLd: [
      breadcrumbJsonLd(origin, [['Feed', '/'], ['For agents', '/mcp']]),
      {
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: 'CVE Feed MCP server',
        applicationCategory: 'DeveloperApplication',
        operatingSystem: 'Any',
        url: canonical,
        description:
          'Model Context Protocol server exposing merged CVE data from NVD, CISA KEV, GitHub Advisories, EUVD and CISA advisories, enriched with exploit availability and a version-aware dependency check, with an AI and agent stack filter.',
        offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      },
    ],
  });
}
