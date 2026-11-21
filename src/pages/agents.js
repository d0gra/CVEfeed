/**
 * The page for people deciding whether to point an agent at this feed.
 *
 * Served on GET /mcp by content negotiation: a browser asking for HTML gets
 * this, an MCP client gets the protocol. One URL to give someone, whichever
 * of the two they are.
 *
 * Kept short on purpose. Someone arriving here wants to connect a client, so
 * the install buttons come first and the explanation is a paragraph, not an
 * essay. The longer argument lives in the README.
 *
 * How each button installs, per each client's own documentation:
 *
 *   VS Code   vscode:mcp/install?<url-encoded JSON {name, type, url}>
 *   Cursor    cursor://anysphere.cursor-deeplink/mcp/install?name=...&config=<base64 JSON {url}>
 *   Claude    no install link exists - the button copies `claude mcp add`, and
 *             claude.ai takes the URL under Customize > Connectors
 *   OpenCode  no install link exists - the button copies `opencode mcp add`
 *
 * Every client here runs the OAuth flow on first use, so the URL is all any of
 * them needs; a key is offered underneath for CI and headless agents.
 */
import { breadcrumbJsonLd, escapeHtml, layout } from './layout.js';
import { brandIcon } from './brandIcons.js';
import config from '../config.js';

const SERVER_NAME = 'cvefeed';

const TOOLS = [
  ['check_dependencies', 'Paste a lockfile; get the vulnerable packages at their exact versions, ordered by whether exploit code exists.'],
  ['search_cves', 'Filter by severity, CVSS, EPSS, exploitation, exploit maturity, AI-stack component, recency or text.'],
  ['get_cve', 'One advisory in full, with exploit links and community PoCs. Unseen CVEs are fetched live.'],
  ['get_exploits', 'Can this be exploited, and with what: Metasploit, Exploit-DB, Nuclei, PoC repositories.'],
  ['list_exploited', 'What CISA confirms is exploited in the wild, optionally only the AI stack.'],
  ['feed_status', 'What is stored and which sources answered, so an empty result can be read correctly.'],
];

/** The one-click links, built from the endpoint so they never drift from it. */
function installTargets(endpoint) {
  const vscodeConfig = { name: SERVER_NAME, type: 'http', url: endpoint };
  const cursorConfig = Buffer.from(JSON.stringify({ url: endpoint })).toString('base64');

  return [
    {
      id: 'vscode',
      label: 'Add to VS Code',
      href: `vscode:mcp/install?${encodeURIComponent(JSON.stringify(vscodeConfig))}`,
      hint: 'Opens VS Code to review and install.',
    },
    {
      id: 'cursor',
      label: 'Add to Cursor',
      href: `cursor://anysphere.cursor-deeplink/mcp/install?name=${SERVER_NAME}&config=${encodeURIComponent(cursorConfig)}`,
      hint: 'Opens Cursor to confirm the install.',
    },
    {
      id: 'claude',
      label: 'Add to Claude',
      copy: `claude mcp add --transport http ${SERVER_NAME} ${endpoint}`,
      hint: 'Copies the Claude Code command. On claude.ai, add the URL under Customize, Connectors.',
    },
    {
      id: 'opencode',
      label: 'Add to OpenCode',
      copy: `opencode mcp add ${SERVER_NAME} --url ${endpoint}`,
      hint: 'Copies the OpenCode command.',
    },
  ];
}

function installButton(target) {
  const inner = `${brandIcon(target.id)}<span>${escapeHtml(target.label)}</span>`;
  if (target.href) {
    return `<a class="install-btn" href="${escapeHtml(target.href)}" title="${escapeHtml(target.hint)}">${inner}</a>`;
  }
  return `<button type="button" class="install-btn" data-copy="${escapeHtml(target.copy)}" title="${escapeHtml(target.hint)}">${inner}</button>`;
}

export function agentsPage({ origin, canonical, assetVersion, stats }) {
  // The endpoint is the gateway once there is one. This page is the thing an
  // agent is pointed at, so it must name the address that actually works.
  const endpoint = config.mcpGatewayUrl || `${origin}/mcp`;
  const authenticated = Boolean(config.mcpGatewayUrl);
  const targets = installTargets(endpoint);

  const tools = TOOLS.map(
    ([name, line]) => `<li><code>${escapeHtml(name)}</code><span>${escapeHtml(line)}</span></li>`,
  ).join('');

  const body = `<article class="doc agents-page">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>For agents</span></nav>

    <h1>Connect your agent</h1>
    <p class="lede">Live vulnerability and exploit intelligence for any MCP client: what landed
    overnight, whether working exploit code exists, and which of your dependencies it hits.
    <strong>${stats?.withExploitSignal ?? 0}</strong> stored records carry a known exploit signal.</p>

    <section class="install">
      <div class="install-grid">${targets.map(installButton).join('')}</div>
      <p class="install-status" id="install-status" role="status"></p>

      <div class="endpoint">
        <span class="endpoint-label">Or use the URL in any client</span>
        <div class="copy-row">
          <code>${escapeHtml(endpoint)}</code>
          <button type="button" class="copy-btn" data-copy="${escapeHtml(endpoint)}">Copy</button>
        </div>
      </div>

      ${
        authenticated
          ? `<p class="aside">Your client opens a browser on first use: sign in with GitHub and approve
        it. New accounts get 60 calls an hour.</p>
      <details class="key-option">
        <summary>No browser? Use an API key</summary>
        <p>For CI or a headless agent, send a key as a bearer token instead of signing in.</p>
        <pre><code>{
  "mcpServers": {
    "${SERVER_NAME}": {
      "type": "http",
      "url": "${escapeHtml(endpoint)}",
      "headers": { "Authorization": "Bearer cvf_live_..." }
    }
  }
}</code></pre>
      </details>`
          : `<p class="aside">No account, no API key. Any MCP client works — the endpoint is all it needs.</p>`
      }
    </section>

    <section class="block">
      <h2>Six tools</h2>
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

  <script>
  (function () {
    var status = document.getElementById('install-status');
    /* Values come from data attributes the server wrote; nothing here is
       user-supplied, and text is set as text. */
    function copy(text, button) {
      var done = function () {
        if (button.classList.contains('copy-btn')) {
          button.textContent = 'Copied';
          setTimeout(function () { button.textContent = 'Copy'; }, 1600);
        }
        if (status) status.textContent = 'Copied: ' + text;
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
      } else { fallback(text); done(); }
    }
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
    document.querySelectorAll('[data-copy]').forEach(function (button) {
      button.addEventListener('click', function () { copy(button.getAttribute('data-copy'), button); });
    });
  })();
  </script>`;

  return layout({
    title: 'Connect your agent | CVE Feed',
    description:
      'Add CVE Feed to VS Code, Cursor, Claude or OpenCode: live vulnerability and exploit ' +
      'intelligence over MCP, plus a dependency check by exact version. ' +
      (authenticated ? 'Free to use; sign in with GitHub.' : 'No account, no API key.'),
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
