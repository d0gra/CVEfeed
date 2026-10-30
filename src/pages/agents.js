/**
 * The page for people deciding whether to point an agent at this feed.
 *
 * Served on GET /mcp by content negotiation: a browser asking for HTML gets
 * this, an MCP client gets the protocol. One URL to give someone, whichever
 * of the two they are.
 */
import { breadcrumbJsonLd, escapeHtml, layout } from './layout.js';
import { STACK_CATEGORIES } from '../stack.js';

const TOOLS = [
  {
    name: 'search_cves',
    line: 'Filter by text, severity, CVSS, exploitation, AI-stack category or recency.',
    example: '{ "stack": ["mcp"], "severity": ["critical", "high"], "limit": 10 }',
  },
  {
    name: 'get_cve',
    line: 'One vulnerability in full, by CVE, GHSA, EUVD or advisory ID. Anything outside the current window is looked up directly at the registers, so any published CVE resolves however old.',
    example: '{ "id": "CVE-2021-44228" }',
  },
  {
    name: 'list_exploited',
    line: 'What CISA has confirmed is being exploited, optionally narrowed to the AI stack.',
    example: '{ "stack": ["any"] }',
  },
  {
    name: 'feed_status',
    line: 'Which sources answered, how old the data is, and the categories available. Worth checking before reading an empty result as "nothing found".',
    example: '{}',
  },
];

export function agentsPage({ origin, canonical, assetVersion, stats }) {
  const endpoint = `${origin}/mcp`;

  const tools = TOOLS.map(
    (t) => `<li class="tool">
      <h3><code>${escapeHtml(t.name)}</code></h3>
      <p>${escapeHtml(t.line)}</p>
      <pre><code>${escapeHtml(t.example)}</code></pre>
    </li>`,
  ).join('');

  const categories = STACK_CATEGORIES.map((c) => `<code>${escapeHtml(c.id)}</code>`).join(', ');

  const body = `<article class="doc doc-wide">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>For agents</span></nav>

    <h1>Vulnerability intelligence your agent can read</h1>
    <p class="lede">This feed speaks the Model Context Protocol, so an agent can query current
    vulnerability disclosures as a tool instead of scraping a dashboard. Five public registers,
    merged and deduplicated, with a dedicated view of the AI and agent stack — the inference
    servers, agent frameworks and MCP servers your own stack is probably made of.</p>

    <section class="hero-add">
      <h2>Add it</h2>
      <pre><code>claude mcp add --transport http cvefeed ${escapeHtml(endpoint)}</code></pre>
      <p class="aside">No account, no API key, no rate limit beyond what the upstream registers
      impose. Any MCP client works — the endpoint is all it needs.</p>
    </section>

    <section class="block">
      <h2>Four tools</h2>
      <ul class="tools">${tools}</ul>
    </section>

    <section class="block">
      <h2>Built for how agents actually read</h2>
      <div class="pair">
        <div>
          <h3>Lean by default</h3>
          <p>Twenty records cost roughly <strong>1,800 tokens</strong> rather than the
          <strong>12,100</strong> the equivalent REST payload would — tools return a trimmed
          record, and <code>detail: true</code> opts back in to descriptions, CVSS vectors, CWEs
          and KEV guidance when you actually need them.</p>
        </div>
        <div>
          <h3>Advisory text is labelled untrusted</h3>
          <p>CVE descriptions are third-party prose and references point at arbitrary pages. Every
          result carries a notice telling the agent to treat the content as data rather than
          instructions, and reference URLs are listed but never fetched. A vulnerability feed is a
          poor thing to turn into an injection path.</p>
        </div>
      </div>
    </section>

    <section class="block">
      <h2>The AI stack, as a filter</h2>
      <p>Records are classified against the software agents run on, by package name and vendor
      rather than by keyword. Pass any of ${categories} to <code>stack</code>, or
      <code>any</code> for everything classified.</p>
      <p class="stat-line">Right now: <strong>${stats?.inStack ?? 0}</strong> disclosures in the
      AI stack, <strong>${stats?.stackExploited ?? 0}</strong> of them
      <a href="/exploited">already being exploited</a>.</p>
      <pre><code>// "is anything in my AI stack being exploited right now?"
search_cves { "stack": ["any"], "exploited": true }</code></pre>
    </section>

    <section class="block">
      <h2>Without MCP</h2>
      <p>The same data is plain JSON over HTTP, and <a href="/llms.txt">/llms.txt</a> describes the
      whole service in prose for an agent handed nothing but a domain.</p>
      <pre><code>curl '${escapeHtml(origin)}/api/feed?stack=any&amp;exploited=1'
curl '${escapeHtml(origin)}/api/cve/CVE-2021-44228'</code></pre>
    </section>

    <section class="block">
      <h2>How it is built</h2>
      <p>The protocol is implemented directly rather than through the official SDK, which pulls
      seventeen transitive dependencies including a second major version of Express. Conformance is
      checked against the real SDK client in the test suite, so the shortcut is in the dependency
      tree rather than in the protocol. There is no database: the feed is fetched from the
      registers and held in memory with a JSON snapshot on disk.</p>
      <p class="aside"><a href="https://github.com/d0gra/CVEfeed" rel="noopener">Source on GitHub</a>
      — GPL-3.0, self-hostable, no telemetry.</p>
    </section>
  </article>`;

  return layout({
    title: 'MCP endpoint for CVE data | CVE Feed',
    description:
      'Query current CVEs from your agent over the Model Context Protocol. Four tools, five merged registers, a dedicated AI-stack filter, and no API key.',
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
          'Model Context Protocol server exposing merged CVE data from NVD, CISA KEV, GitHub Advisories, EUVD and CISA advisories, with an AI and agent stack filter.',
        offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      },
    ],
  });
}
