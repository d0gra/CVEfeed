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
    line: 'Find vulnerabilities by severity, CVSS, EPSS, exploitation status, how reachable an exploit is, AI-stack component, recency or free text. Paginated.',
    example: '{ "stack": ["mcp"], "maturity": "public-exploit", "limit": 10 }',
  },
  {
    name: 'get_cve',
    line: 'One advisory in full — every register\u2019s view merged, plus exploit links and any community proof of concept. A CVE we have never seen is fetched live from the registers and then kept.',
    example: '{ "id": "CVE-2021-44228" }',
  },
  {
    name: 'get_exploits',
    line: 'The exploit picture for one CVE on its own: how reachable it is, and links to the Metasploit module, the Exploit-DB entry, the Nuclei template, PoC repositories by stars, and community submissions.',
    example: '{ "id": "CVE-2021-44228" }',
  },
  {
    name: 'list_exploited',
    line: 'What CISA confirms is being exploited in the wild right now, optionally narrowed to the AI stack.',
    example: '{ "stack": ["any"] }',
  },
  {
    name: 'feed_status',
    line: 'How much is stored, which sources answered, and whether the database or the degraded fallback is serving — so an empty result can be read correctly.',
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

    <h1>Give your agents knowledge of CVEs — and the exploits for them</h1>
    <p class="lede">Models know vulnerabilities up to their training cut-off, and nothing after it.
    Point an agent at this endpoint and it can answer what shipped this morning, whether anyone has
    actually written an exploit for it, and whether that exploit is sitting in Metasploit or on
    GitHub right now.</p>

    <section class="hero-add">
      <h2>Add it</h2>
      <pre><code>claude mcp add --transport http cvefeed ${escapeHtml(endpoint)}</code></pre>
      <p class="aside">No account, no API key. Any MCP client works — the endpoint is all it needs.</p>
    </section>

    <section class="block">
      <h2>What your agent can answer</h2>
      <ul class="earn-list">
        <li><strong>“Is anything in our stack being exploited?”</strong>
          <p>Ask for the AI stack and the exploited filter and it comes back with the handful that
          matter, not a thousand CVEs to read.</p></li>
        <li><strong>“Can this one actually be exploited, and with what?”</strong>
          <p><code>get_exploits</code> answers in one call: the maturity, and the links — the
          Metasploit module, the Exploit-DB entry, the PoC repositories ranked by stars.</p></li>
        <li><strong>“What landed overnight that I should care about?”</strong>
          <p>Newest first, with CVSS, EPSS and exploit availability already attached, so the agent
          can triage instead of fetching five sources itself.</p></li>
        <li><strong>“Tell me everything about CVE-2021-44228.”</strong>
          <p>Any published CVE resolves, however old. If it is not stored yet it is fetched live
          from the registers and kept, so the second ask is instant.</p></li>
      </ul>
    </section>

    <section class="block">
      <h2>Five tools</h2>
      <ul class="tools">${tools}</ul>
    </section>

    <section class="block">
      <h2>Exploit intelligence, not just advisories</h2>
      <p>Most feeds stop at “here is a CVE with a CVSS score”. A score does not tell you whether
      someone can run an attack this afternoon. Every record here also carries whether an exploit
      exists and how reachable it is:</p>
      <div class="pair">
        <div>
          <h3>Four rungs</h3>
          <p><strong>Observed</strong> in the wild (CISA KEV) · <strong>weaponized</strong>, meaning a
          Metasploit module · a <strong>public exploit</strong> archived on Exploit-DB · or
          <strong>proof-of-concept</strong> code on GitHub. A Nuclei template means it is scanned for
          at internet scale.</p>
        </div>
        <div>
          <h3>Why it reorders your work</h3>
          <p>A 7.5 with a ready-made module is a worse afternoon than a 9.8 nobody has written
          anything for. Sorting by exploitability puts that first, and
          <strong>${stats?.withExploitSignal ?? 0}</strong> of the records currently stored carry at
          least one exploit signal.</p>
        </div>
      </div>
    </section>

    <section class="block">
      <h2>Built for how agents actually read</h2>
      <div class="pair">
        <div>
          <h3>Lean by default</h3>
          <p>Twenty records cost roughly <strong>1,800 tokens</strong> rather than the
          <strong>12,100</strong> the equivalent REST payload would. <code>detail: true</code> opts
          back in to descriptions, vectors, CWEs and exploit links when you actually need them.</p>
        </div>
        <div>
          <h3>Advisory text is labelled untrusted</h3>
          <p>CVE descriptions and community PoCs are third-party text, and references point at
          arbitrary pages. Every result says so, and reference URLs are listed but never fetched. A
          vulnerability feed is a poor thing to turn into an injection path.</p>
        </div>
      </div>
    </section>

    <section class="block">
      <h2>The AI stack, as a filter</h2>
      <p>Records are classified against the software agents actually run on — inference servers,
      agent frameworks, MCP servers, vector stores, MLOps — matched by package name and vendor
      rather than keyword. Pass any of ${categories} to <code>stack</code>, or <code>any</code>.</p>
      <p class="stat-line">Right now: <strong>${stats?.inStack ?? 0}</strong> in the AI stack,
      <strong>${stats?.stackExploited ?? 0}</strong> of them
      <a href="/exploited">already being exploited</a>.</p>
      <pre><code>search_cves { "stack": ["any"], "exploited": true }</code></pre>
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
      tree rather than in the protocol. Records live in MongoDB, which is what lets the corpus
      accumulate instead of ageing out, and lets a CVE fetched once stay fetched. If the database
      is ever unreachable the server falls back to serving from memory rather than going down.</p>
      <p class="aside"><a href="https://github.com/d0gra/CVEfeed" rel="noopener">Source on GitHub</a>
      — GPL-3.0, self-hostable, no telemetry.</p>
    </section>
  </article>`;

  return layout({
    title: 'Give your agents CVE and exploit knowledge | CVE Feed',
    description:
      'An MCP endpoint that gives your agent live knowledge of vulnerabilities and the exploits that exist for them - Metasploit, Exploit-DB, public PoCs - with an AI-stack filter and no API key.',
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
