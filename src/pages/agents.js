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
    name: 'check_dependencies',
    line: 'Check a project\u2019s dependencies by exact version and say which findings anyone could actually exploit. Takes coordinates, or a pasted lockfile it parses for you \u2014 npm, PyPI, Go, crates.io, RubyGems, Packagist.',
    example: '{ "manifest": "<your package-lock.json>", "onlyExploitable": true }',
  },
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

    <h1>Give your agent the instincts of an elite hacker</h1>
    <p class="lede">A model knows vulnerabilities up to its training cut-off and nothing after it,
    which makes it a junior analyst reciting last year’s news. Connect this endpoint and your
    agent — pentest, red team, triage, or the one reviewing your pull requests — gets what
    a good operator actually carries in their head: what landed overnight, whether anyone has
    written working code for it, where that code is, and which of the things you ship it lands on.</p>
    <p class="lede">One command. No account, no key.</p>

    <section class="hero-add">
      <h2>Add it</h2>
      <pre><code>claude mcp add --transport http cvefeed ${escapeHtml(endpoint)}</code></pre>
      <p class="aside">No account, no API key. Any MCP client works — the endpoint is all it needs.</p>
    </section>

    <section class="block">
      <h2>What it stops having to guess at</h2>
      <ul class="earn-list">
        <li><strong>“What can I actually hit on this target?”</strong>
          <p>Not a list of CVEs with scores — the subset somebody has already written code for,
          with the Metasploit module, the Exploit-DB entry and the proof-of-concept repositories
          ranked by stars. The difference between knowing a flaw exists and being able to
          demonstrate it.</p></li>
        <li><strong>“Are any of our dependencies vulnerable — and does it matter?”</strong>
          <p>Paste a lockfile. Every package is resolved at its exact installed version, then
          ordered by whether exploit code exists, so the answer is a worklist of four rather than a
          wall of forty. The judgement call a scanner leaves to you.</p></li>
        <li><strong>“What landed overnight that changes my plan?”</strong>
          <p>Newest first, with CVSS, EPSS and exploit availability already attached. Your agent
          triages instead of fetching five sources and guessing which to believe.</p></li>
        <li><strong>“Is anything in our AI stack being exploited right now?”</strong>
          <p>Inference servers, agent frameworks, MCP servers, vector stores — classified as a
          facet of their own, because that is the surface nobody has finished picking over.</p></li>
      </ul>
    </section>

    <section class="block">
      <h2>Where the edge actually comes from</h2>
      <p>What separates a good operator from a scanner is not knowing more CVEs. It is knowing which
      of them is worth an afternoon. A 7.5 with a ready-made module is a worse day than a 9.8 nobody
      has written anything for, and no severity score tells you which is which.</p>
      <p>Every record here carries that judgement as data: whether exploitation has been
      <strong>observed in the wild</strong>, whether it is <strong>weaponized</strong> into a
      Metasploit module, whether a <strong>public exploit</strong> is archived and downloadable,
      whether <strong>proof-of-concept</strong> code is published, and whether a Nuclei template
      means it is being scanned for at internet scale. Sort by that and your agent prioritises the
      way someone experienced would.</p>
      <p class="stat-line"><strong>${'${stats?.withExploitSignal ?? 0}'}</strong> of the records currently stored
      carry at least one exploit signal.</p>
    </section>

    <section class="block">
      <h2>Six tools</h2>
      <ul class="tools">${tools}</ul>
    </section>

    <section class="block">
      <h2>Dependencies, by coordinate rather than by keyword</h2>
      <p>Free-text search is the wrong tool for “is my project affected”, and it is worth
      being plain about why. Searching <code>lodash</code> matches advisories whose <em>text</em>
      contains that word — which is neither the set of advisories affecting the npm package
      lodash nor a subset of it. It has no ecosystem, so npm <code>zip</code> and crates.io
      <code>zip</code> look like the same thing when they are unrelated software. And it has no
      versions, so 4.17.15 and 4.17.21 are indistinguishable when only one of them is vulnerable.</p>
      <div class="pair">
        <div>
          <h3>So it resolves coordinates</h3>
          <p><code>check_dependencies</code> takes an ecosystem, a name and an installed version and
          matches affected version ranges through <a href="https://osv.dev" rel="noopener"
          target="_blank">OSV.dev</a>, the database the ecosystems themselves publish into. Paste a
          package-lock.json, yarn.lock, requirements.txt, poetry.lock, go.mod, Cargo.lock,
          Gemfile.lock or composer.lock and it is parsed for you.</p>
        </div>
        <div>
          <h3>And then adds what audit tools cannot</h3>
          <p><code>npm audit</code> gives you forty advisories sorted by a severity label. This adds
          whether a Metasploit module, an archived exploit or public proof-of-concept code exists for
          each one, sorts by that, and returns <code>patchFirst</code> — what to upgrade, in
          order, and why. A moderate with a working exploit outranks a critical nobody has written
          anything for.</p>
        </div>
      </div>
      <pre><code>check_dependencies { "manifest": "&lt;package-lock.json&gt;", "onlyExploitable": true }</code></pre>
      <p class="aside">Repeat sweeps are cached, so re-checking the same lockfile in CI costs
      almost nothing.</p>
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

    <section class="callout callout-exploit">
      <h2>Authorised testing only</h2>
      <p>This is offensive capability pointed at defence: knowing what can be exploited is how you
      decide what to fix first, and how an engagement proves a finding rather than asserting it.
      Point it at systems you own or have explicit, written permission to test, and nothing else.
      Unauthorised access to computer systems is a crime in most jurisdictions.</p>
      <p class="aside">Advisory text and community proofs of concept are untrusted third-party
      content. Every result says so, and reference URLs are listed but never fetched. See the
      <a href="/terms">terms</a>.</p>
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
      — source-available for noncommercial use, self-hostable, no telemetry.</p>
    </section>
  </article>`;

  return layout({
    title: 'Give your agent the instincts of an elite hacker | CVE Feed',
    description:
      'An MCP endpoint that gives a pentest, red-team or triage agent live knowledge of vulnerabilities and the exploits that exist for them - Metasploit modules, Exploit-DB entries, public PoCs - plus a dependency check by exact version. No account, no API key.',
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
