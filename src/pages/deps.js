/**
 * The dependency check, for people rather than agents.
 *
 * This page exists because the search box cannot answer the question people
 * actually arrive with. Searching "lodash" looks for the word in advisory
 * prose, which is neither the set of advisories affecting the npm package
 * lodash nor a subset of it - and even with a perfect index it could not tell
 * 4.17.15 from 4.17.21, which is the only part that decides the answer.
 *
 * So this takes a lockfile instead and resolves coordinates, exactly as the
 * MCP tool does, through the same endpoint. The page itself renders without
 * JavaScript - the form, the explanation and the format list are all here in
 * the markup - and the result is filled in client-side.
 */
import { breadcrumbJsonLd, escapeHtml, layout } from './layout.js';
import { MANIFEST_TYPES } from '../lib/manifests.js';

const EXAMPLE = `{
  "dependencies": {
    "lodash": "4.17.15",
    "minimist": "1.2.0",
    "axios": "0.21.0"
  }
}`;

export function depsPage({ origin, canonical, assetVersion }) {
  const formats = Object.entries(MANIFEST_TYPES)
    .map(
      ([name, { ecosystem, exact }]) =>
        `<li><code>${escapeHtml(name)}</code> <span class="dep-eco">${escapeHtml(ecosystem)}</span>${
          exact ? '' : ' <span class="dep-warn">ranges only</span>'
        }</li>`,
    )
    .join('');

  const body = `<article class="doc doc-wide">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Dependency check</span></nav>

    <h1>Check what you actually ship</h1>
    <p class="lede">Paste a lockfile. Every package is resolved at its exact installed version
    against OSV.dev, then ordered by whether an exploit for it actually exists \u2014 so what comes
    back is a short worklist rather than a wall of advisories.</p>

    <form class="dep-form" id="dep-form">
      <label class="dep-label" for="dep-input">Your manifest or lockfile</label>
      <textarea id="dep-input" class="dep-input" spellcheck="false" rows="12"
        placeholder="Paste package-lock.json, yarn.lock, requirements.txt, go.mod, Cargo.lock, Gemfile.lock, composer.lock&hellip;"></textarea>

      <div class="dep-controls">
        <button type="submit" id="dep-submit" class="dep-go">Check dependencies</button>
        <label class="toggle">
          <input type="checkbox" id="dep-exploitable">
          <span>Only what is exploitable</span>
        </label>
        <button type="button" class="quiet" id="dep-example">Use an example</button>
        <span class="dep-detected" id="dep-detected" aria-live="polite"></span>
      </div>
      <p class="dep-privacy">Your manifest is used to run the query and is not stored. Only the
      package names and versions in it are sent upstream \u2014 never the rest of the file.</p>
    </form>

    <section class="dep-results" id="dep-results" aria-live="polite" hidden></section>

    <section class="block">
      <h2>Why this is not the search box</h2>
      <p>Free-text search matches words in advisory text. That is the wrong shape of question for
      installed software, in three ways that better ranking would not fix. It has no ecosystem, so
      the npm package <code>zip</code> and the crates.io crate <code>zip</code> look like the same
      thing when they are unrelated software by unrelated authors. It has no versions, so 4.17.15
      and 4.17.21 are indistinguishable when only one of them is vulnerable. And it only knows the
      advisories in this feed\u2019s window, where a dependency check needs every advisory ever
      published against that package.</p>
      <p>This resolves coordinates instead \u2014 an ecosystem, a name, a version \u2014 through
      <a href="https://osv.dev" rel="noopener" target="_blank">OSV.dev</a>, the database the
      ecosystems themselves publish into and which records affected version ranges.</p>
    </section>

    <section class="block">
      <h2>And why not just <code>npm audit</code></h2>
      <p><code>npm audit</code> tells you which advisories apply. It cannot tell you which of them
      anyone could act on, so it sorts by a severity label and leaves you forty rows that all look
      equally urgent. Every finding here also carries whether exploit code exists and how reachable
      it is \u2014 a Metasploit module, an archived Exploit-DB entry, published proof-of-concept
      code, a Nuclei template \u2014 and the list is ordered by that first.</p>
      <p>Which reorders the work: a moderate with a working module is a worse afternoon than a
      critical nobody has written anything for. <strong>Patch first</strong> at the top of the
      result is that ordering, with the version to upgrade to.</p>
    </section>

    <section class="block">
      <h2>Formats it reads</h2>
      <ul class="dep-formats">${formats}</ul>
      <p class="aside">A lockfile is much better than a manifest. A lockfile states the version that
      is installed; <code>package.json</code> states a range, which has to be coerced to its lowest
      version to be queryable at all \u2014 so findings from one are flagged as approximate.</p>
    </section>

    <section class="block">
      <h2>From a script, or an agent</h2>
      <p>The same check over HTTP, with no key:</p>
      <pre><code>curl -X POST ${escapeHtml(origin)}/api/dependencies/check \\
  -H 'Content-Type: application/json' \\
  --data "{\\"manifest\\": $(jq -Rs . &lt; package-lock.json)}"</code></pre>
      <p>Or as a tool your agent can call itself \u2014 <code>check_dependencies</code> over
      <a href="/mcp">MCP</a>, which parses the lockfile for you.</p>
    </section>

    <section class="callout callout-exploit">
      <h2>What a clean result means</h2>
      <p>No advisory is known for that exact version, in the databases consulted. It is not a
      statement that the package is safe, that your configuration is safe, or that nothing will be
      published tomorrow.</p>
      <p class="aside">Exploit maturity says whether exploit code exists publicly \u2014 not whether
      you are reachable or affected in practice. Confirm against the upstream advisory before you
      act.</p>
    </section>
  </article>

  <script type="application/json" id="dep-example-data">${JSON.stringify(EXAMPLE).replace(/</g, '\\u003c')}</script>
  <script src="/assets/deps.js?v=${escapeHtml(assetVersion)}" type="module"></script>`;

  return layout({
    title: 'Check your dependencies for exploitable vulnerabilities | CVE Feed',
    description:
      'Paste a lockfile and get the vulnerabilities affecting your exact installed versions, ordered by whether a public exploit actually exists - not just by severity label. npm, PyPI, Go, crates.io, RubyGems, Packagist.',
    canonical,
    body,
    current: '/dependencies',
    assetVersion,
    jsonLd: [
      breadcrumbJsonLd(origin, [['Feed', '/'], ['Dependency check', '/dependencies']]),
      {
        '@context': 'https://schema.org',
        '@type': 'WebApplication',
        name: 'Dependency vulnerability check',
        applicationCategory: 'SecurityApplication',
        operatingSystem: 'Any',
        url: canonical,
        description:
          'Resolves a manifest or lockfile against OSV.dev and reports the vulnerabilities affecting each exact installed version, enriched with whether public exploit code exists.',
        offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      },
    ],
  });
}

export default { depsPage };
