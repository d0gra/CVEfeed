/**
 * "Earn from what you find" - a marketing page about legitimately making money
 * from vulnerability research.
 *
 * Framing is deliberate and non-negotiable: every channel here is lawful and
 * authorised - bug bounty platforms, vendor programs, competitions. This
 * platform does not buy, sell, or broker exploits, and the page says so
 * plainly, because the one thing a page like this must not do is read as an
 * on-ramp to a grey market.
 */
import { breadcrumbJsonLd, escapeHtml, layout } from './layout.js';

const PLATFORMS = [
  ['HackerOne', 'https://hackerone.com', 'The largest bug bounty platform; thousands of programs across every industry.'],
  ['Bugcrowd', 'https://bugcrowd.com', 'Crowdsourced programs and managed VDPs.'],
  ['Intigriti', 'https://intigriti.com', 'European platform with a strong public-program catalogue.'],
  ['YesWeHack', 'https://yeswehack.com', 'Global platform, large public scope.'],
  ['huntr', 'https://huntr.com', 'Bounties specifically for open-source and the AI/ML stack — the same software this feed tracks.'],
];

const VENDORS = [
  ['Google Vulnerability Reward Program', 'https://bughunters.google.com'],
  ['Microsoft Bug Bounty', 'https://www.microsoft.com/en-us/msrc/bounty'],
  ['Apple Security Bounty', 'https://security.apple.com/bounty/'],
  ['GitHub Security Lab', 'https://securitylab.github.com/bounties/'],
  ['Zero Day Initiative / Pwn2Own', 'https://www.zerodayinitiative.com'],
];

export function earnPage({ origin, canonical, assetVersion }) {
  const platforms = PLATFORMS.map(
    ([name, url, blurb]) =>
      `<li><a href="${escapeHtml(url)}" rel="noopener" target="_blank">${escapeHtml(name)}</a>
        <p>${escapeHtml(blurb)}</p></li>`,
  ).join('');

  const vendors = VENDORS.map(
    ([name, url]) => `<li><a href="${escapeHtml(url)}" rel="noopener" target="_blank">${escapeHtml(name)}</a></li>`,
  ).join('');

  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Earning</span></nav>
    <h1>Get paid for what you find</h1>
    <p class="lede">Vulnerability research is paid work. Not through grey-market buyers \u2014 through
    programs that have invited you to test them, pay for what you report, and let you publish it
    afterwards. The same disclosures that end up in this feed started as someone\u2019s bounty.</p>

    <section class="block">
      <h2>How the money actually works</h2>
      <p>A company runs a bounty program and publishes a scope: these domains, these apps, these
      rules. You test what is in scope, find a flaw, and report it privately through their
      platform. They triage it, pay according to severity, and fix it. Later it gets a CVE and a
      public write-up \u2014 and that is the point at which a proof of concept can be shared.</p>
      <p>Payouts scale with impact, not effort. A low-severity information leak might be a few
      hundred dollars; a solid authentication bypass on a serious target runs into four figures; a
      pre-auth remote code execution on a major vendor can reach five or six. The median report is
      modest, and the people making a living at it go deep on one target rather than spraying
      scanners at a hundred.</p>
    </section>

    <section class="block">
      <h2>Where to start</h2>
      <p>If you are new: pick <em>one</em> program with a wide scope and a public hall of fame,
      read every disclosed report for it, and look for the variant nobody checked. Reading other
      people\u2019s accepted reports is the fastest way to learn what triagers actually pay for.</p>
      <ul class="earn-list">${platforms}</ul>
    </section>

    <section class="block">
      <h2>Straight from the vendors</h2>
      <p>The large vendors run their own programs, often paying more than the platforms for the
      same bug, and competitions pay the most of all for a working chain.</p>
      <ul class="linklist">${vendors}</ul>
    </section>

    <section class="block">
      <h2>The AI stack is wide open right now</h2>
      <p>Inference servers, agent frameworks, MCP servers and vector stores are young code shipping
      fast, and this feed tracks them deliberately. <a href="/ai-stack">Look at what is already
      being found</a> \u2014 unauthenticated RCE in model servers, auth bypasses in MCP transports,
      API keys leaking into traces. huntr pays bounties specifically on this software, and the
      surface is nothing like as picked-over as a bank\u2019s login page.</p>
    </section>

    <section class="block">
      <h2>Then publish it here</h2>
      <p>Once a vulnerability is <strong>publicly disclosed</strong>, add your proof of concept to
      its page. It is reviewed before it appears, you keep your name on it under the licence you
      choose, and defenders get something far more useful than a CVSS score. That is a track record
      you can point at \u2014 not a payment from us.</p>
      <p class="aside"><a href="/exploited">Start from what is already being exploited</a>, or open
      any CVE and use \u201cSubmit a proof of concept\u201d.</p>
    </section>

    <section class="callout callout-exploit">
      <h2>Where the line is</h2>
      <p><strong>This platform does not buy, sell, or broker exploits, and never pays for submissions.</strong>
      Community contributions are for published vulnerabilities only.</p>
      <p>Only ever test systems you own or have explicit, written permission to test. Selling exploits
      or vulnerability details outside an authorised program, or to grey- or black-market buyers, is a
      different activity entirely — frequently illegal, and not something this site facilitates or
      endorses. Unauthorised access to computer systems is a crime in most jurisdictions (for example
      the US Computer Fraud and Abuse Act and the UK Computer Misuse Act).</p>
      <p class="aside">This is general information, not legal advice. See the <a href="/terms">terms</a>.</p>
    </section>
  </article>`;

  return layout({
    title: 'Get paid for finding vulnerabilities | CVE Feed',
    description:
      'How bug bounty money actually works, where to start, which platforms and vendor programs pay, and why the AI stack is the least picked-over surface right now.',
    canonical,
    body,
    current: '/earn',
    assetVersion,
    jsonLd: [breadcrumbJsonLd(origin, [['Feed', '/'], ['Earning', '/earn']])],
  });
}

export default { earnPage };
