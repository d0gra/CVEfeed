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
    <h1>Earn from what you find</h1>
    <p class="lede">Finding and reporting vulnerabilities responsibly is paid work. The legitimate route
    is coordinated disclosure through a program that has invited you to test — and it can be lucrative,
    repeatable and entirely lawful.</p>

    <section class="block">
      <h2>How it pays</h2>
      <p>You find a flaw in software or a service whose owner runs a bounty or disclosure program,
      report it privately through their channel, help them fix it, and are rewarded — in money,
      recognition, or both. The vulnerability is disclosed and gets a CVE; the PoC can then be shared
      with the community, which is where a feed like this one comes in.</p>
    </section>

    <section class="block">
      <h2>Bug bounty platforms</h2>
      <ul class="earn-list">${platforms}</ul>
    </section>

    <section class="block">
      <h2>Vendor programs and competitions</h2>
      <ul class="linklist">${vendors}</ul>
    </section>

    <section class="block">
      <h2>Contribute here</h2>
      <p>Once a vulnerability is <strong>publicly disclosed</strong>, you can add your proof of concept
      to its page on this feed. It builds your public track record and helps defenders understand the
      risk. It is a contribution, not a sale — see the boundary below.</p>
      <p class="aside"><a href="/exploited">Start from what is already being exploited</a>, or open any
      CVE and use “Submit a proof of concept”.</p>
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
    title: 'Earn from vulnerability research | CVE Feed',
    description:
      'Legitimate ways to earn from finding vulnerabilities: bug bounty platforms, vendor programs and competitions — plus where the legal line is.',
    canonical,
    body,
    current: '/earn',
    assetVersion,
    jsonLd: [breadcrumbJsonLd(origin, [['Feed', '/'], ['Earning', '/earn']])],
  });
}

export default { earnPage };
