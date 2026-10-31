/**
 * Terms for submitting and using community proofs of concept.
 *
 * Written to be read, not to be hidden behind. It states plainly what a
 * submitter is agreeing to, what the material may be used for, what is kept
 * private, and how to get something removed.
 */
import { breadcrumbJsonLd, escapeHtml, layout } from './layout.js';
import { ACKNOWLEDGEMENTS, LICENSES } from '../lib/validatePoc.js';

export function termsPage({ origin, canonical, assetVersion }) {
  const acks = Object.values(ACKNOWLEDGEMENTS)
    .map((t) => `<li>${escapeHtml(t)}</li>`)
    .join('');
  const licenses = Object.values(LICENSES)
    .map((t) => `<li>${escapeHtml(t)}</li>`)
    .join('');

  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Terms</span></nav>
    <h1>Submission &amp; use terms</h1>
    <p class="lede">These terms cover community proofs of concept — submitting them, and using the ones
    shown here. Plain-language summary first; it is not legal advice.</p>

    <section class="block">
      <h2>What you may submit</h2>
      <p>Proofs of concept for <strong>publicly disclosed</strong> vulnerabilities only — ones that
      already have a published CVE. Text only; there are no file uploads. By submitting, you confirm each
      of the following:</p>
      <ul class="term-list">${acks}</ul>
      <p>Submissions are <strong>reviewed before they appear</strong> and may be edited for formatting or
      rejected for any reason. We may remove anything at any time.</p>
    </section>

    <section class="block">
      <h2>Licensing of your contribution</h2>
      <p>You choose how your PoC may be reused. The options are:</p>
      <ul class="term-list">${licenses}</ul>
      <p>You keep ownership; you grant this site a non-exclusive right to host and display the submission
      under the licence you pick, and to remove it.</p>
    </section>

    <section class="block">
      <h2>What we store, and privacy</h2>
      <p>We store the submission and a one-way hash of your network address for abuse prevention — not
      the address itself. A contact you provide is <strong>kept private</strong> for moderation or credit
      and is never displayed. Do not submit personal data or live credentials; submissions that contain
      them are rejected.</p>
    </section>

    <section class="callout callout-exploit">
      <h2>Using what is shown here</h2>
      <p>Community PoCs are <strong>unverified</strong> and provided for authorised security testing,
      defence and education. Run them only against systems you own or have explicit permission to test.
      Unauthorised access to computer systems is a crime in most jurisdictions (for example the US
      Computer Fraud and Abuse Act and the UK Computer Misuse Act). The material is provided “as is”,
      without warranty; you are responsible for how you use it.</p>
    </section>

    <section class="block">
      <h2>Earning, and what this is not</h2>
      <p>This platform does not buy, sell, or broker exploits, and does not pay for submissions. For
      legitimate ways to be paid for vulnerability research, see <a href="/earn">earning</a>.</p>
    </section>

    <section class="block">
      <h2>Removal</h2>
      <p>If you are an affected vendor or the author and want a submission removed, or you believe content
      here infringes your rights or breaches these terms, contact the site operator and it will be
      reviewed promptly.</p>
    </section>
  </article>`;

  return layout({
    title: 'Submission & use terms | CVE Feed',
    description:
      'Terms for submitting and using community proofs of concept: published-CVE only, text only, reviewed before publication, authorised use only.',
    canonical,
    body,
    current: '',
    assetVersion,
    jsonLd: [breadcrumbJsonLd(origin, [['Feed', '/'], ['Terms', '/terms']])],
  });
}

export default { termsPage };
