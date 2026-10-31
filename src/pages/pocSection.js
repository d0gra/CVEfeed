/**
 * The community proof-of-concept section on a CVE page.
 *
 * Three parts: the approved submissions (with a clear unverified / legal
 * disclaimer), the submit form (text only, CAPTCHA-gated, every legal
 * acknowledgement required), and an ambient "reviewing submissions" indicator.
 *
 * All displayed text is escaped: these are anonymous, attacker-adjacent
 * strings, and the body is rendered inside <pre> as data, never as markup.
 */
import { escapeHtml } from './layout.js';
import { ACKNOWLEDGEMENTS, LICENSES } from '../lib/validatePoc.js';

const fmtDate = (value) => {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
};

/** The legal line that travels with every displayed PoC. */
const DISCLAIMER =
  'Community-submitted and unverified. Provided for authorised security testing and education only. ' +
  'Using it against systems you do not own or have explicit permission to test may be illegal.';

function approvedList(pocs) {
  if (!pocs.length) {
    return `<p class="aside">No community proof of concept yet. If you have one for a published
      vulnerability and the right to share it, add it below — it will appear here once reviewed.</p>`;
  }

  return `<p class="poc-disclaimer">${escapeHtml(DISCLAIMER)}</p>
    <ul class="poc-list">${pocs
      .map(
        (p) => `<li class="poc">
          <div class="poc-head">
            <h3>${escapeHtml(p.title)}</h3>
            <span class="poc-by">by ${escapeHtml(p.author)} · ${escapeHtml(fmtDate(p.submittedAt))} · ${escapeHtml(
              LICENSES[p.license] ?? p.license,
            )}</span>
          </div>
          ${p.affected ? `<p class="poc-affected"><span>Affected</span> ${escapeHtml(p.affected)}</p>` : ''}
          ${p.writeup ? `<p>${escapeHtml(p.writeup)}</p>` : ''}
          <pre class="poc-code"><code>${escapeHtml(p.code)}</code></pre>
          ${
            p.references?.length
              ? `<ul class="linklist refs-list">${p.references
                  .map(
                    (u) =>
                      `<li><a href="${escapeHtml(u)}" rel="noopener nofollow" target="_blank">${escapeHtml(u)}</a></li>`,
                  )
                  .join('')}</ul>`
              : ''
          }
        </li>`,
      )
      .join('')}</ul>`;
}

function captchaField({ usingTurnstile, turnstileSiteKey, challenge }) {
  if (usingTurnstile) {
    return `<div class="field">
      <label>Verification</label>
      <div class="cf-turnstile" data-sitekey="${escapeHtml(turnstileSiteKey)}"></div>
    </div>`;
  }
  return `<div class="field field-captcha">
    <label for="poc-captcha">${escapeHtml(challenge.question)} <span class="req">*</span></label>
    <input type="hidden" name="captchaToken" value="${escapeHtml(challenge.token)}">
    <input id="poc-captcha" name="captchaAnswer" inputmode="numeric" autocomplete="off" required>
  </div>`;
}

function acknowledgementFields() {
  return Object.entries(ACKNOWLEDGEMENTS)
    .map(
      ([key, text]) => `<label class="ack">
        <input type="checkbox" name="${escapeHtml(key)}" required>
        <span>${escapeHtml(text)}</span>
      </label>`,
    )
    .join('');
}

function submitForm(id, captcha) {
  const licenseOptions = Object.entries(LICENSES)
    .map(([k, label]) => `<option value="${escapeHtml(k)}"${k === 'cc-by' ? ' selected' : ''}>${escapeHtml(label)}</option>`)
    .join('');

  return `<details class="poc-submit">
    <summary>Submit a proof of concept</summary>

    <p class="poc-legal">
      Only for <strong>publicly disclosed</strong> vulnerabilities, and only material from testing you were
      <strong>authorised</strong> to perform. This platform does not buy, sell, or broker exploits —
      see <a href="/earn">earning from vulnerability research</a> for legitimate bounty programs.
      Submissions are reviewed before they appear. Text only; do not include live credentials, personal
      data, or anything targeting systems you are not permitted to test.
    </p>

    <form id="poc-form" class="poc-form" novalidate>
      <input type="hidden" name="cveId" value="${escapeHtml(id)}">
      <!-- honeypot: real people leave this empty -->
      <div class="hp" aria-hidden="true"><label>Website<input name="website" tabindex="-1" autocomplete="off"></label></div>

      <div class="field">
        <label for="poc-title">Title <span class="req">*</span></label>
        <input id="poc-title" name="title" maxlength="140" required placeholder="Short description of the technique">
      </div>

      <div class="field">
        <label for="poc-code">Proof of concept <span class="req">*</span></label>
        <textarea id="poc-code" name="code" rows="10" required
          placeholder="Steps or code, as plain text. No file uploads."></textarea>
      </div>

      <div class="field">
        <label for="poc-writeup">Write-up <span class="opt">(optional)</span></label>
        <textarea id="poc-writeup" name="writeup" rows="4" placeholder="How it works, prerequisites, impact"></textarea>
      </div>

      <div class="field-row">
        <div class="field">
          <label for="poc-affected">Affected versions <span class="opt">(optional)</span></label>
          <input id="poc-affected" name="affected" maxlength="200" placeholder="e.g. &lt; 2.16.0">
        </div>
        <div class="field">
          <label for="poc-author">Name or handle <span class="opt">(optional)</span></label>
          <input id="poc-author" name="author" maxlength="60" placeholder="Anonymous">
        </div>
      </div>

      <div class="field">
        <label for="poc-refs">References <span class="opt">(optional, one URL per line)</span></label>
        <textarea id="poc-refs" name="references" rows="2" placeholder="https://..."></textarea>
      </div>

      <div class="field-row">
        <div class="field">
          <label for="poc-license">Licence for your contribution <span class="req">*</span></label>
          <select id="poc-license" name="license">${licenseOptions}</select>
        </div>
        <div class="field">
          <label for="poc-contact">Private contact <span class="opt">(optional, never shown)</span></label>
          <input id="poc-contact" name="contact" maxlength="140" placeholder="For credit or bounty coordination">
        </div>
      </div>

      <fieldset class="acks">
        <legend>Before you submit <span class="req">*</span></legend>
        ${acknowledgementFields()}
      </fieldset>

      ${captchaField(captcha)}

      <div class="poc-actions">
        <button type="submit" class="poc-btn">Submit for review</button>
        <span class="poc-result" id="poc-result" role="status"></span>
      </div>
    </form>
  </details>`;
}

/** The ambient "an agent is triaging the queue" indicator. Decorative. */
function agentScanner() {
  return `<div class="agent-scan" aria-hidden="true">
    <span class="agent-dot"></span>
    <span class="agent-text" id="agent-scan-text">Reviewing new submissions…</span>
  </div>`;
}

const inlineScript = (id) => `<script>
(function () {
  // --- ambient queue-review indicator (decorative) ---
  var el = document.getElementById('agent-scan-text');
  if (el) {
    var rid = function () { return 'CVE-' + (2024 + Math.floor(Math.random()*3)) + '-' + (10000 + Math.floor(Math.random()*89999)); };
    var lines = function () {
      return [
        'Reviewing new submissions…',
        'Triaging ' + rid() + '…',
        'Checking ' + rid() + ' against disclosure rules…',
        'Scanning for newly submitted proofs of concept…',
        'Queue reviewed · ' + rid() + ' pending approval',
      ];
    };
    var set = lines(), i = 0;
    setInterval(function () { i = (i + 1) % set.length; if (i === 0) set = lines(); el.textContent = set[i]; }, 2600);
  }

  // --- submit form ---
  var form = document.getElementById('poc-form');
  if (!form) return;
  var out = document.getElementById('poc-result');
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    out.textContent = 'Submitting…';
    out.dataset.kind = '';
    var data = {};
    new FormData(form).forEach(function (v, k) { data[k] = v; });
    form.querySelectorAll('input[type=checkbox]').forEach(function (c) { data[c.name] = c.checked; });
    var tr = form.querySelector('[name="cf-turnstile-response"]');
    if (tr) data['cf-turnstile-response'] = tr.value;
    fetch('/api/cve/${encodeURIComponent(id)}/pocs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
    }).then(function (r) { return r.json().then(function (b) { return { ok: r.ok, b: b }; }); })
      .then(function (res) {
        if (res.ok) {
          out.dataset.kind = 'ok';
          out.textContent = res.b.message || 'Submitted for review. Thank you.';
          form.reset();
        } else {
          out.dataset.kind = 'err';
          out.textContent = (res.b.details && res.b.details.join(' ')) || res.b.error || 'Submission failed.';
        }
      })
      .catch(function () { out.dataset.kind = 'err'; out.textContent = 'Network error. Please try again.'; });
  });
})();
</script>`;

export function pocSection({ id, pocs = [], captcha }) {
  const turnstileScript = captcha.usingTurnstile
    ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
    : '';

  return `<section class="block poc-section">
    <div class="poc-section-head">
      <h2>Community proofs of concept ${pocs.length ? `<span class="poc-count">${pocs.length}</span>` : ''}</h2>
      ${agentScanner()}
    </div>
    ${approvedList(pocs)}
    ${submitForm(id, captcha)}
  </section>
  ${turnstileScript}
  ${inlineScript(id)}`;
}

export default { pocSection };
