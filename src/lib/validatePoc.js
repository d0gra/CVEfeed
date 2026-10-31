/**
 * Validation for community proof-of-concept submissions.
 *
 * Pure, dependency-free and testable: it takes the raw form body and returns
 * either a clean, normalised record or a list of field errors. The storage
 * layer never sees anything this has not approved.
 *
 * The rules are deliberately strict. This endpoint accepts attacker-adjacent
 * text from anonymous users and stores it for later display, so the job here
 * is to keep out anything that is not a plain-text PoC for a published CVE:
 * binary pastes, control characters, dangerous URL schemes, oversized bodies,
 * missing legal acknowledgements, and bot spray.
 */

const CVE_ID = /^CVE-\d{4}-\d{4,7}$/i;

// A licence the submitter chooses, which governs how the PoC may be reused.
export const LICENSES = {
  cc0: 'CC0 1.0 (public domain dedication)',
  'mit': 'MIT',
  'cc-by': 'CC BY 4.0 (attribution required)',
  'author-retains': 'Author retains all rights; shared for education only',
};

// Every one of these must be explicitly affirmed. They are the legal spine of
// the feature: without them the submission is refused.
export const ACKNOWLEDGEMENTS = {
  disclosed: 'This vulnerability is already publicly disclosed (it has a published CVE).',
  authorized: 'This material comes only from testing I was authorised to perform.',
  rightToShare: 'I have the legal right to publish this content and am not breaching any agreement by doing so.',
  noSensitive: 'It contains no live credentials, personal data, or anything targeting systems I am not authorised to test.',
  reviewed: 'I understand it will be reviewed before it appears publicly and may be rejected.',
  terms: 'I agree to the submission terms.',
};

const LIMITS = {
  title: { min: 6, max: 140 },
  writeup: { max: 8000 },
  affected: { max: 200 },
  author: { max: 60 },
  contact: { max: 140 },
  reference: { max: 500, count: 10 },
};

const isTrue = (v) => v === true || v === 'true' || v === 'on' || v === '1' || v === 1;

const clean = (v) =>
  String(v ?? '')
    // Normalise line endings and strip control characters except tab/newline.
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .trim();

/** A paste is "binary-ish" if too much of it is non-printable. Rejects dumps. */
function looksBinary(text) {
  if (!text) return false;
  let suspect = 0;
  for (const ch of text) {
    const c = ch.codePointAt(0);
    if (c === 9 || c === 10) continue; // tab, newline
    if (c < 32 || c === 127) suspect += 1;
  }
  return suspect / text.length > 0.02;
}

/** Only http(s) links; never javascript:, data:, file: and the like. */
function cleanReferences(raw) {
  const list = Array.isArray(raw)
    ? raw
    : String(raw ?? '')
        .split(/[\n,]/)
        .map((s) => s.trim());

  const urls = [];
  const errors = [];
  for (const entry of list.filter(Boolean).slice(0, LIMITS.reference.count + 1)) {
    if (urls.length >= LIMITS.reference.count) {
      errors.push(`At most ${LIMITS.reference.count} references.`);
      break;
    }
    if (entry.length > LIMITS.reference.max) {
      errors.push('A reference URL is too long.');
      continue;
    }
    let url;
    try {
      url = new URL(entry);
    } catch {
      errors.push(`Not a valid URL: ${entry.slice(0, 60)}`);
      continue;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      errors.push('References must be http(s) links.');
      continue;
    }
    urls.push(url.toString());
  }
  return { urls, errors };
}

/**
 * @param {object} body       the raw request body
 * @param {number} maxChars   the configured PoC body cap
 * @returns {{ ok: true, value: object } | { ok: false, errors: string[] }}
 */
export function validatePocSubmission(body = {}, maxChars = 20_000) {
  const errors = [];

  // Anti-bot honeypot: a hidden field real users never fill in.
  if (clean(body.website)) return { ok: false, errors: ['Submission rejected.'] };

  const cveId = clean(body.cveId).toUpperCase();
  if (!CVE_ID.test(cveId)) errors.push('A valid published CVE ID is required (e.g. CVE-2021-44228).');

  const title = clean(body.title);
  if (title.length < LIMITS.title.min || title.length > LIMITS.title.max) {
    errors.push(`Title must be ${LIMITS.title.min}–${LIMITS.title.max} characters.`);
  }

  const code = clean(body.code);
  if (code.length < 20) errors.push('The proof of concept is required (at least 20 characters).');
  if (code.length > maxChars) errors.push(`The proof of concept is too long (max ${maxChars} characters).`);
  if (looksBinary(code)) errors.push('The proof of concept must be plain text, not a binary paste.');

  const writeup = clean(body.writeup);
  if (writeup.length > LIMITS.writeup.max) errors.push(`The write-up is too long (max ${LIMITS.writeup.max}).`);

  const affected = clean(body.affected);
  if (affected.length > LIMITS.affected.max) errors.push('The affected-versions field is too long.');

  let author = clean(body.author);
  if (author.length > LIMITS.author.max) errors.push('The name/handle is too long.');
  // Keep the handle to something displayable; default to Anonymous.
  if (author && !/^[\w .@_-]{1,60}$/.test(author)) errors.push('The name/handle has unsupported characters.');
  if (!author) author = 'Anonymous';

  const contact = clean(body.contact);
  if (contact.length > LIMITS.contact.max) errors.push('The contact field is too long.');

  const license = clean(body.license).toLowerCase() || 'cc-by';
  if (!LICENSES[license]) errors.push('Choose a valid licence for your contribution.');

  const { urls: references, errors: refErrors } = cleanReferences(body.references);
  errors.push(...refErrors);

  // Every acknowledgement is mandatory.
  const acks = {};
  for (const key of Object.keys(ACKNOWLEDGEMENTS)) {
    acks[key] = isTrue(body[key] ?? body[`ack_${key}`]);
    if (!acks[key]) errors.push(`You must confirm: ${ACKNOWLEDGEMENTS[key]}`);
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: { cveId, title, code, writeup, affected, author, contact, license, references, acknowledgements: acks },
  };
}

export default { validatePocSubmission, LICENSES, ACKNOWLEDGEMENTS };
