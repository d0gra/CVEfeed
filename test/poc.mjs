/**
 * PoC submission validation and the built-in CAPTCHA. Hermetic, no database.
 *
 *   node test/poc.mjs
 */
process.env.MONGODB_URI = '';
import assert from 'node:assert/strict';
import { validatePocSubmission, ACKNOWLEDGEMENTS } from '../src/lib/validatePoc.js';
import { issueChallenge, verifyCaptcha } from '../src/lib/captcha.js';

let pass = 0;
let fail = 0;
const check = (name, cond, extra = '') => {
  cond ? pass++ : fail++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
};

const allAcks = Object.fromEntries(Object.keys(ACKNOWLEDGEMENTS).map((k) => [k, true]));
const base = {
  cveId: 'CVE-2021-44228',
  title: 'Log4Shell JNDI lookup demonstration',
  code: 'Set a logged header to ${jndi:ldap://127.0.0.1/a} against an authorised local test app.',
  ...allAcks,
};

// --- happy path ---
const good = validatePocSubmission(base);
check('a complete submission validates', good.ok, good.ok ? '' : good.errors.join('; '));
check('  ...defaults the author to Anonymous', good.value?.author === 'Anonymous');
check('  ...defaults the licence', good.value?.license === 'cc-by');

// --- required fields ---
check('an empty body is rejected', !validatePocSubmission({}).ok);
check('a missing acknowledgement is rejected', !validatePocSubmission({ ...base, terms: false }).ok);
check('a bad CVE id is rejected', !validatePocSubmission({ ...base, cveId: 'not-a-cve' }).ok);
check('a too-short title is rejected', !validatePocSubmission({ ...base, title: 'x' }).ok);
check('a too-short PoC is rejected', !validatePocSubmission({ ...base, code: 'short' }).ok);

// --- abuse / injection resistance ---
check('the honeypot rejects bots', !validatePocSubmission({ ...base, website: 'http://spam' }).ok);
check('a binary paste is rejected', !validatePocSubmission({ ...base, code: '\x00\x01\x02\x03\x04\x05\x06'.repeat(20) }).ok);
check('an over-long PoC is rejected', !validatePocSubmission({ ...base, code: 'a'.repeat(21_000) }, 20_000).ok);

// --- references: only http(s) ---
const jsUrl = validatePocSubmission({ ...base, references: 'javascript:alert(1)' });
check('a javascript: reference is rejected', !jsUrl.ok);
const okUrl = validatePocSubmission({ ...base, references: 'https://example.com/a\nhttps://example.com/b' });
check('http(s) references are kept', okUrl.ok && okUrl.value.references.length === 2);
const tooMany = validatePocSubmission({ ...base, references: Array.from({ length: 12 }, (_, i) => `https://e.com/${i}`).join('\n') });
check('too many references is rejected', !tooMany.ok);

// --- captcha ---
const c = issueChallenge();
check('a correct captcha answer passes', await verifyCaptcha({ captchaToken: c.token, captchaAnswer: String(c.answer) }));
check('a wrong captcha answer fails', !(await verifyCaptcha({ captchaToken: c.token, captchaAnswer: String(c.answer + 1) })));
check('a forged captcha token fails', !(await verifyCaptcha({ captchaToken: '9999999999999.forged', captchaAnswer: '5' })));
check('an expired captcha fails', !(await verifyCaptcha({ captchaToken: `${Date.now() - 1000}.x`, captchaAnswer: '5' })));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
