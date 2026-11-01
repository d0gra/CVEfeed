/**
 * The dependency check's client half.
 *
 * It does three things: detect the format as you paste so you know it was
 * understood before you submit, post the manifest, and render the result
 * worst-first. Everything it renders is built with textContent or through an
 * escaping helper - the response carries advisory titles and summaries written
 * by third parties, which is not markup to be trusted into the page.
 */

const form = document.getElementById('dep-form');
const input = document.getElementById('dep-input');
const submit = document.getElementById('dep-submit');
const onlyExploitable = document.getElementById('dep-exploitable');
const detected = document.getElementById('dep-detected');
const results = document.getElementById('dep-results');
const exampleButton = document.getElementById('dep-example');

if (form && input && results) {
  /* ---------- building elements ---------- */

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  };

  const link = (href, text, className) => {
    const a = el('a', className, text);
    a.href = href;
    a.rel = 'noopener noreferrer';
    a.target = '_blank';
    return a;
  };

  /* ---------- format detection, mirrored from the server ---------- */

  /**
   * Deliberately rough: this is a hint shown while typing, not the decision.
   * The server detects the format properly and its answer is what the result
   * reports, so a wrong guess here costs nothing.
   */
  function guessFormat(text) {
    const head = text.slice(0, 4000);
    if (/^\s*\{/.test(text)) {
      if (/"lockfileVersion"\s*:/.test(head)) return 'package-lock.json';
      if (/"pipfile-spec"/i.test(head)) return 'Pipfile.lock';
      if (/"packages-dev"\s*:|"content-hash"\s*:/.test(head)) return 'composer.lock';
      if (/"dependencies"\s*:|"devDependencies"\s*:/.test(head)) return 'package.json';
      return null;
    }
    if (/^\s*module\s+\S+/m.test(head) || /^\s*go\s+\d+\.\d+/m.test(head)) return 'go.mod';
    if (/^\s*GEM\s*$/m.test(head)) return 'Gemfile.lock';
    if (/^\[\[package\]\]/m.test(head)) return /python-versions|\[metadata\]/.test(text) ? 'poetry.lock' : 'Cargo.lock';
    if (/^__metadata:|^# yarn lockfile/m.test(head)) return 'yarn.lock';
    if (/^[A-Za-z0-9._-]+\s*(?:\[[^\]]*\])?\s*[=<>~!]=/m.test(head)) return 'requirements.txt';
    return null;
  }

  const showDetected = () => {
    const text = input.value.trim();
    if (!text) {
      detected.textContent = '';
      return;
    }
    const guess = guessFormat(text);
    detected.textContent = guess ? `Looks like ${guess}` : 'Format not recognised yet';
    detected.classList.toggle('is-unknown', !guess);
  };

  input.addEventListener('input', showDetected);

  if (exampleButton) {
    exampleButton.addEventListener('click', () => {
      const raw = document.getElementById('dep-example-data');
      try {
        input.value = JSON.parse(raw.textContent);
      } catch {
        return;
      }
      showDetected();
      input.focus();
    });
  }

  /* ---------- rendering ---------- */

  const LINK_LABEL = {
    module: 'Metasploit module',
    exploit: 'Exploit-DB entry',
    template: 'Nuclei template',
    'poc-index': 'PoC repositories',
    report: 'VulnCheck report',
  };

  const MATURITY_LABEL = {
    observed: 'Exploited in the wild',
    weaponized: 'Metasploit module',
    'public-exploit': 'Public exploit',
    'proof-of-concept': 'Proof of concept',
  };

  function summaryBar(data) {
    const wrap = el('div', 'dep-summary');

    const stat = (value, label, tone) => {
      const box = el('div', `dep-stat${tone ? ` is-${tone}` : ''}`);
      box.append(el('span', 'dep-stat-num', String(value)), el('span', 'dep-stat-label', label));
      return box;
    };

    wrap.append(
      stat(data.checked, data.checked === 1 ? 'package checked' : 'packages checked'),
      stat(data.vulnerablePackages, 'with advisories', data.vulnerablePackages ? 'warn' : 'ok'),
      stat(data.advisories, 'advisories'),
      stat(data.withKnownExploit, 'with a known exploit', data.withKnownExploit ? 'bad' : 'ok'),
    );
    return wrap;
  }

  function patchFirst(rows) {
    const section = el('section', 'dep-patch');
    section.append(el('h2', null, 'Patch first'));
    section.append(
      el(
        'p',
        'dep-patch-why',
        'Ordered by whether someone could actually run an attack, not by severity label.',
      ),
    );

    const list = el('ol', 'dep-patch-list');
    for (const row of rows) {
      const li = el('li');
      li.append(el('code', 'dep-patch-pkg', row.package));
      if (row.upgradeTo) {
        li.append(el('span', 'dep-arrow', '→'), el('code', 'dep-patch-to', row.upgradeTo));
      } else {
        li.append(el('span', 'dep-nofix', 'no fixed version'));
      }
      li.append(el('p', 'dep-patch-reason', row.because));
      list.append(li);
    }
    section.append(list);
    return section;
  }

  function vulnRow(vuln) {
    const li = el('li', 'dep-vuln');

    const head = el('div', 'dep-vuln-head');
    // Our own page when we hold the record, OSV's when we do not.
    const idLink = /^CVE-/.test(vuln.id)
      ? Object.assign(el('a', 'dep-vuln-id', vuln.id), { href: `/cve/${encodeURIComponent(vuln.id)}` })
      : link(vuln.advisory, vuln.id, 'dep-vuln-id');
    head.append(idLink);

    const sev = el('span', `dep-sev is-${vuln.severity || 'none'}`, vuln.severity || 'unrated');
    head.append(sev);
    if (vuln.cvss != null) head.append(el('span', 'dep-cvss', `CVSS ${vuln.cvss}`));
    if (vuln.epssPercent != null) head.append(el('span', 'dep-epss', `EPSS ${vuln.epssPercent}%`));

    if (vuln.knownExploited) head.append(el('span', 'dep-tag is-bad', 'Exploited in the wild'));
    else if (vuln.exploitation) {
      head.append(
        el('span', 'dep-tag is-warn', MATURITY_LABEL[vuln.exploitation.maturity] ?? vuln.exploitation.maturity),
      );
    }
    li.append(head);

    if (vuln.summary) li.append(el('p', 'dep-vuln-summary', vuln.summary));

    const facts = el('div', 'dep-vuln-facts');
    if (vuln.fixedIn?.length) {
      facts.append(el('span', 'dep-fix', `Fixed in ${vuln.fixedIn.join(', ')}`));
    } else if (vuln.noFixedVersion) {
      facts.append(el('span', 'dep-nofix', 'No fixed version published'));
    }
    if (vuln.exploitation?.evidence?.length) {
      facts.append(el('span', 'dep-evidence', vuln.exploitation.evidence.join(' · ')));
    }
    if (facts.childElementCount) li.append(facts);

    // Where the exploit is. Third-party URLs, opened by the reader, never
    // fetched by us.
    if (vuln.exploitation?.links?.length) {
      const links = el('div', 'dep-links');
      for (const l of vuln.exploitation.links.slice(0, 4)) {
        // Labelled by what the link is rather than by its source, which the
        // evidence line beside it already names.
        links.append(link(l.url, LINK_LABEL[l.kind] ?? l.source, 'dep-link'));
      }
      li.append(links);
    }

    return li;
  }

  function packageCard(pkg) {
    const card = el('section', 'dep-pkg');
    if (pkg.worstMaturity) card.dataset.maturity = pkg.worstMaturity;

    const head = el('header', 'dep-pkg-head');
    const name = el('h3', 'dep-pkg-name');
    name.append(el('code', null, `${pkg.package}@${pkg.version}`));
    head.append(name);
    head.append(el('span', 'dep-eco', pkg.ecosystem));
    head.append(
      el('span', 'dep-count', `${pkg.vulnerabilities.length} ${pkg.vulnerabilities.length === 1 ? 'advisory' : 'advisories'}`),
    );
    card.append(head);

    if (pkg.versionApproximate) {
      card.append(el('p', 'dep-approx', pkg.versionNote ?? 'Version coerced from a range specifier.'));
    }

    const list = el('ul', 'dep-vulns');
    for (const vuln of pkg.vulnerabilities) list.append(vulnRow(vuln));
    card.append(list);

    return card;
  }

  function render(data) {
    results.replaceChildren();
    results.hidden = false;

    if (data.manifest) {
      const note = el('p', 'dep-manifest');
      note.append(
        el('strong', null, data.manifest.format ?? 'manifest'),
        document.createTextNode(` · ${data.manifest.packagesFound} packages · ${data.manifest.ecosystem}`),
      );
      results.append(note);
      if (data.manifest.note) results.append(el('p', 'dep-approx', data.manifest.note));
      if (data.manifest.notChecked) {
        results.append(el('p', 'dep-approx', `${data.manifest.notChecked} packages past the cap were not checked.`));
      }
    }

    results.append(summaryBar(data));

    // A failed upstream must never look like a clean bill of health.
    if (data.osv && data.osv.ok === false) {
      results.append(
        el(
          'p',
          'dep-error',
          `OSV.dev could not be reached, so this answer is incomplete: ${data.osv.error ?? 'unknown error'}`,
        ),
      );
    }

    if (data.patchFirst?.length) results.append(patchFirst(data.patchFirst));

    if (!data.packages?.length) {
      const clean = el('div', 'dep-clean');
      clean.append(el('p', 'dep-clean-lead', 'No known advisories for these versions.'));
      clean.append(
        el(
          'p',
          null,
          'That means nothing is published against these exact versions in the databases consulted — not that the packages are safe.',
        ),
      );
      results.append(clean);
      return;
    }

    const found = el('div', 'dep-pkgs');
    for (const pkg of data.packages) found.append(packageCard(pkg));
    results.append(found);

    if (data.cleanPackages) {
      results.append(
        el('p', 'dep-footnote', `${data.cleanPackages} other ${data.cleanPackages === 1 ? 'package has' : 'packages have'} no known advisories.`),
      );
    }
  }

  function renderError(message) {
    results.replaceChildren(el('p', 'dep-error', message));
    results.hidden = false;
  }

  /* ---------- submitting ---------- */

  let inFlight = false;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (inFlight) return;

    const manifest = input.value.trim();
    if (!manifest) {
      renderError('Paste a manifest or lockfile first.');
      return;
    }

    inFlight = true;
    submit.disabled = true;
    submit.textContent = 'Checking…';
    results.hidden = false;
    results.replaceChildren(el('p', 'dep-working', 'Resolving every package against OSV.dev…'));

    try {
      const response = await fetch('/api/dependencies/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest, onlyExploitable: Boolean(onlyExploitable?.checked) }),
      });
      const data = await response.json();

      if (!response.ok) {
        renderError(
          response.status === 429
            ? 'Too many checks from this address. Try again shortly.'
            : data.error || `The check failed (HTTP ${response.status}).`,
        );
        return;
      }
      render(data);
    } catch (error) {
      renderError(`The check could not be run: ${error.message}`);
    } finally {
      inFlight = false;
      submit.disabled = false;
      submit.textContent = 'Check dependencies';
    }
  });
}
