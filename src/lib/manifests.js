/**
 * Turning a dependency manifest into package coordinates.
 *
 * The point of this file is that "is my dependency vulnerable" is a question
 * about a *coordinate* - an ecosystem, a name and an exact version - and not
 * about words. Free-text search over advisory prose cannot answer it: npm
 * `zip` and crates.io `zip` are different software with different advisories,
 * and lodash 4.17.21 is fine where 4.17.15 is not. So the first job is to get
 * from whatever the caller pasted to a list of coordinates, honestly, saying
 * which ones could not be read rather than quietly dropping them.
 *
 * Lockfiles are preferred over manifests for one reason: a lockfile states the
 * version that is actually installed, while `"lodash": "^4.17.15"` states a
 * range. A range has to be coerced to its floor to be queryable at all, which
 * can only ever be approximate - so anything coerced is flagged, and the
 * caller is told to paste the lockfile instead.
 *
 * No parser here is a full implementation of its format. Each one reads the
 * name/version pairs and ignores everything else, which is all that is needed
 * and keeps a hostile manifest from being interesting.
 */

/** OSV's ecosystem identifiers, as the ones we can actually parse for. */
export const ECOSYSTEMS = [
  'npm',
  'PyPI',
  'Go',
  'crates.io',
  'RubyGems',
  'Maven',
  'NuGet',
  'Packagist',
  'Hex',
  'Pub',
  'CRAN',
  'SwiftURL',
];

/** Case-insensitive match onto the canonical spelling OSV expects. */
const BY_LOWER = new Map(ECOSYSTEMS.map((e) => [e.toLowerCase(), e]));

const ALIASES = {
  node: 'npm',
  nodejs: 'npm',
  javascript: 'npm',
  js: 'npm',
  python: 'PyPI',
  pypi: 'PyPI',
  pip: 'PyPI',
  golang: 'Go',
  go: 'Go',
  rust: 'crates.io',
  cargo: 'crates.io',
  crates: 'crates.io',
  ruby: 'RubyGems',
  gem: 'RubyGems',
  gems: 'RubyGems',
  java: 'Maven',
  maven: 'Maven',
  php: 'Packagist',
  composer: 'Packagist',
  dotnet: 'NuGet',
  nuget: 'NuGet',
  elixir: 'Hex',
  dart: 'Pub',
  flutter: 'Pub',
  r: 'CRAN',
  swift: 'SwiftURL',
};

export function normalizeEcosystem(value) {
  const text = String(value ?? '').trim();
  if (!text) return null;
  const lower = text.toLowerCase();
  return BY_LOWER.get(lower) ?? ALIASES[lower] ?? null;
}

/** The manifest formats we can read, and the ecosystem each one implies. */
export const MANIFEST_TYPES = {
  'package.json': { ecosystem: 'npm', exact: false },
  'package-lock.json': { ecosystem: 'npm', exact: true },
  'npm-shrinkwrap.json': { ecosystem: 'npm', exact: true },
  'yarn.lock': { ecosystem: 'npm', exact: true },
  'requirements.txt': { ecosystem: 'PyPI', exact: true },
  'poetry.lock': { ecosystem: 'PyPI', exact: true },
  'Pipfile.lock': { ecosystem: 'PyPI', exact: true },
  'go.mod': { ecosystem: 'Go', exact: true },
  'Cargo.lock': { ecosystem: 'crates.io', exact: true },
  'Gemfile.lock': { ecosystem: 'RubyGems', exact: true },
  'composer.lock': { ecosystem: 'Packagist', exact: true },
};

export const MANIFEST_TYPE_IDS = Object.keys(MANIFEST_TYPES);

/* ---------- versions ---------- */

// A version-shaped token: digits, then anything a release might carry.
const VERSION = /\d+(?:\.\d+)*(?:[.-][0-9A-Za-z.+-]+)?/;

/**
 * Coerce a range specifier to something queryable.
 *
 * `^4.17.15` and `>=4.17.15 <5` both become `4.17.15`: the lowest version the
 * range admits, which is the one most likely to be vulnerable. That makes a
 * false positive possible where the installed version is newer, so every
 * coerced coordinate is marked `approximate` and the answer says so.
 *
 * Specifiers with no concrete version at all (`*`, `latest`, a git URL, a
 * workspace link) cannot be coerced, and are reported as skipped.
 */
export function coerceVersion(specifier) {
  const text = String(specifier ?? '').trim();
  if (!text) return null;
  // Not a version at all: a URL, a git ref, a local or workspace path.
  if (/^(?:[a-z+]+:|\.{1,2}\/|\/|github:|file:|link:|workspace:|npm:)/i.test(text)) return null;
  if (/^(?:\*|x|latest|any)$/i.test(text)) return null;

  const match = text.match(VERSION);
  if (!match) return null;
  const exact = /^v?\d+(?:\.\d+)*(?:[.-][0-9A-Za-z.+-]+)?$/.test(text);
  return { version: match[0], approximate: !exact };
}

/* ---------- parsers ---------- */

/** Every parser yields { name, version, approximate? } or records a skip. */

function parsePackageJson(text) {
  const json = JSON.parse(text);
  const found = [];
  const skipped = [];
  const blocks = ['dependencies', 'devDependencies', 'optionalDependencies'];

  for (const block of blocks) {
    const deps = json?.[block];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, specifier] of Object.entries(deps)) {
      const coerced = coerceVersion(specifier);
      if (!coerced) {
        skipped.push({ name, reason: `No concrete version in "${String(specifier).slice(0, 40)}".` });
        continue;
      }
      found.push({ name, ...coerced });
    }
  }
  return { found, skipped };
}

function parsePackageLock(text) {
  const json = JSON.parse(text);
  const found = [];

  // v2 and v3 keep a flat map keyed by install path.
  if (json?.packages && typeof json.packages === 'object') {
    for (const [path, entry] of Object.entries(json.packages)) {
      if (!path || !entry?.version || entry.link) continue;
      // "node_modules/a/node_modules/b" -> "b"; scopes keep their slash.
      const name = entry.name ?? path.split('node_modules/').pop();
      if (name) found.push({ name, version: entry.version });
    }
  }

  // v1 nests them instead.
  const walk = (deps) => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      if (entry?.version && !/^(?:[a-z+]+:|github:)/i.test(entry.version)) {
        found.push({ name, version: entry.version });
      }
      if (entry?.dependencies) walk(entry.dependencies);
    }
  };
  if (!json?.packages) walk(json?.dependencies);

  return { found, skipped: [] };
}

function parsePipfileLock(text) {
  const json = JSON.parse(text);
  const found = [];
  const skipped = [];
  for (const block of ['default', 'develop']) {
    for (const [name, entry] of Object.entries(json?.[block] ?? {})) {
      const coerced = coerceVersion(entry?.version);
      if (!coerced) {
        skipped.push({ name, reason: 'No pinned version in the lock entry.' });
        continue;
      }
      found.push({ name, version: coerced.version });
    }
  }
  return { found, skipped };
}

function parseComposerLock(text) {
  const json = JSON.parse(text);
  const found = [];
  for (const block of ['packages', 'packages-dev']) {
    for (const entry of json?.[block] ?? []) {
      const coerced = coerceVersion(entry?.version);
      if (entry?.name && coerced) found.push({ name: entry.name, version: coerced.version });
    }
  }
  return { found, skipped: [] };
}

function parseYarnLock(text) {
  const found = [];
  // v1: `"lodash@^4.17.15":` then an indented `version "4.17.21"`.
  // Berry: `"lodash@npm:^4.17.15":` then `version: 4.17.21`.
  let names = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line || line.startsWith('#')) continue;

    if (!/^\s/.test(line) && line.endsWith(':')) {
      // A header lists every specifier resolving to this one entry; the name
      // is the same in all of them, so the first is enough.
      const first = line.slice(0, -1).split(',')[0].trim().replace(/^"|"$/g, '');
      // Strip the specifier: everything from the last @ that is not the scope's.
      const at = first.lastIndexOf('@');
      names = at > 0 ? [first.slice(0, at)] : [];
      continue;
    }

    const version = line.match(/^\s+version:?\s+"?([^"\s]+)"?$/);
    if (version && names.length) {
      for (const name of names) found.push({ name, version: version[1] });
      names = [];
    }
  }
  return { found, skipped: [] };
}

function parseRequirements(text) {
  const found = [];
  const skipped = [];

  for (const raw of text.split(/\r?\n/)) {
    // Comments, blank lines, pip flags and includes.
    const line = raw.split(/\s+#|^#/)[0].trim();
    if (!line || line.startsWith('-') || line.startsWith('#')) continue;
    // A hash-pinned requirement continues over lines; the name/version is on
    // the first, and `--hash` fragments are ignored by the flag check above.
    const body = line.replace(/\\$/, '').trim();

    const match = body.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/);
    if (!match) continue;
    const [, name, rest] = match;

    const pinned = rest.match(/===?\s*([^,;\s]+)/);
    if (pinned) {
      found.push({ name, version: pinned[1] });
      continue;
    }
    const coerced = rest ? coerceVersion(rest) : null;
    if (coerced) {
      found.push({ name, version: coerced.version, approximate: true });
      continue;
    }
    skipped.push({ name, reason: rest ? `Unpinned specifier "${rest.slice(0, 30)}".` : 'No version given.' });
  }

  return { found, skipped };
}

function parseGoMod(text) {
  const found = [];
  let inBlock = false;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('//')[0].trim();
    if (!line) continue;

    if (/^require\s*\($/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }

    const single = line.match(/^require\s+(\S+)\s+(v\S+)$/);
    if (single) {
      found.push({ name: single[1], version: single[2].replace(/^v/, '') });
      continue;
    }
    if (inBlock) {
      const entry = line.match(/^(\S+)\s+(v\S+)$/);
      // Replace/exclude directives sit outside the require block, so anything
      // in here with two fields is a module requirement.
      if (entry) found.push({ name: entry[1], version: entry[2].replace(/^v/, '') });
    }
  }
  return { found, skipped: [] };
}

/**
 * Cargo.lock and poetry.lock are both TOML arrays of tables with the same two
 * fields we care about, so one reader serves both. Deliberately not a TOML
 * parser: it reads `name` and `version` inside `[[package]]` and nothing else.
 */
function parseTomlLock(text) {
  const found = [];
  let current = null;

  const flush = () => {
    if (current?.name && current.version) found.push({ name: current.name, version: current.version });
    current = null;
  };

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^\[\[(?:package|tool\.poetry\.)/.test(line) || line === '[[package]]') {
      flush();
      current = {};
      continue;
    }
    // Any other table ends the current package.
    if (line.startsWith('[') && !line.startsWith('[[')) {
      flush();
      continue;
    }
    if (!current) continue;

    const field = line.match(/^(name|version)\s*=\s*"([^"]+)"/);
    if (field) current[field[1]] = field[2];
  }
  flush();

  return { found, skipped: [] };
}

function parseGemfileLock(text) {
  const found = [];
  let inSpecs = false;

  for (const raw of text.split(/\r?\n/)) {
    if (/^\s*specs:\s*$/.test(raw)) {
      inSpecs = true;
      continue;
    }
    // A new top-level section ends the spec list.
    if (/^\S/.test(raw)) {
      inSpecs = false;
      continue;
    }
    if (!inSpecs) continue;

    // Four-space entries are the gems themselves; six-space ones are their
    // dependency constraints, which carry no resolved version.
    const entry = raw.match(/^ {4}(\S+) \(([^)]+)\)\s*$/);
    if (entry) {
      const coerced = coerceVersion(entry[2]);
      if (coerced) found.push({ name: entry[1], version: coerced.version });
    }
  }
  return { found, skipped: [] };
}

const PARSERS = {
  'package.json': parsePackageJson,
  'package-lock.json': parsePackageLock,
  'npm-shrinkwrap.json': parsePackageLock,
  'yarn.lock': parseYarnLock,
  'requirements.txt': parseRequirements,
  'poetry.lock': parseTomlLock,
  'Pipfile.lock': parsePipfileLock,
  'go.mod': parseGoMod,
  'Cargo.lock': parseTomlLock,
  'Gemfile.lock': parseGemfileLock,
  'composer.lock': parseComposerLock,
};

/* ---------- detection ---------- */

/**
 * Work out which format was pasted.
 *
 * Callers can say, and should, but an agent handed a file by a user often will
 * not know - and guessing wrong is better diagnosed than guessed at, so the
 * caller is told what was detected.
 */
export function detectManifestType(text) {
  const sample = String(text ?? '');
  const head = sample.slice(0, 4000);

  if (/^\s*\{/.test(sample)) {
    // Distinguishing the JSON formats by their own marker fields rather than
    // by shape, which they partly share.
    if (/"lockfileVersion"\s*:/.test(head)) return 'package-lock.json';
    if (/"_meta"\s*:/.test(head) && /"pipfile-spec"/i.test(head)) return 'Pipfile.lock';
    if (/"packages-dev"\s*:/.test(head) || /"content-hash"\s*:/.test(head)) return 'composer.lock';
    if (/"dependencies"\s*:|"devDependencies"\s*:/.test(head)) return 'package.json';
    return null;
  }

  if (/^\s*module\s+\S+/m.test(head) || /^\s*go\s+\d+\.\d+/m.test(head)) return 'go.mod';
  if (/^\s*GEM\s*$/m.test(head) || /^\s*PLATFORMS\s*$/m.test(head)) return 'Gemfile.lock';
  if (/^\[\[package\]\]/m.test(head)) {
    // Both Cargo and poetry use [[package]]; poetry writes a metadata table.
    return /python-versions|content-hash|\[metadata\]/.test(sample) && !/\[\[package\]\][\s\S]*?source\s*=\s*"registry\+https:\/\/github\.com\/rust-lang/.test(sample)
      ? 'poetry.lock'
      : 'Cargo.lock';
  }
  if (/^__metadata:|^# yarn lockfile/m.test(head) || /^"[^"]+@(?:npm:)?[^"]*":\s*$/m.test(head)) return 'yarn.lock';
  if (/^[A-Za-z0-9._-]+\s*(?:\[[^\]]*\])?\s*[=<>~!]=/m.test(head)) return 'requirements.txt';

  return null;
}

/* ---------- entry point ---------- */

/**
 * Parse a pasted manifest into coordinates.
 *
 * Always resolves to a result: a manifest that cannot be parsed comes back
 * with an `error` and an empty list, because a dependency sweep that silently
 * returns "nothing vulnerable" for an unreadable file is worse than one that
 * says it could not read the file.
 */
export function parseManifest(text, { type, ecosystem, max = 1000 } = {}) {
  const body = String(text ?? '');
  if (!body.trim()) return { packages: [], skipped: [], error: 'The manifest was empty.' };

  const detected = type && PARSERS[type] ? type : detectManifestType(body);
  if (!detected) {
    return {
      packages: [],
      skipped: [],
      error:
        `Could not tell which manifest format this is. Pass manifestType as one of: ${MANIFEST_TYPE_IDS.join(', ')}.`,
    };
  }

  let parsed;
  try {
    parsed = PARSERS[detected](body);
  } catch (error) {
    return { packages: [], skipped: [], detected, error: `${detected} could not be parsed: ${error.message}` };
  }

  const eco = normalizeEcosystem(ecosystem) ?? MANIFEST_TYPES[detected].ecosystem;

  // One coordinate per name+version. A lockfile lists the same package at the
  // same version many times over, once per place it is installed.
  const seen = new Set();
  const packages = [];
  let truncated = 0;

  for (const entry of parsed.found) {
    const name = String(entry.name ?? '').trim();
    if (!name || !entry.version) continue;
    const key = `${eco}|${name}|${entry.version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    if (packages.length >= max) {
      truncated += 1;
      continue;
    }
    packages.push({
      name,
      ecosystem: eco,
      version: String(entry.version).replace(/^v/, ''),
      ...(entry.approximate ? { approximate: true } : {}),
    });
  }

  return {
    packages,
    skipped: parsed.skipped ?? [],
    detected,
    ecosystem: eco,
    exactVersions: MANIFEST_TYPES[detected].exact,
    ...(truncated ? { truncated } : {}),
  };
}

/**
 * The manifest half of a sweep's answer, shaped once.
 *
 * Both the MCP tool and the HTTP route report this, and they drifted apart the
 * first time each shaped it for itself - the route forgot to pass on that a
 * package.json's versions are approximate, which is exactly the caveat a
 * caller must not lose.
 */
export function describeManifest(parsed, { max } = {}) {
  return {
    format: parsed.detected,
    ecosystem: parsed.ecosystem,
    packagesFound: parsed.packages.length,
    exactVersions: parsed.exactVersions,
    ...(parsed.exactVersions
      ? {}
      : {
          note:
            'This format states version ranges, not installed versions. Each was coerced to the ' +
            'lowest version the range admits, so a finding may not apply to what is actually ' +
            'installed - paste the lockfile for an exact answer.',
        }),
    ...(parsed.truncated ? { notChecked: parsed.truncated, ...(max ? { truncatedAt: max } : {}) } : {}),
    ...(parsed.skipped?.length ? { unreadable: parsed.skipped.slice(0, 20) } : {}),
  };
}

export default { parseManifest, describeManifest, detectManifestType, coerceVersion, normalizeEcosystem, ECOSYSTEMS, MANIFEST_TYPES };
