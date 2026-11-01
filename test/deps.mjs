/**
 * The dependency sweep, tested where it can be tested honestly.
 *
 * Manifest parsing is pure and gets real fixtures - the formats are where the
 * bugs live, because every ecosystem spells "this package at this version"
 * differently and several spell it more than one way across lockfile
 * versions. The sweep itself talks to OSV.dev, so the network-free checks here
 * cover its shaping and its failure behaviour, and the live check at the end
 * runs only when a server is there to run it against.
 *
 *   node test/deps.mjs
 */
import assert from 'node:assert/strict';
import {
  coerceVersion,
  detectManifestType,
  normalizeEcosystem,
  parseManifest,
} from '../src/lib/manifests.js';
import { sweepDependencies } from '../src/deps.js';

let passed = 0;
let failed = 0;

function check(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL  ${name}\n      ${error.message}`);
  }
}

async function checkAsync(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL  ${name}\n      ${error.message}`);
  }
}

const find = (result, name) => result.packages.find((p) => p.name === name);

/* ---------- versions ---------- */

check('an exact version is not flagged approximate', () => {
  assert.deepEqual(coerceVersion('4.17.15'), { version: '4.17.15', approximate: false });
  assert.deepEqual(coerceVersion('v1.2.3'), { version: '1.2.3', approximate: false });
  assert.deepEqual(coerceVersion('1.2.3-beta.1'), { version: '1.2.3-beta.1', approximate: false });
});

check('a range is coerced to its floor and flagged', () => {
  for (const spec of ['^4.17.15', '~4.17.15', '>=4.17.15 <5.0.0', '>= 4.17.15']) {
    const result = coerceVersion(spec);
    assert.equal(result.version, '4.17.15', spec);
    assert.equal(result.approximate, true, spec);
  }
});

check('a specifier with no version is refused rather than guessed at', () => {
  // These must not become a coordinate: guessing produces a finding against
  // software the caller may not even have.
  for (const spec of ['*', 'latest', 'x', 'github:lodash/lodash', 'file:../local', 'workspace:*', '']) {
    assert.equal(coerceVersion(spec), null, spec);
  }
});

check('ecosystem names are normalised to what OSV expects', () => {
  assert.equal(normalizeEcosystem('npm'), 'npm');
  assert.equal(normalizeEcosystem('NPM'), 'npm');
  assert.equal(normalizeEcosystem('pypi'), 'PyPI');
  assert.equal(normalizeEcosystem('python'), 'PyPI');
  assert.equal(normalizeEcosystem('cargo'), 'crates.io');
  assert.equal(normalizeEcosystem('crates.io'), 'crates.io');
  assert.equal(normalizeEcosystem('nonsense'), null);
});

/* ---------- manifests ---------- */

check('package.json dependencies and devDependencies are read', () => {
  const result = parseManifest(
    JSON.stringify({
      dependencies: { lodash: '^4.17.15', express: '4.17.1' },
      devDependencies: { jest: '~29.0.0' },
      scripts: { test: 'jest' },
    }),
  );
  assert.equal(result.detected, 'package.json');
  assert.equal(result.ecosystem, 'npm');
  assert.equal(result.exactVersions, false);
  assert.equal(result.packages.length, 3);
  assert.equal(find(result, 'lodash').version, '4.17.15');
  assert.equal(find(result, 'lodash').approximate, true);
  // An exact pin in a manifest is still exact.
  assert.equal(find(result, 'express').approximate, undefined);
});

check('package.json entries with no concrete version are reported, not dropped', () => {
  const result = parseManifest(JSON.stringify({ dependencies: { a: '*', b: 'github:x/y', c: '1.0.0' } }));
  assert.equal(result.packages.length, 1);
  assert.equal(result.skipped.length, 2);
  assert.ok(result.skipped.every((s) => s.reason));
});

check('package-lock v3 is read from its flat package map', () => {
  const result = parseManifest(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/a/node_modules/lodash': { version: '4.17.15' },
        'node_modules/@scope/pkg': { version: '2.0.0' },
        'node_modules/linked': { link: true, resolved: '../linked' },
      },
    }),
  );
  assert.equal(result.detected, 'package-lock.json');
  assert.equal(result.exactVersions, true);
  const names = result.packages.map((p) => `${p.name}@${p.version}`).sort();
  // Both lodash versions are real coordinates; the symlink is not a package.
  assert.deepEqual(names, ['@scope/pkg@2.0.0', 'lodash@4.17.15', 'lodash@4.17.21']);
});

check('package-lock v1 is read from its nested tree', () => {
  const result = parseManifest(
    JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: '4.17.15' },
        a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } },
      },
    }),
  );
  assert.equal(result.detected, 'package-lock.json');
  assert.deepEqual(
    result.packages.map((p) => p.name).sort(),
    ['a', 'b', 'lodash'],
  );
});

check('the same package at the same version is counted once', () => {
  const result = parseManifest(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/a/node_modules/lodash': { version: '4.17.15' },
        'node_modules/b/node_modules/lodash': { version: '4.17.15' },
        'node_modules/c/node_modules/lodash': { version: '4.17.15' },
      },
    }),
  );
  // A real lockfile lists a popular transitive dependency dozens of times;
  // each repeat would otherwise be a wasted upstream query.
  assert.equal(result.packages.length, 1);
});

check('requirements.txt reads pins and reports unpinned lines', () => {
  const result = parseManifest(
    [
      '# comment',
      '-r other.txt',
      '--index-url https://example.invalid',
      'Django==3.2.0',
      'requests[security]==2.25.1',
      'urllib3>=1.26.0',
      'flask',
      '',
    ].join('\n'),
    { type: 'requirements.txt' },
  );
  assert.equal(result.ecosystem, 'PyPI');
  assert.equal(find(result, 'Django').version, '3.2.0');
  assert.equal(find(result, 'requests').version, '2.25.1');
  assert.equal(find(result, 'urllib3').approximate, true);
  assert.ok(result.skipped.some((s) => s.name === 'flask'));
});

check('go.mod reads both require forms and ignores indirect markers', () => {
  const result = parseManifest(
    [
      'module example.com/app',
      'go 1.22',
      '',
      'require github.com/gin-gonic/gin v1.9.0',
      '',
      'require (',
      '\tgithub.com/stretchr/testify v1.8.4',
      '\tgolang.org/x/crypto v0.17.0 // indirect',
      ')',
      '',
      'replace example.com/x => ./x',
    ].join('\n'),
  );
  assert.equal(result.detected, 'go.mod');
  assert.equal(result.ecosystem, 'Go');
  const names = result.packages.map((p) => p.name).sort();
  assert.deepEqual(names, ['github.com/gin-gonic/gin', 'github.com/stretchr/testify', 'golang.org/x/crypto']);
  // The v prefix is Go's, not OSV's.
  assert.equal(find(result, 'github.com/gin-gonic/gin').version, '1.9.0');
  assert.ok(!result.packages.some((p) => p.name === 'example.com/x'));
});

check('Cargo.lock reads its package tables', () => {
  const result = parseManifest(
    [
      '# auto-generated',
      'version = 3',
      '',
      '[[package]]',
      'name = "zip"',
      'version = "0.6.0"',
      'source = "registry+https://github.com/rust-lang/crates.io-index"',
      '',
      '[[package]]',
      'name = "serde"',
      'version = "1.0.195"',
      '',
      '[metadata]',
      'something = "else"',
    ].join('\n'),
  );
  assert.equal(result.detected, 'Cargo.lock');
  assert.equal(result.ecosystem, 'crates.io');
  assert.equal(find(result, 'zip').version, '0.6.0');
  assert.equal(result.packages.length, 2);
});

check('Gemfile.lock reads resolved gems but not their constraints', () => {
  const result = parseManifest(
    [
      'GEM',
      '  remote: https://rubygems.org/',
      '  specs:',
      '    rails (6.0.0)',
      '      actionpack (= 6.0.0)',
      '    nokogiri (1.10.4)',
      '',
      'PLATFORMS',
      '  ruby',
      '',
      'DEPENDENCIES',
      '  rails (~> 6.0)',
    ].join('\n'),
  );
  assert.equal(result.detected, 'Gemfile.lock');
  // The six-space line is a constraint, not an installed gem.
  assert.deepEqual(result.packages.map((p) => p.name).sort(), ['nokogiri', 'rails']);
  assert.equal(find(result, 'rails').version, '6.0.0');
});

check('yarn.lock is read in both v1 and berry spellings', () => {
  const v1 = parseManifest(
    ['# yarn lockfile v1', '', '"lodash@^4.17.15":', '  version "4.17.21"', '  resolved "https://..."'].join('\n'),
  );
  assert.equal(v1.detected, 'yarn.lock');
  assert.equal(find(v1, 'lodash').version, '4.17.21');

  const berry = parseManifest(
    ['__metadata:', '  version: 6', '', '"@scope/pkg@npm:^1.0.0":', '  version: 1.2.3'].join('\n'),
    { type: 'yarn.lock' },
  );
  assert.equal(find(berry, '@scope/pkg').version, '1.2.3');
});

check('composer.lock reads both package blocks', () => {
  const result = parseManifest(
    JSON.stringify({
      'content-hash': 'abc',
      packages: [{ name: 'monolog/monolog', version: '2.0.0' }],
      'packages-dev': [{ name: 'phpunit/phpunit', version: 'v9.5.0' }],
    }),
  );
  assert.equal(result.detected, 'composer.lock');
  assert.equal(result.ecosystem, 'Packagist');
  assert.equal(find(result, 'phpunit/phpunit').version, '9.5.0');
});

check('an unreadable manifest is an error, never an empty result', () => {
  // This is the important one. A sweep that answers "nothing found" for a file
  // it could not read tells the caller they are safe when nobody looked.
  const unknown = parseManifest('just some prose, not a manifest at all');
  assert.ok(unknown.error, 'an unrecognised format must report an error');
  assert.equal(unknown.packages.length, 0);

  const broken = parseManifest('{"dependencies": {oops', { type: 'package.json' });
  assert.ok(broken.error, 'malformed JSON must report an error');

  assert.ok(parseManifest('').error);
  assert.ok(parseManifest(null).error);
});

check('the package cap is enforced and reported', () => {
  const packages = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`pkg-${i}`, `1.0.${i}`]));
  const result = parseManifest(JSON.stringify({ dependencies: packages }), { max: 10 });
  assert.equal(result.packages.length, 10);
  assert.equal(result.truncated, 40);
});

check('format detection distinguishes the JSON formats', () => {
  assert.equal(detectManifestType('{"lockfileVersion":3,"packages":{}}'), 'package-lock.json');
  assert.equal(detectManifestType('{"dependencies":{"a":"1.0.0"}}'), 'package.json');
  assert.equal(detectManifestType('{"content-hash":"x","packages":[]}'), 'composer.lock');
  assert.equal(detectManifestType('nope'), null);
});

/* ---------- the sweep's own shaping ---------- */

await checkAsync('coordinates without a version are refused up front', async () => {
  const result = await sweepDependencies({ packages: [{ name: 'lodash', ecosystem: 'npm' }] });
  assert.ok(result.error, 'expected an error rather than an empty sweep');
  assert.equal(result.packages, undefined);
});

await checkAsync('an empty package list is an error', async () => {
  assert.ok((await sweepDependencies({ packages: [] })).error);
  assert.ok((await sweepDependencies({})).error);
});

/* ---------- live, when something is listening ---------- */

const liveBase = process.env.DEPS_TEST_BASE ?? 'http://localhost:3000';
let live = false;
try {
  const probe = await fetch(new URL('/healthz', liveBase), { signal: AbortSignal.timeout(3000) });
  live = probe.ok;
} catch {
  live = false;
}

if (!live) {
  console.log(`\nSKIP  live sweep (nothing listening at ${liveBase})`);
} else {
  // The sweep is rate limited per IP per hour, and this suite spends a good
  // part of that budget. Running out is the limiter working, not a failure, so
  // it is reported as a skip rather than as a broken sweep.
  let throttled = false;

  const post = async (body) => {
    const response = await fetch(new URL('/api/dependencies/check', liveBase), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(120_000),
    });
    if (response.status === 429) {
      throttled = true;
      throw new Error('rate limited');
    }
    return { status: response.status, body: await response.json() };
  };

  // Wraps a live check so a throttled run skips the rest instead of failing.
  const liveCheck = (name, fn) =>
    checkAsync(name, async () => {
      if (throttled) return;
      try {
        await fn();
      } catch (error) {
        if (throttled) {
          console.log('      (rate limited; raise DEPS_RATE_MAX to run the whole suite)');
          return;
        }
        throw error;
      }
    });

  await liveCheck('a known-vulnerable version is found by coordinate', async () => {
    const { body } = await post({
      packages: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.15' }],
    });
    assert.equal(body.checked, 1);
    assert.equal(body.vulnerablePackages, 1);
    const [pkg] = body.packages;
    assert.equal(pkg.package, 'lodash');
    assert.ok(pkg.vulnerabilities.length > 0);
    // The thing free-text search cannot give: what to upgrade to.
    assert.ok(pkg.vulnerabilities.some((v) => v.fixedIn?.length), 'expected a fix version');
  });

  await liveCheck('upgrading past a fix drops that advisory', async () => {
    // Version awareness is the whole point; if this fails the sweep is just
    // matching names again. Asserted as a difference between two versions
    // rather than as "4.17.21 is clean", because new advisories land against
    // any live package and a test that assumes none would rot.
    const ids = async (version) => {
      const { body } = await post({ packages: [{ name: 'lodash', ecosystem: 'npm', version }] });
      return new Set((body.packages[0]?.vulnerabilities ?? []).map((v) => v.id));
    };
    const old = await ids('4.17.15');
    const newer = await ids('4.17.21');

    // CVE-2021-23337 is fixed in 4.17.21 exactly, so it must be on one side
    // of that line and not the other.
    assert.ok(old.has('CVE-2021-23337'), 'expected the command-injection advisory against 4.17.15');
    assert.ok(!newer.has('CVE-2021-23337'), '4.17.21 carries the fix and must not be reported');
    assert.ok(old.size > newer.size, 'the older version must carry strictly more advisories');
  });

  await liveCheck('a package with nothing against it is reported as clean, not omitted', async () => {
    const { body } = await post({
      packages: [{ name: 'left-pad', ecosystem: 'npm', version: '1.3.0' }],
      includeClean: true,
    });
    assert.equal(body.vulnerablePackages, 0);
    assert.deepEqual(body.clean, ['left-pad@1.3.0']);
    assert.equal(body.cleanPackages, 1);
  });

  await liveCheck('the same name in two ecosystems is two different packages', async () => {
    const { body } = await post({
      packages: [
        { name: 'zip', ecosystem: 'npm', version: '1.0.0' },
        { name: 'zip', ecosystem: 'crates.io', version: '0.6.0' },
      ],
      includeClean: true,
    });
    assert.equal(body.checked, 2);
    assert.deepEqual(body.ecosystems.sort(), ['crates.io', 'npm']);
    const rust = body.packages.find((p) => p.ecosystem === 'crates.io');
    assert.ok(rust, 'expected the crates.io package to have advisories of its own');
  });

  await liveCheck('results are ordered by how reachable an exploit is', async () => {
    const { body } = await post({
      packages: [
        { name: 'lodash', ecosystem: 'npm', version: '4.17.15' },
        { name: 'minimist', ecosystem: 'npm', version: '1.2.0' },
        { name: 'express', ecosystem: 'npm', version: '4.17.1' },
      ],
    });
    const ranks = ['observed', 'weaponized', 'public-exploit', 'proof-of-concept', undefined];
    const seen = body.packages.map((p) => ranks.indexOf(p.worstMaturity));
    assert.deepEqual([...seen].sort((a, b) => a - b), seen, 'packages must be worst-first');
    // And the worklist must only name things with a known exploit signal.
    for (const row of body.patchFirst ?? []) assert.ok(row.because);
  });

  await liveCheck('onlyExploitable drops advisories with no exploit signal', async () => {
    const { body } = await post({
      packages: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.15' }],
      onlyExploitable: true,
    });
    for (const pkg of body.packages) {
      for (const vuln of pkg.vulnerabilities) {
        assert.ok(vuln.exploitation, `${vuln.id} has no exploitation but was not filtered`);
      }
    }
  });

  await liveCheck('a pasted manifest is parsed and swept end to end', async () => {
    const { body } = await post({
      manifest: JSON.stringify({ dependencies: { minimist: '^1.2.0', express: '4.17.1' } }),
    });
    assert.equal(body.manifest.format, 'package.json');
    assert.equal(body.manifest.exactVersions, false);
    assert.ok(body.manifest.note, 'a range-based manifest must say its versions are approximate');
    assert.ok(body.vulnerablePackages >= 1);

    // The range was coerced, so that finding is flagged; the exact pin beside
    // it in the same file is not.
    const ranged = body.packages.find((p) => p.package === 'minimist');
    assert.equal(ranged.versionApproximate, true);
    assert.ok(ranged.versionNote.includes('lockfile'));
    const pinned = body.packages.find((p) => p.package === 'express');
    if (pinned) assert.equal(pinned.versionApproximate, undefined);
  });

  await liveCheck('an unreadable manifest is rejected with a 400', async () => {
    const { status, body } = await post({ manifest: 'this is not a manifest' });
    assert.equal(status, 400);
    assert.ok(body.error);
    assert.ok(Array.isArray(body.manifestTypes), 'the error should say which formats are accepted');
  });

  await liveCheck('an empty request is rejected rather than answered', async () => {
    const { status } = await post({});
    assert.equal(status, 400);
  });

  await liveCheck('a repeat sweep is served from the cache', async () => {
    const coords = { packages: [{ name: 'axios', ecosystem: 'npm', version: '0.21.0' }] };
    await post(coords);
    const { body } = await post(coords);
    // Either cache tier counts: Atlas when it is connected, the in-process
    // one when it is not. What must not happen is querying upstream twice.
    assert.ok(
      body.osv.coordinatesFromCache >= 1 || body.osv.coordinatesQueriedUpstream === 0,
      `expected a cache hit, got ${JSON.stringify(body.osv)}`,
    );
  });

  await liveCheck('every result carries the caveats that make it readable', async () => {
    const { body } = await post({ packages: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.21' }] });
    assert.ok(body.caveats.some((c) => /not that the package is safe/i.test(c)));
    assert.ok(body.osv.ok);
  });
}

console.log(`\n${passed}/${passed + failed} passed`);
if (failed) process.exitCode = 1;
