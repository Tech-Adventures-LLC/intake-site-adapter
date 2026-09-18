import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const PACKAGE_FILES = Object.freeze(['CHANGELOG.md', 'LICENSE', 'NOTICE', 'README.md', 'SECURITY.md', 'index.d.ts', 'index.js', 'package.json', 'validation.js', 'verify-route-worker.js', 'verify-route.d.ts', 'verify-route.js']);
const PACKAGE_NAME = '@tech-adventures-llc/intake-site-adapter';
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const digest = (bytes, algorithm = 'sha256', encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const writeJSON = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
function requireCondition(condition, category) { if (!condition) throw Error(category); }
export function auditPublicBytes(bytes) {
  const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  const rules = [
    ['nul-byte', /\0/],
    ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
    ['credential', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|npm_[A-Za-z0-9]{36,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/],
    ['private-registry', /npm\.pkg\.github\.com/],
    ['private-origin', /https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|[A-Za-z0-9.-]+\.(?:internal|local))(?::|\/|\b)/],
    ['local-path', /\/(?:Users|home)\/[A-Za-z0-9_.-]+\//],
  ];
  return rules.filter(([, pattern]) => pattern.test(text)).map(([rule]) => rule);
}
function npmPath() {
  const candidate = resolve(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js');
  requireCondition(existsSync(candidate), 'npm_cli_missing'); return candidate;
}
function isolatedEnvironment(home, cache) {
  mkdirSync(home, { recursive: true }); mkdirSync(cache, { recursive: true });
  const user = join(home, 'user.npmrc'), global = join(home, 'global.npmrc'); writeFileSync(user, ''); writeFileSync(global, '');
  return { PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, HOME: home, TMPDIR: tmpdir(), NPM_CONFIG_USERCONFIG: user, NPM_CONFIG_GLOBALCONFIG: global, NPM_CONFIG_CACHE: cache, NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org', NPM_CONFIG_UPDATE_NOTIFIER: 'false', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false' };
}
function command(executable, args, cwd, env, category) {
  try { return execFileSync(executable, args, { cwd, env, encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch { throw Error(category); }
}
function copiedFile(source, target) { mkdirSync(dirname(target), { recursive: true }); requireCondition(lstatSync(source).isFile() && !lstatSync(source).isSymbolicLink(), 'source_must_be_regular_file'); copyFileSync(source, target); }
function sourceIdentity(metadata, authority) {
  const repository = authority?.publicRepository;
  const configured = typeof repository === 'string'
    && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)
    && metadata?.repository?.type === 'git'
    && metadata.repository.url === `git+https://github.com/${repository}.git`
    && metadata.repository.directory === 'packages/intake-site-adapter';
  return configured
    ? { status: 'configured-not-live-verified', repository }
    : { status: 'missing-or-mismatched' };
}
function sourceExport(root, output, files) {
  const target = join(output, 'public-source'); mkdirSync(target);
  for (const file of files) copiedFile(join(root, 'packages/intake-site-adapter', file), join(target, 'packages/intake-site-adapter', file));
  const paths = [
    ...readdirSync(join(root, 'test')).filter(file => /^(?:intake-(?:site-)?adapter.*|canary-promotion-guard)\.test\.js$/.test(file)).map(file => `test/${file}`),
    'qa/fixtures/canary-routes/vercel.js', 'qa/fixtures/canary-routes/web.js', 'qa/fixtures/canary-routes/public.js',
    'contracts/intake/v1/lead-command.schema.json', 'contracts/intake/v1/error-response.schema.json',
    'scripts/adapter-test-reporter.js', 'scripts/run-adapter-tests.js', 'scripts/prepare-adapter-package.js',
    'scripts/check-adapter-release.js', 'release/adapter-publication.yml.template', 'release/adapter-release-authority.json',
  ];
  for (const file of paths) copiedFile(join(root, file), join(target, file));
  const development = { ajv: '8.18.0', 'ajv-formats': '3.0.1', typescript: '5.9.3' };
  const metadata = { name: 'intake-adapter-public-source', version: '1.1.0', private: true, type: 'module', scripts: { test: 'node scripts/run-adapter-tests.js', 'adapter:test': 'node scripts/run-adapter-tests.js', 'adapter:pack': 'node scripts/prepare-adapter-package.js' }, devDependencies: development, engines: { node: '>=20' } };
  writeJSON(join(target, 'package.json'), metadata);
  const lock = json(join(root, 'package-lock.json'));
  const packages = { '': { name: metadata.name, version: metadata.version, devDependencies: development, engines: metadata.engines } };
  const pending = Object.keys(development);
  while (pending.length) {
    const name = pending.pop(), key = `node_modules/${name}`;
    if (packages[key]) continue;
    const entry = lock.packages[key]; requireCondition(entry, 'export_dependency_missing');
    packages[key] = { ...entry, dev: true };
    pending.push(...Object.keys(entry.dependencies ?? {}));
  }
  writeJSON(join(target, 'package-lock.json'), { name: metadata.name, version: metadata.version, lockfileVersion: 3, requires: true, packages });
  const identity = sourceIdentity(json(join(root, 'packages/intake-site-adapter/package.json')), json(join(root, 'release/adapter-release-authority.json')));
  const identityReadme = identity.status === 'configured-not-live-verified'
    ? `Configured public source identity: ${identity.repository}. This is configuration only; live repository ownership is not verified.`
    : 'Public source identity is missing or mismatched. Publication remains blocked until matching repository metadata and authority are configured.';
  writeFileSync(join(target, 'README.md'), `# Intake site adapter public source\n\n${identityReadme}\n\nThis package-only source supports Node.js 20 and newer. Run \`npm ci --ignore-scripts --registry=https://registry.npmjs.org\`, \`npm test\`, and \`npm run adapter:pack\` for local preparation. It contains reusable adapter code, public contracts, and synthetic checks only. Publication remains blocked pending npm owner setup, package bootstrap, trusted publishing, 2FA, protected release settings, and provenance verification.\n`);
  const manifest = [];
  function walk(directory, prefix = '') {
    for (const name of readdirSync(directory).sort()) {
      const relative = `${prefix}${name}`, absolute = join(directory, name);
      if (lstatSync(absolute).isDirectory()) walk(absolute, `${relative}/`);
      else { const bytes = readFileSync(absolute); requireCondition(auditPublicBytes(bytes).length === 0, 'public_export_audit_failed'); manifest.push({ path: relative, size: bytes.length, sha256: digest(bytes) }); }
    }
  }
  walk(target); writeJSON(join(output, 'public-source-manifest.json'), manifest);
  return { files: manifest.length, manifest_sha256: digest(Buffer.from(JSON.stringify(manifest))), source_identity: identity };
}

export function prepareAdapterPackage({ root = ROOT, output, exportPublicSource = true } = {}) {
  root = resolve(root);
  output = output ? resolve(output) : mkdtempSync(join(tmpdir(), 'intake-package-proof-'));
  mkdirSync(output, { recursive: true }); requireCondition(readdirSync(output).length === 0, 'output_directory_must_be_empty');
  const temporary = mkdtempSync(join(tmpdir(), 'intake-package-build-'));
  try {
    const env = isolatedEnvironment(join(temporary, 'home'), join(temporary, 'cache'));
    const npm = (args, cwd, category) => command(process.execPath, [npmPath(), ...args], cwd, env, category);
    const source = join(root, 'packages/intake-site-adapter'), staged = join(temporary, 'intake-site-adapter'); mkdirSync(staged);
    const metadata = json(join(source, 'package.json'));
    requireCondition(metadata.name === PACKAGE_NAME && metadata.version === '1.1.0' && metadata.license === 'Apache-2.0' && metadata.type === 'module' && metadata.engines?.node === '>=20', 'package_identity_invalid');
    requireCondition(!metadata.dependencies && !metadata.devDependencies && !metadata.scripts && metadata.publishConfig?.registry === 'https://registry.npmjs.org' && metadata.publishConfig?.access === 'public', 'package_policy_invalid');
    requireCondition(JSON.stringify([...metadata.files, 'package.json'].sort()) === JSON.stringify(PACKAGE_FILES), 'package_allowlist_invalid');
    for (const file of PACKAGE_FILES) {
      const absolute = join(source, file); requireCondition(lstatSync(absolute).isFile() && !lstatSync(absolute).isSymbolicLink(), 'source_must_be_regular_file');
      const bytes = readFileSync(absolute); requireCondition(auditPublicBytes(bytes).length === 0, 'package_content_audit_failed'); copiedFile(absolute, join(staged, file));
    }
    const first = JSON.parse(npm(['pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', temporary], staged, 'pack_failed'))[0];
    requireCondition(first.files.length === PACKAGE_FILES.length && JSON.stringify(first.files.map(file => file.path).sort()) === JSON.stringify(PACKAGE_FILES), 'packed_allowlist_invalid');
    const tarball = readFileSync(join(temporary, first.filename));
    npm(['pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', temporary], staged, 'repack_failed');
    requireCondition(tarball.equals(readFileSync(join(temporary, first.filename))), 'pack_not_reproducible');
    const extracted = join(temporary, 'extracted'); mkdirSync(extracted);
    command('/usr/bin/tar', ['-xzf', join(temporary, first.filename), '-C', extracted], temporary, env, 'tar_extract_failed');
    const manifest = PACKAGE_FILES.map(file => {
      const path = join(extracted, 'package', file); requireCondition(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink(), 'packed_file_not_regular');
      const bytes = readFileSync(path); requireCondition(bytes.equals(readFileSync(join(source, file))), 'packed_source_mismatch'); requireCondition(auditPublicBytes(bytes).length === 0, 'packed_content_audit_failed');
      return { path: file, size: bytes.length, sha256: digest(bytes), mode: first.files.find(entry => entry.path === file).mode };
    });
    const artifactPath = join(output, first.filename); writeFileSync(artifactPath, tarball);
    const consumer = join(temporary, 'consumer'); mkdirSync(consumer); writeFileSync(join(consumer, 'candidate.tgz'), tarball);
    writeJSON(join(consumer, 'package.json'), { name: 'synthetic-adapter-consumer', version: '1.0.0', private: true, type: 'module', dependencies: { [PACKAGE_NAME]: 'file:./candidate.tgz' } });
    npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], consumer, 'offline_install_failed');
    npm(['ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], consumer, 'offline_clean_install_failed');
    const integrity = `sha512-${digest(tarball, 'sha512', 'base64')}`;
    const consumerLock = json(join(consumer, 'package-lock.json'));
    requireCondition(consumerLock.packages[`node_modules/${PACKAGE_NAME}`]?.integrity === integrity, 'lock_integrity_mismatch');
    for (const file of PACKAGE_FILES) requireCondition(readFileSync(join(consumer, 'node_modules', PACKAGE_NAME, file)).equals(readFileSync(join(source, file))), 'installed_source_mismatch');
    writeFileSync(join(consumer, 'route.mjs'), `import {createCanaryHandler} from '${PACKAGE_NAME}'; export default createCanaryHandler({source:'fixture-site',logger:null});\n`);
    writeFileSync(join(consumer, 'consumer.mjs'), `import assert from 'node:assert/strict'; import * as adapter from '${PACKAGE_NAME}'; import * as verifier from '${PACKAGE_NAME}/verify-route'; assert.equal(adapter.ADAPTER_VERSION,'1.1.0'); assert.equal(adapter.CONTRACT_VERSION,'intake-contract-v1'); for(const name of ['createIntakeHandler','createCanaryHandler','createWebHandler','verifyCanaryHandler','SiteAdapterConfigurationError']) assert.equal(typeof adapter[name],'function'); assert.deepEqual(Object.keys(verifier),['verifyCanaryRoute']); const result=await verifier.verifyCanaryRoute({routePath:'route.mjs',source:'fixture-site'}); assert.equal(result.ok,true); assert.equal(result.adapter_version,adapter.ADAPTER_VERSION);\n`);
    command(process.execPath, ['consumer.mjs'], consumer, env, 'runtime_consumer_failed');
    const cli = JSON.parse(command(process.execPath, [join(consumer, 'node_modules/.bin/intake-verify-canary-route'), '--route', 'route.mjs', '--source', 'fixture-site'], consumer, env, 'cli_consumer_failed'));
    requireCondition(cli.ok === true && cli.adapter_version === '1.1.0', 'cli_result_invalid');
    writeFileSync(join(consumer, 'consumer.mts'), `import {ADAPTER_VERSION,CONTRACT_VERSION,createIntakeHandler,createCanaryHandler,createWebHandler,verifyCanaryHandler,SiteAdapterConfigurationError,type NodeHandler} from '${PACKAGE_NAME}';\nimport {verifyCanaryRoute,type VerificationResult} from '${PACKAGE_NAME}/verify-route';\nconst version:'1.1.0'=ADAPTER_VERSION; const contract:'intake-contract-v1'=CONTRACT_VERSION;\nconst handler:NodeHandler=createIntakeHandler({formMap:{contact:{name:'name',email:'email'},details:{notes:'notes'}},turnstile:{action:'contact',allowedHostnames:['example.com']},logger:null});\nconst web:(request:Request)=>Promise<Response>=createWebHandler(handler); const canary=createCanaryHandler({source:'fixture-site',logger:null});\nconst check:Promise<VerificationResult>=verifyCanaryRoute({routePath:'route.mjs',source:'fixture-site',timeoutMs:1000}); verifyCanaryHandler(canary); new SiteAdapterConfigurationError('configuration');\n// @ts-expect-error unknown authority field is not a form-map destination\ncreateIntakeHandler({formMap:{contact:{tenant_id:'tenant'}},turnstile:{action:'contact',allowedHostnames:['example.com']}});\n// @ts-expect-error historical declaration exported a nonexistent API\nimport {verifyRoute} from '${PACKAGE_NAME}/verify-route';\nvoid [version,contract,web,check];\n`);
    writeJSON(join(consumer, 'tsconfig.json'), { compilerOptions: { noEmit: true, strict: true, module: 'NodeNext', target: 'ES2022', lib: ['ES2022', 'DOM'], types: [] }, files: ['consumer.mts'] });
    command(process.execPath, [join(root, 'node_modules/typescript/lib/tsc.js'), '--project', 'tsconfig.json'], consumer, env, 'type_consumer_failed');
    npm(['install', '--package-lock-only', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], staged, 'sbom_lock_failed');
    const sbom = JSON.parse(npm(['sbom', '--sbom-format=cyclonedx', '--omit=dev', '--package-lock-only'], staged, 'sbom_failed'));
    requireCondition(sbom.metadata?.component?.name === PACKAGE_NAME.split('/')[1] || sbom.metadata?.component?.name === PACKAGE_NAME, 'sbom_identity_invalid');
    sbom.metadata.component.hashes = [{ alg: 'SHA-256', content: digest(tarball) }];
    requireCondition(auditPublicBytes(Buffer.from(JSON.stringify(sbom))).length === 0, 'sbom_audit_failed');
    writeJSON(join(output, 'sbom.cdx.json'), sbom); writeJSON(join(output, 'packed-files.json'), manifest); writeJSON(join(output, 'consumer-lock.json'), consumerLock);
    const exported = exportPublicSource ? sourceExport(root, output, PACKAGE_FILES) : null;
    const identity = sourceIdentity(metadata, json(join(root, 'release/adapter-release-authority.json')));
    const identityBlocker = identity.status === 'configured-not-live-verified' ? 'public_source_ownership_not_live_verified' : 'approved_public_source_identity_missing';
    const report = { status: 'local-preparation-only', package: PACKAGE_NAME, version: metadata.version, node: process.version, npm: npm(['--version'], staged, 'npm_version_failed').trim(), tarball: first.filename, bytes: tarball.length, sha256: digest(tarball), integrity, packed_files: manifest.length, reproducible_pack: true, every_packed_byte_matches_source: true, offline_install_and_ci: true, lock_integrity_verified: true, runtime_cli_types: true, runtime_dependencies: 0, source_identity: identity, source_export: exported, publication_ready: false, publication_blockers: [identityBlocker, 'protected_environment_and_npm_owner_setup_unverified', 'first_package_bootstrap_unresolved'] };
    writeJSON(join(output, 'preparation.json'), report); return { output, ...report };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2); requireCondition(args.length === 0 || (args.length === 2 && args[0] === '--output'), 'invalid_arguments');
    console.log(JSON.stringify(prepareAdapterPackage({ output: args[1] })));
  } catch (error) { console.error(JSON.stringify({ ok: false, error: /^[a-z_]+$/.test(error.message) ? error.message : 'package_preparation_failed' })); process.exitCode = 1; }
}
