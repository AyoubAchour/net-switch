// Run after the source job has produced the Go source-with-deps archive.
// Native source stays upstream; sources.txt records exact revisions and the gap.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

const pins = JSON.parse(await readFile('packaging/versions.json', 'utf8'));
const verifyOnly = process.argv.includes('--verify-only');
const { cronetGo, naiveproxy, singTun, wintun } = pins.nativeSources;
const singBox = pins.singBox;
for (const source of [singBox.source, cronetGo, naiveproxy, singTun]) {
  if (!/^https:\/\/github\.com\/SagerNet\/[\w-]+\.git$/.test(source.repository) ||
      !/^[a-f0-9]{40}$/.test(source.commit)) throw new Error('Invalid immutable source pin');
}
for (const commit of [cronetGo.windowsModuleCommit, cronetGo.buildCommit]) {
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('Invalid Cronet build commit');
}

// A connection that fails for a moment is retried, so a brief network hiccup
// on the runner doesn't fail a release; so is a server error (5xx). An answer
// like 404 is final.
async function download(url) {
  const waits = [5, 15, 30];
  for (let attempt = 0; ; attempt += 1) {
    let failure;
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
      if (response.ok) return Buffer.from(await response.arrayBuffer());
      if (response.status < 500) throw new Error(`${url}: HTTP ${response.status}`);
      failure = `HTTP ${response.status}`;
    } catch (error) {
      if (error.message.startsWith(`${url}: HTTP`)) throw error;
      failure = error.message;
    }
    if (attempt >= waits.length) throw new Error(`${url}: download failed after ${attempt + 1} attempts: ${failure}`);
    console.log(`Download failed (${failure}); retrying in ${waits[attempt]} s`);
    await new Promise((resolve) => setTimeout(resolve, waits[attempt] * 1000));
  }
}
const raw = (repo, commit, file) => `https://raw.githubusercontent.com/SagerNet/${repo}/${commit}/${file}`;
const goMod = verifyOnly
  ? (await download(raw('sing-box', singBox.source.commit, 'go.mod'))).toString()
  : await readFile(path.join(process.env.RUNNER_TEMP, `sing-box-${singBox.version}`, 'go.mod'), 'utf8');
for (const [module, version] of [
  ['cronet-go', cronetGo.version],
  ['cronet-go/lib/windows_amd64', cronetGo.windowsModuleVersion],
  ['cronet-go/lib/windows_arm64', cronetGo.windowsModuleVersion],
  ['sing-tun', singTun.version],
]) {
  if (!goMod.split('\n').some(line => {
    const fields = line.trim().split(/\s+/);
    return fields[0] === `github.com/sagernet/${module}` && fields[1] === version;
  })) throw new Error(`Source manifest disagrees with sing-box go.mod: ${module}@${version}`);
}

// Verify the gitlink at both the Go binding and binary-module revisions.
for (const commit of [cronetGo.commit, cronetGo.windowsModuleCommit, cronetGo.buildCommit]) {
  const submodule = JSON.parse(await download(
    `https://api.github.com/repos/SagerNet/cronet-go/contents/naiveproxy?ref=${commit}`));
  if (submodule.sha !== naiveproxy.commit || submodule.submodule_git_url !== naiveproxy.repository) {
    throw new Error(`Cronet ${commit} no longer matches the pinned naiveproxy source`);
  }
}
const chromiumVersion = (await download(raw('naiveproxy', naiveproxy.commit, 'CHROMIUM_VERSION'))).toString().trim();
if (chromiumVersion !== naiveproxy.chromiumVersion) throw new Error('Chromium version pin disagrees with native source');
const dll = await download(raw('cronet-go', cronetGo.windowsModuleCommit, 'lib/windows_amd64/libcronet.dll'));
if (createHash('sha256').update(dll).digest('hex') !== singBox.files['libcronet.dll']) {
  throw new Error('The native module DLL does not match the packaged sing-box DLL');
}
const embeddedWintun = await download(raw('sing-tun', singTun.commit, 'internal/wintun/amd64/wintun.dll'));
if (createHash('sha256').update(embeddedWintun).digest('hex') !== wintun.embeddedAmd64Sha256) {
  throw new Error('The embedded Wintun DLL does not match its provenance pin');
}
const armDll = await download(raw('cronet-go', cronetGo.windowsModuleCommit, 'lib/windows_arm64/libcronet.dll'));
if (createHash('sha256').update(armDll).digest('hex') !== pins.arm64.singBox.files['libcronet.dll']) {
  throw new Error('The ARM64 native module DLL does not match the packaged sing-box DLL');
}
const armWintun = await download(raw('sing-tun', singTun.commit, 'internal/wintun/arm64/wintun.dll'));
if (createHash('sha256').update(armWintun).digest('hex') !== wintun.embeddedArm64Sha256) {
  throw new Error('The embedded ARM64 Wintun DLL does not match its provenance pin');
}
if (verifyOnly) {
  console.log('Verified immutable Go/native source pins and x64/ARM64 native DLL hashes; no manifest written.');
  process.exit(0);
}

const bundle = `sing-box-${singBox.version}-source-with-deps.tar.gz`;
const bundleHash = createHash('sha256').update(await readFile(path.join('dist', bundle))).digest('hex');
const text = `Net Switch bundled engine source provenance

sing-box ${singBox.version}
Repository: ${singBox.source.repository}
Commit: ${singBox.source.commit}
Tag: ${singBox.source.tag}
Go directive: ${singBox.source.goVersion}
Go source and vendored dependencies: ${bundle} (attached to this release)
Bundle SHA-256: ${bundleHash}

cronet-go ${cronetGo.version}
Repository: ${cronetGo.repository}
Go binding commit: ${cronetGo.commit}
Windows binary module: ${cronetGo.windowsModuleVersion}
Windows binary module commit: ${cronetGo.windowsModuleCommit}
Native build source commit: ${cronetGo.buildCommit}
Build recipe: https://github.com/SagerNet/cronet-go/blob/${cronetGo.buildCommit}/cmd/build-naive/cmd_build.go
Publish workflow: https://github.com/SagerNet/cronet-go/blob/${cronetGo.buildCommit}/.github/workflows/naive-build.yml
Windows build: go run ./cmd/build-naive --target=windows/amd64 build
Windows packaging: go run ./cmd/build-naive --target=windows/amd64 package
The build uses GN, Ninja and Visual Studio; target cronet produces cronet.dll.
Packaging renames it libcronet.dll and publishing commits it to the Go module.
Packaged DLL SHA-256: ${singBox.files['libcronet.dll']}
Windows ARM64 uses the same source revisions and windows_arm64 binary module.
Windows ARM64 build: go run ./cmd/build-naive --target=windows/arm64 build
Windows ARM64 packaging: go run ./cmd/build-naive --target=windows/arm64 package
Packaged ARM64 DLL SHA-256: ${pins.arm64.singBox.files['libcronet.dll']}

naiveproxy / Chromium ${naiveproxy.chromiumVersion}
Repository: ${naiveproxy.repository}
Submodule commit: ${naiveproxy.commit}
Native source and distributed notices: ${naiveproxy.noticesUrl}
${naiveproxy.noticesNote}
The native tree and its build dependencies are NOT included in the Go bundle.
This manifest is a source locator, not a complete native Corresponding Source archive.
Before treating the distribution as complete, audit native linked dependencies,
their notices and any source-delivery obligations; preserve the required native
source, dependency revisions and build inputs or arrange compliant source access.

sing-tun ${singTun.version}
Repository: ${singTun.repository}
Commit: ${singTun.commit}
Embedded Wintun ${wintun.version} (amd64), unchanged official prebuilt DLL
Official archive: ${wintun.url}
Archive SHA-256: ${wintun.sha256}
Embedded DLL SHA-256: ${wintun.embeddedAmd64Sha256}
Embedded ARM64 DLL SHA-256: ${wintun.embeddedArm64Sha256}
License: wintun/LICENSE.txt in that archive (installed as licenses/wintun-LICENSE.txt)
License SHA-256: ${pins.licenses.wintun.sha256}
The prebuilt Wintun license differs from the Wintun source GPL-2.0 license.
`;
await writeFile('dist/sources.txt', text);
console.log(`Verified native provenance and wrote dist/sources.txt (${bundleHash})`);
