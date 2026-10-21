import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// These are dependency groups, not folder names. Keep additions conservative:
// a new file has no reviewed dependency map, even inside a familiar folder.
export const groups = [
  'node', 'helper', 'installer', 'legacy_windows', 'testisp', 'wintun',
  'go_windows', 'go_linux', 'acceptance', 'control',
];
export const areas = {
  docs: [],
  // The TestISP proof imports tests/windows/local-traffic.mjs, which imports
  // scripts/tun-test-https.mjs and through it lib/engine.mjs.
  frozen: ['node', 'helper', 'installer', 'legacy_windows', 'testisp', 'go_linux', 'acceptance', 'control'],
  go_shared: ['go_windows', 'go_linux', 'legacy_windows', 'testisp', 'wintun', 'acceptance', 'control'],
  go_windows: ['go_windows', 'legacy_windows', 'testisp', 'wintun', 'control'],
  go_linux: ['go_linux', 'acceptance'],
  tests_linux: ['go_windows', 'go_linux', 'acceptance'],
  tests_windows: ['node', 'go_windows', 'legacy_windows', 'testisp', 'control'],
};

// An area name, or several joined by '+' for a file that sits among code of
// more than one area.
export const groupsOfArea = area => [...new Set(area.split('+').flatMap(name => areas[name]))];

const windowsGo = /_windows(?:_(?:amd64|arm64|386))?(?:_test)?\.go$/;
// Code, for the locality rule below. Everything else is data some code reads.
const isCode = path => /\.(?:go|mjs|ps1)$/.test(path);

// The area of a code file, by where it lives and what it builds for.
function codeArea(path) {
  // Node's trace coverage test reads this Go source. drift.test.mjs fails if
  // a test or script reads another mapped file its area wouldn't select.
  if (path === 'internal/control/http.go') return null;
  // go1-linux vets, tests and builds ./tests/..., so only Windows-suffixed Go
  // files under tests/windows are Windows-only.
  if (/^tests\/windows\/.+\.go$/.test(path) && !windowsGo.test(path)) return null;
  if (/^(?:internal|cmd)\/.+\.go$/.test(path)) {
    if (windowsGo.test(path)) return 'go_windows';
    if (/_linux(?:_(?:amd64|arm64|386))?(?:_test)?\.go$/.test(path)) return 'go_linux';
    // A folder named windows is NOT an OS constraint: meters.go, network.go
    // and others there compile and run tests on Linux too.
    return 'go_shared';
  }
  // tests/linux contains portable Go packages tested on Windows as well.
  if (/^tests\/linux\//.test(path)) return 'tests_linux';
  // Node unit tests import this harness on both operating systems.
  if (/^tests\/windows\//.test(path)) return 'tests_windows';
  if (path === 'server.mjs' || /^lib\//.test(path) || /^helper\/.+\.go$/.test(path) || /^test\//.test(path)) return 'frozen';
  return null;
}

// Code files directly in each folder, per tracked-file set.
const codeByFolder = new WeakMap();
function codeIn(tracked, dir) {
  let index = codeByFolder.get(tracked);
  if (!index) {
    codeByFolder.set(tracked, index = new Map());
    for (const file of tracked) {
      if (!isCode(file)) continue;
      const folder = file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : '';
      if (!index.has(folder)) index.set(folder, []);
      index.get(folder).push(file);
    }
  }
  return index.get(dir) ?? [];
}

// tracked is the set of files at the merge base; the locality rule needs it.
export function areaFor(path, tracked = new Set()) {
  // Shared inputs and generated trees: a change runs everything.
  if (/^(?:\.github|scripts|vendor|third_party)\//.test(path)
      || /(?:^|\/)(?:go\.(?:mod|sum)|package(?:-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(path)) return null;
  // Documentation-only: Markdown at the repository root. The installer ships
  // THIRD_PARTY_NOTICES.md and LICENSE, and copies all of docs/.
  if (!path.includes('/') && /\.md$/i.test(path) && path !== 'THIRD_PARTY_NOTICES.md') return 'docs';
  if (isCode(path)) return codeArea(path);
  // Fixtures that the 0.3.x Node tests and the Go ports beside them both read:
  // test/pure-port-fixtures.test.mjs reads internal/*/node-*.json, and
  // internal/engine/singbox/config_test.go reads the Windows golden configs.
  if (/^internal\/[^/]+\/node-[\w-]+\.json$/.test(path) || path === 'test/fixtures/windows-golden.json') return 'frozen+go_shared';
  // The snap pins and the sing-box config at the top of tests/linux, which
  // holds no code itself; the Linux acceptance job reads both.
  if (/^tests\/linux\/[^/]+\.(?:json|sh)$/.test(path)) return 'tests_linux';
  // Locality: anything else belongs to the code in its folder, or in the
  // nearest folder above that has code. A test that reads a file beside it by
  // a computed name then selects that file's jobs by construction; readers
  // further away build paths drift.mjs follows and checks. No code around it,
  // or code the map doesn't place: everything runs.
  const found = new Set();
  const parts = path.split('/').slice(0, -1);
  for (let depth = parts.length; depth >= 1 && !found.size; depth -= 1) {
    for (const file of codeIn(tracked, parts.slice(0, depth).join('/'))) {
      const area = codeArea(file);
      if (area === null) return null;
      found.add(area);
    }
  }
  if (!found.size) return null;
  // Drop an area whose groups another one already selects.
  const names = [...found].sort();
  const covers = (other, name) => areas[name].every(group => areas[other].includes(group));
  return names.filter(name => !names.some(other => other !== name && covers(other, name) && (!covers(name, other) || other < name))).join('+');
}

// namedDocs: root Markdown files whose name appears in tracked non-Markdown
// text. Something may open such a file by a path nobody can follow statically,
// so a change to it is not documentation-only.
export function classify(paths, knownPaths, { eventName = 'pull_request', labels = [], namedDocs = new Set() } = {}) {
  const selected = new Set();
  const reasons = [];
  let full = eventName !== 'pull_request' || labels.includes('ci:full') || paths.length === 0;
  if (full) reasons.push(eventName !== 'pull_request' ? `event: ${eventName}` : labels.includes('ci:full') ? 'label: ci:full' : 'empty diff');
  for (const path of paths) {
    let area = knownPaths.has(path) ? areaFor(path, knownPaths) : null;
    if (area === 'docs' && namedDocs.has(path)) {
      reasons.push(`${JSON.stringify(path)}: named in tracked code or workflows; full run`);
      full = true;
      continue;
    }
    reasons.push(`${JSON.stringify(path)}: ${area ?? 'new or unclassified; full run'}`);
    if (area === null) full = true;
    else for (const group of groupsOfArea(area)) selected.add(group);
  }
  return { full, reasons, outputs: Object.fromEntries(groups.map(group => [group, full || selected.has(group)])) };
}

export function changedFiles(base, head, git = args => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })) {
  if (![base, head].every(sha => /^[a-f0-9]{40}$/.test(sha))) throw new Error('Expected full base and head commit SHAs');
  const mergeBase = git(['merge-base', base, head]).trim();
  if (!/^[a-f0-9]{40}$/.test(mergeBase)) throw new Error('Invalid merge base');
  // No rename detection: both the deleted source and added destination count.
  // NUL separation preserves spaces, quotes, tabs and newlines in file names.
  const split = text => text.split('\0').filter(Boolean);
  const paths = split(git(['diff', '--name-only', '--no-renames', '-z', mergeBase, head, '--']));
  const knownPaths = new Set(split(git(['ls-tree', '-r', '--name-only', '-z', mergeBase, '--'])));
  return { paths, knownPaths, mergeBase, namedDocs: namedRootDocs(paths, head, git) };
}

// A plain, case-insensitive text search of every tracked non-Markdown file at
// the PR head. Over-matching only costs a full run. .github/ci is left out: it
// holds this classifier and its tests, which name documents as data, and any
// change there already runs everything.
export function namedRootDocs(paths, head, git) {
  const named = new Set();
  for (const path of paths) {
    if (path.includes('/') || !/\.md$/i.test(path)) continue;
    let out = '';
    try {
      out = git(['grep', '-l', '-i', '-F', '-I', '-e', path, head, '--', '.', ':(exclude,glob)**/*.md', ':(exclude,glob)**/*.MD', ':(exclude).github/ci']);
    } catch (error) {
      // git grep exits 1 when nothing matches; any other failure is not a skip.
      if (error.status !== 1) throw error;
    }
    if (out.trim()) named.add(path);
  }
  return named;
}

export function decide(eventName, event, git) {
  if (eventName !== 'pull_request' || event.pull_request?.labels?.some(label => label.name === 'ci:full')) {
    return classify([], new Set(), { eventName, labels: event.pull_request?.labels?.map(label => label.name) });
  }
  // A stacked PR can later be retargeted to the default branch, and that
  // fires no run. Its checks must already cover everything it would merge.
  const base = event.pull_request?.base?.ref, defaultBranch = event.repository?.default_branch;
  if (!base || !defaultBranch || base !== defaultBranch) {
    const result = classify([], new Set(), { eventName: 'stacked' });
    result.reasons = [`base branch ${JSON.stringify(base ?? null)} is not the default branch ${JSON.stringify(defaultBranch ?? null)}`];
    return result;
  }
  const { paths, knownPaths, mergeBase, namedDocs } = changedFiles(event.pull_request?.base?.sha, event.pull_request?.head?.sha, git);
  const result = classify(paths, knownPaths, { namedDocs });
  result.reasons.unshift(`merge base: ${mergeBase}`);
  return result;
}

// Failure must cost capacity, never coverage. The workflow also falls back to
// all jobs if checkout, the tests, or this process fails altogether.
export function run(eventName, readEvent, git) {
  try {
    return decide(eventName, JSON.parse(readEvent()), git);
  } catch (error) {
    const result = classify([], new Set(), { eventName: 'classification-failed' });
    result.warning = `Changed-file classification failed; running everything: ${String(error.message).replace(/[\r\n]/g, ' ')}`;
    return result;
  }
}

export const outputLines = result => groups.map(group => `${group}=${result.outputs[group] === false ? 'false' : 'true'}\n`).join('');

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = run(process.env.GITHUB_EVENT_NAME, () => readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  if (result.warning) console.log(`::warning::${result.warning}`);
  console.log(JSON.stringify(result, null, 2));
  appendFileSync(process.env.GITHUB_OUTPUT, outputLines(result));
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Changed-file decision\n\nFull run: ${result.full}\n\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\`\n`);
}
