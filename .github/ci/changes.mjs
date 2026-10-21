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
  frozen: ['node', 'helper', 'installer', 'legacy_windows', 'go_linux', 'acceptance', 'control'],
  go_shared: ['go_windows', 'go_linux', 'legacy_windows', 'testisp', 'wintun', 'acceptance', 'control'],
  go_windows: ['go_windows', 'legacy_windows', 'testisp', 'wintun', 'control'],
  go_linux: ['go_linux', 'acceptance'],
  tests_linux: ['go_windows', 'go_linux', 'acceptance'],
  tests_windows: ['node', 'go_windows', 'legacy_windows', 'testisp', 'control'],
};

const windowsGo = /_windows(?:_(?:amd64|arm64|386))?(?:_test)?\.go$/;

export function areaFor(path) {
  // These exclusions precede documentation and platform matching. A README
  // in vendor or a fixture is still an input, not documentation-only work.
  if (/^(?:\.github|scripts|vendor|third_party)\//.test(path)
      || /(?:^|\/)(?:go\.(?:mod|sum)|package(?:-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(path)
      || /(?:^|\/)(?:fixtures?|testdata)(?:\/|$)/.test(path)) return null;
  // The installer copies these entire trees, not just today's user guide.
  if (path === 'THIRD_PARTY_NOTICES.md' || (/^(?:lib|ui|tools|licenses|docs)\//.test(path) && path.endsWith('.md'))) return null;
  if (path.endsWith('.md') && !path.startsWith('test/')) return 'docs';
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
  if (/^tests\/linux\/.+\.(?:go|mjs|sh|json)$/.test(path)) return 'tests_linux';
  // Node unit tests import this harness on both operating systems.
  if (/^tests\/windows\/.+\.(?:go|mjs|ps1|json)$/.test(path)) return 'tests_windows';
  if (path === 'server.mjs' || /^lib\/.+\.(?:mjs|cs|json)$/.test(path)
      || /^helper\/.+\.go$/.test(path) || /^test\/.+\.mjs$/.test(path)) return 'frozen';
  return null;
}

export function classify(paths, knownPaths, { eventName = 'pull_request', labels = [] } = {}) {
  const selected = new Set();
  const reasons = [];
  let full = eventName !== 'pull_request' || labels.includes('ci:full') || paths.length === 0;
  if (full) reasons.push(eventName !== 'pull_request' ? `event: ${eventName}` : labels.includes('ci:full') ? 'label: ci:full' : 'empty diff');
  for (const path of paths) {
    const area = knownPaths.has(path) ? areaFor(path) : null;
    reasons.push(`${JSON.stringify(path)}: ${area ?? 'new or unclassified; full run'}`);
    if (area === null) full = true;
    else for (const group of areas[area]) selected.add(group);
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
  return { paths, knownPaths, mergeBase };
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
  const { paths, knownPaths, mergeBase } = changedFiles(event.pull_request?.base?.sha, event.pull_request?.head?.sha, git);
  const result = classify(paths, knownPaths);
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
