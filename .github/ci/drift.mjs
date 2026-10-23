import { posix } from 'node:path';
import { areaFor, groupsOfArea } from './changes.mjs';
import { GoTree, goCommand, goosOf } from './golist.mjs';
import { Reader, languageOf, locate, readerFor, sites } from './readers.mjs';
import { generated, repoView } from './repo.mjs';
import { evaluate, readWorkflow, runnerOS, truthy } from './workflows.mjs';

// The classifier maps files to job groups by where they live. A test, script
// or Go file that reads a file from another area breaks that map silently:
// changing the file would skip the job that reads it. This follows what each
// gated job runs, and what those files compile, import, read, spawn or embed,
// and reports a reached file whose area wouldn't select a job that reaches it.
//
// Nothing here trusts the map being checked. Go code is reached from the go
// commands each job runs, on that job's operating system, through package
// patterns, build constraints and imports (golist.mjs). Paths built at run
// time are evaluated (readers.mjs). One the guard can't place is a problem,
// as is an executable a workflow step computes, unless it's declared below
// at its call site with what it reads and why.

const scannable = path => /\.(?:mjs|js|go|ps1|sh)$/.test(path) && !generated.test(path);

// References these readers make that only some of their jobs exercise. Each
// narrows the jobs carried along that reference and must still be in use.
export const narrowed = [{
  from: 'scripts/e2e-routing.mjs', to: /^internal\/platform\/worker\//, groups: ['control'],
  why: 'it runs go test ./internal/platform/worker only against the Go control server (!isNodeServer), which only the Control jobs start',
}];

// Call sites the guard can't place, each with what it reads (repository
// files or folders, which are followed like any other reference) or, for
// paths that never name a repository file, where they point instead. call is
// the site exactly as the guard reports it; sites is how many such call sites
// the file has. Each needs a reason and must still match.
export const declared = [{
  from: 'scripts/smoke-test-installer.ps1', call: 'import(process.argv[1])', reads: ['lib/engine.mjs'],
  why: 'it imports the installed copy of lib/engine.mjs, passed on the node command line',
}, {
  from: 'test/windows-acceptance.test.mjs', call: 'import(${JSON.stringify(moduleURL)})', sites: 2, reads: ['scripts/server-under-test.mjs', 'tests/windows/launch.mjs'],
  why: 'the child script imports the module URL this test builds from one of those literal paths',
}, {
  from: 'test/windows-acceptance.test.mjs', call: 'import(${JSON.stringify(sharedURL)})', sites: 2, reads: ['tests/windows/launch.mjs'],
  why: 'the child script imports the shared launcher URL this test builds from that literal path',
}, {
  from: 'scripts/build-release.ps1', call: 'Test-Path((Join-Path $repoRoot $_))',
  reads: ['launch.ps1', 'tray.ps1', 'server.mjs', 'package.json', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'assets/net-switch.ico', 'engine/LICENSE', 'lib', 'ui', 'tools', 'licenses', 'docs'],
  why: 'it checks that every entry of the installer allowlist ($required) exists; the entries are the literal root files and trees listed above it',
}, {
  from: 'tests/windows/testisp/network.ps1', call: 'Test-Path($env:TESTISP_PROBE)', outside: 'the probe executable that harness.mjs builds under dist/windows-test',
  why: 'harness.mjs sets TESTISP_PROBE to the probe it built before it starts this script',
}, {
  from: 'tests/oracle/harness.mjs', call: "readFile(new URL(name.slice('/oracle/'.length).replace('monitor-source.mjs', 'monitor.mjs'), root))", reads: ['server.mjs', 'lib'],
  why: 'it loads the 0.3.x modules that server.mjs and lib/ import, named by their /oracle/ specifiers, from the repository root',
}, {
  from: 'tray.ps1', call: '(Join-Path $root $DataDir)', outside: "the data folder named by -DataDir: data/ beside the app by default, a temporary folder in the tests",
  why: 'it holds server.json and tray.log, which the running app writes; no repository file lives there',
}, {
  from: 'tray.ps1', call: "(Join-Path $dataPath 'tray.log')", outside: 'tray.log in the data folder above',
  why: 'the log the tray writes, in the folder -DataDir names',
}, {
  from: 'tests/lifecycle/lifecycle_test.go', call: 'os.ReadFile(path)', sites: 2,
  outside: 'executables lifecycle.yml builds into NETSWITCH_LIFECYCLE_DIR (under Program Files or /usr/lib), and a sing-box binary extracted into a temporary folder',
  why: 'the real-service test hashes the binaries it runs; it fails unless NETSWITCH_LIFECYCLE_DIR is an absolute path, and the other site reads the download it just extracted',
}, {
  from: 'tests/lifecycle/native_engine_test.go', call: 'os.ReadFile(path)',
  outside: 'the four native service binaries built by native-service-contracts.yml into NETSWITCH_LIFECYCLE_DIR under Program Files or /usr/lib',
  why: 'the hosted-only test requires an absolute installation directory and hashes each actual binary before installing the services',
}, {
  from: 'internal/engine/linux/hooks_acceptance_linux.go', call: 'os.OpenFile(path)',
  outside: 'the CPU profile file that NETSWITCH_ACCEPTANCE_PROFILE names, which the acceptance-tagged engine creates (O_CREATE|O_EXCL|O_WRONLY) wherever the person running it chose',
  why: 'it only writes a new profile; no workflow or harness in this repository sets the variable, and nothing reads the file back as a repository input',
}, {
  from: 'internal/engine/linux/hooks_acceptance_linux.go', call: 'os.OpenFile(filepath.Join(filepath.Dir(path), "block-"+p.Instance+".pprof"))',
  outside: 'the block profile that the engine writes beside the CPU profile above',
  why: 'it only writes a new file next to the CPU profile; it reads nothing from the repository',
}];

// What a declaration may say: a reason, one call, and either repository
// paths it reads or where outside the repository it points.
export function declarationProblems(repo, entries = declared) {
  const problems = [];
  for (const entry of entries) {
    const label = `declared reader ${entry.from} ${entry.call}`;
    if (typeof entry.why !== 'string' || !entry.why.trim()) problems.push(`${label}: no reason given`);
    if (typeof entry.call !== 'string' || !entry.call.trim()) problems.push(`declared reader ${entry.from}: no call site given`);
    if (!repo.has(entry.from)) problems.push(`${label}: ${entry.from} is not a tracked file`);
    const reads = Array.isArray(entry.reads) && entry.reads.length > 0, away = typeof entry.outside === 'string' && entry.outside.trim() !== '';
    if (reads === away) problems.push(`${label}: needs either the repository paths it reads or where outside the repository it points, not ${reads ? 'both' : 'neither'}`);
    for (const path of entry.reads ?? []) if (!repo.has(path) && !repo.dirs.has(path)) problems.push(`${label}: ${path} is not a tracked file or folder`);
    if (entry.sites !== undefined && !(Number.isInteger(entry.sites) && entry.sites > 0)) problems.push(`${label}: sites must be a positive count`);
  }
  for (const entry of narrowed) if (typeof entry.why !== 'string' || !entry.why.trim()) problems.push(`narrowed reference from ${entry.from}: no reason given`);
  return problems;
}

const glob = pattern => new RegExp(`^${pattern.split('\0').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '[^/]*')).join('[^/]*')}$`);

function resolve(repo, candidate, directory, fromRoot = true) {
  let path = candidate.replace(/^\$PSScriptRoot[\\/]/, './').replace(/\\/g, '/')
    // Interpolations (${x}, $(x), $x) match one path segment's worth of text.
    .replace(/\$\{[^}]*\}|\$\([^)]*\)|\$\w+/g, '\0');
  // Paths only: not words, URLs, '/' separators or '..' on their own.
  if (!/[/.]/.test(path) || !/[a-z0-9]/i.test(path) || /[\s:]/.test(path)) return { files: [], dirs: [] };
  // "$dir/$name" says nothing about which file it is.
  if (path.includes('\0') && !path.split('/').some(segment => !segment.includes('\0') && /[a-z]/i.test(segment))) return { files: [], dirs: [] };
  // Imports resolve from the file; spawned commands from the repository root.
  // A Go test runs in its package folder, so its paths resolve from there.
  const bases = path.startsWith('../') || !fromRoot ? [posix.join(directory, path)] : [posix.join(directory, path), posix.normalize(path)];
  const files = new Set(), dirs = new Set();
  for (let base of bases) {
    base = base.replace(/\/+$/, '');
    if (!base || base === '.' || base.startsWith('../')) continue;
    if (base.includes('\0')) {
      const pattern = glob(base);
      for (const file of repo.tracked) if (pattern.test(file)) files.add(file);
    } else if (repo.has(base)) files.add(base);
    else if (repo.dirs.has(base)) dirs.add(base);
  }
  return { files: [...files], dirs: [...dirs] };
}

// What a file reads: files, directories (a Go package there is loaded with
// its tests, everything else in the tree is read), and reader forms that
// couldn't be resolved.
export function references(repo, tree, file) {
  const directory = posix.dirname(file);
  const isGo = file.endsWith('.go');
  const comment = /\.(?:ps1|sh)$/.test(file) ? /^\s*#/ : /^\s*\/\/(?!go:embed)/;
  const text = repo.read(file).split('\n').filter(line => !comment.test(line)).join('\n');
  const candidates = [];
  const unresolved = [];
  const literal = /'([^'\n]*)'|"([^"\n]*)"|`([^`\n]*)`/g;
  // Scripts and Go tests name files in plain strings: any string that names
  // a tracked file or folder counts as a read, wherever it ends up. Other Go
  // strings are mostly data, so there only literals passed straight to a file
  // call count, plus the paths readers.mjs evaluates and embeds.
  const goTest = isGo && (file.endsWith('_test.go') || file.startsWith('tests/'));
  const direct = isGo && !goTest ? /\b(?:ReadFile|ReadDir|Open|OpenFile|Stat|Lstat)\(\s*("[^"\n]*")/g : isGo ? /"((?:[^"\\\n]|\\.)*)"|`([^`]*)`/g : literal;
  for (const match of text.matchAll(direct)) {
    if (isGo && !goTest) candidates.push(match[1].slice(1, -1));
    else candidates.push(match[1] ?? match[2] ?? match[3]);
  }
  // path.join(root, 'lib', name): computed parts become one open segment, and
  // the literal prefix still names where the read happens.
  for (const match of text.matchAll(/\b(?:join|Join|resolve)\s*\(((?:[^()\n]|\([^()\n]*\))*)\)/g)) {
    const args = match[1].split(/,(?![^(]*\))/).map(arg => arg.trim()).filter(Boolean);
    const parts = args.map(arg => {
      const only = /^(?:'([^'\n]*)'|"([^"\n]*)"|`([^`$\n]*)`)$/.exec(arg);
      return only ? only[1] ?? only[2] ?? only[3] : '\0';
    });
    while (parts[0] === '\0') parts.shift();
    if (parts.some(part => part !== '\0') && parts.length > 1) candidates.push(parts.join('/'));
  }
  const files = new Set(), dirs = new Set(), packages = new Set();
  for (const candidate of new Set(candidates)) {
    // "./internal/..." in a script is a Go package pattern for go commands
    // run from the repository root: Go files only, not a folder read.
    if (!isGo && /^\.\/[\w/.-]+\/\.\.\.$/.test(candidate)) {
      try { for (const dir of tree.expand(candidate, '') ?? []) packages.add(dir); } catch (error) { unresolved.push(error.message); }
      continue;
    }
    const found = resolve(repo, candidate, directory, !(isGo && file.endsWith('_test.go')));
    for (const path of found.files) if (path !== file) files.add(path);
    for (const path of found.dirs) dirs.add(path);
  }
  const follow = (entry, offset) => { entry.found?.add(`${file}:${offset}`); for (const path of entry.reads ?? []) (repo.has(path) ? files : dirs).add(path); };
  const declaredAt = call => declared.find(item => item.from === file && item.call === call);
  if (isGo) {
    const embedded = tree.embeds(file);
    for (const path of embedded.files) files.add(path);
    unresolved.push(...embedded.errors);
  } else {
    // A module loaded by a computed name can't be followed. This reads the
    // raw text, so code a script hands to node -e as a string counts too.
    for (const match of text.matchAll(/\b(import|require)\(/g)) {
      // The argument runs to the matching parenthesis on the same line.
      let depth = 1, end = match.index + match[0].length;
      for (; end < text.length && text[end] !== '\n' && depth; end += 1) depth += text[end] === '(' ? 1 : text[end] === ')' ? -1 : 0;
      const argument = text.slice(match.index + match[0].length, depth ? end : end - 1).trim();
      if (/^(?:'[^'\n]*'|"[^"\n]*"|`[^`$\n]*`)$/.test(argument)) continue;
      const call = `${match[1]}(${argument})`;
      const entry = declaredAt(call);
      if (entry) follow(entry, match.index);
      else unresolved.push(`${file}: computed import ${call}`);
    }
  }
  // Paths built at run time: see readers.mjs for what's accepted.
  if (languageOf(file)) {
    const reader = readerFor(repo, file);
    for (const site of sites(reader)) {
      const entry = declaredAt(site.key);
      if (entry) { follow(entry, site.offset); continue; }
      for (const where of placed(repo, reader, site, unresolved)) {
        for (const path of where.files ?? []) if (path !== file) files.add(path);
        for (const path of where.dirs ?? []) dirs.add(path);
      }
    }
  }
  return { files: [...files], dirs: [...dirs], packages: [...packages], unresolved };
}

// Where one site's values point. Problems go to unresolved, prefixed with
// the site so a declaration can name it.
function placed(repo, reader, site, unresolved) {
  const found = [];
  const at = `${reader.file}:${site.line}: ${site.key}`;
  for (const item of site.values) {
    // A plain string with a computed part, not built on a known folder, is
    // only a path once it's read; its read site decides.
    if (site.kind === 'build' && item.root === 'literal' && !reader.isTest) continue;
    const where = locate(repo, item, reader);
    if (where.problem) unresolved.push(`${at}: ${where.problem}`);
    else if (where.external && site.kind !== 'build') unresolved.push(`${at}: reads a path from ${item.why}`);
    else if (where.root && site.kind === 'list') unresolved.push(`${at}: lists the whole repository`);
    else found.push(where);
  }
  return found;
}

// Shell text (bash or PowerShell) as commands of words, quotes removed. A
// word holding a variable or an unevaluated expression is dynamic. Enough for
// these workflows, not a shell.
export function commands(text) {
  const result = [];
  let words = [], word = null;
  const flush = () => { if (word) words.push(word); word = null; };
  const end = () => { flush(); if (words.length) result.push(words); words = []; };
  for (let index = 0; index < text.length;) {
    const char = text[index];
    if ((char === '\\' || char === '`') && text[index + 1] === '\n') { index += 2; continue; }
    if ('\n;{}()|&<>'.includes(char)) {
      end();
      // A redirection's target is not a command.
      if (char === '>' || char === '<') {
        index += 1;
        while ('>&12'.includes(text[index] ?? '')) index += 1;
        while (text[index] === ' ') index += 1;
        while (index < text.length && !/\s/.test(text[index])) index += 1;
        continue;
      }
      index += 1;
      continue;
    }
    if (/\s/.test(char)) { flush(); index += 1; continue; }
    if (char === '#' && !word) { while (index < text.length && text[index] !== '\n') index += 1; continue; }
    word ??= { text: '', dynamic: false };
    if (char === "'") {
      const close = text.indexOf("'", index + 1);
      if (close < 0) throw new Error(`Unterminated quote in ${text}`);
      word.text += text.slice(index + 1, close);
      index = close + 1;
    } else if (char === '"') {
      let at = index + 1;
      for (; at < text.length && text[at] !== '"'; at += 1) {
        if (text[at] === '$' || text[at] === '\u0001') word.dynamic = true;
        if ((text[at] === '\\' || text[at] === '`') && at + 1 < text.length) at += 1;
        word.text += text[at];
      }
      if (at >= text.length) throw new Error(`Unterminated quote in ${text}`);
      index = at + 1;
    } else {
      // $x, ${{ }} left unevaluated, and PowerShell's @(...) and @splat.
      if (char === '$' || char === '\u0001' || (char === '@' && word.text === '')) word.dynamic = true;
      word.text += char;
      index += 1;
    }
  }
  end();
  return result;
}

// ${{ }} expressions for one matrix entry; unknown ones stay dynamic.
function substitute(text, entry) {
  return text.replace(/\$\{\{([\s\S]*?)\}\}/g, (_, expression) => {
    try {
      const value = evaluate(expression, {
        matrix: entry, runner: { os: runnerOS(entry.runner) }, github: {}, inputs: {}, steps: {}, needs: {}, strategy: {}, env: {},
        functions: { always: () => true, success: () => true, failure: () => false, cancelled: () => false },
      });
      return value === null ? '' : String(value);
    } catch {
      return '\u0001';
    }
  });
}

const literalPath = (repo, word, wd) => {
  const candidates = [posix.normalize(posix.join(wd || '.', word.replace(/\\/g, '/')))];
  return candidates.map(path => path.replace(/^\.\//, '')).find(path => repo.has(path) || repo.dirs.has(path) || path.includes('*'));
};

// Files a job's own go build -o and go test -c -o write, as written: running
// one of them runs code the job compiled, which the go command already
// reached.
function buildOutputs(texts) {
  const outputs = new Set();
  for (const text of texts) for (const words of commands(text)) {
    const at = words.findIndex(word => word.text === 'go');
    if (at < 0 || !['build', 'test'].includes(words[at + 1]?.text) && words[at + 1]?.text !== '-C') continue;
    const flag = words.findIndex(word => word.text === '-o');
    if (flag > at) outputs.add(words[flag + 1]?.text);
    for (const word of words) if (word.text.startsWith('-o=')) outputs.add(word.text.slice(3));
  }
  outputs.delete(undefined);
  return outputs;
}

// What one command line starts: Go packages, scripts and test files. Throws
// when a command it knows names something it can't resolve, or when a POSIX
// shell runs a computed executable that the job didn't build.
function commandSeeds(repo, tree, words, wd, seeds, npmScripts, step = {}) {
  let at = 0;
  for (;;) {
    if (at < words.length && (/^(?:sudo|env|exit|\.)$/.test(words[at].text) || /^\w+=/.test(words[at].text))) at += 1;
    // systemd-run [options] -- command
    else if (words[at]?.text === 'systemd-run') { const end = words.findIndex((word, index) => index > at && word.text === '--'); if (end < 0) return; at = end + 1; }
    else break;
  }
  const command = words.slice(at);
  if (!command.length) return;
  const name = command[0].text;
  if (step.posix && command[0].dynamic && !step.outputs?.has(name)) throw new Error(`computed executable ${name}`);
  const fileArg = (word, what) => {
    if (word.dynamic) throw new Error(`${what} ${word.text} is computed`);
    const path = literalPath(repo, word.text, wd);
    if (!path) throw new Error(`${what} ${word.text} from ${wd || '.'} is not a tracked file, folder or pattern`);
    if (path.includes('*')) {
      const pattern = glob(path.replace(/\*/g, '\0'));
      const matched = repo.tracked.filter(file => pattern.test(file));
      if (!matched.length) throw new Error(`${what} ${word.text} matches nothing`);
      for (const file of matched) seeds.files.add(file);
    } else if (repo.has(path)) seeds.files.add(path);
    else {
      // node --test <folder> runs the JavaScript files under it.
      const scripts = repo.tracked.filter(file => file.startsWith(`${path}/`) && /\.[cm]?js$/.test(file));
      if (!scripts.length) throw new Error(`${what} ${word.text} has no scripts under it`);
      for (const file of scripts) seeds.files.add(file);
    }
  };
  if (name === 'go' || name === 'govulncheck') {
    const texts = command.map(word => word.text);
    const parsed = name === 'go' ? goCommand(texts) : { chdir: null, tests: texts.includes('-test'), packages: texts.slice(1).filter(word => !word.startsWith('-')) };
    if (!parsed) return;
    if (command.some(word => word.dynamic && !word.text.startsWith('-') && parsed.packages.includes(word.text))) throw new Error(`computed package argument in ${texts.join(' ')}`);
    const dir = parsed.chdir ? posix.normalize(posix.join(wd || '.', parsed.chdir)).replace(/^\.$/, '') : wd;
    const local = [];
    for (const pattern of parsed.packages) {
      const found = tree.expand(pattern, dir);
      if (found) local.push(pattern);
      for (const pkg of found ?? []) seeds.packages.push({ dir: pkg, tests: parsed.tests, command: texts.join(' ') });
    }
    // For the go list oracle: what this command compiles, with the settings
    // that choose files.
    if (name === 'go' && local.length) {
      const tags = texts.flatMap((word, index) => word === '-tags' ? [texts[index + 1]] : word.startsWith('-tags=') ? [word.slice(6)] : []);
      seeds.go.push({ dir, patterns: local, tests: parsed.tests, tags: tags.join(',').split(',').filter(Boolean), race: texts.includes('-race'), env: step.env ?? {}, command: texts.join(' ') });
    }
  } else if (name === 'node') {
    let test = false;
    for (let index = 1; index < command.length; index += 1) {
      const word = command[index].text;
      if (word === '--test') { test = true; continue; }
      if (['-e', '--eval', '-p', '--print'].includes(word)) return;
      if (['--import', '--require', '-r', '--input-type', '--test-reporter', '--test-name-pattern'].includes(word)) { index += 1; continue; }
      if (word.startsWith('-')) continue;
      fileArg(command[index], test ? 'node test argument' : 'node script');
      if (!test) return;
    }
  } else if (name === 'npm') {
    const script = command[1]?.text === 'test' ? 'test' : command[1]?.text === 'run' ? command[2]?.text : null;
    if (['ci', 'install', '--version'].includes(command[1]?.text)) return;
    if (!script || !npmScripts[script]) throw new Error(`unknown npm command: ${command.map(word => word.text).join(' ')}`);
    for (const inner of commands(npmScripts[script])) commandSeeds(repo, tree, inner, wd, seeds, npmScripts, step);
  } else if (['bash', 'sh'].includes(name)) {
    const script = command.slice(1).find(word => !word.text.startsWith('-'));
    if (script) fileArg(script, `${name} script`);
  } else if (['pwsh', 'powershell', 'powershell.exe'].includes(name)) {
    const file = command.findIndex(word => /^-File$/i.test(word.text));
    if (file > 0) fileArg(command[file + 1] ?? { text: '', dynamic: true }, `${name} script`);
  } else if (/\.(?:ps1|sh|mjs|js)$/.test(name)) fileArg(command[0], 'script');
}

// A job's seeds per operating system: files its steps name or start, and Go
// packages its go commands compile.
const stepEnv = step => Object.fromEntries((step.keys.env?.lines ?? []).map(line => /^\s+([\w-]+):\s*(.*?)\s*$/.exec(line)).filter(Boolean).map(match => [match[1], match[2].replace(/^'(.*)'$/, '$1')]));

function jobSeeds(repo, tree, job, label, workflow) {
  const npmScripts = JSON.parse(repo.read('package.json')).scripts;
  const bySystem = new Map();
  const problems = [];
  const outputs = buildOutputs(job.steps.map(step => step.run ?? ''));
  for (const entry of job.matrix) {
    const os = runnerOS(entry.runner);
    if (!bySystem.has(os)) bySystem.set(os, { files: new Set(), packages: [], go: [], runners: new Set() });
    const seeds = bySystem.get(os);
    seeds.runners.add(entry.runner);
    const go = seeds.go.length;
    const sources = [];
    for (const value of Object.values(job.env)) sources.push({ text: value, wd: job.workingDirectory ?? '' });
    job.steps.forEach((step, index) => {
      if (step.if && /runner\.os|matrix\./.test(step.if)) {
        const runs = truthy(evaluate(step.if, {
          runner: { os }, matrix: entry, inputs: {}, steps: {},
          functions: { always: () => true, success: () => true, failure: () => false, cancelled: () => false },
        }));
        if (!runs) return;
      }
      const wd = step.keys['working-directory']?.inline ?? job.workingDirectory ?? '';
      sources.push({ text: step.text, wd });
      // A local action's own run steps belong to the job too.
      const uses = /^\.\/(.+)$/.exec(step.keys.uses?.inline ?? '');
      if (uses) {
        const action = `${uses[1].replace(/\/$/, '')}/action.yml`;
        if (!repo.has(action)) { problems.push(`${label}: local action ${uses[1]} has no action.yml`); return; }
        seeds.files.add(action);
        const text = repo.read(action);
        sources.push({ text, wd: '' });
        for (const match of text.matchAll(/^( *)run: \|\n((?:\1 {2}.*\n|\s*\n)*)/gm)) {
          for (const words of commands(match[2])) {
            try { commandSeeds(repo, tree, words, '', seeds, npmScripts, { posix: false, outputs }); } catch (error) { problems.push(`${label} via ${action}: ${error.message}`); }
          }
        }
      }
      if (!step.run) return;
      const shell = step.keys.shell?.inline ?? job.shell ?? (os === 'Windows' ? 'pwsh' : 'bash');
      const powershell = /^(?:pwsh|powershell)\b/.test(shell);
      const run = substitute(step.run, entry);
      const context = { posix: !powershell, outputs, env: { ...job.env, ...stepEnv(step) } };
      for (const words of commands(run)) {
        try { commandSeeds(repo, tree, words, wd, seeds, npmScripts, context); } catch (error) { problems.push(`${label}: ${error.message}`); }
      }
      // A PowerShell step's reads and & or . invocations, like a script's.
      // Its $PSScriptRoot is the runner's temporary script folder.
      if (powershell) {
        const reader = new Reader(repo, `${workflow}#${job.id}/${index + 1}`, { text: run, lang: 'ps', here: null, cwd: wd });
        for (const site of sites(reader)) {
          const declaredEntry = declared.find(item => item.from === workflow && item.call === site.key);
          if (declaredEntry) {
            declaredEntry.found?.add(`${reader.file}:${site.offset}`);
            for (const path of declaredEntry.reads ?? []) for (const file of repo.tracked) if (file === path || file.startsWith(`${path}/`)) seeds.files.add(file);
            continue;
          }
          if (site.kind === 'run' && site.values.some(item => item.root === 'unknown' && !outputs.has(site.key.slice(2, -1)))) {
            problems.push(`${label}: step ${index + 1}: computed executable ${site.key}`);
            continue;
          }
          for (const where of placed(repo, reader, site, problems)) {
            for (const path of where.files ?? []) seeds.files.add(path);
            for (const path of where.dirs ?? []) for (const file of repo.tracked) if (file.startsWith(`${path}/`)) seeds.files.add(file);
          }
        }
      }
    });
    for (const command of seeds.go.slice(go)) Object.assign(command, { runner: entry.runner, label });
    // Paths written anywhere in a step (with:, env:, arguments) are read,
    // including those under the workspace.
    for (const { text, wd } of sources) {
      const plain = text.replace(/\bnpm test\b/g, npmScripts.test).replace(/\$\{\{\s*github\.workspace\s*\}\}\/|\$\{?GITHUB_WORKSPACE\}?\//g, '');
      for (const token of plain.split(/[\s'"`(),;=|&>]+/)) {
        if (!token || token.includes('${{')) continue;
        for (const base of new Set([posix.normalize(posix.join(wd || '.', token)), token.replace(/^\.\//, '')])) {
          if (base.includes('*')) { const pattern = glob(base.replace(/\*/g, '\0')); for (const file of repo.tracked) if (pattern.test(file)) seeds.files.add(file); }
          else if (repo.has(base)) seeds.files.add(base);
        }
      }
    }
  }
  return { bySystem, problems };
}

export function driftProblems({ areaOf = areaFor, groupsOf = groupsOfArea, overrides = {} } = {}) {
  const repo = repoView(overrides);
  const tree = new GoTree(repo, { skip: path => generated.test(path) });
  const reach = new Map(); // file -> Map("group os" -> what carried it there)
  const queue = [];
  const problems = declarationProblems(repo);
  const used = new Set();
  for (const entry of declared) entry.found = new Set();
  const go = [];
  const add = (file, keys, from) => {
    let here = reach.get(file);
    if (!here) reach.set(file, here = new Map());
    let grew = false;
    for (const key of keys) if (!here.has(key)) { here.set(key, from); grew = true; }
    if (grew && scannable(file)) queue.push(file);
  };
  const loadPackages = (dirs, tests, keys, from) => {
    const bySystem = new Map();
    for (const key of keys) {
      const os = key.split(' ')[1];
      if (!bySystem.has(os)) bySystem.set(os, []);
      bySystem.get(os).push(key);
    }
    for (const [os, osKeys] of bySystem) {
      if (!goosOf[os]) { problems.push(`${from}: no GOOS for runner OS ${os}`); continue; }
      try {
        for (const [file, via] of tree.load(dirs, goosOf[os], tests)) add(file, osKeys, `${from} (${via})`);
      } catch (error) { problems.push(`${from}: ${error.message}`); }
    }
  };
  const jobs = ['ci', 'control', 'linux-acceptance'].flatMap(name => [...readWorkflow(repo.read(`.github/workflows/${name}.yml`)).jobs.values()].map(job => ({
    job, label: `${name}.yml ${job.id}`, workflow: `.github/workflows/${name}.yml`,
    group: [...(job.if ?? '').matchAll(/needs\.changes\.outputs\.(\w+)/g)].map(match => match[1]),
  }))).filter(({ group }) => group.length === 1); // not the classifier, the oracle or manual investigations
  for (const { job, group, label, workflow } of jobs) {
    const { bySystem, problems: seedProblems } = jobSeeds(repo, tree, job, label, workflow);
    problems.push(...seedProblems);
    for (const [os, seeds] of bySystem) {
      const key = `${group[0]} ${os}`;
      for (const file of seeds.files) add(file, [key], label);
      for (const { dir, tests, command } of seeds.packages) loadPackages([dir], tests, [key], `${label}: ${command}`);
      go.push(...seeds.go.map(command => ({ ...command, group: group[0], os })));
    }
  }
  const scanned = new Map();
  while (queue.length) {
    const file = queue.shift();
    if (!scanned.has(file)) {
      const found = references(repo, tree, file);
      scanned.set(file, found);
      for (const message of found.unresolved) problems.push(message.startsWith(file) ? message : `${file}: ${message}`);
    }
    const { files, dirs, packages } = scanned.get(file);
    const carriedTo = target => {
      let keys = [...reach.get(file).keys()];
      const narrow = narrowed.find(entry => entry.from === file && entry.to.test(target));
      if (narrow) { used.add(narrow); keys = keys.filter(key => narrow.groups.includes(key.split(' ')[0])); }
      return keys;
    };
    for (const target of files) add(target, carriedTo(target), file);
    for (const dir of dirs) {
      const keys = carriedTo(`${dir}/`);
      for (const target of repo.tracked) if (target.startsWith(`${dir}/`) && !target.endsWith('.go')) add(target, keys, file);
      if (tree.hasGo(dir)) loadPackages([dir], true, keys, file);
    }
    for (const dir of packages) loadPackages([dir], true, carriedTo(`${dir}/`), file);
  }
  const seen = new Set();
  const tracked = new Set(repo.tracked);
  for (const [file, here] of reach) {
    const area = areaOf(file, tracked);
    if (area === null) continue;
    for (const [key, from] of here) {
      const group = key.split(' ')[0];
      if (groupsOf(area).includes(group) || seen.has(`${file} ${group}`)) continue;
      seen.add(`${file} ${group}`);
      problems.push(`${file} (area ${area}) is read by ${from}, which a ${group} job runs, but its area doesn't select ${group}`);
    }
  }
  for (const entry of narrowed) if (!used.has(entry)) problems.push(`stale narrowed reference from ${entry.from}`);
  for (const entry of declared) {
    const expected = entry.sites ?? 1;
    if (entry.found.size !== expected) problems.push(`${entry.found.size ? 'miscounted' : 'stale'} declared reader in ${entry.from}: ${entry.call} matches ${entry.found.size} call sites, declared ${expected}`);
  }
  return { problems: [...new Set(problems)], reach, go, groupsAt: file => [...new Set([...(reach.get(file)?.keys() ?? [])].map(key => key.split(' ')[0]))].sort() };
}
