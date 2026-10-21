import { posix } from 'node:path';
import { areaFor, areas } from './changes.mjs';
import { GoTree, goCommand, goosOf } from './golist.mjs';
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
// patterns, build constraints and imports (golist.mjs). A reader form the
// guard recognises but can't resolve is a problem too, unless it's declared
// below with what it reads and why.

const scannable = path => /\.(?:mjs|js|go|ps1|sh)$/.test(path) && !generated.test(path);

// References these readers make that only some of their jobs exercise. Each
// narrows the jobs carried along that reference and must still be in use.
export const narrowed = [{
  from: 'scripts/e2e-routing.mjs', to: /^internal\/platform\/worker\//, groups: ['control'],
  why: 'it runs go test ./internal/platform/worker only against the Go control server (!isNodeServer), which only the Control jobs start',
}];

// Reader forms the guard can't resolve, with what they read. Each must still
// match, and what it declares is followed like any other reference.
export const declared = [{
  from: 'scripts/smoke-test-installer.ps1', form: /import\(process\.argv\[1\]\)/, reads: ['lib/engine.mjs'],
  why: 'it imports the installed copy of lib/engine.mjs, passed on the node command line',
}, {
  from: 'test/windows-acceptance.test.mjs', form: /import\(\$\{JSON\.stringify\((?:moduleURL|sharedURL)\)\}\)/, reads: ['scripts/server-under-test.mjs', 'tests/windows/launch.mjs'],
  why: 'the child script imports URLs this test builds from those literal paths',
}];

const glob = pattern => new RegExp(`^${pattern.split('\0').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '[^/]*')).join('[^/]*')}$`);

function resolve(repo, candidate, directory) {
  let path = candidate.replace(/^\$PSScriptRoot[\\/]/, './').replace(/\\/g, '/')
    // Interpolations (${x}, $(x), $x) match one path segment's worth of text.
    .replace(/\$\{[^}]*\}|\$\([^)]*\)|\$\w+/g, '\0');
  // Paths only: not words, URLs, '/' separators or '..' on their own.
  if (!/[/.]/.test(path) || !/[a-z0-9]/i.test(path) || /[\s:]/.test(path)) return { files: [], dirs: [] };
  // "$dir/$name" says nothing about which file it is.
  if (path.includes('\0') && !path.split('/').some(segment => !segment.includes('\0') && /[a-z]/i.test(segment))) return { files: [], dirs: [] };
  // Imports resolve from the file; spawned commands from the repository root.
  const bases = path.startsWith('../') ? [posix.join(directory, path)] : [posix.join(directory, path), posix.normalize(path)];
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
  // Scripts name files in plain strings. Go strings are mostly data, so for Go
  // only literals passed straight to a file call count, plus joins and embeds.
  const direct = isGo ? /\b(?:ReadFile|ReadDir|Open|OpenFile|Stat|Lstat)\(\s*("[^"\n]*")/g : literal;
  for (const match of text.matchAll(direct)) {
    if (isGo) candidates.push(match[1].slice(1, -1));
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
    const found = resolve(repo, candidate, directory);
    for (const path of found.files) if (path !== file) files.add(path);
    for (const path of found.dirs) dirs.add(path);
  }
  if (isGo) {
    const embedded = tree.embeds(file);
    for (const path of embedded.files) files.add(path);
    unresolved.push(...embedded.errors);
  } else {
    // A module loaded by a computed name can't be followed.
    for (const match of text.matchAll(/\b(?:import|require)\(\s*([^)\n]*)/g)) {
      if (/^(?:'[^'\n]*'|"[^"\n]*"|`[^`$\n]*`)\s*$/.test(match[1].replace(/\)$/, ''))) continue;
      const line = text.slice(text.lastIndexOf('\n', match.index) + 1, text.indexOf('\n', match.index) >>> 0);
      const entry = declared.find(item => item.from === file && item.form.test(line));
      if (entry) { entry.used = true; for (const path of entry.reads) files.add(path); }
      else unresolved.push(`${file}: computed import ${match[0].trim()})`);
    }
  }
  return { files: [...files], dirs: [...dirs], packages: [...packages], unresolved };
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

// What one command line starts: Go packages, scripts and test files. Throws
// when a command it knows names something it can't resolve.
function commandSeeds(repo, tree, words, wd, seeds, npmScripts) {
  let at = 0;
  while (at < words.length && (/^(?:sudo|env|exit|\.)$/.test(words[at].text) || /^\w+=/.test(words[at].text))) at += 1;
  const command = words.slice(at);
  if (!command.length) return;
  const name = command[0].text;
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
    for (const pattern of parsed.packages) {
      for (const pkg of tree.expand(pattern, dir) ?? []) seeds.packages.push({ dir: pkg, tests: parsed.tests, command: texts.join(' ') });
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
    for (const inner of commands(npmScripts[script])) commandSeeds(repo, tree, inner, wd, seeds, npmScripts);
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
function jobSeeds(repo, tree, job, label) {
  const npmScripts = JSON.parse(repo.read('package.json')).scripts;
  const bySystem = new Map();
  const problems = [];
  for (const entry of job.matrix) {
    const os = runnerOS(entry.runner);
    if (!bySystem.has(os)) bySystem.set(os, { files: new Set(), packages: [] });
    const seeds = bySystem.get(os);
    const sources = [];
    for (const value of Object.values(job.env)) sources.push({ text: value, wd: job.workingDirectory ?? '' });
    for (const step of job.steps) {
      if (step.if && /runner\.os|matrix\./.test(step.if)) {
        const runs = truthy(evaluate(step.if, {
          runner: { os }, matrix: entry, inputs: {}, steps: {},
          functions: { always: () => true, success: () => true, failure: () => false, cancelled: () => false },
        }));
        if (!runs) continue;
      }
      const wd = step.keys['working-directory']?.inline ?? job.workingDirectory ?? '';
      sources.push({ text: step.text, wd });
      if (step.run) {
        for (const words of commands(substitute(step.run, entry))) {
          try { commandSeeds(repo, tree, words, wd, seeds, npmScripts); } catch (error) { problems.push(`${label}: ${error.message}`); }
        }
      }
      // A local action's own run steps belong to the job too.
      const uses = /^\.\/(.+)$/.exec(step.keys.uses?.inline ?? '');
      if (uses) {
        const action = `${uses[1].replace(/\/$/, '')}/action.yml`;
        if (!repo.has(action)) { problems.push(`${label}: local action ${uses[1]} has no action.yml`); continue; }
        seeds.files.add(action);
        const text = repo.read(action);
        sources.push({ text, wd: '' });
        for (const match of text.matchAll(/^( *)run: \|\n((?:\1 {2}.*\n|\s*\n)*)/gm)) {
          for (const words of commands(match[2])) {
            try { commandSeeds(repo, tree, words, '', seeds, npmScripts); } catch (error) { problems.push(`${label} via ${action}: ${error.message}`); }
          }
        }
      }
    }
    // Paths written anywhere in a step (with:, env:, arguments) are read.
    for (const { text, wd } of sources) {
      for (const token of text.replace(/\bnpm test\b/g, npmScripts.test).split(/[\s'"`(),;=|&>]+/)) {
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

export function driftProblems({ areaOf = areaFor, groupsOf = areas, overrides = {} } = {}) {
  const repo = repoView(overrides);
  const tree = new GoTree(repo, { skip: path => generated.test(path) });
  const reach = new Map(); // file -> Map("group os" -> what carried it there)
  const queue = [];
  const problems = [];
  const used = new Set();
  for (const entry of declared) entry.used = false;
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
    job, label: `${name}.yml ${job.id}`,
    group: [...(job.if ?? '').matchAll(/needs\.changes\.outputs\.(\w+)/g)].map(match => match[1]),
  }))).filter(({ group }) => group.length === 1); // not the classifier or manual investigations
  for (const { job, group, label } of jobs) {
    const { bySystem, problems: seedProblems } = jobSeeds(repo, tree, job, label);
    problems.push(...seedProblems);
    for (const [os, seeds] of bySystem) {
      const key = `${group[0]} ${os}`;
      for (const file of seeds.files) add(file, [key], label);
      for (const { dir, tests, command } of seeds.packages) loadPackages([dir], tests, [key], `${label}: ${command}`);
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
  for (const [file, here] of reach) {
    const area = areaOf(file);
    if (area === null) continue;
    for (const [key, from] of here) {
      const group = key.split(' ')[0];
      if (groupsOf[area].includes(group) || seen.has(`${file} ${group}`)) continue;
      seen.add(`${file} ${group}`);
      problems.push(`${file} (area ${area}) is read by ${from}, which a ${group} job runs, but its area doesn't select ${group}`);
    }
  }
  for (const entry of narrowed) if (!used.has(entry)) problems.push(`stale narrowed reference from ${entry.from}`);
  for (const entry of declared) if (!entry.used) problems.push(`stale declared reader in ${entry.from}`);
  return { problems: [...new Set(problems)], reach, groupsAt: file => [...new Set([...(reach.get(file)?.keys() ?? [])].map(key => key.split(' ')[0]))].sort() };
}
