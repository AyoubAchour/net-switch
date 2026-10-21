import { posix } from 'node:path';

// Which Go files a go command compiles, worked out from the repository alone:
// package patterns, GOOS file-name and //go:build constraints, imports within
// the importing file's module, and //go:embed patterns. It follows the go
// command's own rules (cmd/go/internal/search for "./...", go/build for file
// constraints, cmd/go/internal/load for embeds) for the forms this repository
// uses, and throws on anything it can't place, so a new form fails the drift
// check instead of silently reaching nothing.
//
// GOOS is exact. Architecture and custom build tags are left open: a file is
// compiled if some setting of them would compile it on amd64 or arm64, the
// only architectures CI runs. That over-counts, which can only add checks.
// golist-check.mjs also asks for exact settings ({ goarch, tags }), to
// compare these rules with go list for each setting the workflows use.

const knownOS = new Set(['aix', 'android', 'darwin', 'dragonfly', 'freebsd', 'hurd', 'illumos', 'ios', 'js', 'linux', 'nacl', 'netbsd', 'openbsd', 'plan9', 'solaris', 'wasip1', 'windows', 'zos']);
const unixOS = new Set(['aix', 'android', 'darwin', 'dragonfly', 'freebsd', 'hurd', 'illumos', 'ios', 'linux', 'netbsd', 'openbsd', 'solaris']);
const knownArch = new Set(['386', 'amd64', 'amd64p32', 'arm', 'armbe', 'arm64', 'arm64be', 'loong64', 'mips', 'mipsle', 'mips64', 'mips64le', 'mips64p32', 'mips64p32le', 'ppc', 'ppc64', 'ppc64le', 'riscv', 'riscv64', 's390', 's390x', 'sparc', 'sparc64', 'wasm']);
const runnerArch = new Set(['amd64', 'arm64']);
export const goosOf = { Windows: 'windows', Linux: 'linux' };

// The value a tag has for this GOOS: true, false, or null when it's open.
// With exact settings nothing is open: the architecture is the one given,
// gc is the compiler, and every other tag is set only if listed (race comes
// from -race, cgo from CGO_ENABLED).
function tagValue(tag, goos, exact) {
  if (tag === 'unix') return unixOS.has(goos);
  if (knownOS.has(tag)) return tag === goos || (goos === 'android' && tag === 'linux');
  if (knownArch.has(tag)) return exact ? tag === exact.goarch : runnerArch.has(tag) ? null : false;
  if (!exact) return null;
  if (/^go1\.\d+$/.test(tag)) throw new Error(`release tag ${tag} isn't modelled`);
  if (tag === 'gc') return true;
  if (tag === 'gccgo') return false;
  return exact.tags.has(tag);
}

function parseExpression(source) {
  const tokens = source.match(/!|&&|\|\||\(|\)|[\w.]+|\S/g) ?? [];
  let at = 0;
  const fail = () => { throw new Error(`Unsupported //go:build expression: ${source}`); };
  const or = () => { let node = and(); while (tokens[at] === '||') { at += 1; node = { op: '||', left: node, right: and() }; } return node; };
  const and = () => { let node = not(); while (tokens[at] === '&&') { at += 1; node = { op: '&&', left: node, right: not() }; } return node; };
  const not = () => {
    if (tokens[at] === '!') { at += 1; return { op: '!', operand: not() }; }
    if (tokens[at] === '(') { at += 1; const node = or(); if (tokens[at++] !== ')') fail(); return node; }
    const tag = tokens[at++];
    if (!tag || !/^[\w.]+$/.test(tag)) fail();
    return { tag };
  };
  const node = or();
  if (at !== tokens.length) fail();
  return node;
}

export function constraintHolds(source, goos, exact) {
  const node = parseExpression(source);
  const open = new Set();
  const collect = item => item.tag ? (tagValue(item.tag, goos, exact) === null && open.add(item.tag)) : [item.left, item.right, item.operand].filter(Boolean).forEach(collect);
  collect(node);
  const free = [...open];
  if (free.length > 12) throw new Error(`Too many open tags in //go:build ${source}`);
  const evaluate = (item, assignment) => item.tag ? (tagValue(item.tag, goos, exact) ?? assignment.get(item.tag))
    : item.op === '!' ? !evaluate(item.operand, assignment)
    : item.op === '&&' ? evaluate(item.left, assignment) && evaluate(item.right, assignment)
    : evaluate(item.left, assignment) || evaluate(item.right, assignment);
  for (let bits = 0; bits < 2 ** free.length; bits += 1) {
    if (evaluate(node, new Map(free.map((tag, index) => [tag, Boolean(bits & (1 << index))])))) return true;
  }
  return false;
}

// go/build's goodOSArchFile: name_GOOS, name_GOARCH and name_GOOS_GOARCH,
// each optionally followed by _test, and only after the first underscore.
export function nameHolds(name, goos, exact) {
  const stem = name.split('.')[0];
  const underscore = stem.indexOf('_');
  if (underscore < 0) return true;
  const parts = stem.slice(underscore).split('_');
  if (parts.at(-1) === 'test') parts.pop();
  const last = parts.at(-1), before = parts.at(-2);
  const value = tag => tagValue(tag, goos, exact) !== false;
  if (parts.length >= 2 && knownOS.has(before) && knownArch.has(last)) return value(before) && value(last);
  if (parts.length >= 1 && (knownOS.has(last) || knownArch.has(last))) return value(last);
  return true;
}

// The //go:build line in the header before the package clause, if any.
export function buildLine(text) {
  let line = null, legacy = false, inBlock = false;
  for (const raw of text.split('\n')) {
    const trimmed = raw.trim();
    if (inBlock) { if (trimmed.includes('*/')) inBlock = false; continue; }
    if (trimmed === '') continue;
    if (trimmed.startsWith('/*')) { inBlock = !trimmed.includes('*/'); continue; }
    if (!trimmed.startsWith('//')) break;
    const build = /^\/\/go:build\s+(.+)$/.exec(trimmed);
    if (build) {
      if (line !== null) throw new Error('Two //go:build lines');
      line = build[1].trim();
    }
    if (/^\/\/\s*\+build\b/.test(trimmed)) legacy = true;
  }
  if (legacy && line === null) throw new Error('// +build without //go:build');
  return line;
}

export function imports(text) {
  const found = [];
  for (const match of text.matchAll(/^import\s+(?:[\w.]+\s+)?"([^"]+)"/gm)) found.push(match[1]);
  for (const match of text.matchAll(/^import\s*\(([\s\S]*?)^\)/gm)) {
    for (const line of match[1].split('\n')) {
      const spec = line.replace(/\/\/.*$/, '').trim();
      if (!spec) continue;
      const item = /^(?:[\w.]+\s+)?"([^"]+)"$/.exec(spec);
      if (!item) throw new Error(`Unsupported import line: ${line.trim()}`);
      found.push(item[1]);
    }
  }
  return found;
}

// path.Match syntax, per element: * and ? never cross '/'.
export function matchRegExp(pattern) {
  let source = '', index = 0;
  while (index < pattern.length) {
    const char = pattern[index++];
    if (char === '*') source += '[^/]*';
    else if (char === '?') source += '[^/]';
    else if (char === '\\') {
      if (index >= pattern.length) throw new Error('trailing backslash');
      source += escape(pattern[index++]);
    } else if (char === '[') {
      let body = '';
      if (pattern[index] === '^') { body += '^'; index += 1; }
      let closed = false, first = true;
      while (index < pattern.length) {
        let item = pattern[index++];
        if (item === ']' && !first) { closed = true; break; }
        first = false;
        if (item === '\\') { if (index >= pattern.length) break; item = pattern[index++]; }
        if (item === '/') throw new Error('separator in class');
        body += escape(item);
        if (pattern[index] === '-' && pattern[index + 1] !== ']' && index + 1 < pattern.length) {
          index += 1;
          let end = pattern[index++];
          if (end === '\\') end = pattern[index++];
          if (end === undefined) break;
          body += `-${escape(end)}`;
        }
      }
      if (!closed || body === '' || body === '^') throw new Error('bad character class');
      source += `(?![/])[${body}]`;
    } else source += escape(char);
  }
  return new RegExp(`^${source}$`);
}
const escape = char => char.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');

// Go string syntax on a directive line: plain words, "quoted" and `raw`.
export function directiveArgs(rest) {
  const args = [];
  for (const match of rest.matchAll(/"((?:[^"\\]|\\.)*)"|`([^`]*)`|(\S+)/g)) {
    if (match[1] !== undefined) args.push(JSON.parse(`"${match[1]}"`));
    else if (match[2] !== undefined) args.push(match[2]);
    else if (/^["`]/.test(match[3])) throw new Error(`unterminated quote in ${rest.trim()}`);
    else args.push(match[3]);
  }
  return args;
}

const badEmbedName = name => !name || /["*<>?`'|/\\:]/.test(name) || ['.bzr', '.hg', '.git', '.svn'].includes(name);
const validPath = pattern => pattern !== '.' && pattern !== '' && !pattern.startsWith('/') && !pattern.endsWith('/')
  && pattern.split('/').every(element => element !== '' && element !== '.' && element !== '..');

export class GoTree {
  constructor(repo, { skip = () => false } = {}) {
    this.repo = repo;
    this.skip = skip;
    this.byDir = new Map();
    this.dirs = new Set(['']);
    for (const file of repo.tracked) {
      const dir = posix.dirname(file) === '.' ? '' : posix.dirname(file);
      if (!this.byDir.has(dir)) this.byDir.set(dir, []);
      this.byDir.get(dir).push(posix.basename(file));
      const parts = file.split('/');
      for (let index = 1; index < parts.length; index += 1) this.dirs.add(parts.slice(0, index).join('/'));
    }
    // Local modules, longest root first. Generated trees aren't followed.
    this.modules = repo.tracked.filter(file => posix.basename(file) === 'go.mod' && !skip(file)).map(file => {
      const root = posix.dirname(file) === '.' ? '' : posix.dirname(file);
      const text = repo.read(file);
      const path = /^module\s+(\S+)/m.exec(text)?.[1];
      if (!path) throw new Error(`${file}: no module line`);
      if (/^ignore\b/m.test(text)) throw new Error(`${file}: ignore directives aren't modelled`);
      return { root, path };
    }).sort((a, b) => b.root.length - a.root.length);
    this.cache = new Map();
  }

  join(dir, name) { return dir ? `${dir}/${name}` : name; }
  hasGoMod(dir) { return (this.byDir.get(dir) ?? []).includes('go.mod'); }
  moduleOf(dir) { return this.modules.find(module => module.root === '' || dir === module.root || dir.startsWith(`${module.root}/`)); }

  // Files of the package in dir that compile for goos (and exact settings).
  packageFiles(dir, goos, tests, exact) {
    const key = `${dir}\0${goos}\0${tests}\0${exact ? `${exact.goarch} ${[...exact.tags].sort()}` : ''}`;
    if (this.cache.has(key)) return this.cache.get(key);
    const files = [];
    for (const name of this.byDir.get(dir) ?? []) {
      if (!name.endsWith('.go') || /^[._]/.test(name)) continue;
      if (!tests && name.endsWith('_test.go')) continue;
      const file = this.join(dir, name);
      if (!nameHolds(name, goos, exact)) continue;
      const line = buildLine(this.repo.read(file));
      if (line !== null && !constraintHolds(line, goos, exact)) continue;
      files.push(file);
    }
    this.cache.set(key, files);
    return files;
  }

  hasGo(dir) { return (this.byDir.get(dir) ?? []).some(name => name.endsWith('.go')); }

  // Package directories a pattern names, from the working directory wd.
  // Returns null for a package outside the local modules (standard library
  // or a dependency, which lives in vendor or third_party).
  expand(pattern, wd) {
    if (/^\.\.?(?:\/|$)/.test(pattern)) {
      const wildcard = pattern.endsWith('/...');
      if (pattern.includes('...') && !wildcard) throw new Error(`unsupported package pattern ${pattern}`);
      const base = posix.normalize(posix.join(wd || '.', wildcard ? pattern.slice(0, -3) : pattern)).replace(/\/$/, '');
      const dir = base === '.' ? '' : base;
      if (dir.startsWith('..')) throw new Error(`package pattern ${pattern} leaves the repository`);
      if (!wildcard) {
        if (!this.hasGo(dir)) throw new Error(`package pattern ${pattern} from ${wd || '.'}: no Go files in ${dir || '.'}`);
        return [dir];
      }
      const found = [...this.dirs].filter(candidate => {
        if (dir && candidate !== dir && !candidate.startsWith(`${dir}/`)) return false;
        const below = dir ? candidate.slice(dir.length).replace(/^\//, '') : candidate;
        const elements = below ? below.split('/') : [];
        for (let index = 0; index < elements.length; index += 1) {
          const element = elements[index];
          if (/^[._]/.test(element) || element === 'testdata' || element === 'vendor') return false;
          if (this.hasGoMod(elements.slice(0, index + 1).reduce((path, part) => this.join(path, part), dir))) return false;
        }
        return this.hasGo(candidate);
      });
      if (!found.length) throw new Error(`package pattern ${pattern} from ${wd || '.'} matches no packages`);
      return found;
    }
    const module = this.modules.find(item => pattern === item.path || pattern.startsWith(`${item.path}/`));
    // Another local module's packages come through go.mod, not this tree.
    if (module && module !== this.moduleOf(wd)) return null;
    if (module) return this.expand(`./${pattern.slice(module.path.length).replace(/^\//, '')}`, module.root);
    const first = pattern.split('/')[0];
    // A dependency (gvisor.dev/..., golang.org/x/...@v1) lives in vendor or
    // third_party, which the classifier treats as shared input.
    if (/^[\w-]+(?:\.[\w-]+)+$/.test(first) && /^[\w.@/~-]+$/.test(pattern)) return null;
    // Standard library paths, unless they look like a repository folder
    // written without "./", which the go command would reject.
    if (/^[a-z0-9]+(?:\/[a-z0-9_]+)*$/.test(pattern) && !this.dirs.has(first)) return null;
    throw new Error(`unsupported package argument ${JSON.stringify(pattern)}`);
  }

  // Files these packages and their local imports compile, as a map from file
  // to the package path that pulled it in.
  load(dirs, goos, tests, exact) {
    const files = new Map();
    const seen = new Set();
    const queue = dirs.map(dir => ({ dir, tests, via: dir || '.' }));
    while (queue.length) {
      const { dir, tests: withTests, via } = queue.shift();
      const key = `${dir}\0${withTests}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const module = this.moduleOf(dir);
      for (const file of this.packageFiles(dir, goos, withTests, exact)) {
        if (!files.has(file)) files.set(file, via);
        for (const path of imports(this.repo.read(file))) {
          if (module && (path === module.path || path.startsWith(`${module.path}/`))) {
            const target = this.join(module.root, path.slice(module.path.length).replace(/^\//, '')).replace(/\/$/, '');
            if (this.skip(`${target}/`)) continue;
            if (!this.hasGo(target)) throw new Error(`${file} imports ${path}, which has no Go files`);
            queue.push({ dir: target, tests: false, via: `${via} imports ${path}` });
          }
        }
      }
    }
    return files;
  }

  // Files the //go:embed lines in a Go file embed, by resolveEmbed's rules.
  embeds(file) {
    const dir = posix.dirname(file) === '.' ? '' : posix.dirname(file);
    const results = { files: [], errors: [] };
    for (const match of this.repo.read(file).matchAll(/^\/\/go:embed(?:\s+(.*))?$/gm)) {
      let patterns;
      try { patterns = directiveArgs(match[1] ?? ''); } catch (error) { results.errors.push(`${file}: //go:embed: ${error.message}`); continue; }
      if (!patterns.length) results.errors.push(`${file}: //go:embed with no patterns`);
      for (const pattern of patterns) {
        try { results.files.push(...this.embedPattern(dir, pattern)); } catch (error) { results.errors.push(`${file}: //go:embed ${pattern}: ${error.message}`); }
      }
    }
    return results;
  }

  embedPattern(dir, pattern) {
    const all = pattern.startsWith('all:');
    const glob = all ? pattern.slice(4) : pattern;
    let regexp;
    try { regexp = matchRegExp(glob); } catch { throw new Error('invalid pattern syntax'); }
    if (!validPath(glob)) throw new Error('invalid pattern syntax');
    const prefix = dir ? `${dir}/` : '';
    const candidates = [...this.repo.tracked, ...this.dirs].filter(path => path.startsWith(prefix) && path !== dir);
    const found = new Set();
    for (const path of candidates) {
      const relative = path.slice(prefix.length);
      if (!regexp.test(relative)) continue;
      const isDir = this.dirs.has(path);
      const elements = relative.split('/');
      for (let index = elements.length; index >= 1; index -= 1) {
        const at = prefix + elements.slice(0, index).join('/');
        if (this.hasGoMod(at)) throw new Error(`cannot embed ${relative}: in different module`);
        if (badEmbedName(elements[index - 1])) throw new Error(`cannot embed ${relative}: invalid name ${elements[index - 1]}`);
      }
      if (!isDir) { found.add(path); continue; }
      let count = 0;
      for (const file of this.repo.tracked) {
        if (!file.startsWith(`${path}/`)) continue;
        const below = file.slice(path.length + 1).split('/');
        let skipped = false;
        for (let index = 0; index < below.length && !skipped; index += 1) {
          const name = below[index];
          if (badEmbedName(name) || (/^[._]/.test(name) && !all)) {
            if (index === below.length - 1 && badEmbedName(name) && !/^[._]/.test(name)) throw new Error(`cannot embed file ${file.slice(prefix.length)}: invalid name ${name}`);
            skipped = true;
          } else if (index < below.length - 1 && this.hasGoMod(`${path}/${below.slice(0, index + 1).join('/')}`)) skipped = true;
        }
        if (skipped) continue;
        count += 1;
        found.add(file);
      }
      if (!count) throw new Error(`cannot embed directory ${relative}: contains no embeddable files`);
    }
    if (!found.size) throw new Error('no matching files found');
    return [...found];
  }
}

// One go command, already split into words. Returns its working directory
// change, whether it compiles test files, and its package arguments; or null
// for subcommands that compile nothing (mod, tool, env, version).
const valueFlags = new Set(['o', 'tags', 'ldflags', 'gcflags', 'asmflags', 'mod', 'modfile', 'p', 'buildmode', 'buildvcs', 'pgo', 'overlay', 'pkgdir', 'toolexec', 'installsuffix', 'compiler', 'gccgoflags', 'covermode', 'coverpkg', 'exec', 'vet', 'run', 'bench', 'benchtime', 'fuzz', 'fuzztime', 'fuzzminimizetime', 'parallel', 'count', 'timeout', 'cpu', 'skip', 'list', 'shuffle', 'memprofilerate', 'cpuprofile', 'memprofile', 'blockprofile', 'mutexprofile', 'coverprofile', 'outputdir', 'trace']);
const boolFlags = new Set(['race', 'msan', 'asan', 'trimpath', 'a', 'n', 'x', 'work', 'cover', 'c', 'i', 'linkshared', 'modcacherw', 'v', 'json', 'failfast', 'short', 'benchmem', 'fullpath']);
export function goCommand(words) {
  let index = 1, chdir = null;
  if (words[index] === '-C') { chdir = words[index + 1]; index += 2; }
  else if (/^-C=/.test(words[index] ?? '')) chdir = words[index++].slice(3);
  const sub = words[index++];
  // A bare "go" is a word (a PowerShell switch case), or prints help.
  if (sub === undefined && !chdir) return null;
  if (['mod', 'tool', 'env', 'version', 'clean', 'work', 'help', 'doc', 'fmt', 'telemetry'].includes(sub)) return null;
  if (!['build', 'test', 'vet', 'install', 'list'].includes(sub)) throw new Error(`unsupported go subcommand: go ${words.slice(1).join(' ')}`);
  const packages = [];
  for (; index < words.length; index += 1) {
    const word = words[index];
    if (word === '-args') break;
    if (word.startsWith('-')) {
      const name = word.replace(/^--?/, '').replace(/=.*$/, '');
      if (word.includes('=') || boolFlags.has(name)) continue;
      if (valueFlags.has(name)) { index += 1; continue; }
      throw new Error(`unknown go ${sub} flag ${word}`);
    }
    packages.push(word);
  }
  return { chdir, sub, tests: sub === 'test' || sub === 'vet', packages: packages.length ? packages : ['.'] };
}
