import { posix } from 'node:path';

// Where a file's computed paths point, for drift.mjs. A reader that builds a
// path at run time can reach a file no literal names, so the guard evaluates
// the path expressions themselves: joins, URLs, Join-Path, interpolated
// strings and the variables they come from, in JavaScript, Go and PowerShell.
//
// A path is a root plus segments, with HOLE for a part the guard can't know.
// Roots: the reader's own folder ('here'; a Go test's working directory is
// its package folder), the working directory ('cwd', the repository root for
// workflow steps and the scripts they start), the repository root ('repo',
// GITHUB_WORKSPACE), somewhere outside the repository ('outside': temporary,
// profile, system and runner folders), or an unknown origin (a parameter, a
// property, a call's result). Names resolve through the file's assignments,
// loop variables over literal lists and imported constants, by scope.
//
// Accepted without a declaration:
//  1. a literal path, which is followed like any other reference;
//  2. a fixed prefix below the repository root with computed parts after it:
//     everything under the prefix that fits is followed. A computed part is
//     taken to hold names, never '..', so a climb after one may come back to
//     the prefix but not above it. join(here, name) is the in-tree case;
//  3. a path outside the repository;
//  4. a value of unknown origin, as is, extended downward or its parent
//     folder. If it holds a repository path, that path was built by 1 or 2 in
//     a followed file and checked there.
// Rejected unless declared: a computed part directly on the repository root,
// a climb above the fixed prefix, '..' joined onto an unknown origin, a path
// read straight from an environment variable or process.argv, and listing
// the whole repository. drift.mjs adds computed imports and executables.

export const HOLE = '\0';
const ANY = '\u0002';

// ---- Comments and strings. code blanks comments; mask also fills string
// contents with STRING, which is neither a space nor a word character. Both
// keep every offset, so positions found in mask slice code.

const STRING = '\u0001';
const isString = mask => !/[^\u0001]/.test(mask);

function blankInto(arrays, text, from, to, fill = ' ') {
  for (const array of arrays) for (let index = from; index < to; index += 1) if (fill !== ' ' || text[index] !== '\n') array[index] = fill;
}

function lexJS(text) {
  const code = [...text], mask = [...text];
  const n = text.length;
  let index = 0, previous = '', word = '';
  const regexAfter = new Set(['return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'yield', 'await', 'void', 'delete', 'throw', 'new', '']);
  const template = start => {
    // From after the opening backtick to after the closing one, skipping
    // ${...} with nested strings and templates.
    let at = start;
    while (at < n && text[at] !== '`') {
      if (text[at] === '\\') { at += 2; continue; }
      if (text[at] === '$' && text[at + 1] === '{') {
        let depth = 1; at += 2;
        while (at < n && depth) {
          const char = text[at];
          if (char === '`') { at = template(at + 1); continue; }
          if (char === "'" || char === '"') { at += 1; while (at < n && text[at] !== char) at += text[at] === '\\' ? 2 : 1; at += 1; continue; }
          if (char === '{') depth += 1; else if (char === '}') depth -= 1;
          at += 1;
        }
        continue;
      }
      at += 1;
    }
    return at + 1;
  };
  while (index < n) {
    const char = text[index], next = text[index + 1];
    if (char === '/' && next === '/') { const end = text.indexOf('\n', index); const stop = end < 0 ? n : end; blankInto([code, mask], text, index, stop); index = stop; continue; }
    if (char === '/' && next === '*') { const end = text.indexOf('*/', index + 2); const stop = end < 0 ? n : end + 2; blankInto([code, mask], text, index, stop); index = stop; continue; }
    if (char === "'" || char === '"') {
      let at = index + 1;
      while (at < n && text[at] !== char && text[at] !== '\n') at += text[at] === '\\' ? 2 : 1;
      blankInto([mask], text, index + 1, at, STRING); index = at + 1; previous = 'string'; word = ''; continue;
    }
    if (char === '`') { const end = template(index + 1); blankInto([mask], text, index + 1, end - 1, STRING); index = end; previous = 'string'; word = ''; continue; }
    if (char === '/' && (('(,=:[!&|?{};+-*%<>~^'.includes(previous)) || (previous === 'word' && regexAfter.has(word)) || previous === '')) {
      let at = index + 1, inClass = false;
      while (at < n && text[at] !== '\n') {
        if (text[at] === '\\') { at += 2; continue; }
        if (text[at] === '[') inClass = true; else if (text[at] === ']') inClass = false; else if (text[at] === '/' && !inClass) break;
        at += 1;
      }
      blankInto([mask], text, index + 1, at, STRING); index = at + 1;
      while (/[a-z]/i.test(text[index] ?? '')) index += 1;
      previous = 'regex'; word = ''; continue;
    }
    if (/[\w$]/.test(char)) {
      let at = index; while (at < n && /[\w$]/.test(text[at])) at += 1;
      word = text.slice(index, at); previous = 'word'; index = at; continue;
    }
    if (!/\s/.test(char)) { previous = char; word = ''; }
    index += 1;
  }
  return { code: code.join(''), mask: mask.join('') };
}

function lexGo(text) {
  const code = [...text], mask = [...text];
  const n = text.length;
  let index = 0;
  while (index < n) {
    const char = text[index], next = text[index + 1];
    if (char === '/' && next === '/') { const end = text.indexOf('\n', index); const stop = end < 0 ? n : end; blankInto([code, mask], text, index, stop); index = stop; continue; }
    if (char === '/' && next === '*') { const end = text.indexOf('*/', index + 2); const stop = end < 0 ? n : end + 2; blankInto([code, mask], text, index, stop); index = stop; continue; }
    if (char === '"' || char === "'") {
      let at = index + 1;
      while (at < n && text[at] !== char && text[at] !== '\n') at += text[at] === '\\' ? 2 : 1;
      blankInto([mask], text, index + 1, at, STRING); index = at + 1; continue;
    }
    if (char === '`') { const end = text.indexOf('`', index + 1); const stop = end < 0 ? n : end; blankInto([mask], text, index + 1, stop, STRING); index = stop + 1; continue; }
    index += 1;
  }
  return { code: code.join(''), mask: mask.join('') };
}

function lexPS(text) {
  const code = [...text], mask = [...text];
  const n = text.length;
  let index = 0;
  while (index < n) {
    const char = text[index], next = text[index + 1];
    if (char === '<' && next === '#') { const end = text.indexOf('#>', index + 2); const stop = end < 0 ? n : end + 2; blankInto([code, mask], text, index, stop); index = stop; continue; }
    if (char === '#' && (index === 0 || /[\s;|({}]/.test(text[index - 1]))) { const end = text.indexOf('\n', index); const stop = end < 0 ? n : end; blankInto([code, mask], text, index, stop); index = stop; continue; }
    if (char === '@' && (next === "'" || next === '"') && text[index + 2] === '\n' || (char === '@' && (next === "'" || next === '"') && text[index + 2] === '\r')) {
      const close = new RegExp(`\\n${next}@`, 'g');
      close.lastIndex = index + 2;
      const found = close.exec(text);
      const stop = found ? found.index + 1 : n;
      blankInto([mask], text, index + 2, stop, STRING); index = stop + 2; continue;
    }
    if (char === "'") {
      let at = index + 1;
      while (at < n) { if (text[at] === "'") { if (text[at + 1] === "'") { at += 2; continue; } break; } at += 1; }
      blankInto([mask], text, index + 1, at, STRING); index = at + 1; continue;
    }
    if (char === '"') {
      let at = index + 1;
      while (at < n) {
        if (text[at] === '`') { at += 2; continue; }
        if (text[at] === '"') { if (text[at + 1] === '"') { at += 2; continue; } break; }
        at += 1;
      }
      blankInto([mask], text, index + 1, at, STRING); index = at + 1; continue;
    }
    index += 1;
  }
  return { code: code.join(''), mask: mask.join('') };
}

export const languageOf = file => /\.(?:mjs|js|cjs)$/.test(file) ? 'js' : file.endsWith('.go') ? 'go' : /\.ps1$/.test(file) ? 'ps' : null;
export const lex = (text, lang) => (lang === 'js' ? lexJS : lang === 'go' ? lexGo : lexPS)(text);

// ---- Brackets and splitting, on mask so strings don't count.

const opens = { '(': ')', '[': ']', '{': '}' };
export function closing(mask, open) {
  const stack = [];
  for (let index = open; index < mask.length; index += 1) {
    const char = mask[index];
    if (opens[char]) stack.push(opens[char]);
    else if (')]}'.includes(char)) {
      if (stack.pop() !== char) return -1;
      if (!stack.length) return index;
    }
  }
  return -1;
}

// Splits at separators outside brackets. separator(mask, index) returns the
// separator's length there, or 0.
function splitTop(text, mask, separator) {
  const parts = [];
  let depth = 0, start = 0;
  for (let index = 0; index < mask.length; index += 1) {
    const char = mask[index];
    if (opens[char]) depth += 1;
    else if (')]}'.includes(char)) depth -= 1;
    else if (depth === 0) {
      const length = separator(mask, index);
      if (length) { parts.push([text.slice(start, index), mask.slice(start, index)]); start = index + length; index += length - 1; }
    }
  }
  parts.push([text.slice(start), mask.slice(start)]);
  return parts;
}

const commaSplit = (text, mask) => splitTop(text, mask, (m, i) => m[i] === ',' ? 1 : 0).map(([t, m]) => [t.trim(), m.trim() === '' && t.trim() !== '' ? maskOf(t.trim()) : alignMask(t, m)]);
function alignMask(text, mask) {
  const lead = text.length - text.trimStart().length;
  const trail = text.length - text.trimEnd().length;
  return mask.slice(lead, mask.length - trail);
}
// A string-blanked mask for a snippet: strings inside a snippet are complete,
// so lexing it alone gives the same mask.
let snippetLang = 'js';
function maskOf(text) { return lex(text, snippetLang).mask; }

// ---- Values.

const value = (root, path, extra = {}) => ({ root, path, ...extra });
const unknown = why => ({ root: 'unknown', path: '', why });
const outside = () => value('outside', '');
// A computed name with no folder in it, like basename(x) or a readdir entry.
const segment = () => value('literal', HOLE);

function joinValues(values) {
  // Each argument is a list of alternatives; the result is their product,
  // capped so a pathological file can't explode.
  let results = [null];
  for (const alternatives of values) {
    const next = [];
    for (const left of results) for (const right of alternatives) {
      if (next.length > 64) break;
      next.push(left === null ? right : joinTwo(left, right));
    }
    results = next;
  }
  return results;
}

// path.join semantics, plus resolve's: an absolute part replaces what came
// before it. Anchors (the reader's folder, the working directory, outside
// folders) are absolute.
function joinTwo(left, right) {
  if (right.root === 'literal' && isAbsolute(right.path)) return outside();
  if (['here', 'cwd', 'repo', 'outside'].includes(right.root)) return right;
  if (left.root === 'outside') return left;
  const tail = right.root === 'literal' ? right.path : HOLE;
  const path = left.path === '' ? tail : tail === '' ? left.path : `${left.path.replace(/\/$/, '')}/${tail}`;
  // The result names a folder or file below left, never left's own file.
  const rest = { ...left };
  delete rest.file;
  if (left.root === 'unknown') return { ...rest, path, dots: left.dots || (right.root === 'literal' && hasDots(right.path)) };
  return { ...rest, path };
}

function concatValues(parts) {
  // String concatenation: the pieces abut without a separator.
  let results = [value('literal', '')];
  for (const alternatives of parts) {
    const next = [];
    for (const left of results) for (const right of alternatives) {
      if (next.length > 64) break;
      if (left.root === 'literal' && left.path === '') { next.push(right); continue; }
      if (left.root === 'outside') { next.push(left); continue; }
      const tail = right.root === 'literal' ? right.path : HOLE;
      next.push({ ...left, path: left.path + tail });
    }
    results = next;
  }
  return results;
}

const hasDots = path => path.split('/').includes('..');
const climb = values => values.map(({ file, ...item }) => item.root === 'outside' ? item
  : item.root === 'unknown' ? { ...item, climbs: true }
  : { ...item, path: item.path === '' ? '..' : `${item.path}/..` });

// ---- Evaluation context for one file.

export class Reader {
  // here: the reader's own folder, or null when it has none in the
  // repository (a workflow step's script). cwd: its working directory.
  constructor(repo, file, { text, lang, isTest, here, cwd = '' } = {}) {
    this.repo = repo;
    this.file = file;
    this.lang = lang ?? languageOf(file);
    this.text = (text ?? repo.read(file)).replace(/\r\n/g, '\n');
    ({ code: this.code, mask: this.mask } = lex(this.text, this.lang));
    this.dir = here !== undefined ? here : posix.dirname(file) === '.' ? '' : posix.dirname(file);
    this.cwd = cwd;
    // go test runs a package's tests in its folder; a program runs wherever
    // it was started.
    this.isTest = isTest ?? (this.lang === 'go' && file.endsWith('_test.go'));
    this.lookups = new Map();
    this.depth = 0;
    this.at = 0; // the offset whose names are being resolved
    if (this.lang === 'js') this.fs = fsImports(this.mask, this.code);
  }

  line(offset) { return this.text.slice(0, offset).split('\n').length; }

  evaluate(expression, mask) {
    snippetLang = this.lang;
    const text = expression.trim();
    if (!text) return [unknown('empty')];
    mask = mask === undefined || mask.length !== expression.length ? maskOf(text) : alignMask(expression, mask);
    if (++this.depth > 40) { this.depth -= 1; return [unknown('too deep')]; }
    try {
      return (this.lang === 'js' ? this.evaluateJS : this.lang === 'go' ? this.evaluateGo : this.evaluatePS).call(this, text, mask);
    } finally { this.depth -= 1; }
  }

  // ---- JavaScript.
  evaluateJS(text, mask) {
    const strip = /^(?:await|new\s+String)\s+/.exec(text);
    if (strip && !/^new\s+URL/.test(text)) return this.evaluate(text.slice(strip[0].length));
    if (mask[0] === '(' && closing(mask, 0) === mask.length - 1) return this.evaluate(text.slice(1, -1), mask.slice(1, -1));
    for (const suffix of ['.href', '.pathname', '.toString()']) if (text.endsWith(suffix) && mask.endsWith(suffix)) return this.evaluate(text.slice(0, -suffix.length), mask.slice(0, -suffix.length));
    // Alternatives: a ? b : c, a || b, a ?? b.
    const ternary = splitTop(text, mask, (m, i) => m[i] === '?' && m[i + 1] !== '?' && m[i + 1] !== '.' && m[i - 1] !== '?' ? 1 : 0);
    if (ternary.length === 2) {
      const branches = splitTop(ternary[1][0], ternary[1][1], (m, i) => m[i] === ':' ? 1 : 0);
      if (branches.length === 2) return [...this.evaluate(branches[0][0], branches[0][1]), ...this.evaluate(branches[1][0], branches[1][1])];
    }
    const either = splitTop(text, mask, (m, i) => (m.startsWith('||', i) || m.startsWith('??', i)) ? 2 : 0);
    if (either.length > 1) return either.flatMap(([t, m]) => this.evaluate(t, m));
    const plus = splitTop(text, mask, (m, i) => m[i] === '+' && m[i + 1] !== '+' && m[i - 1] !== '+' && m[i + 1] !== '=' ? 1 : 0);
    if (plus.length > 1) return concatValues(plus.map(([t, m]) => this.evaluate(t, m)));
    if (/^'[^']*'$|^"[^"]*"$/.test(text) && isString(mask.slice(1, -1))) return [literal(text.slice(1, -1))];
    if (text[0] === '`' && text.endsWith('`') && isString(mask.slice(1, -1))) return this.template(text.slice(1, -1));
    if (/^\d+$/.test(text)) return [outside()]; // a file descriptor
    const call = /^(new\s+)?([\w$.]+)\s*\(/.exec(mask);
    if (call && closing(mask, call[0].length - 1) === mask.length - 1) {
      const name = call[2], args = commaSplit(text.slice(call[0].length, -1), mask.slice(call[0].length, -1));
      return this.callJS(call[1] ? `new ${name}` : name, args);
    }
    if (/^import\.meta\.(?:url|filename)$/.test(text) || text === '__filename') return [value('here', posix.basename(this.file), { file: true })];
    if (/^import\.meta\.dirname$/.test(text) || text === '__dirname') return [value('here', '')];
    if (text === 'process.execPath') return [outside()];
    const env = /^process\.env(?:\.(\w+)|\[\s*['"](\w+)['"]\s*\])$/.exec(text);
    if (env) return [environment(env[1] ?? env[2])];
    if (/^process\.argv\b/.test(text)) return [{ ...unknown('argument'), external: true }];
    if (/^[A-Za-z_$][\w$]*$/.test(text)) return this.lookupJS(text);
    return [unknown('expression')];
  }

  template(body) {
    const parts = [];
    let at = 0;
    while (at < body.length) {
      const start = body.indexOf('${', at);
      if (start < 0) { parts.push([literal(body.slice(at))]); break; }
      if (start > at) parts.push([literal(body.slice(at, start))]);
      const inner = maskOf(body.slice(start + 1));
      const end = closing(inner, 0);
      if (end < 0) return [unknown('template')];
      parts.push(this.evaluate(body.slice(start + 2, start + 1 + end)));
      at = start + 2 + end;
    }
    return concatValues(parts);
  }

  callJS(name, args) {
    const each = () => args.map(([t, m]) => this.evaluate(t, m));
    const base = name.split('.').at(-1);
    const pathCall = new Set(['path', 'posix', 'win32', 'path.posix', 'path.win32']).has(name.split('.').slice(0, -1).join('.')) || this.fs?.pathNames.has(name);
    if (pathCall && ['join', 'resolve'].includes(base)) return joinValues(each());
    if (pathCall && base === 'dirname') return climb(this.evaluate(...args[0]));
    if (pathCall && ['normalize', 'toNamespacedPath'].includes(base)) return this.evaluate(...args[0]);
    if (pathCall && ['basename', 'extname', 'relative'].includes(base)) return [segment()];
    if (['fileURLToPath', 'pathToFileURL', 'url.fileURLToPath', 'url.pathToFileURL', 'String'].includes(name)) return this.evaluate(...args[0]);
    if (['tmpdir', 'os.tmpdir', 'homedir', 'os.homedir', 'mkdtemp', 'mkdtempSync', 'fs.mkdtemp', 'fs.mkdtempSync', 'fsp.mkdtemp'].includes(name)) return [outside()];
    if (name === 'process.cwd') return [value('cwd', '')];
    if (name === 'new URL') {
      if (args.length < 2) return [unknown('URL without a base')];
      const target = this.evaluate(...args[0]);
      return this.evaluate(...args[1]).flatMap(baseValue => target.map(item => {
        if (item.root === 'outside') return item;
        if (baseValue.root === 'outside') return baseValue;
        // A URL base that names a file resolves against its folder.
        const folder = baseValue.file || (baseValue.root !== 'unknown' && baseValue.path !== '' && !baseValue.path.endsWith('/')) ? climb([baseValue])[0] : baseValue;
        return joinTwo(folder, item.root === 'literal' ? item : unknown('URL path'));
      }));
    }
    return [unknown(`result of ${name}()`)];
  }

  // ---- Names. A binding is where a name gets a value: an assignment, a loop
  // variable, a parameter. A use sees the bindings whose scope holds it and
  // that come before it; failing that, those whose scope holds it; failing
  // that, every binding of the name.
  binding(pos, scope, compute) {
    let cached = null, busy = false;
    return {
      pos, scope, values: () => {
        if (cached) return cached;
        if (busy) return [unknown('recursive')];
        busy = true;
        const saved = this.at;
        this.at = pos;
        try { cached = compute(); } finally { this.at = saved; busy = false; }
        return cached;
      },
    };
  }

  resolveName(key, collect) {
    if (!this.lookups.has(key)) this.lookups.set(key, collect());
    const list = this.lookups.get(key);
    const at = this.at;
    const holds = item => item.scope[0] < at && at <= item.scope[1];
    let visible = list.filter(item => holds(item) && item.pos < at);
    if (!visible.length) visible = list.filter(holds);
    if (!visible.length) visible = list;
    return visible.length ? visible.flatMap(item => item.values()) : [unknown(`unresolved ${key.slice(3)}`)];
  }

  get whole() { return [-1, this.mask.length + 1]; }

  // Innermost {...} around an offset. PowerShell variables live in their
  // function or script, so its if, loop and try blocks don't count.
  scopeAt(offset) {
    if (!this.blocks) {
      this.blocks = [];
      const stack = [];
      for (let index = 0; index < this.mask.length; index += 1) {
        if (this.mask[index] === '{') stack.push(index);
        else if (this.mask[index] === '}' && stack.length) this.blocks.push([stack.pop(), index]);
      }
      this.blocks.sort((a, b) => (a[1] - a[0]) - (b[1] - b[0]));
    }
    const innermost = at => this.blocks.find(block => block[0] < at && at < block[1]) ?? this.whole;
    let block = innermost(offset);
    if (this.lang === 'ps') while (block[0] >= 0 && controlFlowPS(this.mask, block[0])) block = innermost(block[0]);
    return block;
  }

  // The block that follows index: a function body after its parameters (and a
  // Go result list), or a loop body.
  bodyAfter(index) {
    const match = /^\s*(?:=>\s*)?(?:[\w.*[\]]+\s*|\([^()]*\)\s*)?\{/.exec(this.mask.slice(index + 1, index + 300));
    if (!match) return null;
    const open = index + match[0].length;
    const close = closing(this.mask, open);
    return close > 0 ? [open, close] : null;
  }

  // The innermost (...) around an offset.
  parenAround(offset) {
    let depth = 0;
    for (let index = offset - 1; index >= 0; index -= 1) {
      const char = this.mask[index];
      if (char === ')' || char === ']' || char === '}') depth += 1;
      else if (char === '(' || char === '[' || char === '{') {
        if (depth === 0) return char === '(' ? [index, closing(this.mask, index)] : null;
        depth -= 1;
      }
    }
    return null;
  }

  lookupJS(name) {
    return this.resolveName(`js ${name}`, () => this.bindingsJS(name));
  }

  bindingsJS(name) {
    const found = [];
    const escaped = name.replace(/\$/g, '\\$');
    const rhs = start => { const end = expressionEnd(this.mask, start); return () => this.evaluate(this.code.slice(start, end), this.mask.slice(start, end)); };
    // const x = ..., let x = ..., var x = ..., and x = ... (whose scope is
    // the declaration's, so the whole file here).
    for (const match of this.mask.matchAll(new RegExp(`(?<![\\w$.])(?:(const|let|var)\\s+)?${escaped}\\s*=(?![=>])`, 'g'))) {
      const scope = match[1] && match[1] !== 'var' ? this.scopeAt(match.index) : this.whole;
      found.push(this.binding(match.index, scope, rhs(match.index + match[0].length)));
    }
    for (const match of this.mask.matchAll(new RegExp(`for\\s*\\(\\s*(?:const|let|var)\\s+${escaped}\\s+(?:of|in)\\s+`, 'g'))) {
      const open = this.mask.lastIndexOf('(', match.index + match[0].length);
      const close = closing(this.mask, open);
      const start = match.index + match[0].length;
      found.push(this.binding(match.index, this.bodyAfter(close) ?? this.scopeAt(match.index), () => this.elements(this.code.slice(start, close), this.mask.slice(start, close))));
    }
    // Parameters: the name inside (...) followed by => or a function body.
    for (const match of this.mask.matchAll(new RegExp(`(?<![\\w$.])${escaped}(?![\\w$])`, 'g'))) {
      const group = this.parenAround(match.index);
      if (!group || group[1] < 0) continue;
      const after = this.mask.slice(group[1] + 1, group[1] + 4);
      const before = this.mask.slice(Math.max(0, group[0] - 60), group[0]);
      const keyword = /([\w$]+)\s*$/.exec(before)?.[1];
      const arrow = /^\s*=>/.test(after);
      const body = /^\s*\{/.test(after) && (/\bfunction\s*\*?\s*[\w$]*\s*$/.test(before) || (keyword && !['if', 'for', 'while', 'switch', 'with', 'return'].includes(keyword)));
      if (!arrow && !body) continue;
      found.push(this.binding(match.index, this.bodyAfter(group[1]) ?? this.scopeAt(match.index), () => [unknown(keyword === 'catch' ? 'caught error' : 'parameter')]));
    }
    for (const match of this.mask.matchAll(new RegExp(`(?<![\\w$.])${escaped}\\s*=>`, 'g')))
      found.push(this.binding(match.index, this.bodyAfter(match.index + name.length - 1) ?? this.scopeAt(match.index), () => [unknown('parameter')]));
    for (const match of this.mask.matchAll(new RegExp(`(?:const|let|var)\\s*[{[][^=;]*(?<![\\w$])${escaped}(?![\\w$])[^=;]*[}\\]]\\s*=`, 'g')))
      found.push(this.binding(match.index, this.scopeAt(match.index), () => [unknown('destructured')]));
    // import { name } from './module.mjs': the exported value, from there.
    for (const match of this.code.matchAll(/import\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/g)) {
      for (const spec of match[1].split(',')) {
        const [exported, local = exported] = spec.trim().split(/\s+as\s+/).map(part => part.trim());
        if (local !== name) continue;
        const target = posix.normalize(posix.join(this.dir, match[3]));
        found.push(this.binding(match.index, this.whole, () => {
          if (!match[3].startsWith('.') || !this.repo.has(target)) return [unknown('import')];
          const other = readerFor(this.repo, target);
          if (other.lang !== 'js') return [unknown('import')];
          const saved = other.at;
          other.at = other.mask.length;
          try {
            return other.lookupJS(exported).map(item => item.root === 'here' ? { ...item, root: 'cwd', path: posix.join(other.dir, item.path) } : item);
          } finally { other.at = saved; }
        }));
      }
    }
    return found;
  }

  elements(text, mask) {
    const trimmed = text.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const inner = maskOf(trimmed).slice(1, -1);
      return commaSplit(trimmed.slice(1, -1), inner).filter(([t]) => t).flatMap(([t, m]) => this.evaluate(t, m));
    }
    const listed = this.evaluate(text, mask);
    // Elements of an enumeration are names: one computed segment.
    if (/\b(?:readdir|readdirSync|Object\.keys|Object\.entries)\b/.test(trimmed)) return [segment()];
    return listed.map(item => item.root === 'unknown' ? unknown('element') : item.root === 'literal' ? segment() : item);
  }

  // ---- Go.
  evaluateGo(text, mask) {
    if (mask[0] === '(' && closing(mask, 0) === mask.length - 1) return this.evaluate(text.slice(1, -1), mask.slice(1, -1));
    const plus = splitTop(text, mask, (m, i) => m[i] === '+' && m[i + 1] !== '+' && m[i + 1] !== '=' ? 1 : 0);
    if (plus.length > 1) return concatValues(plus.map(([t, m]) => this.evaluate(t, m)));
    if (/^"(?:[^"\\]|\\.)*"$/.test(text) && isString(mask.slice(1, -1))) return [literal(JSON.parse(text))];
    if (/^`[^`]*`$/.test(text)) return [literal(text.slice(1, -1))];
    const call = /^([\w.]+)\s*\(/.exec(mask);
    if (call && closing(mask, call[0].length - 1) === mask.length - 1) {
      const name = call[1], args = commaSplit(text.slice(call[0].length, -1), mask.slice(call[0].length, -1));
      const each = () => args.map(([t, m]) => this.evaluate(t, m));
      if (['filepath.Join', 'path.Join'].includes(name)) return joinValues(each());
      if (['filepath.Dir', 'path.Dir'].includes(name)) return climb(this.evaluate(...args[0]));
      if (['filepath.Clean', 'path.Clean', 'filepath.FromSlash', 'filepath.ToSlash', 'filepath.Abs'].includes(name)) return this.evaluate(...args[0]);
      if (['filepath.Base', 'path.Base', 'filepath.Ext', 'filepath.Rel'].includes(name)) return [segment()];
      if (/^(?:t|b|f|tb)\.TempDir$/.test(name) || ['os.TempDir', 'os.MkdirTemp', 'os.CreateTemp', 'os.UserHomeDir', 'os.UserConfigDir', 'os.UserCacheDir', 'os.Executable'].includes(name)) return [outside()];
      if (name === 'os.Getwd') return [value(this.isTest ? 'here' : 'cwd', '')];
      if (['os.Getenv', 'os.LookupEnv'].includes(name)) {
        const variable = /^"(\w+)"$/.exec(args[0]?.[0] ?? '');
        return [variable ? environment(variable[1]) : unknown('environment')];
      }
      return [unknown(`result of ${name}()`)];
    }
    if (/^[A-Za-z_]\w*$/.test(text)) return this.lookupGo(text);
    return [unknown('expression')];
  }

  lookupGo(name) {
    return this.resolveName(`go ${name}`, () => this.bindingsGo(name));
  }

  bindingsGo(name) {
    const found = [];
    // name := x, name = x, var name = x, var name T = x, const name = x,
    // multiple assignment from a known producer, and range variables.
    for (const match of this.mask.matchAll(new RegExp(`(?<![\\w.])((?:[\\w.]+\\s*,\\s*)*)${name}((?:\\s*,\\s*[\\w.]+)*)\\s*(?:[\\w.\\[\\]*]+\\s*)?(:?=)(?!=)`, 'g'))) {
      const before = match.index > 0 ? this.mask[match.index - 1] : '\n';
      if (!/[\s(;{]/.test(before)) continue;
      const start = match.index + match[0].length;
      const names = `${match[1]}${name}${match[2]}`.split(',').map(part => part.trim());
      const position = names.indexOf(name);
      const declared = match[3] === ':=' || /\b(?:var|const)\s*$/.test(this.mask.slice(Math.max(0, match.index - 8), match.index));
      if (/^\s*range\b/.test(this.mask.slice(start))) {
        const open = this.mask.indexOf('{', start);
        const close = closing(this.mask, open);
        const listed = this.code.slice(start, open).replace(/^\s*range\b/, '');
        found.push(this.binding(match.index, close > 0 ? [open, close] : this.scopeAt(match.index), () => this.rangeElements(listed, position)));
        continue;
      }
      const end = expressionEnd(this.mask, start, 'go');
      const rhs = this.code.slice(start, end), rhsMask = this.mask.slice(start, end);
      found.push(this.binding(match.index, declared ? this.scopeAt(match.index) : this.whole, () => {
        if (names.length === 1) return this.evaluate(rhs, rhsMask);
        const producer = /^\s*([\w.]+)\s*\(/.exec(rhsMask)?.[1];
        if (['os.MkdirTemp', 'os.CreateTemp', 'os.UserHomeDir', 'os.UserConfigDir', 'os.UserCacheDir', 'os.Executable'].includes(producer) && position === 0) return [outside()];
        if (producer === 'os.Getwd' && position === 0) return [value(this.isTest ? 'here' : 'cwd', '')];
        if (producer === 'runtime.Caller' && position === 1) return [value('here', posix.basename(this.file), { file: true })];
        const sides = commaSplit(rhs, rhsMask);
        return sides.length === names.length ? this.evaluate(...sides[position]) : [unknown('multiple assignment')];
      }));
    }
    // Parameters and receivers: the name inside a func's (...).
    for (const match of this.mask.matchAll(new RegExp(`(?<![\\w.])${name}(?![\\w.])`, 'g'))) {
      const group = this.parenAround(match.index);
      if (!group || group[1] < 0) continue;
      if (!/\bfunc\s*(?:\([^()]*\)\s*)?\w*\s*$/.test(this.mask.slice(Math.max(0, group[0] - 80), group[0]))) continue;
      // The body is the first { after the signature, outside its parentheses.
      let depth = 0, open = -1;
      for (let index = group[1] + 1; index < this.mask.length; index += 1) {
        const char = this.mask[index];
        if (char === '(') depth += 1; else if (char === ')') depth -= 1;
        else if (char === '{' && depth === 0) { open = index; break; }
        else if (char === '\n' && depth === 0 && !/[,(]\s*$/.test(this.mask.slice(group[1], index))) break;
      }
      const close = open > 0 ? closing(this.mask, open) : -1;
      found.push(this.binding(match.index, close > 0 ? [open, close] : this.scopeAt(match.index), () => [unknown('parameter')]));
    }
    return found;
  }

  rangeElements(text, position) {
    const trimmed = text.trim();
    // for _, name := range []string{"a", "b"}
    const literalList = /^\[\]string\s*\{([\s\S]*)\}$/.exec(trimmed);
    if (literalList && position === 1) return commaSplit(literalList[1], maskOf(literalList[1])).filter(([t]) => t).flatMap(([t, m]) => this.evaluate(t, m));
    return [unknown('element')];
  }

  // ---- PowerShell.
  evaluatePS(text, mask) {
    if (mask[0] === '(' && closing(mask, 0) === mask.length - 1) return this.evaluateCommandPS(text.slice(1, -1), mask.slice(1, -1));
    const member = /^\(([\s\S]*)\)\.(\w+)$/.exec(text);
    if (member && closing(mask, 0) === text.length - member[2].length - 2) {
      if (/^(?:Path|FullName|ProviderPath)$/i.test(member[2])) return this.evaluateCommandPS(member[1], mask.slice(1, 1 + member[1].length));
      if (/^(?:Source|Definition)$/i.test(member[2])) return [outside()];
      return [unknown('property')];
    }
    const plus = splitTop(text, mask, (m, i) => m[i] === '+' && /\s/.test(m[i - 1] ?? '') ? 1 : 0);
    if (plus.length > 1) return concatValues(plus.map(([t, m]) => this.evaluate(t, m)));
    if (/^'(?:[^']|'')*'$/.test(text)) return [literal(text.slice(1, -1).replace(/''/g, "'"))];
    if (/^"[\s\S]*"$/.test(text) && isString(mask.slice(1, -1))) return this.interpolated(text.slice(1, -1));
    const dotnet = /^\[(?:System\.)?IO\.Path\]::(\w+)\(/i.exec(mask);
    if (dotnet && closing(mask, dotnet[0].length - 1) === mask.length - 1) {
      const args = commaSplit(text.slice(dotnet[0].length, -1), mask.slice(dotnet[0].length, -1));
      const method = dotnet[1].toLowerCase();
      if (method === 'combine') return joinValues(args.map(([t, m]) => this.evaluate(t, m)));
      if (method === 'getfullpath') return this.evaluate(...args[0]);
      if (method === 'getdirectoryname') return climb(this.evaluate(...args[0]));
      if (/^gettemp(?:path|filename)$/.test(method)) return [outside()];
      if (/^getfilename/.test(method) || method === 'getextension') return [segment()];
      return [unknown(`[IO.Path]::${dotnet[1]}`)];
    }
    if (/^\[Environment\]::GetFolderPath/i.test(text)) return [outside()];
    if (/^\$PSScriptRoot$/i.test(text)) return [this.dir === null ? outside() : value('here', '')];
    if (/^\$PSCommandPath$|^\$MyInvocation\.MyCommand\.Path$/i.test(text)) return [this.dir === null ? outside() : value('here', posix.basename(this.file), { file: true })];
    const env = /^\$env:(\w+)$/i.exec(text);
    if (env) return [environment(env[1])];
    if (/^\$(?:HOME)$/i.test(text)) return [outside()];
    if (/^\$(?:pwd)$/i.test(text)) return [value('cwd', '')];
    if (/^\$_(?:\.|$)/.test(text)) return [unknown('pipeline element')];
    const variable = /^\$(?:\{(\w+)\}|(\w+))$/.exec(text);
    if (variable) return this.lookupPS(variable[1] ?? variable[2]);
    if (/^\$\w+[.[]/.test(text)) return [unknown('property')];
    // A bare word argument is a literal: packaging/versions.json.
    if (/^[\w./\\:*-]+$/.test(text) && !text.startsWith('-')) return [literal(text)];
    return [unknown('expression')];
  }

  interpolated(body) {
    const parts = [];
    const pattern = /`.|\$(?:\{(\w+)\}|\((?=)|((?:env:)?\w+))/gi;
    let match;
    let lastEnd = 0;
    while ((match = pattern.exec(body))) {
      if (match[0][0] === '`') continue;
      if (match.index > lastEnd) parts.push([literal(body.slice(lastEnd, match.index).replace(/`(.)/g, '$1'))]);
      if (match[0] === '$(') {
        const inner = maskOf(body.slice(match.index + 1));
        const end = closing(inner, 0);
        if (end < 0) return [unknown('subexpression')];
        parts.push(this.evaluateCommandPS(body.slice(match.index + 2, match.index + 1 + end), inner.slice(1, end)));
        lastEnd = match.index + 2 + end;
        pattern.lastIndex = lastEnd;
        continue;
      }
      parts.push(this.evaluate(`$${match[1] ?? match[2]}`));
      // $x.Property and $x[0] inside a string: only the variable interpolates.
      lastEnd = match.index + match[0].length;
    }
    if (lastEnd < body.length) parts.push([literal(body.slice(lastEnd).replace(/`(.)/g, '$1'))]);
    return concatValues(parts);
  }

  // The inside of (...): a command (Join-Path, Resolve-Path, Split-Path) or
  // an expression.
  evaluateCommandPS(text, mask) {
    const words = wordsPS(text.trim(), alignMask(text, mask ?? maskOf(text)));
    const name = words[0]?.[0].toLowerCase();
    if (name === 'join-path') {
      const { named, positional } = argumentsPS(words.slice(1));
      const parts = [named.path ?? positional[0], named.childpath ?? positional[1], ...(named.additionalchildpath ? [named.additionalchildpath] : positional.slice(2))].filter(Boolean);
      return joinValues(parts.map(([t, m]) => this.evaluate(t, m)));
    }
    if (name === 'resolve-path' || name === 'convert-path' || name === 'get-item') {
      const { named, positional } = argumentsPS(words.slice(1));
      const target = named.literalpath ?? named.path ?? positional[0];
      return target ? this.evaluate(...target) : [unknown(name)];
    }
    if (name === 'split-path') {
      const { named, positional, switches } = argumentsPS(words.slice(1));
      const target = named.literalpath ?? named.path ?? positional[0];
      if (!target) return [unknown('split-path')];
      return switches.has('leaf') ? [segment()] : climb(this.evaluate(...target));
    }
    if (name === 'get-command') return [outside()];
    if (words.length === 1) return this.evaluate(...words[0]);
    return [unknown('expression')];
  }

  lookupPS(name) {
    return this.resolveName(`ps ${name.toLowerCase()}`, () => this.bindingsPS(name));
  }

  bindingsPS(name) {
    const found = [];
    for (const match of this.mask.matchAll(new RegExp(`(?<![\\w:.])\\$${name}\\s*=(?!=)`, 'gi'))) {
      const start = match.index + match[0].length;
      const end = statementEndPS(this.mask, start);
      const rhs = this.code.slice(start, end), rhsMask = this.mask.slice(start, end);
      found.push(this.binding(match.index, this.scopeAt(match.index), () => {
        if (/^\s*if\s*\(/i.test(rhsMask)) {
          // $x = if (...) { A } else { B }
          const values = [];
          for (const block of rhsMask.matchAll(/\{/g)) {
            const close = closing(rhsMask, block.index);
            if (close > 0) values.push(...this.evaluateCommandPS(rhs.slice(block.index + 1, close), rhsMask.slice(block.index + 1, close)));
          }
          return values;
        }
        if (/^\s*@\(/.test(rhsMask)) return this.arrayPS(rhs, rhsMask);
        return /^\s*[($'"[]/.test(rhs) ? this.evaluate(rhs, rhsMask) : this.evaluateCommandPS(rhs, rhsMask);
      }));
    }
    for (const match of this.mask.matchAll(new RegExp(`foreach\\s*\\(\\s*\\$${name}\\s+in\\s+`, 'gi'))) {
      const open = this.mask.lastIndexOf('(', match.index + match[0].length);
      const close = closing(this.mask, open);
      const start = match.index + match[0].length;
      found.push(this.binding(match.index, this.bodyAfter(close) ?? this.scopeAt(match.index), () => this.elementsPS(this.code.slice(start, close), this.mask.slice(start, close))));
    }
    // param(...) blocks, function f($a) and [type]$a parameters.
    for (const match of this.mask.matchAll(new RegExp(`\\$${name}(?![\\w:])`, 'gi'))) {
      const group = this.parenAround(match.index);
      if (!group) continue;
      const before = this.mask.slice(Math.max(0, group[0] - 60), group[0]);
      if (!/(?:\bparam|\bfunction\s+[\w-]+)\s*$/i.test(before)) continue;
      found.push(this.binding(match.index, /\bparam\s*$/i.test(before) ? this.scopeAt(group[0]) : this.bodyAfter(group[1]) ?? this.scopeAt(group[0]), () => [unknown('parameter')]));
    }
    return found;
  }

  arrayPS(text, mask) {
    const start = mask.indexOf('@(');
    const end = closing(mask, start + 1);
    const body = text.slice(start + 2, end), bodyMask = mask.slice(start + 2, end);
    const items = splitTop(body, bodyMask, (m, i) => m[i] === ',' || m[i] === '\n' ? 1 : 0).map(([t, m]) => [t.trim(), alignMask(t, m)]).filter(([t]) => t);
    return items.flatMap(([t, m]) => this.evaluate(t, m));
  }

  elementsPS(text, mask) {
    const trimmed = text.trim();
    if (/^@\(/.test(trimmed)) return this.arrayPS(text, mask);
    if (/^\$\w+$/.test(trimmed)) {
      const listed = this.lookupPS(trimmed.slice(1));
      return listed.map(item => item.root === 'unknown' ? unknown('element') : item);
    }
    // foreach ($x in 'a', 'b')
    const items = commaSplit(text, alignMask(text, mask));
    if (items.length > 1 && items.every(([t]) => /^'[^']*'$|^"[^"$]*"$/.test(t))) return items.flatMap(([t, m]) => this.evaluate(t, m));
    return [unknown('element')];
  }
}

// Whether the { at open belongs to if, elseif, else, switch, a loop, try,
// catch or finally.
function controlFlowPS(mask, open) {
  let end = open;
  while (end > 0 && /\s/.test(mask[end - 1])) end -= 1;
  let word;
  if (mask[end - 1] === ')') {
    let depth = 0, at = end - 1;
    for (; at >= 0; at -= 1) {
      if (mask[at] === ')') depth += 1;
      else if (mask[at] === '(' && --depth === 0) break;
    }
    word = /([\w-]+)\s*$/.exec(mask.slice(Math.max(0, at - 40), at))?.[1];
  } else if (mask[end - 1] === ']') {
    word = /\b(catch)\s*\[[^\]]*\]\s*$/i.exec(mask.slice(Math.max(0, end - 120), end))?.[1];
  } else word = /([\w-]+)\s*$/.exec(mask.slice(Math.max(0, end - 40), end))?.[1];
  return /^(?:if|elseif|else|switch|foreach|for|while|do|until|try|catch|finally)$/i.test(word ?? '');
}

const literal = text => value('literal', text.replace(/\\/g, '/'));
// A drive, a leading slash or a URL scheme: not under the repository.
const isAbsolute = path => /^[a-z]:\//i.test(path) || path.startsWith('/') || /^[a-z][\w+.-]+:/i.test(path);

// Environment variables the guard knows: the workspace is the repository
// root; temporary, profile, system and runner files are outside it.
const outsideVariables = new Set(['TEMP', 'TMP', 'TMPDIR', 'RUNNER_TEMP', 'RUNNER_TOOL_CACHE', 'LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'USERPROFILE', 'HOME', 'SYSTEMROOT', 'WINDIR', 'GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_STEP_SUMMARY', 'GITHUB_EVENT_PATH', 'COMSPEC']);
function environment(name) {
  if (name.toUpperCase() === 'GITHUB_WORKSPACE') return value('repo', '');
  if (outsideVariables.has(name.toUpperCase())) return outside();
  return { ...unknown(`environment variable ${name}`), external: true };
}

function expressionEnd(mask, start, lang = 'js') {
  let depth = 0;
  for (let index = start; index < mask.length; index += 1) {
    const char = mask[index];
    if (opens[char]) depth += 1;
    else if (')]}'.includes(char)) { if (depth === 0) return index; depth -= 1; }
    else if (depth === 0 && (char === ';' || (char === ',' && lang === 'js'))) return index;
    else if (depth === 0 && char === '\n') {
      const before = mask.slice(start, index).trimEnd();
      const after = mask.slice(index + 1).trimStart();
      if (before === '' || /[=+\-*/|&?:,(]$/.test(before) || /^[.?:+|&]/.test(after)) continue;
      return index;
    }
  }
  return mask.length;
}

function statementEndPS(mask, start) {
  let depth = 0;
  for (let index = start; index < mask.length; index += 1) {
    const char = mask[index];
    if (opens[char]) depth += 1;
    else if (')]}'.includes(char)) { if (depth === 0) return index; depth -= 1; }
    else if (depth === 0 && (char === ';' || (char === '|' && mask[index + 1] !== '|'))) return index;
    else if (depth === 0 && char === '\n') {
      const before = mask.slice(start, index).trimEnd();
      if (before === '' || before.endsWith('`') || before.endsWith('|')) continue;
      return index;
    }
  }
  return mask.length;
}

// PowerShell words of one command, as [text, mask] pairs.
export function wordsPS(text, mask) {
  const words = [];
  let start = -1, depth = 0;
  for (let index = 0; index <= mask.length; index += 1) {
    const char = mask[index] ?? ' ';
    if (opens[char]) { if (start < 0) start = index; depth += 1; continue; }
    if (')]}'.includes(char)) { depth -= 1; continue; }
    if (depth === 0 && /\s/.test(char)) {
      if (start >= 0) { words.push([text.slice(start, index), mask.slice(start, index)]); start = -1; }
      continue;
    }
    if (start < 0) start = index;
  }
  return words;
}

const switchesPS = new Set(['raw', 'recurse', 'force', 'file', 'directory', 'leaf', 'parent', 'passthru', 'nonewline', 'asbytestream', 'wait', 'isvalid', 'hidden', 'readonly', 'system', 'name', 'qualifier', 'noqualifier', 'resolve', 'extension', 'leafbase', 'container', 'simplematch', 'casesensitive', 'list', 'quiet', 'notmatch', 'allmatches', 'global', 'disablenamechecking']);
function argumentsPS(words) {
  const named = {}, positional = [], switches = new Set();
  for (let index = 0; index < words.length; index += 1) {
    const [text] = words[index];
    const flag = /^-([A-Za-z]\w*)(?::(.*))?$/.exec(text);
    if (flag) {
      const name = flag[1].toLowerCase();
      if (flag[2] !== undefined) named[name] = [flag[2], maskOf(flag[2])];
      else if (switchesPS.has(name)) switches.add(name);
      else { named[name] = words[index + 1]; index += 1; }
      continue;
    }
    positional.push(words[index]);
  }
  return { named, positional, switches };
}

// fs functions a JavaScript file imports, by local name, and its path module.
function fsImports(mask, code) {
  const readers = new Map(), namespaces = new Set(), pathNames = new Set();
  for (const match of code.matchAll(/^\s*import\s+([^'";]*?)\s+from\s*(['"])([^'"]+)\2/gm)) {
    if (!/^\s*import\b/.test(mask.slice(match.index, match.index + match[0].length))) continue;
    const clause = match[1], module = match[3].replace(/^node:/, '');
    const isFs = /^fs(?:\/promises)?$/.test(module);
    const isPath = /^path(?:\/posix|\/win32)?$/.test(module);
    if (!isFs && !isPath) continue;
    const named = /\{([^}]*)\}/.exec(clause);
    const rest = clause.replace(/\{[^}]*\}/, '').replace(/,/g, ' ').trim();
    const namespace = /\*\s*as\s+(\w+)/.exec(rest)?.[1] ?? (/^\w+$/.test(rest) ? rest : null);
    if (namespace && isFs) namespaces.add(namespace);
    if (named) for (const spec of named[1].split(',')) {
      const [exported, local = exported] = spec.trim().split(/\s+as\s+/).map(part => part.trim());
      if (!exported) continue;
      if (isFs) readers.set(local, exported);
      if (isPath) pathNames.add(local);
    }
  }
  return { readers, namespaces, pathNames };
}

const readersJS = new Set(['readFileSync', 'readFile', 'readdirSync', 'readdir', 'opendirSync', 'opendir', 'statSync', 'stat', 'lstatSync', 'lstat', 'existsSync', 'accessSync', 'access', 'createReadStream', 'globSync', 'glob', 'cpSync', 'cp', 'copyFileSync', 'copyFile', 'readlinkSync', 'readlink', 'realpathSync', 'realpath', 'openSync', 'open', 'watch']);
const listsJS = new Set(['readdirSync', 'readdir', 'opendirSync', 'opendir', 'globSync', 'glob', 'cpSync', 'cp']);
const readersGo = /(?<![\w.])(os\.(?:ReadFile|ReadDir|Open|OpenFile|Stat|Lstat|DirFS)|ioutil\.(?:ReadFile|ReadDir)|filepath\.(?:Glob|Walk|WalkDir))\s*\(/g;
const listsGo = /ReadDir|DirFS|Glob|Walk/;
const readersPS = /(?<![\w-])(Get-Content|Get-ChildItem|Get-Item|Test-Path|Resolve-Path|Copy-Item|Get-FileHash|Select-String|Import-Module|Import-PowerShellDataFile|Import-Csv)(?![\w-])/gi;
const dotnetPS = /\[(?:System\.)?IO\.(File|Directory)\]::(ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|OpenRead|OpenText|Exists|GetFiles|GetDirectories|EnumerateFiles|EnumerateDirectories|EnumerateFileSystemEntries)\s*\(/gi;

const cache = new WeakMap();
export function readerFor(repo, file) {
  let byFile = cache.get(repo);
  if (!byFile) cache.set(repo, byFile = new Map());
  if (!byFile.has(file)) byFile.set(file, new Reader(repo, file));
  return byFile.get(file);
}

// Path sites in a file: reads, enumerations, invocations and constructions,
// each with the values its path can take. key names the call site for
// declarations: the call and its path argument for a read, the expression for
// a construction. A construction inside another site's expression is part of
// that site.
export function sites(reader) {
  const found = [];
  const { code, mask } = reader;
  const add = (kind, call, argText, argMask, offset, span) => {
    const at = span?.[0] ?? (code.indexOf(argText, offset) >= 0 ? code.indexOf(argText, offset) : offset);
    found.push({ kind, offset, call, argText, argMask, span: span ?? [at, at + argText.length] });
  };
  collect(reader, add);
  const outer = found.filter(site => !found.some(other => other !== site && other.span[0] <= site.span[0] && site.span[1] <= other.span[1]
    && (other.span[1] - other.span[0] > site.span[1] - site.span[0] || other.kind !== 'build') && site.kind === 'build'));
  return outer.map(({ kind, offset, call, argText, argMask }) => {
    reader.at = offset;
    const text = argText.replace(/\s+/g, ' ').trim();
    return { kind, offset, key: kind === 'build' ? text : `${call}(${text})`, line: reader.line(offset), values: reader.evaluate(argText, argMask) };
  });
}

function collect(reader, add) {
  const { code, mask } = reader;
  if (reader.lang === 'js') {
    const { readers, namespaces, pathNames } = reader.fs;
    const names = [...readers.keys()].filter(local => readersJS.has(readers.get(local)));
    const callee = new RegExp(`(?<![\\w$.])(?:(${[...namespaces].join('|') || '(?!)'})\\.(\\w+)|(${names.join('|') || '(?!)'}))\\s*\\(`, 'g');
    for (const match of mask.matchAll(callee)) {
      const fn = match[2] ?? readers.get(match[3]);
      if (!readersJS.has(fn)) continue;
      const open = match.index + match[0].length - 1, close = closing(mask, open);
      if (close < 0) continue;
      const args = commaSplit(code.slice(open + 1, close), mask.slice(open + 1, close));
      if (!args[0]?.[0]) continue;
      add(listsJS.has(fn) ? 'list' : 'read', match[0].slice(0, -1).trim(), args[0][0], args[0][1], match.index);
    }
    const builders = new RegExp(`(?<![\\w$.])(?:new\\s+URL|(?:path|posix|win32)(?:\\.posix|\\.win32)?\\.(?:join|resolve)|${[...pathNames].filter(name => /^(?:join|resolve)$/.test(name)).join('|') || '(?!)'})\\s*\\(`, 'g');
    for (const match of mask.matchAll(builders)) {
      const open = match.index + match[0].length - 1, close = closing(mask, open);
      if (close < 0) continue;
      add('build', match[0].slice(0, -1).trim(), code.slice(match.index, close + 1), mask.slice(match.index, close + 1), match.index, [match.index, close + 1]);
    }
    // Templates that start from a path: `${root}/lib/${name}`. Only those
    // whose start is anchored count; drift.mjs ignores other build sites.
    for (const match of code.matchAll(/`\$\{/g)) {
      const end = code.indexOf('`', match.index + 1);
      const body = code.slice(match.index, end + 1);
      if (end < 0 || !/[/\\]/.test(body)) continue;
      add('build', 'template', body, maskOf(body), match.index, [match.index, end + 1]);
    }
  } else if (reader.lang === 'go') {
    for (const match of mask.matchAll(readersGo)) {
      const open = match.index + match[0].length - 1, close = closing(mask, open);
      if (close < 0) continue;
      const args = commaSplit(code.slice(open + 1, close), mask.slice(open + 1, close));
      if (!args[0]?.[0]) continue;
      add(listsGo.test(match[1]) ? 'list' : 'read', match[1], args[0][0], args[0][1], match.index);
    }
    for (const match of mask.matchAll(/(?<![\w.])(?:filepath|path)\.(?:Join|Dir)\s*\(/g)) {
      const open = match.index + match[0].length - 1, close = closing(mask, open);
      if (close < 0) continue;
      add('build', match[0].slice(0, -1).trim(), code.slice(match.index, close + 1), mask.slice(match.index, close + 1), match.index, [match.index, close + 1]);
    }
  } else {
    for (const match of mask.matchAll(readersPS)) {
      const start = match.index + match[0].length, end = statementEndPS(mask, start);
      const { named, positional } = argumentsPS(wordsPS(code.slice(start, end), mask.slice(start, end)));
      const target = named.literalpath ?? named.path ?? named.filepath ?? named.name ?? positional[match[1].toLowerCase() === 'select-string' && !named.pattern ? 1 : 0];
      const cmdlet = match[1].toLowerCase();
      if (!target) {
        // Get-ChildItem alone lists the working directory; the others read
        // their pipeline input, which an earlier site produced.
        if (cmdlet === 'get-childitem') add('list', match[1], '$pwd', '$pwd', match.index);
        continue;
      }
      add(cmdlet === 'get-childitem' ? 'list' : 'read', match[1], target[0], target[1], match.index);
    }
    for (const match of mask.matchAll(dotnetPS)) {
      const open = match.index + match[0].length - 1, close = closing(mask, open);
      if (close < 0) continue;
      const args = commaSplit(code.slice(open + 1, close), mask.slice(open + 1, close));
      add(match[1].toLowerCase() === 'directory' && match[2].toLowerCase() !== 'exists' ? 'list' : 'read', `[IO.${match[1]}]::${match[2]}`, args[0][0], args[0][1], match.index);
    }
    // . script and & script: the script is read.
    for (const match of mask.matchAll(/(?:^|[\s;{(|=])([.&])[ \t]+(?=[$('"\w./\\])/gm)) {
      const start = match.index + match[0].length, end = statementEndPS(mask, start);
      const words = wordsPS(code.slice(start, end), mask.slice(start, end));
      if (words[0]) add('run', match[1], words[0][0], words[0][1], start);
    }
    for (const match of mask.matchAll(/(?<![\w-])(?:Join|Split)-Path(?![\w-])/gi)) {
      const end = statementEndPS(mask, match.index);
      // As a command: (Join-Path a b) evaluates the way an argument does.
      const length = code.slice(match.index, end).trimEnd().length;
      add('build', match[0], `(${code.slice(match.index, match.index + length)})`, `(${mask.slice(match.index, match.index + length)})`, match.index, [match.index, end]);
    }
    for (const match of code.matchAll(/"\$(?:PSScriptRoot|\{PSScriptRoot\})[^"\n]*"/gi)) {
      if (!isString(mask.slice(match.index + 1, match.index + match[0].length - 1))) continue;
      add('build', 'string', match[0], maskOf(match[0]), match.index, [match.index, match.index + match[0].length]);
    }
  }
}

// Where one value points, from a reader in dir: { files, dirs } it reaches,
// 'outside', or a problem.
export function locate(repo, item, reader) {
  if (item.root === 'outside' || (item.root === 'literal' && isAbsolute(item.path))) return { outside: true };
  if (item.root === 'unknown') {
    // join(dir, '..', name) leaves whatever dir is; dirname(dir) is accepted
    // like dir itself.
    if (item.dots) return { problem: `climbs with '..' from a ${item.why}` };
    return item.external ? { external: true } : { unknown: true };
  }
  // literal paths are relative: to the package folder for a Go test, to the
  // working directory otherwise. Workflows start scripts from the repository
  // root, and resolve() in drift.mjs also tries the file's own folder.
  const base = item.root === 'repo' ? '' : item.root === 'here' || (item.root === 'literal' && reader.isTest) ? reader.dir : reader.cwd;
  const stack = base ? base.split('/') : [];
  const segments = item.path.split('/').filter(part => part !== '' && part !== '.');
  // A computed part holds one or more names and no '..'. A climb after one
  // can therefore come back to the fixed part before it, but not above it.
  // ANY marks "zero or more names" once a climb has eaten into a computed part.
  let fixed = -1;
  for (const part of segments) {
    if (part === '..') {
      const top = stack.at(-1);
      if (fixed < 0) {
        if (!stack.length) return { outside: true };
        stack.pop();
      } else if (top === ANY) {
        if (stack.length - 1 <= fixed) return { problem: 'climbs above the fixed part of a computed path' };
        stack.splice(-2, 2, ANY);
      } else if (top.includes(HOLE)) stack.splice(-1, 1, ANY);
      else if (stack.length > fixed) stack.pop();
      else return { problem: 'climbs above the fixed part of a computed path' };
      continue;
    }
    if (part.includes(HOLE) && fixed < 0) fixed = stack.length;
    stack.push(part);
  }
  const firstHole = stack.findIndex(part => part.includes(HOLE) || part === ANY);
  if (firstHole < 0) {
    const path = stack.join('/');
    if (path === '') return { root: true };
    if (repo.has(path)) return { files: [path], dirs: [] };
    if (repo.dirs.has(path)) return { files: [], dirs: [path] };
    return { files: [], dirs: [] };
  }
  if (firstHole === 0) return { problem: 'a computed part directly on the repository root' };
  const prefix = stack.slice(0, firstHole).join('/');
  if (!repo.dirs.has(prefix)) return { files: [], dirs: [] };
  let source = '';
  stack.forEach((part, index) => {
    const last = index === stack.length - 1;
    if (part === ANY) source += last ? '[^]*' : '(?:[^]*/)?';
    else source += part.split(HOLE).map(piece => piece.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^]*') + (last ? '' : '/');
  });
  const pattern = new RegExp(`^${source}(?:/|$)`);
  return { files: repo.tracked.filter(file => file.startsWith(`${prefix}/`) && pattern.test(file)), dirs: [], pattern: true };
}
