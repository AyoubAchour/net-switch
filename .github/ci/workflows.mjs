// Reads the parts of this repository's workflow files that gates.test.mjs and
// drift.test.mjs check. It is not a YAML parser: it knows the layout these
// files use (two-space indentation, jobs at column 2, job keys at column 4,
// steps at column 6, anchors and aliases on step lists and step items), and
// throws where that layout breaks, so a format change fails the tests instead
// of letting them pass on nothing.

const stripComment = value => value.replace(/\s+#.*$/, '').trim();

function blocks(lines, indent) {
  // Splits lines into "key: value" entries at exactly this indentation.
  const entries = [];
  const key = new RegExp(`^ {${indent}}([\\w-]+):(?:\\s+(.*))?$`);
  for (const line of lines) {
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    const match = key.exec(line);
    if (match) entries.push({ key: match[1], inline: stripComment(match[2] ?? ''), lines: [] });
    else if (entries.length && line.startsWith(' '.repeat(indent + 1))) entries.at(-1).lines.push(line);
    else throw new Error(`Unexpected workflow line at indent ${indent}: ${JSON.stringify(line)}`);
  }
  return entries;
}

function items(lines, indent) {
  // Splits a block sequence at this indentation into items. Each item's lines
  // are re-indented so its keys sit at indent + 2, the dash line included.
  const result = [];
  const dash = new RegExp(`^ {${indent}}- (.*)$`);
  for (const line of lines) {
    if (/^\s*(?:#.*)?$/.test(line)) continue;
    const match = dash.exec(line);
    if (match) {
      const [, anchor, alias, rest] = /^(?:&([\w-]+)\s*|\*([\w-]+)\s*)?(.*)$/.exec(match[1]);
      result.push({ anchor, alias, lines: rest ? [`${' '.repeat(indent + 2)}${rest}`] : [] });
    } else if (result.length && line.startsWith(' '.repeat(indent + 2))) result.at(-1).lines.push(line);
    else throw new Error(`Unexpected sequence line at indent ${indent}: ${JSON.stringify(line)}`);
  }
  return result;
}

const flowList = value => /^\[(.*)\]$/.test(value)
  ? value.slice(1, -1).split(',').map(part => part.trim().replace(/^'(.*)'$/, '$1')).filter(Boolean)
  : [value.replace(/^'(.*)'$/, '$1')];

export function readWorkflow(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const start = lines.indexOf('jobs:');
  if (start < 0) throw new Error('No jobs block');
  const end = lines.findIndex((line, index) => index > start && /^\S/.test(line));
  const jobs = blocks(lines.slice(start + 1, end < 0 ? undefined : end), 2);
  const anchors = new Map();
  const parsed = new Map();
  for (const job of jobs) {
    if (job.inline) throw new Error(`Job ${job.key} must be a block`);
    const fields = Object.fromEntries(blocks(job.lines, 4).map(field => [field.key, field]));
    const steps = fields.steps;
    let stepItems;
    if (!steps) throw new Error(`Job ${job.key} has no steps`);
    if (steps.inline.startsWith('*')) stepItems = { alias: steps.inline.slice(1) };
    else {
      if (steps.inline && !steps.inline.startsWith('&')) throw new Error(`Job ${job.key} steps must be a block`);
      stepItems = items(steps.lines, 6);
      if (steps.inline) anchors.set(steps.inline.slice(1), stepItems);
      for (const item of stepItems) if (item.anchor) anchors.set(item.anchor, item);
    }
    parsed.set(job.key, { id: job.key, fields, stepItems });
  }
  const result = new Map();
  for (const { id, fields, stepItems } of parsed.values()) {
    const list = stepItems.alias ? anchors.get(stepItems.alias) : stepItems;
    if (!list) throw new Error(`Job ${id} uses unknown steps anchor ${stepItems.alias}`);
    const steps = list.map(item => {
      const resolved = item.alias ? anchors.get(item.alias) : item;
      if (!resolved) throw new Error(`Job ${id} uses unknown step anchor ${item.alias}`);
      const keys = Object.fromEntries(blocks(resolved.lines, 8).map(entry => [entry.key, entry]));
      return { if: keys.if?.inline, text: resolved.lines.join('\n'), keys };
    });
    const strategy = fields.strategy ? [fields.strategy.inline, ...fields.strategy.lines].join('\n') : '';
    result.set(id, {
      id,
      name: fields.name?.inline,
      if: fields.if?.inline,
      needs: fields.needs ? flowList(fields.needs.inline) : [],
      runsOn: fields['runs-on']?.inline,
      matrix: matrixEntries(fields['runs-on']?.inline, strategy),
      hasStrategy: Boolean(fields.strategy),
      outputs: fields.outputs ? Object.fromEntries(blocks(fields.outputs.lines, 6).map(entry => [entry.key, entry.inline])) : {},
      steps,
    });
  }
  return { header: lines.slice(0, start).join('\n'), jobs: result };
}

// One entry per runner a job may use, with the matrix values that step
// conditions read (name, arch). Covers "include" lists and runner lists.
function matrixEntries(runsOn, strategy) {
  if (!/\$\{\{/.test(runsOn ?? '')) return [{ runner: runsOn }];
  const include = [];
  for (const line of strategy.split('\n')) {
    const item = /^\s+- (\w+): (.+)$/.exec(line);
    const field = /^\s+(\w+): (.+)$/.exec(line);
    if (item) include.push({ [item[1]]: stripComment(item[2]) });
    else if (field && include.length && !['matrix', 'include', 'fail-fast', 'max-parallel'].includes(field[1])) include.at(-1)[field[1]] = stripComment(field[2]);
  }
  const listed = /^\s+runner: (\[.*\])$/m.exec(strategy);
  const runners = listed ? flowList(listed[1]) : [];
  const entries = include.filter(entry => entry.runner && !runners.includes(entry.runner));
  for (const runner of runners) entries.push({ ...include.find(entry => entry.runner === runner), runner });
  if (!entries.length) throw new Error(`No runners found for matrix job: ${strategy}`);
  return entries;
}

export const runnerOS = runner => /^windows/.test(runner) ? 'Windows' : /^ubuntu/.test(runner) ? 'Linux' : null;

// GitHub Actions expressions, for the operators these workflows use. Same
// rules as GitHub: && and || return an operand, == compares strings without
// case and converts mismatched types to numbers, missing properties are null.
export function evaluate(source, context) {
  const expression = source.trim().replace(/^\$\{\{([\s\S]*)\}\}$/, '$1');
  const tokens = [];
  const pattern = /\s*(?:(\|\||&&|==|!=|!|\(|\)|,)|'((?:[^']|'')*)'|(\d+(?:\.\d+)?)|([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)*))/y;
  let index = 0;
  while (index < expression.length) {
    if (/^\s*$/.test(expression.slice(index))) break;
    pattern.lastIndex = index;
    const match = pattern.exec(expression);
    if (!match) throw new Error(`Unsupported expression at ${JSON.stringify(expression.slice(index))}`);
    index = pattern.lastIndex;
    if (match[1]) tokens.push({ op: match[1] });
    else if (match[2] !== undefined) tokens.push({ value: match[2].replace(/''/g, "'") });
    else if (match[3]) tokens.push({ value: Number(match[3]) });
    else tokens.push({ name: match[4] });
  }
  let at = 0;
  const peek = op => tokens[at]?.op === op;
  const take = op => { if (!peek(op)) throw new Error(`Expected ${op} in ${expression}`); at += 1; };
  const or = () => { let left = and(); while (peek('||')) { at += 1; const right = and(); left = truthy(left) ? left : right; } return left; };
  const and = () => { let left = equality(); while (peek('&&')) { at += 1; const right = equality(); left = truthy(left) ? right : left; } return left; };
  const equality = () => {
    let left = unary();
    while (peek('==') || peek('!=')) {
      const op = tokens[at++].op;
      const same = equal(left, unary());
      left = op === '==' ? same : !same;
    }
    return left;
  };
  const unary = () => { if (peek('!')) { at += 1; return !truthy(unary()); } return primary(); };
  const primary = () => {
    if (peek('(')) { at += 1; const value = or(); take(')'); return value; }
    const token = tokens[at++];
    if (!token || token.op) throw new Error(`Unexpected token in ${expression}`);
    if ('value' in token) return token.value;
    if (token.name === 'true' || token.name === 'false') return token.name === 'true';
    if (token.name === 'null') return null;
    if (peek('(')) {
      at += 1; take(')');
      const call = context.functions?.[token.name];
      if (!call) throw new Error(`Unsupported function ${token.name}`);
      return call();
    }
    return token.name.split('.').reduce((value, key) => value == null ? null : value[key] ?? null, context);
  };
  const value = or();
  if (at !== tokens.length) throw new Error(`Trailing tokens in ${expression}`);
  return value;
}

export function truthy(value) {
  return !(value === null || value === false || value === 0 || value === '' || Number.isNaN(value));
}

function equal(left, right) {
  if (typeof left === 'string' && typeof right === 'string') return left.toLowerCase() === right.toLowerCase();
  if (typeof left === typeof right) return left === right;
  const number = value => value === null ? 0 : typeof value === 'boolean' ? Number(value) : typeof value === 'string' ? (value.trim() === '' ? 0 : Number(value)) : NaN;
  return number(left) === number(right);
}

// A job condition without a status function gets an implicit success().
export function jobRuns(job, context) {
  const condition = job.if ?? 'success()';
  const explicit = /\b(?:success|failure|cancelled|always)\s*\(/.test(condition);
  return truthy(evaluate(explicit ? condition : `success() && (${condition.replace(/^\$\{\{([\s\S]*)\}\}$/, '$1')})`, context));
}
