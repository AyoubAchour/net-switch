'use strict';

let token = readToken();
const MASTER_CELLS = 36;
const ROW_CELLS = 12;
// One cell per 5%, the step shares move in.
const SHARE_CELLS = 20;
const RESORT_MS = 3000;
// Line colors, by position: the main line amber, the next cyan, then four more
// hues (styles.css --line-0 to --line-5). A seventh line starts over.
const PALETTE_SIZE = 6;
const MB = 1024 * 1024;
const GB = 1024 * MB;
// Up to this many choices per app show as keys; more become a list. A narrow
// window has room for fewer.
const MAX_KEYS = 4;
const MAX_KEYS_NARROW = 3;
const narrowWindow = matchMedia('(max-width: 640px)');

const els = {
  status: document.getElementById('routing-status'),
  toggle: document.getElementById('routing-toggle'),
  lines: document.getElementById('lines'),
  combine: document.getElementById('combine'),
  notices: document.getElementById('notices'),
  apps: document.getElementById('apps'),
  empty: document.getElementById('empty'),
  listMessage: document.getElementById('list-message'),
  legends: document.querySelector('.legends'),
  channels: document.querySelector('.channels'),
  footerNote: document.getElementById('footer-note'),
  openSettings: document.getElementById('open-settings'),
  quit: document.getElementById('quit'),
  panel: document.getElementById('panel'),
};

let state = null;
let unreachable = false;
// The server restarted since this window opened, so its key no longer works.
let outdated = false;
let actionError = null;
// Which action the error is about, so a panel can show it under its field.
let failedAction = null;
let busyAction = null;
let order = [];
let lastSortAt = 0;
let pollTimer = null;
// The line an app is being moved to: a line id, or '' for the default.
const pendingLine = new Map();
const rows = new Map();
// Line cards by line id, reused from poll to poll.
const cards = new Map();
let addCard = null;
// After a reconnect, what the person should know for a short while.
const reconnected = new Map();
const RECONNECT_NOTE_MS = 15_000;
// The app whose Reconnect is waiting for a second, confirming click.
let confirmingReconnect = null;
// After Quit only the closed screen is left: nothing polls or redraws any more.
let closed = false;

// The side panel: { kind: 'line', id } or { kind: 'settings' }, or null.
let panel = null;
let confirmingRemove = false;
// What's typed in the panel and not saved yet; null while nothing is.
const drafts = { label: null, cap: null, probeTargets: null };
let advancedOpen = false;
// Shares being set by hand, by line id, until the server has them.
let shareDraft = null;
let sendingShares = false;
let sharesQueued = false;
let combineParts = null;

// ------------------------------------------------------------ helpers

// The key arrives in the address, and is moved out of it at once so it doesn't
// stay in the address bar or the browser's history. The tab keeps it, so
// reloading the window still works.
function readToken() {
  const fromAddress = new URLSearchParams(location.hash.slice(1)).get('token');
  if (fromAddress) {
    sessionStorage.setItem('token', fromAddress);
    history.replaceState(null, '', location.pathname + location.search);
    return fromAddress;
  }
  return sessionStorage.getItem('token');
}

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) {
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }
  return node;
}

async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: { 'X-Token': token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw Object.assign(new Error('Net Switch isn’t responding.'), { unreachable: true });
  }
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) throw Object.assign(new Error(data.error), { outdated: true });
  if (!response.ok) throw new Error(data.error || 'Something went wrong. Try again.');
  return data;
}

// [number, unit], so a line's big reading can set the unit smaller.
function rateParts(bytesPerSecond) {
  if (!bytesPerSecond || bytesPerSecond < 1) return ['0', 'KB/s'];
  if (bytesPerSecond < 1024) return ['<1', 'KB/s'];
  if (bytesPerSecond < 1024 * 1024) return [String(Math.round(bytesPerSecond / 1024)), 'KB/s'];
  return [(bytesPerSecond / 1024 / 1024).toFixed(1), 'MB/s'];
}

function formatRate(bytesPerSecond) {
  return rateParts(bytesPerSecond).join(' ');
}

// Data amounts: MB under a gigabyte, then GB with one decimal ("10 GB", not
// "10.0 GB"). A no-break space keeps the number and its unit on one line.
function formatData(bytes) {
  if (!bytes || bytes < MB) return bytes > 0 ? '<1 MB' : '0 MB';
  if (bytes < GB) return `${Math.round(bytes / MB)} MB`;
  const gigabytes = bytes / GB;
  return `${gigabytes >= 100 ? Math.round(gigabytes) : Number(gigabytes.toFixed(1))} GB`;
}

// Log scale like an audio meter: 1 KB/s is the first cell, 10 MB/s fills it.
function litCells(bytesPerSecond, cells) {
  if (!bytesPerSecond || bytesPerSecond < 1) return 0;
  const level = Math.log10(bytesPerSecond / 1024) / Math.log10(10 * 1024);
  return Math.max(1, Math.min(cells, Math.round(level * cells)));
}

function connectionWord(count) {
  return count === 1 ? '1 connection is' : `${count} connections are`;
}

function connectionCount(count) {
  return count === 1 ? '1 connection' : `${count} connections`;
}

// "a", "a and b", "a, b and c".
function listText(items) {
  if (items.length < 2) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
}

// Splits total into 5% steps that add up to it, in proportion to the weights.
function percentSteps(weights, total = 100) {
  const units = Math.round(total / 5);
  const sum = weights.reduce((a, b) => a + b, 0);
  const exact = weights.map((weight) => (sum > 0 ? (weight / sum) * units : units / weights.length));
  const counts = exact.map(Math.floor);
  let left = units - counts.reduce((a, b) => a + b, 0);
  const byRemainder = exact.map((value, index) => [value - Math.floor(value), index]).sort((a, b) => b[0] - a[0]);
  for (const [, index] of byRemainder) {
    if (left <= 0) break;
    counts[index] += 1;
    left -= 1;
  }
  return counts.map((count) => count * 5);
}

// ------------------------------------------------------------ lines

function allLines() {
  return state?.lines ?? [];
}

function mainLine() {
  return allLines()[0] ?? null;
}

function lineById(id) {
  if (id === null || id === undefined) return null;
  return allLines().find((line) => line.id === id) ?? null;
}

function colorOf(id) {
  const index = allLines().findIndex((line) => line.id === id);
  return index < 0 ? 0 : index % PALETTE_SIZE;
}

function lineIcon(kind) {
  return ['wired', 'wifi', 'phone'].includes(kind) ? kind : 'other';
}

function lineUp(line) {
  return Boolean(line.connected) && !line.problem;
}

// The line a line's own apps use now, when that isn't the line itself: it is
// down or over its data cap.
function standIn(line) {
  const target = lineById(line?.target);
  return target && target.id !== line.id ? target : null;
}

// Lines that take part in sharing: not kept for chosen apps, not over their cap.
function sharingLines() {
  return allLines().filter((line) => !line.strict && !line.exhausted);
}

function periodWord(cap) {
  return cap?.period === 'day' ? 'today' : 'this month';
}

// When a capped line's count starts over: "tomorrow" or "on November 1".
function resetText(line) {
  if (line.cap?.period === 'day') return 'tomorrow';
  const start = new Date(line.usage?.periodStart ?? Number.NaN);
  if (Number.isNaN(start.getTime())) return 'next month';
  const next = new Date(start);
  while (next <= new Date()) next.setMonth(next.getMonth() + 1);
  return `on ${next.toLocaleDateString([], { month: 'long', day: 'numeric' })}`;
}

function usageText(line) {
  const used = line.usage?.bytes ?? 0;
  if (line.cap) return `${formatData(used)} of ${formatData(line.cap.bytes)} ${periodWord(line.cap)}`;
  const start = new Date(line.usage?.periodStart ?? Number.NaN);
  const since = Number.isNaN(start.getTime()) ? '' : ` since ${start.toLocaleDateString([], { month: 'long', day: 'numeric' })}`;
  return `${formatData(used)} used${since}`;
}

// A line's health in its card: [text, tone]. The ping is the last internet
// test's round trip, which only runs while routing is on.
function lineHealth(line) {
  // Connected again, and trusted once an internet test passes.
  if (line.problem === 'checking') return ['Checking…', 'warn'];
  if (line.problem === 'no internet') return ['No internet', 'warn'];
  if (line.problem) return [line.problem === 'no address' ? 'No address' : 'No route', 'down'];
  if (!line.connected) return ['Not connected', 'down'];
  if (line.exhausted) return ['Cap reached', 'warn'];
  if (routingOn() && Number.isFinite(line.ping)) return [`${line.ping} ms`, 'ok'];
  return ['Online', 'ok'];
}

// The line under a line's meter: what it is doing right now. A slim card
// leaves out the "until": its health beside it already says why.
function lineFoot(line, compact = false) {
  if (!routingOn()) return 'Routing is off';
  const other = standIn(line);
  if (other && compact) return `Its apps use the ${other.label}`;
  if (other && line.exhausted) return `Its apps use the ${other.label} until the cap resets`;
  if (other) return `Its apps use the ${other.label} until it’s back`;
  if (Number.isFinite(line.connections)) return `Carrying ${connectionCount(line.connections)}`;
  return '';
}

// The pill in the top bar: [text, tone].
function routingSummary() {
  const status = state.routing.status;
  if (status === 'starting') return ['Starting routing…', 'idle'];
  if (status === 'stopping') return ['Turning off routing…', 'idle'];
  if (status === 'off') return ['Routing off', 'idle'];
  if (status === 'error') return ['Routing stopped', 'down'];
  const list = allLines();
  const main = mainLine();
  if (!main || list.length === 1) return ['Routing on', 'ok'];
  const other = standIn(main);
  if (other) return [`Routing on · running on the ${other.label}`, 'warn'];
  const online = list.filter(lineUp).length;
  if (online === list.length) return [list.length === 2 ? 'Routing on · both lines online' : `Routing on · all ${list.length} lines online`, 'ok'];
  if (list.length === 2) return [`Routing on · ${main.label} only`, 'warn'];
  return [`Routing on · ${online} of ${list.length} lines online`, 'warn'];
}

function routingOn() {
  return state?.routing.status === 'on';
}

// Routing is on and the engine is answering, so the speeds shown are current.
function measuring() {
  return routingOn() && state.routing.measuring;
}

// The person chose to combine lines, and there are lines to combine.
function combining() {
  return Boolean(state?.combine?.on) && allLines().length > 1 && state.features?.combine !== false;
}

// Combining is really splitting new connections right now. While only one
// line works they all use it, so apps behave as without combining.
function sharing() {
  return combining() && Boolean(state.combine.active);
}

// ------------------------------------------------------------ app choices

// The line the app is put on, or null for the default.
function pinnedLine(app) {
  return lineById(app.line);
}

// The choice shown as made: a line id, or null for Shared while combining.
// Without combining the default is the main line, so that key shows it.
function choiceOf(app) {
  const pinned = pinnedLine(app)?.id ?? null;
  if (combining()) return pinned;
  return pinned ?? mainLine()?.id ?? null;
}

// The line an app belongs on when it isn't spread over several.
function homeLine(app) {
  return pinnedLine(app) ?? mainLine();
}

// This app's new connections are spread over the lines right now.
function sharesLines(app) {
  return !pinnedLine(app) && sharing();
}

function lineOptions() {
  const options = allLines().map((line, index) => ({ value: line.id, label: line.label, color: index % PALETTE_SIZE }));
  if (combining()) options.unshift({ value: null, label: 'Shared', shared: true });
  return options;
}

// The Shared mark: a short pill with a stripe per sharing line, wide enough
// that the stripes don't blend.
function sharedLook(node) {
  const colors = sharingLines().map((line) => `var(--line-${colorOf(line.id)})`);
  const step = 100 / Math.max(colors.length, 1);
  const stripes = colors.map((color, index) => `${color} ${(index * step).toFixed(2)}% ${((index + 1) * step).toFixed(2)}%`);
  node.dataset.look = 'shared';
  // Set through the style object: the page's security policy allows that, not style attributes.
  node.style.setProperty('--lane', colors.length > 1 ? `linear-gradient(90deg, ${stripes.join(', ')})` : (colors[0] ?? 'var(--line-0)'));
  node.style.setProperty('--pill', `${Math.max(12, colors.length * 5)}px`);
  return node;
}

// ------------------------------------------------------------ meters

function createMeter(count, kind) {
  const meter = h('div', { class: `meter meter-${kind}`, 'aria-hidden': 'true' });
  for (let i = 0; i < count; i += 1) meter.append(h('span', { class: 'cell' }));
  return meter;
}

// segments: [[color, cells], ...], lit in order from the left.
function setMeter(meter, segments) {
  const values = [];
  for (const [color, count] of segments) for (let i = 0; i < count; i += 1) values.push(String(color));
  const cells = meter.children;
  for (let i = 0; i < cells.length; i += 1) {
    const value = values[i] ?? null;
    if (cells[i].dataset.lit !== value) {
      if (value) cells[i].dataset.lit = value;
      else delete cells[i].dataset.lit;
    }
  }
}

// An app's lit cells split over its lines by how much it downloads on each,
// in line order, so the colors show where its traffic really goes.
function rowSegments(app, lit) {
  if (!lit) return [];
  const parts = allLines().map((line, index) => [index % PALETTE_SIZE, Math.max(0, app.lineDown?.[line.id] ?? 0)]);
  const total = parts.reduce((sum, [, value]) => sum + value, 0);
  if (total <= 0) return [[colorOf(homeLine(app)?.id), lit]];
  const exact = parts.map(([, value]) => (value / total) * lit);
  const counts = exact.map(Math.floor);
  let left = lit - counts.reduce((a, b) => a + b, 0);
  const byRemainder = exact.map((value, index) => [value - Math.floor(value), index]).sort((a, b) => b[0] - a[0]);
  for (const [, index] of byRemainder) {
    if (left <= 0) break;
    counts[index] += 1;
    left -= 1;
  }
  return parts.map(([color], index) => [color, counts[index]]).filter(([, count]) => count > 0);
}

// ------------------------------------------------------------ actions

// Resolves true when the action worked.
async function run(name, task) {
  if (busyAction) return false;
  busyAction = name;
  actionError = null;
  failedAction = null;
  render();
  let ok = false;
  try {
    const result = await task();
    if (result?.lines) state = result;
    ok = true;
  } catch (error) {
    actionError = error.message;
    failedAction = name;
  } finally {
    busyAction = null;
    render();
  }
  return ok;
}

async function chooseLine(app, value) {
  if (choiceOf(app) === value || pendingLine.has(app.key)) return;
  pendingLine.set(app.key, value ?? '');
  actionError = null;
  failedAction = null;
  render();
  // Without combining the main line is the default, so choosing it clears the app's choice.
  const line = !combining() && value === mainLine()?.id ? null : value;
  try {
    state = await api('/api/app-line', { path: app.path, line });
  } catch (error) {
    actionError = error.message;
  } finally {
    pendingLine.delete(app.key);
    render();
  }
}

// Closes the app's connections that aren't on its chosen line, so the app opens new ones there.
async function reconnect(app) {
  const name = `reconnect:${app.key}`;
  if (busyAction) return;
  busyAction = name;
  confirmingReconnect = null;
  actionError = null;
  failedAction = null;
  render();
  try {
    const result = await api('/api/reconnect', { key: app.key });
    if (result.state) state = result.state;
    reconnected.set(app.key, { closed: result.closed, failed: result.failed, at: Date.now() });
  } catch (error) {
    actionError = error.message;
  } finally {
    busyAction = null;
    render();
  }
}

function askToReconnect(app) {
  confirmingReconnect = app.key;
  render();
}

function cancelReconnect() {
  confirmingReconnect = null;
  render();
}

// Routing the person wants on: on, starting, or failing and about to be tried
// again. Turning it off from any of those stops the retries too.
function routingWanted() {
  return state?.routing.wanted ?? routingOn();
}

// The busy name says which way it was pressed, so the label stays right even
// after a poll has brought the new state.
function toggleRouting() {
  const on = !routingWanted();
  run(on ? 'routing-on' : 'routing-off', () => api('/api/routing', { on }));
}

// The closed screen only appears once Net Switch confirmed it is shutting down.
async function quit() {
  els.quit.disabled = true;
  els.quit.textContent = 'Quitting…';
  try {
    await api('/api/quit', {});
  } catch (error) {
    if (error.outdated) outdated = true;
    else actionError = `Net Switch couldn’t quit. ${error.message}`;
    els.quit.disabled = false;
    els.quit.textContent = 'Quit Net Switch';
    render();
    return;
  }
  closed = true;
  clearTimeout(pollTimer);
  if (els.panel.open) els.panel.close();
  document.title = 'Net Switch (closed)';
  document.body.replaceChildren(
    h(
      'div',
      { class: 'closed' },
      h('h1', { text: 'Net Switch is closed' }),
      h('p', { text: 'Every app uses Windows’ normal connection again. You can close this window.' }),
    ),
  );
}

// ------------------------------------------------------------ top bar

// The tray icon brings back only a window titled exactly "Net Switch", so a
// window that can't work, or one from test mode, says so in its title as well.
function windowTitle() {
  if (outdated || !token) return 'Net Switch (old window)';
  return state?.mode === 'proxy' ? 'Net Switch (test mode)' : 'Net Switch';
}

function renderTopbar() {
  const status = state?.routing.status;
  const stale = unreachable || outdated;
  document.title = windowTitle();
  let [text, tone] = stale ? ['Not connected to Net Switch', 'down'] : state ? routingSummary() : ['Connecting…', 'idle'];
  // Test mode only routes traffic sent through its local proxy, so say where that is.
  if (state?.mode === 'proxy' && !stale) {
    text += state.routing.proxyPort ? ` (test mode, proxy 127.0.0.1:${state.routing.proxyPort})` : ' (test mode)';
  }
  if (els.status.textContent !== text) els.status.textContent = text;
  els.status.dataset.tone = tone;
  // Keep the last known screen visible, but clearly out of date and not clickable.
  if (stale) document.body.dataset.stale = '';
  else delete document.body.dataset.stale;

  // Quit and the settings need a working connection to the server; without one they would only pretend.
  els.quit.hidden = stale || !token;
  els.openSettings.hidden = stale || !state;
  renderFooter();

  const toggle = els.toggle;
  toggle.hidden = !state || stale;
  if (busyAction === 'routing-on' || busyAction === 'routing-off') {
    toggle.textContent = busyAction === 'routing-on' ? 'Starting…' : 'Turning off…';
    toggle.disabled = true;
  } else if (status === 'stopping') {
    toggle.textContent = 'Turning off…';
    toggle.disabled = true;
  } else {
    // Also while starting or retrying: Turn off is how the person stops it.
    toggle.textContent = routingWanted() ? 'Turn off' : 'Turn on';
    toggle.disabled = Boolean(busyAction);
  }
}

function renderFooter() {
  const version = state?.version;
  const note = `${version ? `Net Switch ${version}. ` : ''}Closing this window keeps routing on.`;
  if (els.footerNote.textContent !== note) els.footerNote.textContent = note;
}

// ------------------------------------------------------------ line cards

function openLinePanel(id) {
  panel = { kind: 'line', id };
  confirmingRemove = false;
  drafts.label = null;
  drafts.cap = null;
  actionError = null;
  failedAction = null;
  render();
}

// A card's parts. A compact card (three lines and more) puts the speed beside
// the name and the health in the foot, and leaves the adapter to the tooltip
// and the settings, so two rows of cards still leave the app list its room.
function buildCard(line, index, compact) {
  const where = [line.alias, line.ssid].filter(Boolean).join(' · ');
  const name = h(
    'div',
    { class: 'bus-name' },
    h(
      'strong',
      {},
      h('span', { class: 'bus-label', text: line.label, title: compact && where ? `${line.label} (${where})` : line.label }),
      // "Main" only means something next to other lines.
      index === 0 && allLines().length > 1 ? h('span', { class: 'badge', text: 'Main' }) : null,
      line.metered ? h('span', { class: 'badge', text: 'Metered' }) : null,
    ),
    where && !compact ? h('span', { text: where, title: where }) : null,
  );
  const icon = h('span', { class: 'line-icon', 'data-icon': lineIcon(line.kind), 'aria-hidden': 'true' });
  const health = h('div', { class: 'health' }, h('i', { class: 'dot' }), h('span'));
  const down = h('div', { class: 'reading-down' }, h('span', { class: 'reading-value' }), h('span', { class: 'reading-unit' }));
  const up = h('span', { class: 'reading-up' });
  const usage =
    line.cap || line.metered
      ? h('div', { class: 'bus-usage' }, h('span', { class: 'usage-bar', 'aria-hidden': 'true' }, h('i')), h('span', { class: 'usage-text' }))
      : null;
  const settings = h('button', {
    class: 'button button-quiet',
    type: 'button',
    text: 'Settings',
    'aria-label': `Settings for ${line.label}`,
    'aria-haspopup': 'dialog',
    onclick: () => openLinePanel(line.id),
  });
  const note = h('span', { class: 'bus-note' });
  const meter = createMeter(MASTER_CELLS, 'master');
  if (compact) {
    // The data used takes the note's place in the foot rather than a row of its own.
    return [
      h('div', { class: 'bus-head' }, icon, name, h('div', { class: 'bus-reading' }, down, up)),
      meter,
      h('div', { class: 'bus-foot' }, health, note, usage, settings),
    ].filter(Boolean);
  }
  return [
    h('div', { class: 'bus-head' }, icon, name, health),
    h('div', { class: 'bus-reading' }, down, up),
    meter,
    usage,
    h('div', { class: 'bus-foot' }, note, settings),
  ].filter(Boolean);
}

// Built when what it shows changes; the values change in place every second.
function updateCard(card, line, index, compact) {
  const node = card.node;
  const showUsage = Boolean(line.cap || line.metered);
  const signature = JSON.stringify([index, allLines().length > 1, line.label, line.alias, line.ssid, line.kind, line.metered, showUsage, compact]);
  if (card.signature !== signature) {
    node.dataset.color = String(index % PALETTE_SIZE);
    rebuildKeepingFocus(node, () => buildCard(line, index, compact), `card:${line.id}`);
    card.signature = signature;
  }

  const rate = line.rate;
  setMeter(node.querySelector('.meter'), rate ? [[index % PALETTE_SIZE, litCells(rate.down, MASTER_CELLS)]] : []);
  const [number, unit] = rate ? rateParts(rate.down) : ['—', ''];
  node.querySelector('.reading-value').textContent = number;
  node.querySelector('.reading-unit').textContent = rate ? `${unit} ↓` : '';
  node.querySelector('.reading-up').textContent = rate ? `↑ ${formatRate(rate.up)}` : 'Speed isn’t available right now';
  const [healthText, tone] = lineHealth(line);
  const health = node.querySelector('.health');
  health.dataset.tone = tone;
  health.querySelector('span').textContent = healthText;
  const note = node.querySelector('.bus-note');
  const foot = lineFoot(line, compact);
  if (note.textContent !== foot) {
    note.textContent = foot;
    note.title = foot;
  }
  if (tone === 'ok') delete node.dataset.down;
  else node.dataset.down = tone;

  if (showUsage) {
    const usage = node.querySelector('.bus-usage');
    const bar = usage.querySelector('.usage-bar');
    const used = line.usage?.bytes ?? 0;
    const fraction = line.cap ? Math.min(1, used / line.cap.bytes) : 0;
    bar.hidden = !line.cap;
    bar.style.setProperty('--used', String(fraction));
    bar.dataset.level = line.exhausted || fraction >= 1 ? 'full' : fraction >= 0.9 ? 'high' : 'ok';
    const text = usageText(line);
    const label = usage.querySelector('.usage-text');
    if (label.textContent !== text) {
      label.textContent = text;
      label.title = text;
    }
    // In a slim card the foot shows the data used on a capped line, unless
    // its apps are on another line: that matters more.
    if (compact) {
      const instead = Boolean(line.cap) && routingOn() && !standIn(line);
      usage.hidden = !instead;
      note.hidden = instead;
    }
  } else {
    note.hidden = false;
  }
}

function renderLines() {
  const list = allLines();
  // More than one row of cards: the cards get shorter so the app list keeps its room.
  const compact = list.length > 2;
  els.lines.dataset.density = compact ? 'compact' : 'roomy';
  // Past two rows they scroll in their own area (the add card counts when it takes a cell).
  const columns = narrowWindow.matches ? 1 : 2;
  const adding = (state.candidates?.length ?? 0) > 0 || list.length === 1;
  const cells = list.length + (adding && (columns === 1 || list.length % 2 === 1) ? 1 : 0);
  els.lines.dataset.rows = Math.ceil(cells / columns) > 2 ? 'many' : 'few';
  list.forEach((line, index) => {
    let card = cards.get(line.id);
    if (!card) {
      const id = line.id;
      card = {
        signature: '',
        // A click anywhere on the card opens its settings; the Settings button
        // is the same thing for the keyboard.
        node: h('div', {
          class: 'bus',
          'data-id': id,
          onclick: (event) => {
            if (!event.target.closest('button, a, input, select')) openLinePanel(id);
          },
        }),
      };
      cards.set(id, card);
    }
    updateCard(card, line, index, compact);
    if (els.lines.children[index] !== card.node) els.lines.insertBefore(card.node, els.lines.children[index] ?? null);
  });
  for (const [id, card] of cards) {
    if (!list.some((line) => line.id === id)) {
      card.node.remove();
      cards.delete(id);
    }
  }
  renderAddCard(list.length);
}

// Adapters that could become a line, or with one line and none found, how to
// get one. Beside the last card when it has room, else a strip under them.
function renderAddCard(lineCount) {
  const candidates = state.candidates ?? [];
  const show = candidates.length > 0 || lineCount === 1;
  if (!show) {
    addCard?.remove();
    addCard = null;
    return;
  }
  if (!addCard) addCard = h('div', { class: 'bus bus-add' });
  if (addCard.parentNode !== els.lines || addCard.nextSibling) els.lines.append(addCard);
  const wide = lineCount % 2 === 0;
  const signature = JSON.stringify([candidates, busyAction, routingOn(), wide]);
  if (addCard.dataset.signature === signature) return;
  addCard.dataset.signature = signature;
  addCard.dataset.wide = String(wide);

  let detail = 'None found yet';
  if (candidates.length) detail = routingOn() ? 'Routing restarts for a moment' : 'Found on this PC';
  // The detail sits beside the title, so the card is no taller than a slim line card.
  const head = h(
    'div',
    { class: 'bus-head' },
    h('span', { class: 'line-icon', 'data-icon': 'add', 'aria-hidden': 'true' }),
    h('div', { class: 'bus-name add-name' }, h('strong', { text: 'Add a line' }), h('span', { text: detail })),
  );
  if (candidates.length === 0) {
    addCard.replaceChildren(
      head,
      h('p', {
        class: 'bus-note',
        text: 'Plug in a Wi-Fi stick or another network cable, or connect a phone with USB tethering. It shows up here.',
      }),
    );
    return;
  }
  const list = h('div', { class: 'candidates' });
  for (const candidate of candidates) {
    const adding = busyAction === `add:${candidate.alias}`;
    const where = [candidate.alias, candidate.ssid].filter(Boolean).join(' · ');
    list.append(
      h(
        'div',
        { class: 'candidate' },
        h('span', { class: 'line-icon line-icon-small', 'data-icon': lineIcon(candidate.kind), 'aria-hidden': 'true' }),
        h(
          'div',
          { class: 'candidate-name' },
          h('strong', { text: candidate.label, title: candidate.label }),
          h('span', { text: where, title: where }),
        ),
        h('button', {
          class: 'button',
          type: 'button',
          text: adding ? 'Adding…' : 'Add',
          'aria-label': `Add ${candidate.label} (${where})`,
          disabled: Boolean(busyAction),
          onclick: () => run(`add:${candidate.alias}`, () => api('/api/lines/add', { alias: candidate.alias })),
        }),
      ),
    );
  }
  addCard.replaceChildren(head, list);
}

// ------------------------------------------------------------ combining

function toggleCombine() {
  if (busyAction) return;
  const on = !combining();
  run('combine', () => api('/api/combine', { on }));
}

function markUnavailable(node, unavailable) {
  if (unavailable) node.setAttribute('aria-disabled', 'true');
  else node.removeAttribute('aria-disabled');
}

function chooseMode(mode) {
  if (busyAction) return;
  shareDraft = null;
  run('combine-mode', () => api('/api/combine', { mode }));
}

// The shares set by hand, in 5% steps adding up to 100, by line id.
function manualShares(lines) {
  if (shareDraft && lines.every((line) => line.id in shareDraft)) return shareDraft;
  const percents = percentSteps(lines.map((line) => Math.max(0, Number(line.weight) || 0)));
  return Object.fromEntries(lines.map((line, index) => [line.id, percents[index]]));
}

// One slider moved: the others share what is left, keeping their proportions.
function moveShare(lines, id, value) {
  const current = manualShares(lines);
  const others = lines.filter((line) => line.id !== id);
  const rest = percentSteps(
    others.map((line) => current[line.id]),
    100 - value,
  );
  shareDraft = { [id]: value, ...Object.fromEntries(others.map((line, index) => [line.id, rest[index]])) };
  renderShareValues();
}

// Sends the latest shares; a newer drag while one is on its way follows it.
async function sendShares() {
  if (sendingShares) {
    sharesQueued = true;
    return;
  }
  sendingShares = true;
  try {
    do {
      sharesQueued = false;
      const weights = { ...shareDraft };
      try {
        state = await api('/api/combine', { weights });
        actionError = null;
      } catch (error) {
        actionError = error.message;
        failedAction = null;
      }
    } while (sharesQueued);
  } finally {
    sendingShares = false;
    shareDraft = null;
    render();
  }
}

function ensureCombine() {
  if (combineParts) return combineParts;
  const parts = {
    cells: h('span', { class: 'feature-cells', 'aria-hidden': 'true' }),
    name: h('strong', { class: 'feature-name', id: 'combine-name' }),
    text: h('p', { class: 'feature-text', 'aria-live': 'polite' }),
    modes: h('div', { class: 'keys keys-plain mode-keys', role: 'group', 'aria-label': 'How the lines are shared' }),
    button: h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-labelledby': 'combine-name', onclick: toggleCombine }),
    shares: h('div', { class: 'shares' }),
  };
  for (const [mode, label] of [
    ['auto', 'Auto'],
    ['manual', 'Manual'],
  ]) {
    parts.modes.append(
      h('button', {
        class: 'key',
        type: 'button',
        'data-mode': mode,
        text: label,
        onclick: (event) => {
          if (event.currentTarget.getAttribute('aria-pressed') !== 'true') chooseMode(mode);
        },
      }),
    );
  }
  els.combine.append(
    h(
      'div',
      { class: 'feature-row' },
      parts.cells,
      h('div', { class: 'feature-body' }, parts.name, parts.text),
      parts.modes,
      parts.button,
    ),
    parts.shares,
  );
  combineParts = parts;
  return parts;
}

function combineMessage(on, sharers) {
  const names = sharers.map((line) => `the ${line.label}`);
  if (sharers.length < 2) {
    const kept = allLines()
      .filter((line) => line.strict || line.exhausted)
      .map((line) => `the ${line.label} ${line.exhausted ? 'has used its data cap' : 'only carries apps you choose'}`);
    return `Combining needs two lines that can be shared, and ${listText(kept)}.`;
  }
  if (!on) {
    return `Share new connections between ${listText(names)}, so speed tests and downloads in several parts get ${sharers.length === 2 ? 'both speeds' : 'all their speeds'}.`;
  }
  if (!routingOn()) return 'Combining starts when routing is on.';
  if (!state.combine.active) {
    const main = mainLine();
    const carrier = standIn(main) ?? main;
    return `Paused while only one line works. New connections use the ${carrier.label} until another is back.`;
  }
  return state.combine.mode === 'manual'
    ? 'Apps set to Shared spread new connections in the shares you set below. If a website keeps signing you out, put that app on one line.'
    : 'Apps set to Shared spread new connections. Auto follows each line’s measured speed. If a website keeps signing you out, put that app on one line.';
}

// The row under the line cards: the switch, Auto or Manual, and each line's share.
function renderCombine() {
  const list = allLines();
  els.combine.hidden = list.length < 2 || state.features?.combine === false;
  if (els.combine.hidden) return;
  const parts = ensureCombine();
  const on = combining();
  const manual = state.combine?.mode === 'manual';
  const active = on && Boolean(state.combine.active);
  const waiting = on && routingOn() && !active;
  const sharers = sharingLines();

  const title = list.length === 2 ? 'Combine both lines' : 'Combine lines';
  if (parts.name.textContent !== title) parts.name.textContent = title;
  const message = combineMessage(on, sharers);
  if (parts.text.textContent !== message) parts.text.textContent = message;
  els.combine.dataset.state = active ? 'active' : waiting ? 'waiting' : on ? 'on' : 'off';

  // A short meter of which lines combining is using right now: all that
  // share while it works, only the one carrying everything while it waits.
  if (parts.cells.childElementCount !== sharers.length) {
    parts.cells.replaceChildren(...sharers.map(() => h('span', { class: 'cell' })));
    // The shares line up with the text beside the cells.
    els.combine.style.setProperty('--count', String(Math.max(sharers.length, 1)));
  }
  const main = mainLine();
  const carrier = waiting ? (standIn(main) ?? main) : null;
  sharers.forEach((line, index) => {
    const cell = parts.cells.children[index];
    const lit = (active && lineUp(line)) || carrier?.id === line.id;
    const value = lit ? String(colorOf(line.id)) : null;
    if (cell.dataset.lit !== (value ?? undefined)) {
      if (value) cell.dataset.lit = value;
      else delete cell.dataset.lit;
    }
  });

  // The switch moves at once and says it is busy until the server agrees.
  // Busy controls are marked unavailable rather than disabled, so the
  // keyboard focus stays on them.
  const busy = busyAction === 'combine';
  parts.button.setAttribute('aria-checked', String(busy ? !on : on));
  if (busy) parts.button.setAttribute('aria-busy', 'true');
  else parts.button.removeAttribute('aria-busy');
  markUnavailable(parts.button, Boolean(busyAction));
  parts.button.disabled = !on && sharers.length < 2;

  parts.modes.hidden = !on;
  for (const key of parts.modes.children) {
    const pressed = (key.dataset.mode === 'manual') === manual;
    key.setAttribute('aria-pressed', String(pressed && busyAction !== 'combine-mode'));
    if (busyAction === 'combine-mode' && !pressed) key.setAttribute('aria-busy', 'true');
    else key.removeAttribute('aria-busy');
    markUnavailable(key, Boolean(busyAction));
  }

  parts.shares.hidden = !on;
  if (!on) return;
  const left = list.filter((line) => line.strict || line.exhausted);
  const signature = JSON.stringify([
    manual,
    sharers.map((line) => [line.id, line.label, colorOf(line.id)]),
    left.map((line) => [line.id, line.label, colorOf(line.id), line.strict]),
  ]);
  if (parts.shares.dataset.signature !== signature) {
    parts.shares.dataset.signature = signature;
    rebuildKeepingFocus(parts.shares, () => [
      ...sharers.map((line) => shareItem(line, manual, sharers)),
      ...left.map((line) => leftOutItem(line)),
    ]);
  }
  renderShareValues();
}

function shareItem(line, manual, sharers) {
  const item = h(
    'div',
    { class: 'share', 'data-color': String(colorOf(line.id)), 'data-id': line.id },
    h('span', { class: 'share-name', text: line.label, title: line.label }),
    h('div', { class: 'share-track' }, createMeter(SHARE_CELLS, 'share')),
    h('span', { class: 'share-value' }),
  );
  if (manual) {
    const slider = h('input', {
      class: 'share-range',
      type: 'range',
      min: '0',
      max: '100',
      step: '5',
      'data-focus': `share:${line.id}`,
      'aria-label': `${line.label}’s share`,
      oninput: (event) => moveShare(sharers, line.id, Number(event.target.value)),
      onchange: () => sendShares(),
    });
    item.querySelector('.share-track').append(slider);
  }
  return item;
}

// A line that combining leaves alone, and why.
function leftOutItem(line) {
  return h(
    'div',
    {
      class: 'share',
      'data-color': String(colorOf(line.id)),
      'data-off': '',
      title: line.exhausted
        ? `The ${line.label} has used its data cap, so combining leaves it out until the cap resets.`
        : `Only apps you put on the ${line.label} use it, so combining leaves it out.`,
    },
    h('span', { class: 'share-name', text: line.label }),
    h('span', { class: 'share-value', text: line.exhausted ? 'Cap reached' : 'Chosen apps only' }),
  );
}

// Each share's number and cells: measured ones in Auto, the set ones in Manual.
function renderShareValues() {
  if (!combineParts || !state) return;
  const manual = state.combine?.mode === 'manual';
  const sharers = sharingLines();
  const set = manual ? manualShares(sharers) : null;
  for (const item of combineParts.shares.querySelectorAll('.share[data-id]')) {
    const line = lineById(item.dataset.id);
    if (!line) continue;
    // Measured shares only mean something while combining really splits; paused, it shows none.
    let percent = null;
    if (manual) percent = set[line.id] ?? 0;
    else if (Number.isFinite(line.share) && sharing()) percent = Math.round(line.share * 100);
    const text = percent === null ? '—' : `${percent}%`;
    const value = item.querySelector('.share-value');
    if (value.textContent !== text) value.textContent = text;
    setMeter(item.querySelector('.meter'), percent ? [[colorOf(line.id), Math.round(percent / 5)]] : []);
    const slider = item.querySelector('.share-range');
    if (slider) {
      if (slider.value !== String(percent)) slider.value = String(percent);
      slider.setAttribute('aria-valuetext', text);
    }
  }
}

// ------------------------------------------------------------ notices

function notice(kind, text, actions = [], details = null) {
  return h(
    'div',
    { class: 'notice', 'data-kind': kind, role: kind === 'error' ? 'alert' : null },
    h('span', { class: 'notice-icon', 'aria-hidden': 'true' }),
    h(
      'div',
      { class: 'notice-body' },
      h('p', { text }),
      details ? h('details', {}, h('summary', { text: 'Details' }), h('pre', { text: details })) : null,
    ),
    actions.length ? h('div', { class: 'notice-actions' }, actions) : null,
  );
}

function actionButton(label, busyLabel, name, task, { quiet = false } = {}) {
  return h('button', {
    class: quiet ? 'button button-quiet' : 'button',
    type: 'button',
    text: busyAction === name ? busyLabel : label,
    disabled: Boolean(busyAction),
    onclick: () => run(name, task),
  });
}

// The Wi-Fi line Windows' Wi-Fi settings are about, for their notices.
function wifiName() {
  const wifi = allLines().find((line) => line.kind === 'wifi');
  return wifi ? `the ${wifi.label}` : 'Wi-Fi';
}

function renderNotices() {
  const list = [];
  if (!token) {
    list.push(notice('error', 'Open Net Switch from its shortcut.'));
  } else if (outdated) {
    list.push(
      notice('error', 'This window is from an earlier session of Net Switch. Close it and open Net Switch from its shortcut.'),
    );
  } else if (unreachable) {
    list.push(notice('error', 'Net Switch isn’t running. Open it again from its shortcut.'));
  }
  if (state && !unreachable && !outdated) {
    const { routing, setup } = state;
    // A newer release. The download is an ordinary one in the browser; the
    // installer then updates this copy and keeps the settings.
    const update = state.update;
    if (update) {
      list.push(
        notice(
          'update',
          `Net Switch ${update.version} is out (you have ${state.version}). Download it and run the installer: it updates this copy and keeps your settings.`,
          [
            h('a', { class: 'button', href: update.installer, target: '_blank', rel: 'noopener noreferrer', text: 'Download' }),
            h('a', { class: 'button button-quiet', href: update.page, target: '_blank', rel: 'noopener noreferrer', text: 'What’s new' }),
            actionButton('Not now', 'Hiding…', 'update-dismiss', () => api('/api/update/dismiss', { version: update.version }), { quiet: true }),
          ],
        ),
      );
    }
    if (routing.status === 'error' && routing.error) {
      const [first, ...rest] = routing.error.split('\n');
      const canRetry = state.elevated || state.mode === 'proxy';
      // Routing that should be on is started again by itself after a while. The
      // time is given to the minute: text that changed every second would
      // rebuild the notice, and its button, under the pointer.
      const when = routing.retryAt
        ? ` Net Switch tries again by itself${routing.retryAt - Date.now() > 60_000 ? ` at ${new Date(routing.retryAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : ' shortly'}.`
        : '';
      list.push(
        notice(
          'error',
          first + when,
          canRetry ? [actionButton('Try again', 'Starting…', 'retry', () => api('/api/routing', { on: true }))] : [],
          rest.join('\n') || null,
        ),
      );
    }
    if (routing.status === 'on' && !routing.measuring) {
      list.push(
        notice('error', 'Speeds aren’t updating because the routing engine isn’t answering. If this lasts, restart routing.', [
          actionButton('Restart routing', 'Restarting…', 'restart', async () => {
            await api('/api/routing', { on: false });
            return api('/api/routing', { on: true });
          }),
        ]),
      );
    }
    // A line that used up its data cap: its apps moved, and the person may want to raise it.
    if (routing.status === 'on') {
      for (const line of allLines()) {
        if (!line.exhausted || !line.cap) continue;
        const other = standIn(line);
        const where = other ? ` Its apps use the ${other.label} until the cap resets ${resetText(line)}.` : ` It is used again ${resetText(line)}.`;
        list.push(
          notice('setup', `The ${line.label} has used its ${formatData(line.cap.bytes)} for ${periodWord(line.cap)}.${where}`, [
            h('button', {
              class: 'button',
              type: 'button',
              text: 'Change the cap',
              'aria-haspopup': 'dialog',
              disabled: Boolean(busyAction),
              onclick: () => openLinePanel(line.id),
            }),
          ]),
        );
      }
    }
    const main = mainLine();
    if (setup.wifiBlocked) {
      list.push(
        notice('setup', `Windows is set to block Wi-Fi while a cable is plugged in, so ${wifiName()} can’t connect.`, [
          actionButton('Allow Wi-Fi with the cable', 'Changing…', 'keep-both', () => api('/api/setup/keep-both', {})),
        ]),
      );
    }
    if (setup.cableNotDefault && main) {
      list.push(
        notice('setup', `When routing is off, Windows sends your internet through another line, not the ${main.label}.`, [
          actionButton(`Make the ${main.label} the default`, 'Changing…', 'cable-default', () =>
            api('/api/setup/cable-default', {}),
          ),
        ]),
      );
    }
    if (setup.keepBothConnected) {
      list.push(
        notice('setup', `Windows may disconnect ${wifiName()} while a cable is plugged in, mostly after a restart.`, [
          actionButton('Keep both connected', 'Changing…', 'keep-both', () => api('/api/setup/keep-both', {})),
        ]),
      );
    }
    const changed = [];
    if (setup.changed.cableDefault) changed.push(`the ${main?.label ?? 'main line'} is the default connection`);
    if (setup.changed.keepBoth) changed.push('Wi-Fi stays connected while a cable is plugged in');
    if (changed.length) {
      list.push(
        notice('status', `Net Switch changed Windows settings: ${changed.join(', and ')}.`, [
          actionButton('Undo', 'Undoing…', 'undo', () => api('/api/setup/undo', {})),
        ]),
      );
    }
  }
  // While a panel is open its own error line shows this.
  if (actionError && !panel) list.push(notice('error', actionError));

  const signature = JSON.stringify([list.map((item) => item.textContent), busyAction]);
  if (els.notices.dataset.signature !== signature) {
    els.notices.replaceChildren(...list);
    els.notices.dataset.signature = signature;
  }
}

// ------------------------------------------------------------ channel strips

// A steady hue per app, so a letter avatar keeps its color from poll to poll.
function nameHue(name) {
  let hash = 0;
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return hash % 360;
}

function appIcon(app) {
  if (app.hasIcon) {
    const src = `/api/icon?key=${encodeURIComponent(app.key)}&token=${encodeURIComponent(token)}`;
    return h('span', { class: 'app-icon has-image' }, h('img', { src, alt: '', width: 18, height: 18 }));
  }
  const avatar = h('span', { class: 'app-icon', 'aria-hidden': 'true', text: (app.name || '?').charAt(0).toUpperCase() });
  // Set through the style object: the page's security policy allows that, not style attributes.
  avatar.style.setProperty('--hue', String(nameHue(app.name || '?')));
  return avatar;
}

function createRow(app) {
  const parts = {
    icon: h('span', { class: 'icon-slot' }),
    name: h('span', { class: 'app-name' }),
    meter: createMeter(ROW_CELLS, 'row'),
    down: h('span', { class: 'rate rate-down' }),
    up: h('span', { class: 'rate rate-up' }),
    route: h('div', { class: 'route' }),
    note: h('p', { class: 'strip-note', hidden: true }),
  };
  const node = h(
    'li',
    { class: 'strip' },
    h('div', { class: 'strip-main' }, parts.icon, parts.name, parts.meter, parts.down, parts.up, parts.route),
    parts.note,
  );
  const row = { node, parts, signature: {} };
  rows.set(app.key, row);
  return row;
}

function maxKeys() {
  return narrowWindow.matches ? MAX_KEYS_NARROW : MAX_KEYS;
}

// One key of the segmented control. Pressing the shown choice changes nothing.
// While a move is on its way the keys are marked unavailable rather than
// disabled, so the keyboard focus stays on the key that was pressed.
function lineKey(app, option) {
  const pending = pendingLine.has(app.key);
  const value = option.value ?? '';
  const pressed = !pending && (choiceOf(app) ?? '') === value;
  // No line changes for this app while its reconnect is running.
  const locked = pending || busyAction === `reconnect:${app.key}`;
  const key = h('button', {
    class: 'key',
    type: 'button',
    'data-focus': `key:${app.key}:${value}`,
    'aria-pressed': String(pressed),
    'aria-busy': pending && pendingLine.get(app.key) === value ? 'true' : null,
    'aria-disabled': locked ? 'true' : null,
    title: option.label.length > 12 ? option.label : null,
    onclick: () => {
      if (!pressed && !locked) chooseLine(app, option.value);
    },
  }, h('span', { class: 'key-label', text: option.label }));
  if (option.shared) sharedLook(key);
  else key.dataset.color = String(option.color);
  return key;
}

// More choices than keys fit: one list, its mark in the chosen line's color.
function linePicker(app, options) {
  const pending = pendingLine.has(app.key);
  const shown = pending ? pendingLine.get(app.key) : (choiceOf(app) ?? '');
  const chosen = options.find((option) => (option.value ?? '') === shown) ?? options[0];
  const locked = pending || busyAction === `reconnect:${app.key}`;
  const select = h(
    'select',
    {
      'aria-label': `Line for ${app.name}`,
      'data-focus': `pick:${app.key}`,
      'aria-busy': pending ? 'true' : null,
      'aria-disabled': locked ? 'true' : null,
      onchange: (event) => {
        if (locked) return;
        chooseLine(app, event.target.value || null);
      },
    },
    options.map((option) =>
      h('option', { value: option.value ?? '', text: option.label, selected: (option.value ?? '') === shown }),
    ),
  );
  const pick = h('div', { class: 'pick' }, select);
  if (chosen?.shared) sharedLook(pick);
  else pick.dataset.color = String(chosen?.color ?? 0);
  return pick;
}

function rowNote(app) {
  // Moving notes offer to reconnect, when the running Net Switch supports it.
  const canReconnect = state.features?.reconnect !== false && Boolean(app.reconnectable);
  const note = baseRowNote(app, canReconnect ? ', or press Reconnect' : '');
  if (note && note.movable && canReconnect) note.reconnect = true;
  return note;
}

// An app's connections on lines other than the one it belongs on: [[line, count], ...].
function strayConnections(app, withOutside = false) {
  const home = homeLine(app);
  return allLines()
    .filter((line) => line.id !== home?.id)
    .map((line) => [line, (app.connections?.[line.id] ?? 0) + (withOutside ? (app.outside?.byLine?.[line.id] ?? 0) : 0)])
    .filter(([, count]) => count > 0);
}

function placeText(entries) {
  return entries.length === 1 ? `the ${entries[0][0].label}` : 'other lines';
}

// What a reconnect would interrupt: the app's connections on other lines.
// While combining splits traffic, every sharing line is right for an app that
// shares them, so only the connections that go around Net Switch are
// interrupted (where is null then).
function reconnectSummary(app) {
  if (sharesLines(app)) return { count: app.outside?.connections ?? 0, where: null };
  const entries = strayConnections(app, true);
  return { count: entries.reduce((sum, [, count]) => sum + count, 0), where: placeText(entries) };
}

function baseRowNote(app, orReconnect) {
  const done = reconnected.get(app.key);
  if (done && Date.now() - done.at < RECONNECT_NOTE_MS) {
    if (done.failed > 0 && done.closed === 0) {
      return {
        kind: 'failed',
        text: `Couldn’t close ${app.name}’s connections. Try pausing and resuming the download in ${app.name} instead.`,
      };
    }
    if (done.closed > 0) {
      const partly = done.failed > 0 ? ` ${connectionCount(done.failed)} couldn’t be closed.` : '';
      return { kind: 'done', text: `Connections closed. If ${app.name} stopped, press resume in ${app.name}.${partly}` };
    }
    return { kind: 'done', text: 'Nothing left to close: those connections had already ended.' };
  }
  if (!routingOn()) return null;
  const home = homeLine(app);
  if (!home) return null;
  // Its line is down or over its cap, and another stands in: where the app is
  // now is right for the moment, so nothing is offered to move.
  const other = sharesLines(app) ? null : standIn(home);
  if (other) {
    const leftBehind = app.connections?.[home.id] ?? 0;
    const why = home.exhausted ? `The ${home.label} has used its data cap` : `The ${home.label} isn’t connected`;
    const until = home.exhausted ? 'until the cap resets' : 'until it’s back';
    const text =
      leftBehind > 0
        ? `${why}, so new connections use the ${other.label}. ${connectionWord(leftBehind)} still on the ${home.label}.`
        : `${why}, so new connections use the ${other.label} ${until}.`;
    return { kind: 'waiting', text, color: colorOf(other.id) };
  }
  // Connections that go around routing, usually because they were already open
  // when routing started. Worth a note while they carry data, or when the
  // person put this app on a line of its own.
  const extra = app.outside;
  if (extra && extra.connections > 0) {
    const active = extra.rate.down + extra.rate.up >= 1024 || !extra.measured;
    const placed = pinnedLine(app) && pinnedLine(app).id !== mainLine()?.id;
    if (active || placed) {
      const count = extra.connections;
      const text = extra.beforeRouting
        ? `${connectionCount(count)} started before routing was on, so Net Switch can’t move ${count === 1 ? 'it' : 'them'}. Try pausing and resuming the download in ${app.name}${orReconnect}.`
        : `${connectionCount(count)} ${count === 1 ? 'goes' : 'go'} around Net Switch, so ${count === 1 ? 'it' : 'they'} can’t be moved.`;
      return { kind: 'outside', text, movable: true };
    }
  }
  // While combining splits traffic, connections on any sharing line are where
  // they belong for an app that shares them.
  if (!sharesLines(app)) {
    const stray = strayConnections(app);
    const count = stray.reduce((sum, [, n]) => sum + n, 0);
    if (count > 0) {
      return {
        kind: 'moving',
        text: `${connectionWord(count)} still on ${placeText(stray)}. To move a running download, try pausing and resuming it in ${app.name}${orReconnect}.`,
        movable: true,
      };
    }
  }
  return null;
}

function reconnectButton(app) {
  const home = homeLine(app);
  const title = sharesLines(app)
    ? `Closes ${app.name}’s connections that go around Net Switch, so new ones are shared.`
    : `Closes ${app.name}’s connections that aren’t on the ${home?.label ?? 'main line'}, so new ones use the ${home?.label ?? 'main line'}.`;
  return h('button', {
    class: 'button',
    type: 'button',
    text: 'Reconnect',
    disabled: Boolean(busyAction),
    title,
    onclick: () => askToReconnect(app),
  });
}

// The second step: say exactly what will be interrupted before doing it.
function reconnectConfirmation(app) {
  const { count, where } = reconnectSummary(app);
  const busy = busyAction === `reconnect:${app.key}`;
  const what = where
    ? `the ${connectionCount(count)} ${app.name} has on ${where}`
    : `${app.name}’s ${connectionCount(count)} that ${count === 1 ? 'goes' : 'go'} around Net Switch`;
  return [
    h('span', {
      text: `This interrupts ${what}. A download may need you to press resume, or may start over.`,
    }),
    h(
      'span',
      { class: 'note-actions' },
      h('button', {
        class: 'button',
        type: 'button',
        text: busy ? 'Closing…' : 'Close connections',
        disabled: Boolean(busyAction),
        onclick: () => reconnect(app),
      }),
      h('button', {
        class: 'button button-quiet',
        type: 'button',
        text: 'Cancel',
        disabled: busy,
        onclick: cancelReconnect,
      }),
    ),
  ];
}

function updateRow(row, app, options, useList) {
  const { parts } = row;
  const iconSignature = `${app.hasIcon}|${app.name}`;
  if (row.signature.icon !== iconSignature) {
    parts.icon.replaceChildren(appIcon(app));
    row.signature.icon = iconSignature;
  }
  if (parts.name.textContent !== app.name) parts.name.textContent = app.name;
  parts.name.title = app.path || 'This app could not be identified';

  // Without current measurements show nothing rather than a false zero.
  const current = measuring();
  const lit = current ? litCells(app.rate.down, ROW_CELLS) : 0;
  setMeter(parts.meter, rowSegments(app, lit));

  parts.down.textContent = current ? formatRate(app.rate.down) : '';
  parts.up.textContent = current ? formatRate(app.rate.up) : '';
  if (app.rate.down < 1) parts.down.dataset.idle = '';
  else delete parts.down.dataset.idle;
  if (app.rate.up < 1) parts.up.dataset.idle = '';
  else delete parts.up.dataset.idle;

  const keysSignature = JSON.stringify([
    app.switchable,
    choiceOf(app),
    pendingLine.get(app.key) ?? null,
    busyAction === `reconnect:${app.key}`,
    options,
    useList,
    app.name,
    combining() ? sharingLines().map((line) => line.id) : null,
  ]);
  if (row.signature.keys !== keysSignature) {
    let control;
    if (!app.switchable) {
      control = h('div', { class: 'keys' }, h('span', { class: 'key-placeholder', text: 'Can’t be moved' }));
    } else if (useList) {
      control = linePicker(app, options);
    } else {
      control = h(
        'div',
        { class: 'keys', role: 'group', 'aria-label': `Line for ${app.name}` },
        options.map((option) => lineKey(app, option)),
      );
    }
    rebuildKeepingFocus(parts.route, () => [control], `route:${app.key}`);
    row.signature.keys = keysSignature;
  }

  const idle = !current || (app.rate.down < 1 && app.rate.up < 1);
  if (idle) row.node.dataset.idle = '';
  else delete row.node.dataset.idle;

  const note = rowNote(app);
  // A confirmation only makes sense while there is still something to reconnect.
  if (confirmingReconnect === app.key && !note?.reconnect) confirmingReconnect = null;
  const confirming = confirmingReconnect === app.key;
  parts.note.hidden = !note;
  const noteSignature = note
    ? `${note.kind}|${note.text}|${note.color ?? ''}|${Boolean(note.reconnect)}|${confirming}|${confirming ? reconnectSummary(app).count : ''}|${busyAction}|${sharing()}`
    : '';
  if (note && row.signature.note !== noteSignature) {
    parts.note.dataset.kind = confirming ? 'confirm' : note.kind;
    if (note.color !== undefined && !confirming) parts.note.dataset.color = String(note.color);
    else delete parts.note.dataset.color;
    if (confirming) {
      parts.note.replaceChildren(...reconnectConfirmation(app));
    } else {
      const content = [h('span', { text: note.text })];
      if (note.reconnect) content.push(reconnectButton(app));
      parts.note.replaceChildren(...content);
    }
  }
  row.signature.note = noteSignature;
}

function renderApps() {
  const apps = state.apps;
  const byKey = new Map(apps.map((app) => [app.key, app]));
  const now = Date.now();
  const unseen = apps.some((app) => !order.includes(app.key));
  if (unseen || now - lastSortAt > RESORT_MS) {
    order = [...apps]
      .sort((a, b) => b.sortScore - a.sortScore || a.name.localeCompare(b.name))
      .map((app) => app.key);
    lastSortAt = now;
  }
  order = order.filter((key) => byKey.has(key));

  for (const [key, row] of rows) {
    if (!byKey.has(key)) {
      row.node.remove();
      rows.delete(key);
    }
  }
  const options = lineOptions();
  const useList = options.length > maxKeys();
  order.forEach((key, index) => {
    const app = byKey.get(key);
    const row = rows.get(key) ?? createRow(app);
    updateRow(row, app, options, useList);
    if (els.apps.children[index] !== row.node) els.apps.insertBefore(row.node, els.apps.children[index] ?? null);
  });

  els.legends.hidden = apps.length === 0;
  // The route column widens with the number of keys; a list takes a fixed width.
  els.channels.dataset.keys = useList ? 'list' : String(options.length);
  renderEmpty(apps.length === 0);
}

function renderEmpty(isEmpty) {
  const status = state.routing.status;
  const showEmpty = isEmpty && status === 'on';
  els.empty.hidden = !showEmpty;
  if (showEmpty && !els.empty.hasChildNodes()) {
    els.empty.append(h('p', { text: 'No app is using the internet right now.' }));
  }

  // Above the strips: what happens to every app while routing isn't on.
  let signature = '';
  let content = [];
  if (status === 'off') {
    signature = `off|${busyAction}`;
    content = [
      h('p', { text: 'Routing is off. Every app uses Windows’ normal connection.' }),
      actionButton('Turn on routing', 'Starting…', 'routing-on', () => api('/api/routing', { on: true })),
    ];
  } else if (status === 'starting') {
    signature = 'starting';
    content = [h('p', { text: 'Starting routing…' })];
  } else if (status === 'stopping') {
    signature = 'stopping';
    content = [h('p', { text: 'Turning off routing…' })];
  }
  els.listMessage.hidden = signature === '';
  if (els.listMessage.dataset.signature !== signature) {
    els.listMessage.replaceChildren(...content);
    els.listMessage.dataset.signature = signature;
  }
}

// ------------------------------------------------------------ side panel

// Rebuilds a part of the window without losing the keyboard's place in it:
// the element with the same data-focus gets the focus back, and a text field
// its caret.
function rebuildKeepingFocus(container, build, fallbackKey = null) {
  const active = document.activeElement;
  const inside = active && active !== document.body && container.contains(active);
  const key = inside ? (active.dataset.focus ?? fallbackKey) : null;
  let selection = null;
  if (inside && typeof active.selectionStart === 'number') selection = [active.selectionStart, active.selectionEnd];
  container.replaceChildren(...build());
  if (!key) return;
  // A control that is gone (Make main line, once the line is main) hands the
  // focus to the panel's Close, so it never drops out of the panel.
  const next =
    container.querySelector(`[data-focus="${CSS.escape(key)}"]`) ??
    (key === fallbackKey ? container.querySelector('button:not(:disabled), select:not(:disabled)') : null) ??
    (container === els.panel ? container.querySelector('[data-focus="close"]') : null);
  if (!next) return;
  next.focus();
  if (selection && typeof next.setSelectionRange === 'function') {
    try {
      next.setSelectionRange(...selection);
    } catch {
      // Not every field keeps a caret.
    }
  }
}

function openSettingsPanel() {
  panel = { kind: 'settings' };
  drafts.probeTargets = null;
  actionError = null;
  failedAction = null;
  render();
}

function closePanel() {
  if (els.panel.open) els.panel.close();
}

function panelHead(title, detail, icon = null) {
  return h(
    'header',
    { class: 'panel-head' },
    icon,
    h(
      'div',
      { class: 'panel-title' },
      h('h2', { id: 'panel-title', text: title, title }),
      detail ? h('p', { text: detail, title: detail }) : null,
    ),
    h('button', {
      class: 'icon-button icon-close',
      type: 'button',
      'aria-label': 'Close',
      title: 'Close (Esc)',
      'data-focus': 'close',
      onclick: closePanel,
    }),
  );
}

// An on/off setting: its name and what it does on the left, the switch on the
// right. While something else is saving it is marked unavailable, not
// disabled, so the keyboard focus stays on it.
function switchRow({ id, name, help, checked, busy, disabled, onToggle }) {
  return h(
    'div',
    { class: 'setting' },
    h(
      'div',
      { class: 'setting-text' },
      h('label', { class: 'setting-name', for: id, text: name }),
      help ? h('p', { class: 'setting-help', id: `${id}-help`, text: help }) : null,
    ),
    h('button', {
      class: 'switch',
      id,
      type: 'button',
      role: 'switch',
      'data-focus': id,
      'aria-checked': String(busy ? !checked : checked),
      'aria-busy': busy ? 'true' : null,
      'aria-describedby': help ? `${id}-help` : null,
      'aria-disabled': disabled ? 'true' : null,
      onclick: () => {
        if (!disabled) onToggle();
      },
    }),
  );
}

// The field each saving action belongs to: its error shows under that field.
const FIELD_OF = { 'line-label': 'name', 'line-cap': 'cap', 'probe-targets': 'targets' };

function fieldFailed(field) {
  return Boolean(actionError) && FIELD_OF[failedAction] === field;
}

function fieldError(field) {
  return fieldFailed(field) ? h('p', { class: 'field-error', id: `${field}-error`, role: 'alert', text: actionError }) : null;
}

// The keyboard goes to a field with an error, so it can be fixed straight away.
function focusField(field) {
  const focusKey = { name: 'name', cap: 'cap-amount', targets: 'targets' }[field];
  els.panel.querySelector(`[data-focus="${focusKey}"]`)?.focus();
}

// A field's error, shown under it before anything is sent.
function failField(action, message) {
  actionError = message;
  failedAction = action;
  render();
  focusField(FIELD_OF[action]);
}

function panelError() {
  if (!actionError || FIELD_OF[failedAction]) return null;
  return h('p', { class: 'panel-error', role: 'alert', text: actionError });
}

function updateLine(line, changes, name) {
  return run(name, () => api('/api/lines/update', { id: line.id, ...changes }));
}

async function saveLabel(line) {
  const label = (drafts.label ?? line.label).trim();
  if (!label) {
    failField('line-label', 'Give the line a name.');
    return;
  }
  if (label === line.label) {
    drafts.label = null;
    render();
    return;
  }
  if (await updateLine(line, { label }, 'line-label')) {
    drafts.label = null;
    render();
  } else if (fieldFailed('name')) {
    focusField('name');
  }
}

async function saveCap(line, form) {
  if (line.cap && drafts.cap === null) return;
  const amount = Number(String(form.elements.amount.value).replace(',', '.'));
  const period = drafts.cap?.period ?? line.cap?.period ?? 'month';
  if (!(amount > 0)) {
    failField('line-cap', 'Enter a data cap above 0 GB, like 10.');
    return;
  }
  const cap = { bytes: Math.round(amount * GB), period };
  if (await updateLine(line, { cap }, 'line-cap')) {
    drafts.cap = null;
    render();
  } else if (fieldFailed('cap')) {
    focusField('cap');
  }
}

function toggleCap(line) {
  if (line.cap) {
    drafts.cap = null;
    updateLine(line, { cap: null }, 'line-cap-off');
  } else {
    drafts.cap = drafts.cap ? null : { period: 'month' };
    actionError = null;
    failedAction = null;
    render();
    els.panel.querySelector('[data-focus="cap-amount"]')?.focus();
  }
}

function capAmountText(line) {
  if (!line.cap) return '10';
  return String(Number((line.cap.bytes / GB).toFixed(2)));
}

function buildLinePanel(line) {
  const index = allLines().indexOf(line);
  const count = allLines().length;
  const main = mainLine();
  const busy = Boolean(busyAction);
  const restartNote = routingOn() ? ' Routing restarts for a moment.' : '';
  const where = [line.alias, line.ssid].filter(Boolean).join(' · ');
  const icon = h('span', { class: 'line-icon', 'data-icon': lineIcon(line.kind), 'data-color': String(index % PALETTE_SIZE), 'aria-hidden': 'true' });
  const sections = [];

  const nameField = h('input', {
    id: 'line-name',
    class: 'input',
    type: 'text',
    name: 'label',
    maxlength: '40',
    autocomplete: 'off',
    spellcheck: 'false',
    'data-focus': 'name',
    'aria-invalid': fieldFailed('name') ? 'true' : null,
    'aria-describedby': fieldFailed('name') ? 'name-error' : null,
    value: drafts.label ?? line.label,
    oninput: (event) => {
      drafts.label = event.target.value;
      markUnavailable(saveName, busy || drafts.label.trim() === line.label);
    },
  });
  // Saving an unchanged name does nothing, so the button only looks unavailable then.
  const saveName = h('button', {
    class: 'button',
    type: 'submit',
    'data-focus': 'name-save',
    text: busyAction === 'line-label' ? 'Saving…' : 'Save',
    'aria-disabled': busy || (drafts.label ?? line.label).trim() === line.label ? 'true' : null,
  });
  sections.push(
    h(
      'section',
      { class: 'panel-section' },
      h('label', { class: 'field-label', for: 'line-name', text: 'Name' }),
      h(
        'form',
        {
          class: 'field-row',
          onsubmit: (event) => {
            event.preventDefault();
            saveLabel(line);
          },
        },
        nameField,
        saveName,
      ),
      fieldError('name'),
    ),
  );

  sections.push(
    h(
      'section',
      { class: 'panel-section' },
      index === 0
        ? h(
            'div',
            { class: 'setting' },
            h(
              'div',
              { class: 'setting-text' },
              h('span', { class: 'setting-name', text: 'Main line' }),
              h('p', { class: 'setting-help', text: 'Apps you haven’t put on a line use this one. If it drops, they move to the next line that works.' }),
            ),
          )
        : h(
            'div',
            { class: 'setting' },
            h(
              'div',
              { class: 'setting-text' },
              h('span', { class: 'setting-name', text: 'Main line' }),
              h('p', {
                class: 'setting-help',
                id: 'make-main-help',
                text: `Apps you haven’t put on a line use the ${main.label} now.${restartNote}`,
              }),
            ),
            h('button', {
              class: 'button',
              type: 'button',
              'data-focus': 'make-main',
              'aria-describedby': 'make-main-help',
              text: busyAction === 'line-main' ? 'Changing…' : 'Make main line',
              'aria-disabled': busy ? 'true' : null,
              // By id: the panel was built from an earlier reading of the lines.
              onclick: () =>
                run('line-main', () =>
                  api('/api/lines/order', {
                    ids: [line.id, ...allLines().filter((item) => item.id !== line.id).map((item) => item.id)],
                  }),
                ),
            }),
          ),
    ),
  );

  const data = [
    switchRow({
      id: 'line-metered',
      name: 'Metered',
      help: 'It costs data, like a phone plan. Net Switch counts what this line uses.',
      checked: Boolean(line.metered),
      busy: busyAction === 'line-metered',
      disabled: busy,
      onToggle: () => updateLine(line, { metered: !line.metered }, 'line-metered'),
    }),
  ];
  // Any line but the main one, which carries every app without a line of its own.
  if (index !== 0) {
    data.push(
      switchRow({
        id: 'line-strict',
        name: 'Only apps I choose',
        help: 'Other apps never use it, even when another line drops.',
        checked: Boolean(line.strict),
        busy: busyAction === 'line-strict',
        disabled: busy,
        onToggle: () => updateLine(line, { strict: !line.strict }, 'line-strict'),
      }),
    );
  }
  if (line.metered || line.cap) {
    const editing = Boolean(line.cap) || drafts.cap !== null;
    data.push(
      switchRow({
        id: 'line-cap',
        name: 'Data cap',
        help: line.cap || drafts.cap ? null : 'Stop using this line for a while once it has used a set amount.',
        checked: editing,
        busy: busyAction === 'line-cap-off',
        disabled: busy,
        onToggle: () => toggleCap(line),
      }),
    );
    if (editing) {
      const period = drafts.cap?.period ?? line.cap?.period ?? 'month';
      const save = h('button', {
        class: 'button',
        type: 'submit',
        'data-focus': 'cap-save',
        text: busyAction === 'line-cap' ? 'Saving…' : 'Save',
        'aria-disabled': busy || (Boolean(line.cap) && drafts.cap === null) ? 'true' : null,
      });
      const markChanged = (next) => {
        drafts.cap = { ...(drafts.cap ?? {}), period: drafts.cap?.period ?? period, ...next };
      };
      data.push(
        h(
          'form',
          {
            class: 'cap-form',
            onsubmit: (event) => {
              event.preventDefault();
              saveCap(line, event.currentTarget);
            },
          },
          h(
            'div',
            { class: 'field-row' },
            h(
              'span',
              { class: 'input-unit' },
              h('input', {
                class: 'input',
                type: 'number',
                name: 'amount',
                min: '0.1',
                step: '0.1',
                inputmode: 'decimal',
                'aria-label': 'Data cap in GB',
                'aria-invalid': fieldFailed('cap') ? 'true' : null,
                'aria-describedby': fieldFailed('cap') ? 'cap-error' : null,
                'data-focus': 'cap-amount',
                value: drafts.cap?.amount ?? capAmountText(line),
                oninput: (event) => {
                  markChanged({ amount: event.target.value });
                  markUnavailable(save, busy);
                },
              }),
              h('span', { text: 'GB', 'aria-hidden': 'true' }),
            ),
            h(
              'div',
              { class: 'keys keys-plain', role: 'group', 'aria-label': 'Cap per' },
              ['day', 'month'].map((value) =>
                h('button', {
                  class: 'key',
                  type: 'button',
                  'data-focus': `cap-${value}`,
                  'aria-pressed': String(period === value),
                  text: value === 'day' ? 'Per day' : 'Per month',
                  'aria-disabled': busy ? 'true' : null,
                  onclick: (event) => {
                    if (busyAction || period === value) return;
                    markChanged({ period: value, amount: event.currentTarget.form.elements.amount.value });
                    render();
                  },
                }),
              ),
            ),
            save,
          ),
          fieldError('cap'),
          h('p', {
            class: 'field-help',
            'data-live': 'usage',
            text: capHelp(line, period),
          }),
        ),
      );
    }
  }
  sections.push(h('section', { class: 'panel-section' }, data));

  let remove;
  if (confirmingRemove) {
    const goes =
      index === 0
        ? `The ${allLines()[1]?.label} becomes the main line, and this line’s apps go to it.`
        : `Its apps go to the ${main.label}.`;
    remove = h(
      'div',
      { class: 'confirm' },
      h('p', { text: `Stop using the ${line.label}? ${goes}${restartNote}` }),
      h(
        'div',
        { class: 'confirm-actions' },
        h('button', {
          class: 'button button-danger',
          type: 'button',
          'data-focus': 'remove-confirm',
          text: busyAction === 'line-remove' ? 'Removing…' : 'Remove line',
          'aria-disabled': busy ? 'true' : null,
          onclick: () => run('line-remove', () => api('/api/lines/remove', { id: line.id })),
        }),
        h('button', {
          class: 'button button-quiet',
          type: 'button',
          'data-focus': 'remove-cancel',
          text: 'Cancel',
          'aria-disabled': busyAction === 'line-remove' ? 'true' : null,
          onclick: () => {
            if (busyAction === 'line-remove') return;
            confirmingRemove = false;
            render();
            els.panel.querySelector('[data-focus="remove"]')?.focus();
          },
        }),
      ),
    );
  } else {
    remove = h(
      'div',
      { class: 'setting' },
      h(
        'div',
        { class: 'setting-text' },
        h('span', { class: 'setting-name', text: 'Remove line' }),
        h('p', {
          class: 'setting-help',
          id: 'remove-help',
          text: count === 1 ? 'Net Switch needs at least one line.' : 'Net Switch stops using this adapter. You can add it again later.',
        }),
      ),
      h('button', {
        class: 'button button-quiet button-danger',
        type: 'button',
        'data-focus': 'remove',
        'aria-describedby': 'remove-help',
        text: 'Remove…',
        disabled: count === 1,
        'aria-disabled': busy ? 'true' : null,
        onclick: () => {
          if (busyAction) return;
          confirmingRemove = true;
          render();
          els.panel.querySelector('[data-focus="remove-confirm"]')?.focus();
        },
      }),
    );
  }
  sections.push(h('section', { class: 'panel-section' }, remove));

  return [panelHead(line.label, where, icon), h('div', { class: 'panel-body' }, panelError(), sections)];
}

function capHelp(line, period) {
  const until = period === 'day' ? 'the next day' : 'next month';
  if (!line.cap) return `When it’s used up, this line’s apps use other lines until ${until}.`;
  if (line.exhausted) return `${usageText(line)}. It’s used up, so this line’s apps use other lines until ${until}.`;
  return `${usageText(line)}. When it’s used up, this line’s apps use other lines until ${until}.`;
}

function parseTargets(text) {
  const items = text.split(/[\s,]+/).filter(Boolean);
  if (items.length === 0) return { error: 'Enter at least one test site, like 1.1.1.1:443.' };
  for (const item of items) {
    const match = /^([\w.-]+):(\d{1,5})$/.exec(item);
    if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) {
      return { error: `“${item}” isn’t written as address:port, like 1.1.1.1:443.` };
    }
  }
  return { targets: items };
}

async function saveTargets(form) {
  if (drafts.probeTargets === null) return;
  const { targets, error } = parseTargets(form.elements.targets.value);
  if (error) {
    failField('probe-targets', error);
    return;
  }
  if (await run('probe-targets', () => api('/api/settings', { probeTargets: targets }))) {
    drafts.probeTargets = null;
    render();
  } else if (fieldFailed('targets')) {
    focusField('targets');
  }
}

function updateChecksValue() {
  const value = state.settings?.checkForUpdates ?? state.updateChecks;
  return typeof value === 'boolean' ? value : null;
}

function buildSettingsPanel() {
  const settings = state.settings ?? {};
  const busy = Boolean(busyAction);
  const rows = [];
  if (typeof settings.autostart === 'boolean') {
    rows.push(
      switchRow({
        id: 'setting-autostart',
        name: 'Start with Windows',
        help: 'Open Net Switch when you sign in to Windows.',
        checked: settings.autostart,
        busy: busyAction === 'autostart',
        disabled: busy,
        onToggle: () => run('autostart', () => api('/api/settings', { autostart: !settings.autostart })),
      }),
    );
  }
  // Test mode never checks for updates, so it offers no switch for it.
  const checks = updateChecksValue();
  if (checks !== null && state.mode !== 'proxy') {
    rows.push(
      switchRow({
        id: 'setting-updates',
        name: 'Check for updates',
        help: 'Net Switch asks GitHub twice a day whether a newer version is out. It never installs anything by itself.',
        checked: checks,
        busy: busyAction === 'update-checks',
        disabled: busy,
        onToggle: () => run('update-checks', () => api('/api/settings', { checkForUpdates: !checks })),
      }),
    );
  }
  const sections = rows.length ? [h('section', { class: 'panel-section' }, rows)] : [];

  if (Array.isArray(settings.probeTargets)) {
    const save = h('button', {
      class: 'button',
      type: 'submit',
      'data-focus': 'targets-save',
      text: busyAction === 'probe-targets' ? 'Saving…' : 'Save',
      'aria-disabled': busy || drafts.probeTargets === null ? 'true' : null,
    });
    sections.push(
      h(
        'details',
        {
          class: 'panel-section advanced',
          open: advancedOpen,
          ontoggle: (event) => {
            advancedOpen = event.currentTarget.open;
          },
        },
        h('summary', { 'data-focus': 'advanced', text: 'Advanced' }),
        h(
          'div',
          { class: 'details-body' },
          h('label', { class: 'field-label', for: 'probe-targets', text: 'Test sites' }),
          h(
            'form',
            {
              class: 'field-row',
              onsubmit: (event) => {
                event.preventDefault();
                saveTargets(event.currentTarget);
              },
            },
            h('input', {
              id: 'probe-targets',
              class: 'input input-mono',
              type: 'text',
              name: 'targets',
              autocomplete: 'off',
              spellcheck: 'false',
              'aria-describedby': fieldFailed('targets') ? 'targets-error probe-targets-help' : 'probe-targets-help',
              'aria-invalid': fieldFailed('targets') ? 'true' : null,
              'data-focus': 'targets',
              value: drafts.probeTargets ?? settings.probeTargets.join(', '),
              oninput: (event) => {
                drafts.probeTargets = event.target.value;
                markUnavailable(save, busy);
              },
            }),
            save,
          ),
          fieldError('targets'),
          h('p', {
            class: 'field-help',
            id: 'probe-targets-help',
            text: 'Net Switch checks each line’s internet by connecting to these through that line. Write each as address:port, separated by commas.',
          }),
        ),
      ),
    );
  }

  return [panelHead('Settings', state.version ? `Net Switch ${state.version}` : null), h('div', { class: 'panel-body' }, panelError(), sections)];
}

function renderPanel() {
  const dialog = els.panel;
  const line = panel?.kind === 'line' ? lineById(panel.id) : null;
  if (!panel || !state || (panel.kind === 'line' && !line)) {
    // The line was removed, or nothing is open.
    panel = null;
    if (dialog.open) dialog.close();
    return;
  }
  const signature =
    panel.kind === 'line'
      ? JSON.stringify([
          'line',
          allLines().indexOf(line),
          allLines().length,
          line.label,
          line.alias,
          line.ssid,
          line.kind,
          line.metered,
          line.strict,
          line.cap,
          mainLine()?.label,
          routingOn(),
          busyAction,
          actionError,
          failedAction,
          confirmingRemove,
          !line.cap && drafts.cap !== null,
          drafts.cap?.period ?? null,
        ])
      : JSON.stringify(['settings', state.settings, state.updateChecks, state.mode, state.version, busyAction, actionError, failedAction]);
  if (dialog.dataset.signature !== signature) {
    rebuildKeepingFocus(dialog, () => [
      h('div', { class: 'panel' }, ...(panel.kind === 'line' ? buildLinePanel(line) : buildSettingsPanel())),
    ]);
    dialog.dataset.signature = signature;
  }
  // The data used moves every second; only its text changes.
  if (line) {
    const usage = dialog.querySelector('[data-live="usage"]');
    if (usage) {
      const text = capHelp(line, drafts.cap?.period ?? line.cap?.period ?? 'month');
      if (usage.textContent !== text) usage.textContent = text;
    }
  }
  if (!dialog.open) dialog.showModal();
}

els.panel.addEventListener('close', () => {
  panel = null;
  confirmingRemove = false;
  drafts.label = null;
  drafts.cap = null;
  drafts.probeTargets = null;
  // An error shown in the panel was seen there.
  actionError = null;
  failedAction = null;
  els.panel.dataset.signature = '';
  render();
  // The panel hands the focus back to what opened it; when that is gone (the
  // line was removed), the main line's Settings takes it rather than the page.
  if (document.activeElement === document.body || !document.activeElement) {
    els.lines.querySelector('.bus [aria-haspopup="dialog"]')?.focus();
  }
});

// A click on the dimmed window around the panel closes it.
els.panel.addEventListener('click', (event) => {
  if (event.target === els.panel) closePanel();
});

// ------------------------------------------------------------ main loop

function render() {
  renderTopbar();
  renderNotices();
  if (!state) return;
  renderLines();
  renderCombine();
  renderApps();
  renderPanel();
}

async function poll() {
  if (closed) return;
  try {
    state = await api('/api/state');
    unreachable = false;
    outdated = false;
  } catch (error) {
    if (error.outdated) outdated = true;
    else unreachable = true;
  }
  // A reading that was under way when Net Switch quit must not redraw over the closed screen.
  if (closed) return;
  render();
  // An outdated window can't recover on its own; a new key arrives only by reopening.
  if (!outdated) pollTimer = setTimeout(poll, 1000);
}

els.toggle.addEventListener('click', toggleRouting);
els.quit.addEventListener('click', quit);
els.openSettings.addEventListener('click', openSettingsPanel);
narrowWindow.addEventListener('change', () => {
  if (state) render();
});
window.addEventListener('hashchange', () => {
  const next = readToken();
  if (!next || next === token) return;
  token = next;
  outdated = false;
  clearTimeout(pollTimer);
  poll();
});

if (token) {
  poll();
} else {
  render();
}
