'use strict';

let token = readToken();
const MASTER_CELLS = 36;
const ROW_CELLS = 12;
const RESORT_MS = 3000;

const els = {
  status: document.getElementById('routing-status'),
  toggle: document.getElementById('routing-toggle'),
  busMain: document.getElementById('bus-main'),
  busSecond: document.getElementById('bus-second'),
  combine: document.getElementById('combine'),
  notices: document.getElementById('notices'),
  apps: document.getElementById('apps'),
  empty: document.getElementById('empty'),
  listMessage: document.getElementById('list-message'),
  legends: document.querySelector('.legends'),
  quit: document.getElementById('quit'),
  statDownload: document.getElementById('stat-download'),
  statUpload: document.getElementById('stat-upload'),
};

let state = null;
let unreachable = false;
// The server restarted since this window opened, so its key no longer works.
let outdated = false;
let actionError = null;
let busyAction = null;
let order = [];
let lastSortAt = 0;
let pollTimer = null;
const pendingLane = new Map();
const rows = new Map();
// After a reconnect, what the person should know for a short while.
const reconnected = new Map();
const RECONNECT_NOTE_MS = 15_000;
// How long the note about connections moved back to the second connection stays.
const MOVED_BACK_NOTE_MS = 30_000;
// The app whose Reconnect is waiting for a second, confirming click.
let confirmingReconnect = null;
// After Quit only the closed screen is left: nothing polls or redraws any more.
let closed = false;

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

// Net Switch closed the connections that had moved to the other line while a
// line was away, so their apps open new ones on it. line is 'main' or 'second'.
function movedBackText(line, { closed, failed }) {
  const label = line === 'main' ? 'cable' : secondLabel();
  const other = line === 'main' ? secondLabel() : 'cable';
  if (closed === 0) {
    return `The ${label} is back, but ${connectionCount(failed)} that had moved to the ${other} couldn’t be closed. Try pausing and resuming those downloads.`;
  }
  const partly = failed > 0 ? ` ${connectionCount(failed)} couldn’t be closed.` : '';
  return `The ${label} is back. ${connectionCount(closed)} that had moved to the ${other} ${closed === 1 ? 'was' : 'were'} closed so apps can open new ones on it. A download may need you to press resume.${partly}`;
}

// A line's health in its card: [text, tone]. The ping is the last internet
// test's round trip, which only runs while routing is on with both lines.
function lineHealth(lane) {
  if (lane.problem === 'no internet') return ['No internet', 'warn'];
  if (lane.problem) return [lane.problem === 'no address' ? 'No address' : 'No route', 'down'];
  if (!lane.connected) return ['Not connected', 'down'];
  if (routingOn() && Number.isFinite(lane.ping)) return [`${lane.ping} ms`, 'ok'];
  return ['Online', 'ok'];
}

// The line under a line's meter: what it is doing right now.
function lineFoot(line, lane) {
  if (!routingOn()) return 'Routing is off';
  if (line === 'main' && lane.carryingApps === false) return `Its apps use the ${secondLabel()} until it’s back`;
  if (line === 'second' && !lane.carryingApps) return 'Its apps use the cable until it’s back';
  if (Number.isFinite(lane.connections)) return `Carrying ${connectionCount(lane.connections)}`;
  return '';
}

// The pill in the top bar: [text, tone].
function routingSummary() {
  const status = state.routing.status;
  if (status === 'starting') return ['Starting routing…', 'idle'];
  if (status === 'stopping') return ['Turning off routing…', 'idle'];
  if (status === 'off') return ['Routing off', 'idle'];
  if (status === 'error') return ['Routing stopped', 'down'];
  const { main, second } = state.lanes;
  if (main.carryingApps === false) return [`Routing on · running on the ${secondLabel()}`, 'warn'];
  if (second && !second.carryingApps) return ['Routing on · cable only', 'warn'];
  return [second ? 'Routing on · both lines online' : 'Routing on', 'ok'];
}

function secondLabel() {
  return state?.lanes.second?.label ?? 'Wi-Fi stick';
}

function routingOn() {
  return state?.routing.status === 'on';
}

// Routing is on and the engine is answering, so the speeds shown are current.
function measuring() {
  return routingOn() && state.routing.measuring;
}

// The person chose to combine both lines. An older Net Switch that can't
// combine sends no combine state, so this window then shows none of it.
function combining() {
  return Boolean(state?.features?.combine && state.combine?.on && state.lanes.second);
}

// Combining is really splitting new connections right now. While the second
// connection is down they all use the cable, so apps behave as without it.
function sharing() {
  return combining() && Boolean(state.combine.active);
}

// ------------------------------------------------------------ meters

function createMeter(count, kind) {
  const meter = h('div', { class: `meter meter-${kind}`, 'aria-hidden': 'true' });
  for (let i = 0; i < count; i += 1) meter.append(h('span', { class: 'cell' }));
  return meter;
}

// mainShare cells light in the cable color first, the rest in the second color.
function setMeter(meter, lit, secondLit) {
  const cells = meter.children;
  const mainLit = lit - secondLit;
  for (let i = 0; i < cells.length; i += 1) {
    const value = i < mainLit ? 'main' : i < lit ? 'second' : null;
    if (cells[i].dataset.lit !== value) {
      if (value) cells[i].dataset.lit = value;
      else delete cells[i].dataset.lit;
    }
  }
}

// ------------------------------------------------------------ actions

async function run(name, task) {
  if (busyAction) return;
  busyAction = name;
  actionError = null;
  render();
  try {
    const result = await task();
    if (result?.lanes) state = result;
  } catch (error) {
    actionError = error.message;
  } finally {
    busyAction = null;
    render();
  }
}

async function chooseLane(app, lane) {
  if (app.lane === lane || pendingLane.has(app.key)) return;
  pendingLane.set(app.key, lane);
  actionError = null;
  render();
  try {
    state = await api('/api/app-lane', { path: app.path, lane });
  } catch (error) {
    actionError = error.message;
  } finally {
    pendingLane.delete(app.key);
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

  // Quit needs a working connection to the server; without one it would only pretend.
  els.quit.hidden = stale || !token;

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

function renderStats() {
  if (!els.statDownload || !els.statUpload || !state?.lanes) return;
  const lanes = Object.values(state.lanes).filter(Boolean);
  const download = lanes.reduce((total, lane) => total + (lane.rate?.down ?? 0), 0);
  const upload = lanes.reduce((total, lane) => total + (lane.rate?.up ?? 0), 0);
  els.statDownload.textContent = measuring() ? formatRate(download) : '—';
  els.statUpload.textContent = measuring() ? formatRate(upload) : '—';
}

// ------------------------------------------------------------ master section

// The head of a line's card: its icon, name and adapter, and on the right its
// health, or for a card without a line yet, nothing.
function busHead(icon, name, detail, health) {
  return h(
    'div',
    { class: 'bus-head' },
    h('span', { class: 'line-icon', 'data-icon': icon, 'aria-hidden': 'true' }),
    h('div', { class: 'bus-name' }, h('strong', { text: name }), detail ? h('span', { text: detail }) : null),
    health ? h('div', { class: 'health' }, h('i', { class: 'dot' }), h('span')) : null,
  );
}

// Built once per card; the values change in place every second (renderBus).
function lineCard(bus, icon, name, detail, action) {
  bus.append(
    busHead(icon, name, detail, true),
    h(
      'div',
      { class: 'bus-reading' },
      h('div', { class: 'reading-down' }, h('span', { class: 'reading-value' }), h('span', { class: 'reading-unit' })),
      h('span', { class: 'reading-up' }),
    ),
    createMeter(MASTER_CELLS, 'master'),
    h('div', { class: 'bus-foot' }, h('span', { class: 'bus-note' }), action ?? null),
  );
}

// Rebuilding the cards each second would restart the meter transitions, so
// the structure is reused while it is unchanged and only the values move.
function renderBus(bus, signature, build, line, lane) {
  if (bus.dataset.signature !== signature) {
    bus.replaceChildren();
    build();
    bus.dataset.signature = signature;
  }
  const rate = lane?.rate;
  const meter = bus.querySelector('.meter');
  if (meter) {
    const lit = rate ? litCells(rate.down, MASTER_CELLS) : 0;
    setMeter(meter, lit, line === 'second' ? lit : 0);
  }
  const value = bus.querySelector('.reading-value');
  if (!value) return;
  const [number, unit] = rate ? rateParts(rate.down) : ['—', ''];
  value.textContent = number;
  bus.querySelector('.reading-unit').textContent = rate ? `${unit} ↓` : '';
  bus.querySelector('.reading-up').textContent = rate ? `↑ ${formatRate(rate.up)}` : 'Speed isn’t available right now';
  const [healthText, tone] = lineHealth(lane);
  const health = bus.querySelector('.health');
  health.dataset.tone = tone;
  health.querySelector('span').textContent = healthText;
  bus.querySelector('.bus-foot .bus-note').textContent = lineFoot(line, lane);
  if (tone === 'ok') delete bus.dataset.down;
  else bus.dataset.down = tone;
}

function renderMaster() {
  const main = state.lanes.main;
  renderBus(
    els.busMain,
    `main|${main.alias}`,
    () => lineCard(els.busMain, 'cable', 'Cable', main.alias ?? 'No cable found'),
    'main',
    main,
  );

  const second = state.lanes.second;
  if (!second) {
    renderSecondSetup();
    return;
  }
  const where = second.ssid ? `${second.alias} · ${second.ssid}` : second.alias;
  const removing = busyAction === 'second';
  renderBus(
    els.busSecond,
    `second|${second.label}|${where}|${second.kind}|${removing}|${Boolean(busyAction)}`,
    () =>
      lineCard(
        els.busSecond,
        second.kind === 'phone' ? 'phone' : 'wifi',
        second.label,
        where,
        h('button', {
          class: 'button button-quiet',
          type: 'button',
          text: removing ? 'Removing…' : 'Remove',
          disabled: Boolean(busyAction),
          title: 'Stop using this connection. Its apps go back to the cable.',
          onclick: () => run('second', () => api('/api/second-connection', { alias: null })),
        }),
      ),
    'second',
    second,
  );
}

function renderSecondSetup() {
  const candidates = state.candidates;
  const signature = `setup|${candidates.map((item) => `${item.alias}:${item.ssid}`).join(',')}|${busyAction}|${routingOn()}`;
  if (els.busSecond.dataset.signature === signature) return;
  els.busSecond.dataset.signature = signature;
  delete els.busSecond.dataset.down;

  if (candidates.length === 0) {
    els.busSecond.replaceChildren(
      busHead('wifi', 'Wi-Fi stick', 'not set up'),
      h('p', {
        class: 'bus-note',
        text: 'Plug in the Wi-Fi stick and connect it to a Wi-Fi network. A phone with USB tethering works too.',
      }),
    );
    return;
  }

  const list = h('div', { class: 'bus-setup' });
  for (const candidate of candidates) {
    const name = candidate.ssid ? `${candidate.alias} · ${candidate.ssid}` : candidate.alias;
    const choosing = busyAction === `use:${candidate.alias}`;
    list.append(
      h(
        'div',
        { class: 'candidate' },
        h('span', { text: `${candidate.label}: ${name}` }),
        h('button', {
          class: 'button',
          type: 'button',
          text: choosing ? 'Setting up…' : 'Use as second connection',
          disabled: Boolean(busyAction),
          onclick: () =>
            run(`use:${candidate.alias}`, () => api('/api/second-connection', { alias: candidate.alias })),
        }),
      ),
    );
  }
  if (routingOn()) {
    list.append(
      h('p', {
        class: 'bus-note',
        text: 'Routing restarts for a moment. A running download may need you to press resume.',
      }),
    );
  }
  els.busSecond.replaceChildren(busHead('wifi', 'Second connection', 'found'), list);
}

// ------------------------------------------------------------ combining

function toggleCombine() {
  const on = !combining();
  run('combine', () => api('/api/combine', { on }));
}

// One row under both lines. Its two cells light for the lines combining is
// using: both while the second connection carries traffic, only the cable
// while combining waits for it.
function renderCombine() {
  const second = state.lanes.second;
  els.combine.hidden = !(state.features?.combine && second);
  if (els.combine.hidden) return;

  if (!els.combine.hasChildNodes()) {
    els.combine.append(
      h('span', { class: 'feature-cells', 'aria-hidden': 'true' }, h('span', { class: 'cell' }), h('span', { class: 'cell' })),
      h(
        'div',
        { class: 'feature-body' },
        h('strong', { class: 'feature-name', text: 'Combine both lines' }),
        h('p', { class: 'feature-text', 'aria-live': 'polite' }),
      ),
      h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-label': 'Combine both lines', onclick: toggleCombine }),
    );
  }
  const [cells, body, button] = els.combine.children;
  const text = body.lastElementChild;
  const on = combining();
  const active = on && state.combine.active;
  const waiting = on && routingOn() && !active;

  let message;
  if (!on) {
    message = `Share new connections between the cable and the ${second.label}, so speed tests and downloads in several parts get both speeds.`;
  } else if (!routingOn()) {
    message = 'Combining starts when routing is on.';
  } else if (waiting && state.lanes.main.carryingApps === false) {
    message = `Paused while the cable isn’t connected. New connections use the ${second.label} until it’s back.`;
  } else if (waiting) {
    message = `Paused while the ${second.label} isn’t connected. New connections use the cable until it’s back.`;
  } else {
    message = `Every app you haven’t moved to the ${second.label} shares both lines. If a website keeps signing you out or a download fails, stop combining.`;
  }
  if (text.textContent !== message) text.textContent = message;

  // While one line is down, only the line carrying everything lights.
  const cableDown = waiting && state.lanes.main.carryingApps === false;
  const lit = [active || (waiting && !cableDown) ? 'main' : null, active || cableDown ? 'second' : null];
  [...cells.children].forEach((cell, index) => {
    if (lit[index]) cell.dataset.lit = lit[index];
    else delete cell.dataset.lit;
  });
  els.combine.dataset.state = active ? 'active' : waiting ? 'waiting' : on ? 'on' : 'off';

  // The switch moves at once and says it is busy until the server agrees.
  const busy = busyAction === 'combine';
  button.setAttribute('aria-checked', String(busy ? !on : on));
  if (busy) button.setAttribute('aria-busy', 'true');
  else button.removeAttribute('aria-busy');
  button.disabled = Boolean(busyAction);
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

function actionButton(label, busyLabel, name, task) {
  return h('button', {
    class: 'button',
    type: 'button',
    text: busyAction === name ? busyLabel : label,
    disabled: Boolean(busyAction),
    onclick: () => run(name, task),
  });
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
    // An older Net Switch sends no such field, so this window then shows nothing.
    for (const line of ['main', 'second']) {
      const lane = state.lanes[line];
      const back = lane?.movedBack;
      if (back && lane.carryingApps && Date.now() - back.at < MOVED_BACK_NOTE_MS) {
        list.push(notice('status', movedBackText(line, back)));
      }
    }
    if (setup.wifiBlocked) {
      list.push(
        notice('setup', 'Windows is set to block Wi-Fi while the cable is plugged in, so the Wi-Fi stick can’t connect.', [
          actionButton('Allow Wi-Fi with the cable', 'Changing…', 'keep-both', () => api('/api/setup/keep-both', {})),
        ]),
      );
    }
    if (setup.cableNotDefault) {
      list.push(
        notice('setup', `When routing is off, Windows sends your internet through the ${secondLabel()}, not the cable.`, [
          actionButton('Make the cable the default', 'Changing…', 'cable-default', () =>
            api('/api/setup/cable-default', {}),
          ),
        ]),
      );
    }
    if (setup.keepBothConnected) {
      list.push(
        notice('setup', `Windows may disconnect the ${secondLabel()} while the cable is plugged in, mostly after a restart.`, [
          actionButton('Keep both connected', 'Changing…', 'keep-both', () => api('/api/setup/keep-both', {})),
        ]),
      );
    }
    const changed = [];
    if (setup.changed.cableDefault) changed.push('the cable is the default connection');
    if (setup.changed.keepBoth) changed.push('both connections stay on together');
    if (changed.length) {
      list.push(
        notice('status', `Net Switch changed Windows settings: ${changed.join(', and ')}.`, [
          actionButton('Undo', 'Undoing…', 'undo', () => api('/api/setup/undo', {})),
        ]),
      );
    }
  }
  if (actionError) list.push(notice('error', actionError));

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
    keys: h('div', { class: 'keys', role: 'group' }),
    note: h('p', { class: 'strip-note', hidden: true }),
  };
  const node = h(
    'li',
    { class: 'strip' },
    h('div', { class: 'strip-main' }, parts.icon, parts.name, parts.meter, parts.down, parts.up, parts.keys),
    parts.note,
  );
  const row = { node, parts, signature: {} };
  rows.set(app.key, row);
  return row;
}

// look colors the key: 'both' while the cable key stands for both lines.
function laneKey(app, lane, label, look = lane) {
  const pending = pendingLane.get(app.key);
  const pressed = pending ? false : app.lane === lane;
  const unavailable = lane === 'second' && !state.lanes.second;
  // No line changes for this app while its reconnect is running.
  const reconnecting = busyAction === `reconnect:${app.key}`;
  return h('button', {
    class: 'key',
    type: 'button',
    'data-lane': look,
    'aria-pressed': String(pressed),
    'aria-busy': pending === lane ? 'true' : null,
    disabled: unavailable || Boolean(pending) || reconnecting,
    title: unavailable ? 'Set up the second connection first' : null,
    text: label,
    onclick: () => chooseLane(app, lane),
  });
}

function rowNote(app) {
  // Moving notes offer to reconnect, when the running Net Switch supports it.
  const canReconnect = Boolean(state.features?.reconnect && app.reconnectable);
  const note = baseRowNote(app, canReconnect ? ', or press Reconnect' : '');
  if (note && note.movable && canReconnect) note.reconnect = true;
  return note;
}

// What a reconnect would interrupt: the app's connections on the other line.
// While combining splits traffic, both lines are right for an app on the cable,
// so only the connections that go around Net Switch are interrupted (line is null then).
function reconnectSummary(app) {
  if (app.lane === 'main' && sharing()) return { count: app.outside?.connections ?? 0, line: null };
  const other = app.lane === 'second' ? 'main' : 'second';
  const count = app.connections[other] + (app.outside?.byLane?.[other] ?? 0);
  const line = other === 'main' ? 'cable' : (state.lanes.second?.label ?? 'second connection');
  return { count, line };
}

function baseRowNote(app, orReconnect) {
  const second = state.lanes.second;
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
  if (app.lane === 'second' && !second) {
    return { kind: 'waiting', text: 'Uses the cable until a second connection is set up.' };
  }
  if (!routingOn()) return null;
  if (app.lane === 'second' && !second.carryingApps) {
    // The fallback only steers new connections; say so, and count any that stayed behind.
    const leftBehind = app.connections.second;
    const text =
      leftBehind > 0
        ? `The ${second.label} isn’t connected, so new connections use the cable. ${connectionWord(leftBehind)} still on the ${second.label}.`
        : `The ${second.label} isn’t connected, so new connections use the cable until it’s back.`;
    return { kind: 'waiting', text };
  }
  // The cable is down and its apps use the second connection: where they are
  // is right for now, so nothing is offered to move.
  if (app.lane === 'main' && second && state.lanes.main.carryingApps === false) {
    return { kind: 'waiting', text: `The cable isn’t connected, so new connections use the ${second.label} until it’s back.` };
  }
  // Connections that go around routing, usually because they were already open
  // when routing started. Worth a note while they carry data, or when the
  // person wants this app on the second connection.
  const extra = app.outside;
  if (extra && extra.connections > 0) {
    const active = extra.rate.down + extra.rate.up >= 1024 || !extra.measured;
    if (active || app.lane === 'second') {
      const count = extra.connections;
      const text = extra.beforeRouting
        ? `${connectionCount(count)} started before routing was on, so Net Switch can’t move ${count === 1 ? 'it' : 'them'}. Try pausing and resuming the download in ${app.name}${orReconnect}.`
        : `${connectionCount(count)} ${count === 1 ? 'goes' : 'go'} around Net Switch, so ${count === 1 ? 'it' : 'they'} can’t be moved.`;
      return { kind: 'outside', text, movable: true };
    }
  }
  if (app.lane === 'second' && app.connections.main > 0) {
    return {
      kind: 'moving',
      text: `${connectionWord(app.connections.main)} still on the cable. To move a running download, try pausing and resuming it in ${app.name}${orReconnect}.`,
      movable: true,
    };
  }
  // While combining splits traffic, connections on the second connection are where they belong.
  if (app.lane === 'main' && app.connections.second > 0 && !sharing()) {
    return {
      kind: 'moving',
      text: `${connectionWord(app.connections.second)} still on the ${second?.label ?? 'second connection'}. Try pausing and resuming in ${app.name}${orReconnect}.`,
      movable: true,
    };
  }
  return null;
}

function reconnectButton(app) {
  const line = app.lane === 'second' ? (state.lanes.second?.label ?? 'second connection') : 'cable';
  const title =
    app.lane === 'main' && sharing()
      ? `Closes ${app.name}’s connections that go around Net Switch, so new ones share both lines.`
      : `Closes ${app.name}’s connections that aren’t on the ${line}, so new ones use the ${line}.`;
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
  const { count, line } = reconnectSummary(app);
  const busy = busyAction === `reconnect:${app.key}`;
  const what = line
    ? `the ${connectionCount(count)} ${app.name} has on the ${line}`
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

function updateRow(row, app) {
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
  const total = app.laneDown.main + app.laneDown.second;
  const secondLit = total > 0 ? Math.round((lit * app.laneDown.second) / total) : 0;
  setMeter(parts.meter, lit, secondLit);

  parts.down.textContent = current ? formatRate(app.rate.down) : '';
  parts.up.textContent = current ? formatRate(app.rate.up) : '';
  if (app.rate.down < 1) parts.down.dataset.idle = '';
  else delete parts.down.dataset.idle;
  if (app.rate.up < 1) parts.up.dataset.idle = '';
  else delete parts.up.dataset.idle;

  const keysSignature = [
    app.switchable,
    app.lane,
    pendingLane.get(app.key) ?? '',
    busyAction === `reconnect:${app.key}`,
    Boolean(state.lanes.second),
    secondLabel(),
    app.name,
    combining(),
  ].join('|');
  if (row.signature.keys !== keysSignature) {
    if (app.switchable) {
      const main = combining() ? laneKey(app, 'main', 'Both lines', 'both') : laneKey(app, 'main', 'Cable');
      parts.keys.setAttribute('aria-label', `Connection for ${app.name}`);
      parts.keys.replaceChildren(main, laneKey(app, 'second', secondLabel()));
    } else {
      parts.keys.removeAttribute('aria-label');
      parts.keys.replaceChildren(h('span', { class: 'key-placeholder', text: 'Can’t be moved' }));
    }
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
    ? `${note.kind}|${note.text}|${Boolean(note.reconnect)}|${confirming}|${confirming ? reconnectSummary(app).count : ''}|${busyAction}|${sharing()}`
    : '';
  if (note && row.signature.note !== noteSignature) {
    parts.note.dataset.kind = confirming ? 'confirm' : note.kind;
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
  order.forEach((key, index) => {
    const app = byKey.get(key);
    const row = rows.get(key) ?? createRow(app);
    updateRow(row, app);
    if (els.apps.children[index] !== row.node) els.apps.insertBefore(row.node, els.apps.children[index] ?? null);
  });

  els.legends.hidden = apps.length === 0;
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

// ------------------------------------------------------------ main loop

function render() {
  renderTopbar();
  renderStats();
  renderNotices();
  if (!state) return;
  renderMaster();
  renderCombine();
  renderApps();
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
