// Made-up states in the shape server.mjs buildState() gives, for the tray's
// tests (test/tray.test.mjs) and its screenshots (dev/render-tray.mjs).
const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

export function line(id, label, extra = {}) {
  return {
    id,
    alias: 'Ethernet',
    label,
    kind: 'wired',
    main: false,
    connected: true,
    problem: null,
    ping: 18,
    connections: 6,
    carrying: true,
    target: id,
    rate: { down: 38 * KB, up: 1234 },
    ssid: null,
    metered: false,
    strict: false,
    cap: null,
    usage: { bytes: 0.4 * GB, periodStart: '2026-10-01T00:00:00.000Z' },
    exhausted: false,
    weight: 1,
    share: null,
    ...extra,
  };
}

// A line that is down: its own apps use `target` until it is back.
export function down(base, problem, target) {
  return { ...base, connected: false, problem, ping: null, connections: 0, carrying: false, target, rate: { down: 0, up: 0 } };
}

export function app(name, score, down = score, extra = {}) {
  return {
    key: name.toLowerCase(),
    path: `C:\\Apps\\${name}.exe`,
    name,
    hasIcon: false,
    switchable: true,
    reconnectable: true,
    line: null,
    rate: { down, up: 0 },
    lineDown: {},
    sortScore: score,
    connections: {},
    outside: null,
    ...extra,
  };
}

export function state({ status = 'on', mode = 'tun', lines = [], apps = [], combine = {}, events = [] } = {}) {
  return {
    mode,
    elevated: true,
    version: '0.3.0',
    update: null,
    features: { reconnect: true, combine: true, lines: true },
    combine: { on: false, active: false, mode: 'auto', ...combine },
    routing: { status, wanted: status === 'on' || status === 'starting', error: null, measuring: status === 'on', proxyPort: null, retryAt: null, ipv6: status === 'on' ? false : null },
    lines: lines.map((item, index) => ({ ...item, main: index === 0 })),
    candidates: [],
    apps,
    events,
    settings: { autostart: null, checkForUpdates: true, probeTargets: ['1.1.1.1:443', '8.8.8.8:443'] },
  };
}

export const cable = line('k3f9', 'Cable', { alias: 'Ethernet', rate: { down: 38 * KB, up: 1234 } });
export const wifi = line('p2x1', 'Wi-Fi stick', {
  alias: 'Wi-Fi 2',
  ssid: 'Home',
  kind: 'wifi',
  ping: 31,
  rate: { down: 915 * KB, up: 50 },
});
export const phone = line('ph01', 'Phone', {
  alias: 'Ethernet 3',
  kind: 'phone',
  ping: 54,
  metered: true,
  cap: { bytes: 10 * GB, period: 'month' },
  usage: { bytes: 6.2 * GB, periodStart: '2026-10-01T00:00:00.000Z' },
  rate: { down: 120 * KB, up: 8 * KB },
});
export const wifi2 = line('w2x9', 'Wi-Fi stick 2', {
  alias: 'Wi-Fi 3',
  ssid: 'Upstairs',
  kind: 'wifi',
  ping: 27,
  rate: { down: 300 * KB, up: 20 * KB },
});

const busy = [
  app('Steam', 2600 * KB),
  app('Firefox', 640 * KB, 640 * KB, { line: wifi.id }),
  app('Discord', 14 * KB),
  app('Spotify', 160 * KB, 160 * KB, { line: phone.id }),
];

// The flyout's states, by name. Each is one situation the tray has to show well.
export const STATES = {
  oneLine: state({ lines: [cable], apps: [app('Steam', 2600 * KB), app('Firefox', 640 * KB), app('Discord', 14 * KB)] }),
  twoLines: state({ lines: [cable, wifi], apps: busy.slice(0, 3) }),
  fourLines: state({ lines: [cable, wifi, phone, wifi2], apps: busy }),
  lineDown: state({
    lines: [cable, down(wifi, 'no internet', cable.id)],
    apps: busy.slice(0, 3),
  }),
  mainDown: state({
    lines: [down(cable, 'no address', wifi.id), wifi],
    apps: busy.slice(0, 3),
  }),
  capped: state({
    lines: [
      cable,
      wifi,
      { ...phone, usage: { bytes: 10.3 * GB, periodStart: '2026-10-01T00:00:00.000Z' }, exhausted: true, carrying: false, target: cable.id, rate: { down: 0, up: 0 } },
    ],
    apps: busy.slice(0, 3),
  }),
  combining: state({
    lines: [{ ...cable, share: 0.4 }, { ...wifi, share: 0.6 }],
    combine: { on: true, active: true },
    apps: [app('Steam', 2600 * KB), app('Firefox', 640 * KB, 640 * KB, { line: wifi.id }), app('Discord', 14 * KB, 14 * KB, { line: cable.id })],
  }),
  checking: state({
    lines: [cable, { ...down(wifi, 'checking', cable.id), connected: false }],
    apps: busy.slice(0, 3),
  }),
  longNames: state({
    lines: [
      line('l1', 'Fibre from the basement router', { alias: 'Realtek USB GbE Family Controller #2', rate: { down: 123_456_789, up: 123_456_789 } }),
      line('l2', 'Wi-Fi stick on the upstairs network', { alias: 'Wi-Fi 2', ssid: 'A very long network name indeed', kind: 'wifi', metered: true }),
      line('l3', 'Ayoub’s phone on the unlimited weekend plan', { alias: 'Ethernet 3', kind: 'phone', metered: true, cap: { bytes: 10 * GB, period: 'day' }, usage: { bytes: 2.5 * GB, periodStart: '2026-10-17T00:00:00.000Z' } }),
    ],
    apps: [
      app('Microsoft Edge WebView2 helper for the company sign-in page', 900 * KB, 900 * KB, { line: 'l2' }),
      app('Steam', 300 * KB),
      app('Discord', 14 * KB, 14 * KB, { line: 'l3' }),
    ],
  }),
  routingOff: state({ status: 'off', lines: [cable, wifi], apps: [] }),
};
