import { networkInterfaces } from 'node:os';

export const TUN_NAME = 'NetSwitch';

export function adapterKind(adapter) {
  const text = `${adapter.mediaType ?? ''} ${adapter.description ?? ''}`;
  if (/802\.11|wireless|wi-?fi|wlan/i.test(text)) return 'wifi';
  if (/remote ndis|rndis|apple mobile device ethernet|internet sharing/i.test(text)) return 'phone';
  return 'wired';
}

export function findAdapter(adapters, { alias, guid }) {
  const normalize = (value) => String(value ?? '').replace(/[{}]/g, '').toLowerCase();
  if (guid) {
    const match = adapters.find((adapter) => normalize(adapter.guid) === normalize(guid));
    if (match) return match;
  }
  return adapters.find((adapter) => alias != null && adapter.alias === alias) ?? null;
}

// Windows gets this long to answer the scan; a longer wait means it is stuck.
export const SCAN_TIMEOUT_MS = 20_000;

export function prepareAdapters(list) {
  // The script hides its errors, so a Windows hiccup can come back as an empty
  // list. No PC has no adapters: treat it as a failed scan and keep the last good one.
  if (list.length === 0) throw new Error('Windows returned no network adapters.');
  return list
    .filter((adapter) => adapter.alias !== TUN_NAME)
    .map((adapter) => ({
      ...adapter,
      kind: adapterKind(adapter),
      connected: adapter.status === 'Up' && Boolean(adapter.gateway),
    }));
}

// A short, readable reason for the log. The failed command itself is thousands
// of characters of encoded script.
export function describeFailure(error, timeoutMs = SCAN_TIMEOUT_MS) {
  if (error?.killed || error?.signal) return `Windows did not answer within ${Math.round(timeoutMs / 1000)} seconds`;
  const lines = String(error?.stderr ?? '')
    .replace(/#< CLIXML[\s\S]*$/, '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length > 0) return lines[0].slice(0, 160);
  const message = String(error?.message ?? '');
  // execFile starts its message with the whole command line.
  return message.startsWith('Command failed:') ? `Windows reported an error (exit code ${error?.code ?? 'unknown'})` : message.slice(0, 160);
}

// Cheap checks that need no PowerShell (and no WMI, which can hang): a
// disconnected adapter loses its address.
export function usableAddresses(alias, interfaces = networkInterfaces) {
  const entries = interfaces()[alias] ?? [];
  return entries
    .filter((entry) => entry.family === 'IPv4' && !entry.internal && !entry.address.startsWith('169.254.'))
    .map((entry) => entry.address);
}

export function hasUsableAddress(alias) {
  return usableAddresses(alias).length > 0;
}

// Whether an adapter has a global IPv6 address (2000::/3), the kind that
// reaches the internet; link-local and private ones don't.
export function hasGlobalIPv6(alias, interfaces = networkInterfaces()) {
  return (interfaces[alias] ?? []).some(
    (entry) => entry.family === 'IPv6' && !entry.internal && /^[23][0-9a-f]{3}:/i.test(entry.address),
  );
}

// A burst of notifications during a USB reset must not replace the cable.
export class MissingAdapter {
  constructor() {
    this.identity = null;
    this.since = null;
    this.readings = 0;
  }

  update(identity, missing, now = Date.now()) {
    if (!missing || identity !== this.identity) {
      this.since = null;
      this.readings = 0;
    }
    this.identity = identity;
    if (!missing) return false;
    this.since ??= now;
    this.readings++;
    return this.readings >= 2 && now - this.since >= 20_000;
  }
}

// The IPv4 routes, from route.exe. Its rows are plain numbers, so this reads
// the same in any Windows language, and it doesn't go through WMI.
// "<destination>  <mask>  <gateway or On-link>  <this adapter's address>  <metric>".
const ADDRESS = String.raw`\d+\.\d+\.\d+\.\d+`;
const ROUTE_ROW = new RegExp(String.raw`^\s*(${ADDRESS})\s+(${ADDRESS})\s+(${ADDRESS}|On-link)\s+(${ADDRESS})\s+(\d+)\s*$`);

// rows: how many route rows were recognized at all. A real table always has a
// few (the loopback routes), so none means the output was not a route table.
export function parseRouteTable(text) {
  const routes = [];
  let rows = 0;
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const match = ROUTE_ROW.exec(line);
    if (!match) continue;
    rows += 1;
    if (match[1] === '0.0.0.0' && match[2] === '0.0.0.0') {
      routes.push({ gateway: match[3], interfaceAddress: match[4], metric: Number(match[5]) });
    }
  }
  return { routes, rows };
}

export function parseDefaultRoutes(text) {
  return parseRouteTable(text).routes;
}

// Does a default route leave through one of these addresses?
export function hasDefaultRouteVia(routes, addresses) {
  return routes.some((route) => addresses.includes(route.interfaceAddress));
}

// Windows picks the default route with the lowest route metric plus interface metric.
export function effectiveMetric(adapter) {
  return (adapter.routeMetric ?? 0) + (adapter.metric ?? 9999);
}
