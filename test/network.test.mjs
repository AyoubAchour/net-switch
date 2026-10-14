import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeFailure, findAdapter, hasDefaultRouteVia, parseDefaultRoutes, parseRouteTable } from '../lib/network.mjs';

test('adapter identity takes precedence over an old alias, ignoring GUID case and braces', () => {
  const adapters = [
    { alias: 'Old name', guid: '{BBBB-2222}' },
    { alias: 'Renamed cable', guid: '{AAAA-1111}' },
  ];
  assert.equal(findAdapter(adapters, { alias: 'Old name', guid: 'aaaa-1111' }), adapters[1]);
  assert.equal(findAdapter(adapters, { guid: '{bbbb-2222}' }), adapters[0]);
  assert.equal(findAdapter([{ alias: 'Cable', guid: 'aaaa-1111' }], { guid: '{AAAA-1111}' }).alias, 'Cable');
});

test('adapter lookup falls back to the alias when its GUID is missing or absent', () => {
  const adapters = [{ alias: 'Cable' }, { alias: 'Wi-Fi', guid: 'aaaa' }];
  assert.equal(findAdapter(adapters, { alias: 'Cable' }), adapters[0]);
  assert.equal(findAdapter(adapters, { alias: 'Wi-Fi', guid: 'missing' }), adapters[1]);
  assert.equal(findAdapter(adapters, { alias: 'gone', guid: 'missing' }), null);
  assert.equal(findAdapter(adapters, {}), null);
  assert.equal(findAdapter([], { alias: 'Cable' }), null);
});

// Shaped like "route print -4" on this PC: two routers that both use 192.168.1.1.
const ENGLISH = `
===========================================================================
Interface List
 17...00 11 22 33 44 55 ......Wired adapter
 22...00 11 22 33 44 66 ......Wireless stick
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.11     35
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.21     55
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link      192.168.1.11    291
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.1.1  Default
===========================================================================
`;

// Same rows under a French header: only the numbers matter.
const FRENCH = ENGLISH.replace('Active Routes:', 'Itinéraires actifs :').replace('Network Destination', 'Destination réseau');

test('default routes are read from the numeric rows, with the address of the adapter they leave through', () => {
  assert.deepEqual(parseDefaultRoutes(ENGLISH), [
    { gateway: '192.168.1.1', interfaceAddress: '192.168.1.11', metric: 35 },
    { gateway: '192.168.1.1', interfaceAddress: '192.168.1.21', metric: 55 },
  ]);
});

test('the same rows are found under another Windows language', () => {
  assert.equal(parseDefaultRoutes(FRENCH).length, 2);
});

test('persistent routes and other destinations are not default routes, but an on-link default is', () => {
  const text = `
          0.0.0.0          0.0.0.0         On-link       198.18.0.1      1
          0.0.0.0          0.0.0.0      192.168.1.1  Default
        127.0.0.0        255.0.0.0      192.168.1.1     192.168.1.11     10
          0.0.0.0        128.0.0.0      192.168.1.1     192.168.1.11     10
`;
  assert.deepEqual(parseDefaultRoutes(text), [{ gateway: 'On-link', interfaceAddress: '198.18.0.1', metric: 1 }]);
  assert.deepEqual(parseDefaultRoutes(''), []);
  assert.deepEqual(parseDefaultRoutes(undefined), []);
});

test('output that is not a route table has no route rows at all, so it can be told from "no default route"', () => {
  assert.equal(parseRouteTable(ENGLISH).rows, 4);
  assert.equal(parseRouteTable('The route table could not be printed.').rows, 0);
  assert.equal(parseRouteTable('').rows, 0);
  // A table without a default route still has its other rows.
  const noDefault = ENGLISH.replace(/^.*0\.0\.0\.0 {10}0\.0\.0\.0.*$/gm, '');
  const parsed = parseRouteTable(noDefault);
  assert.equal(parsed.routes.length, 0);
  assert.ok(parsed.rows >= 2);
});

test('a line has a default route when one leaves through any of its addresses', () => {
  const routes = parseDefaultRoutes(ENGLISH);
  assert.equal(hasDefaultRouteVia(routes, ['192.168.1.21']), true);
  assert.equal(hasDefaultRouteVia(routes, ['10.0.0.5', '192.168.1.11']), true);
  assert.equal(hasDefaultRouteVia(routes, ['192.168.1.99']), false);
  assert.equal(hasDefaultRouteVia(routes, []), false);
  assert.equal(hasDefaultRouteVia([], ['192.168.1.21']), false);
});

test('a scan that was killed for taking too long says so in plain words', () => {
  const error = Object.assign(new Error('Command failed: powershell.exe -EncodedCommand AAAA…'), { killed: true, signal: 'SIGTERM' });
  assert.equal(describeFailure(error, 20_000), 'Windows did not answer within 20 seconds');
});

test('a scan that failed with a message gives its first line, and never the command', () => {
  const failed = Object.assign(new Error('Command failed: powershell.exe -EncodedCommand AAAA'), {
    code: 1,
    stderr: '#< CLIXML\n<Objs>…</Objs>',
  });
  const reason = describeFailure(failed);
  assert.doesNotMatch(reason, /EncodedCommand/);
  assert.match(reason, /exit code 1/);

  const withText = Object.assign(new Error('Command failed: x'), { stderr: 'The shell cannot be started.\nMore detail.' });
  assert.equal(describeFailure(withText), 'The shell cannot be started.');
  assert.equal(describeFailure(new Error('Windows returned no network adapters.')), 'Windows returned no network adapters.');
});
