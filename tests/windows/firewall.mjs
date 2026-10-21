import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { hostedOnly, run } from './testisp/harness.mjs';

const arrival = '{618A9B6D-386B-4136-AD6E-B51587CFB1CD}';
const type = '{0C1BA1AF-5765-453F-AF22-A8F791AC775B}';
const v4 = '{61499990-3CB6-4E84-B950-53B94B6964F3}';
const v6 = '{65F9BDFF-3B2D-4E5D-B8C6-C720651FE898}';

export async function engineFirewall(exe, running, { luid, live = true } = {}) {
  hostedOnly();
  const state = JSON.parse((await run(exe, ['firewall-state'])).stdout);
  assert.equal(state.sublayer, running, JSON.stringify(state));
  assert.equal(state.filters.length, running ? 3 : 0, JSON.stringify(state));
  if (running) {
    assert.deepEqual(state.filters.map((filter) => `${filter.layer}:${filter.conditions[type]?.value}`).sort(),
      [`${v4}:3`, `${v6}:1`, `${v6}:2`].sort(), 'WFP allowance includes an unexpected protocol type or direction');
    for (const filter of state.filters) {
      assert.equal(Object.keys(filter.conditions).length, 2);
      assert.equal(filter.conditions[arrival]?.type, 4);
      assert.equal(filter.conditions[arrival]?.match, 0);
      assert.equal(filter.conditions[type]?.type, 2);
      assert.equal(filter.conditions[type]?.match, 0);
      assert(filter.conditions[arrival].value > 0, 'WFP filter has no interface scope');
      if (luid !== undefined) assert.equal(filter.conditions[arrival].value, luid, 'WFP filter targets another interface');
      if (live) assert.equal(filter.interfaceGUID?.toUpperCase(), '{D9B44E84-B5C7-4DC4-97A4-4E7CA6722686}', `WFP allowance is not on NetSwitch: ${JSON.stringify(filter)}`);
    }
  }
  return state;
}

export async function plantUnrelatedFirewallRule() {
  hostedOnly();
  const name = `NetSwitchAcceptanceUnrelated-${randomUUID()}`;
  await run('netsh.exe', ['advfirewall', 'firewall', 'add', 'rule', `name=${name}`, 'dir=in', 'action=allow',
    'protocol=tcp', 'localport=9', 'localip=127.0.0.1', 'remoteip=127.0.0.1', 'profile=any']);
  const read = async () => (await run('netsh.exe', ['advfirewall', 'firewall', 'show', 'rule', `name=${name}`, 'verbose'])).stdout;
  const before = await read();
  assert(before.includes(name), 'Unrelated-rule precondition was not established');
  return {
    name,
    async check() {
      assert.equal(await read(), before, 'Engine cleanup changed the unrelated firewall rule');
    },
    async close() {
      await run('netsh.exe', ['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`]);
    },
  };
}
