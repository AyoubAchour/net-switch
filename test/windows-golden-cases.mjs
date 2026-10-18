import { createHash } from 'node:crypto';
import { buildEngineConfig, buildRuleSets } from '../lib/engine.mjs';
import { offerFrom } from '../lib/updates.mjs';

export const goldenLines = [
  { id: 'aa', alias: 'Ethernet' },
  { id: 'bb', alias: 'Wi-Fi' },
  { id: 'cc', alias: 'Phone' },
];

export function ruleCases() {
  return [1, 2, 3].flatMap((count) => [false, true].map((combine) => ({
    name: `${count}-lines-${combine ? 'combined' : 'pinned'}`,
    options: {
      lines: goldenLines.slice(0, count),
      appLines: {
        'C:\\Apps\\app-1.2.3\\Browser.exe': 'aa',
        'C:\\Games\\game.exe': 'bb',
        'C:\\Program Files\\WindowsApps\\Example_1.2.3_x64__publisher\\App.exe': 'cc',
      },
      combine,
      shares: count === 1 ? { aa: 1 } : count === 2 ? { aa: 0.6, bb: 0.4 } : { aa: 0.5, bb: 0.3, cc: 0.2 },
      blocked: [goldenLines[count - 1].id],
    },
  }))).concat([{ name: 'empty-apps', options: { lines: goldenLines } }]);
}

export const digest = (text) => createHash('sha256').update(text).digest('hex');
export const ruleText = (tag, set) => JSON.stringify(set, null, tag.startsWith('share-') ? undefined : 2);

// Hash the exact serialized bytes: even ordering and whitespace must stay put.
// An empty rule directory keeps config paths identical on either test host.
export function goldenOutputs() {
  const outputs = {};
  for (const count of [1, 2, 3]) {
    for (const mode of ['tun', 'proxy']) {
      for (const ipv6 of [false, true]) {
        outputs[`${count}-${mode}-ipv6-${ipv6}`] = digest(JSON.stringify(buildEngineConfig({
          mode, lines: goldenLines.slice(0, count), ipv6,
          apiPort: 12345, apiSecret: 'golden-secret', proxyPort: 12346, ruleDir: '',
        }), null, 2));
      }
    }
  }
  for (const { name, options } of ruleCases()) {
    const sets = buildRuleSets(options);
    outputs[name] = Object.fromEntries(Object.entries(sets).map(([tag, set]) => [tag, digest(ruleText(tag, set))]));
  }
  for (const arch of ['x64', 'arm64', 'ia32']) {
    const version = '1.2.3';
    const name = `NetSwitch-Setup-${version}-${arch}.exe`;
    outputs[`update-${arch}`] = offerFrom({
      tag_name: `v${version}`,
      html_url: `https://github.com/AyoubAchour/net-switch/releases/tag/v${version}`,
      assets: [{ name, browser_download_url: `https://github.com/AyoubAchour/net-switch/releases/download/v${version}/${name}` }],
    }, '0.3.1', arch);
  }
  return outputs;
}
