import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isNewer, LATEST_RELEASE_URL, offerFrom, parseVersion, UpdateChecker } from '../lib/updates.mjs';

const PAGE = 'https://github.com/AyoubAchour/net-switch/releases/tag/v0.3.0';
const INSTALLER = 'https://github.com/AyoubAchour/net-switch/releases/download/v0.3.0/NetSwitch-Setup-0.3.0-x64.exe';

function release(overrides = {}) {
  return {
    tag_name: 'v0.3.0',
    html_url: PAGE,
    draft: false,
    prerelease: false,
    assets: [
      { name: 'SHA256SUMS.txt', browser_download_url: 'https://github.com/AyoubAchour/net-switch/releases/download/v0.3.0/SHA256SUMS.txt' },
      { name: 'NetSwitch-Setup-0.3.0-x64.exe', browser_download_url: INSTALLER },
    ],
    ...overrides,
  };
}

test('versions compare by number, and anything that isn’t a plain version is never newer', () => {
  assert.deepEqual(parseVersion('v1.20.3'), [1, 20, 3]);
  assert.equal(parseVersion('1.2'), null);
  assert.equal(isNewer('0.10.0', '0.9.9'), true);
  assert.equal(isNewer('0.2.0', '0.2.0'), false);
  assert.equal(isNewer('0.1.9', '0.2.0'), false);
  assert.equal(isNewer('1.0.0-beta', '0.2.0'), false);
  assert.equal(isNewer('garbage', '0.2.0'), false);
});

test('a newer published release is offered with its page and installer', () => {
  assert.deepEqual(offerFrom(release(), '0.2.0'), { version: '0.3.0', page: PAGE, installer: INSTALLER });
});

test('nothing is offered for the same or an older version, a draft or a prerelease', () => {
  assert.equal(offerFrom(release(), '0.3.0'), null);
  assert.equal(offerFrom(release(), '0.4.0'), null);
  assert.equal(offerFrom(release({ draft: true }), '0.2.0'), null);
  assert.equal(offerFrom(release({ prerelease: true }), '0.2.0'), null);
  assert.equal(offerFrom(null, '0.2.0'), null);
});

test('links that don’t point at this project’s releases are never offered', () => {
  assert.equal(offerFrom(release({ html_url: 'https://example.com/net-switch' }), '0.2.0'), null);
  const elsewhere = release({ assets: [{ name: 'NetSwitch-Setup-0.3.0-x64.exe', browser_download_url: 'https://example.com/NetSwitch-Setup-0.3.0-x64.exe' }] });
  assert.equal(offerFrom(elsewhere, '0.2.0'), null);
  // A release without the installer has nothing to download.
  assert.equal(offerFrom(release({ assets: [] }), '0.2.0'), null);
});

function fakeFetch(answers) {
  const calls = [];
  const fetch = async (url, options) => {
    calls.push({ url, options });
    const answer = answers.shift();
    if (answer instanceof Error) throw answer;
    return { ok: answer.status === 200, status: answer.status, json: async () => answer.body };
  };
  return { fetch, calls };
}

test('the checker asks GitHub’s latest release, and keeps the offer it finds', async () => {
  const { fetch, calls } = fakeFetch([{ status: 200, body: release() }]);
  const logs = [];
  const checker = new UpdateChecker({ currentVersion: '0.2.0', fetch, log: (line) => logs.push(line) });
  await checker.check();
  assert.equal(calls[0].url, LATEST_RELEASE_URL);
  assert.equal(calls[0].options.headers['User-Agent'], 'NetSwitch/0.2.0');
  assert.deepEqual(checker.offer, { version: '0.3.0', page: PAGE, installer: INSTALLER });
  assert.deepEqual(logs, ['Net Switch 0.3.0 is available (this is 0.2.0)']);
});

test('a failed check keeps the last offer and logs each new problem once', async () => {
  const { fetch } = fakeFetch([{ status: 200, body: release() }, new Error('getaddrinfo ENOTFOUND'), new Error('getaddrinfo ENOTFOUND'), { status: 403 }]);
  const logs = [];
  const checker = new UpdateChecker({ currentVersion: '0.2.0', fetch, log: (line) => logs.push(line) });
  await checker.check();
  await checker.check();
  await checker.check();
  await checker.check();
  assert.equal(checker.offer?.version, '0.3.0');
  assert.deepEqual(logs.slice(1), ['could not check for updates: getaddrinfo ENOTFOUND', 'could not check for updates: GitHub answered 403']);
});

test('with checking turned off, or no release published yet, nothing is offered', async () => {
  const off = fakeFetch([{ status: 200, body: release() }]);
  const disabled = new UpdateChecker({ currentVersion: '0.2.0', fetch: off.fetch, enabled: () => false });
  await disabled.check();
  assert.equal(off.calls.length, 0);
  assert.equal(disabled.offer, null);

  const none = fakeFetch([{ status: 404 }]);
  const empty = new UpdateChecker({ currentVersion: '0.2.0', fetch: none.fetch });
  await empty.check();
  assert.equal(empty.offer, null);
});

test('two checks at once make one request', async () => {
  const { fetch, calls } = fakeFetch([{ status: 200, body: release() }]);
  const checker = new UpdateChecker({ currentVersion: '0.2.0', fetch });
  await Promise.all([checker.check(), checker.check()]);
  assert.equal(calls.length, 1);
});
