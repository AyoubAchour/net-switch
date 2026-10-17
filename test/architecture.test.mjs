import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createArchitectureReader, nativeArchitecture } from '../lib/architecture.mjs';

test('Windows architecture comes from the shared registry once, even with an emulated x64 runtime', () => {
  for (const [value, expected] of [['ARM64', 'arm64'], ['AMD64', 'x64']]) {
    let queries = 0;
    const architecture = createArchitectureReader({ platform: 'win32', arch: 'x64', query: (file, args, options) => {
      queries++;
      assert.match(file, /[\\/]System32[\\/]reg\.exe$/i);
      assert.deepEqual(args, ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment', '/v', 'PROCESSOR_ARCHITECTURE']);
      assert.equal(options.windowsHide, true);
      assert.equal(options.timeout, 5000);
      return `\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\r\n    PROCESSOR_ARCHITECTURE    REG_SZ    ${value}\r\n\r\n`;
    } });
    assert.equal(architecture(), expected);
    assert.equal(architecture(), expected);
    assert.equal(queries, 1);
  }
});

test('a failed or malformed registry query is cached and reported instead of guessing x64', () => {
  for (const answer of [new Error('access denied'), '', 'PROCESSOR_ARCHITECTURE REG_SZ IA64']) {
    let queries = 0;
    const architecture = createArchitectureReader({ platform: 'win32', arch: 'x64', query: () => {
      queries++;
      if (answer instanceof Error) throw answer;
      return answer;
    } });
    assert.throws(architecture, /Could not read Windows architecture from the registry/);
    assert.throws(architecture, /Could not read Windows architecture from the registry/);
    assert.equal(queries, 1);
  }
});

test('non-Windows tests do not query the registry', () => {
  const architecture = createArchitectureReader({ platform: 'linux', arch: 'arm64', query: () => assert.fail('unexpected query') });
  assert.equal(architecture(), 'arm64');
  assert.equal(architecture(), 'arm64');
});

test('the real registry reader detects ARM64 under x64 emulation in CI', { skip: !process.env.NETSWITCH_TEST_X64_ON_ARM64 }, () => {
  assert.equal(process.platform, 'win32');
  assert.equal(process.arch, 'x64');
  assert.equal(nativeArchitecture(), 'arm64');
});
