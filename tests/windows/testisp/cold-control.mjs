import { startHarness, run } from './harness.mjs';

const harness = await startHarness('dist/testisp-cold');
const source = `
  import { subscribe } from 'node:diagnostics_channel';
  const events = [];
  for (const name of ['client:beforeConnect', 'client:connected', 'client:sendHeaders', 'request:error']) {
    subscribe('undici:' + name, (event) => events.push({ name, at: Date.now(), port: event.socket?.localPort, error: event.error?.message }));
  }
  const started = performance.now();
  try {
    for (let i = 0; i < 2; i++) {
      const response = await fetch(process.env.TESTISP_COLD_URL + '/stats', {
        headers: { Authorization: 'Bearer ' + process.env.TESTISP_COLD_TOKEN }, signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw Error('HTTP ' + response.status);
      await response.json();
    }
    console.log(JSON.stringify({ ms: performance.now() - started, events }));
  } catch (error) {
    console.error(JSON.stringify({ error: error.message, cause: error.cause?.message, events }));
    process.exitCode = 1;
  }
`;
try {
  for (let i = 1; i <= 100; i++) {
    const result = await run(process.execPath, ['--input-type=module', '-e', source], {
      env: { TESTISP_COLD_URL: harness.diagnosticClient.url, TESTISP_COLD_TOKEN: harness.diagnosticClient.token },
      timeout: 15000,
    });
    console.log(`COLD CONTROL ${i} ${result.stdout}`);
  }
} finally {
  await harness.close();
}
