import assert from 'node:assert/strict';
import test from 'node:test';
import { publicFailure } from '../tests/windows/public-https.mjs';

test('only verified public 5xx can blame a public endpoint', () => {
  for (const verified of [false, true]) for (const status of [0, 200, 404, 499, 500, 503, 599, 600]) {
    const message = publicFailure({ endpoint: '1.1.1.1:443', phase: 'response body', status, verified });
    assert.equal(message.startsWith('public target unavailable'), verified && status >= 500 && status < 600);
    assert.match(message, /endpoint=1\.1\.1\.1:443; phase=response body/);
  }
});

test('resets and incomplete bodies do not imply a public outage', () => {
  assert.match(publicFailure({ code: 'ECONNRESET' }), /^transport reset \(origin unproven\)/);
  for (const code of ['EOF', 'ERR_STREAM_PREMATURE_CLOSE']) {
    assert.match(publicFailure({ code }), /^early close \(origin unproven\)/);
  }
  assert.match(publicFailure({ code: 'ABORT_ERR' }), /^public HTTPS failure \(origin unproven\)/);
});
