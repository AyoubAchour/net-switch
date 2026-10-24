import assert from 'node:assert/strict';
import {test} from 'node:test';
import {assertNoIntegrityBuild} from '../../scripts/check-wintun-release.mjs';

test('release guard rejects a tag even when symbols were stripped, and rejects hook symbols',()=>{
 const meta='build\tGOOS=windows\nbuild\tGOARCH=arm64', symbols='123 T main.main\n';
 assert.doesNotThrow(()=>assertNoIntegrityBuild(meta,symbols));
 assert.throws(()=>assertNoIntegrityBuild(meta+'\nbuild\t-tags=wintun_integrity',symbols),/Diagnostic/);
 assert.throws(()=>assertNoIntegrityBuild(meta,symbols+'123 D github.com/AyoubAchour/net-switch/internal/wintun.integrityRingHook'),/Diagnostic/);
 assert.throws(()=>assertNoIntegrityBuild(meta,''),/Missing/);
 assert.throws(()=>assertNoIntegrityBuild('',symbols),/Missing/);
 assert.throws(()=>assertNoIntegrityBuild(meta+'\nbuild\t-tags=wintun_boundaries',symbols),/Diagnostic/);
 for (const name of ['wordRingHook','wordPacketHook']) assert.throws(()=>assertNoIntegrityBuild(meta,symbols+'123 D example.'+name),/Diagnostic/);
});
