import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export function assertNoIntegrityBuild(metadata, symbols) {
  if (!/\bbuild\s+/.test(metadata) || !/\bmain\.main\b/.test(symbols)) throw Error('Missing build metadata or engine symbols');
  if (/\b(?:wintun_integrity|wintun_boundaries)\b/.test(metadata) || /\b(?:integrityRingHook|wordRingHook|wordPacketHook)\b/.test(symbols)) throw Error('Diagnostic tag/hook reached a release engine');
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  const [release,audit,negative]=process.argv.slice(2);
  if (!release || !audit) throw Error('Expected stripped release and unstripped audit engine paths');
  const go=args=>execFileSync('go',args,{encoding:'utf8',windowsHide:true,maxBuffer:64*1024*1024});
  // -s removes nm symbols, but retains build settings. Check the ACTUAL release
  // settings and the same source's unstripped engine, not an empty nm result.
  assertNoIntegrityBuild(go(['version','-m',release]),go(['tool','nm',audit]));
  if (negative && !/\b(?:integrityRingHook|wordRingHook)\b/.test(go(['tool','nm',negative]))) throw Error('Tagged negative control has no hook symbol');
  console.log('WINTUN_RELEASE_GUARD no diagnostic build tag or hook in release engine');
}
