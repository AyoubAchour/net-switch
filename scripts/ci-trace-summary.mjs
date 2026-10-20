import { inflateRawSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { summarizeProfile } from './profile-summary.mjs';

// CI-only analysis. ZIP, trace and generated profiles stay in memory; neither
// a local Go runtime run nor an extracted artifact file is needed.
if (process.platform !== 'linux') throw Error('Run this diagnostic on a Linux CI runner');
const chunks=[];
let bytes=0;
for await (const chunk of process.stdin) {
  bytes+=chunk.length;
  if (bytes>64*1024*1024) throw Error('trace artifact exceeds 64 MiB');
  chunks.push(chunk);
}
const zip=Buffer.concat(chunks);
let end=zip.length-22;
while(end>=Math.max(0,zip.length-65557) && zip.readUInt32LE(end)!==0x06054b50) end--;
if(end<0) throw Error('not a complete ZIP archive');
let at=zip.readUInt32LE(end+16), found=0;
const count=zip.readUInt16LE(end+10);
for(let i=0;i<count;i++) {
  if(zip.readUInt32LE(at)!==0x02014b50) throw Error('bad ZIP directory');
  const method=zip.readUInt16LE(at+10), compressed=zip.readUInt32LE(at+20);
  const nameLength=zip.readUInt16LE(at+28), extraLength=zip.readUInt16LE(at+30), commentLength=zip.readUInt16LE(at+32);
  const name=zip.toString('utf8',at+46,at+46+nameLength), local=zip.readUInt32LE(at+42);
  at+=46+nameLength+extraLength+commentLength;
  if(!name.endsWith('/runtime.trace')) continue;
  const offset=local+30+zip.readUInt16LE(local+26)+zip.readUInt16LE(local+28);
  const raw=zip.subarray(offset,offset+compressed);
  if(method!==0 && method!==8) throw Error('unsupported ZIP method');
  const trace=method===0?raw:inflateRawSync(raw,{maxOutputLength:64*1024*1024});
  for(const kind of ['sched','syscall']) {
    const result=spawnSync('go',['tool','trace','-pprof='+kind,'/dev/stdin'],{input:trace,maxBuffer:32*1024*1024,timeout:60000});
    if(result.error || result.status!==0) throw Error('trace conversion failed: '+(result.error||result.stderr.toString()));
    console.log(JSON.stringify({name,kind,traceBytes:trace.length,profileBytes:result.stdout.length,...summarizeProfile(result.stdout)}));
  }
  found++;
}
if(!found) throw Error('artifact contains no runtime trace');
