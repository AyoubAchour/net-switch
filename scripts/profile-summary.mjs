import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';

// Read the documented pprof protobuf in memory; no executable or native
// profiler is run on this PC. Unknown fields are skipped by their wire type.
function integer(b, cursor) {
  let value = 0n;
  for (let shift=0n; shift<70n; shift+=7n) {
    if (cursor.at >= b.length) throw Error('truncated varint');
    const byte=b[cursor.at++]; value |= BigInt(byte&127)<<shift;
    if (!(byte&128)) return Number(value);
  }
  throw Error('invalid varint');
}
function message(b) {
  const out=new Map(), cursor={at:0};
  while(cursor.at<b.length) {
    const key=integer(b,cursor), field=Math.floor(key/8), wire=key%8;
    let value;
    if(wire===0) value=integer(b,cursor);
    else if(wire===2) {
      const length=integer(b,cursor), end=cursor.at+length;
      if(end>b.length) throw Error('truncated field');
      value=b.subarray(cursor.at,end);cursor.at=end;
    } else if(wire===1) { cursor.at+=8;continue; }
    else if(wire===5) { cursor.at+=4;continue; }
    else throw Error('unsupported wire type');
    if(!out.has(field)) out.set(field,[]);
    out.get(field).push(value);
  }
  return out;
}
const one=(m,k)=>m.get(k)?.[0]??0;
function vector(m,k) {
  return (m.get(k)||[]).flatMap(value=>{
    if(typeof value==='number') return [value];
    const cursor={at:0}, out=[];
    while(cursor.at<value.length) out.push(integer(value,cursor));
    return out;
  });
}
const short=name=>name.replace('github.com/AyoubAchour/net-switch/internal/','ns/').replace('gvisor.dev/gvisor/pkg/','gv/');
export function summarizeProfile(compressed) {
  const p=message(gunzipSync(compressed)), strings=(p.get(6)||[]).map(b=>b.toString());
  const types=(p.get(1)||[]).map(b=>{const m=message(b);return {type:strings[one(m,1)],unit:strings[one(m,2)]};});
  const functions=new Map((p.get(5)||[]).map(b=>{const m=message(b);return [one(m,1),{name:short(strings[one(m,2)]),file:strings[one(m,4)]}];}));
  const locations=new Map((p.get(4)||[]).map(b=>{
    const m=message(b);return [one(m,1),(m.get(4)||[]).map(b=>{
      const line=message(b), fn=functions.get(one(line,1));
      return {...fn,line:one(line,2)};
    })];
  }));
  const totals=new Map(), sites=new Map(), samples=[];
  let total=0;
  for(const b of p.get(2)||[]) {
    const m=message(b), values=vector(m,2), value=values.at(-1), frames=vector(m,1).flatMap(id=>locations.get(id)||[]);
    if(!Number.isFinite(value)) throw Error('missing sample value');
    total+=value;
    for(const name of new Set(frames.map(f=>f.name))) totals.set(name,(totals.get(name)||0)+value);
    for(const name of new Set(frames.map(f=>`${f.name} ${f.file?.split('/').at(-1)}:${f.line}`))) sites.set(name,(sites.get(name)||0)+value);
    samples.push({value,stack:frames.slice(0,9).map(f=>`${f.name}:${f.line}`)});
  }
  const scale=types.at(-1)?.unit==='nanoseconds'?1e9:1;
  const top=(map,filter)=>[...map].filter(([name])=>filter(name)).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([name,value])=>({name,value:value/scale,percent:100*value/total}));
  return {type:types.at(-1),total:total/scale,scale,
    allFunctions:top(totals,()=>true),
    functions:top(totals,name=>name.startsWith('ns/')||name.startsWith('gv/')),
    sites:top(sites,name=>name.startsWith('ns/')),
    samples:samples.sort((a,b)=>b.value-a.value).slice(0,8).map(s=>({...s,value:s.value/scale}))};
}


if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const chunks=[];
  for await (const chunk of process.stdin) chunks.push(chunk);
  console.log(JSON.stringify({kind:process.argv[2], ...summarizeProfile(Buffer.concat(chunks))}));
}
