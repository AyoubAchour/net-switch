import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {readWorkflow,jobRuns,evaluate} from './workflows.mjs';

const text=readFileSync(new URL('../workflows/ci.yml',import.meta.url),'utf8');
const {jobs}=readWorkflow(text);
test('boundary pilot is two jobs; expansion requires an explicit hunt and replica count',()=>{
 for(const scenario of ['boundaries','boundaries-hunt']){
  const context={github:{event_name:'workflow_dispatch'},inputs:{regular_jobs:false,control_security:false,wintun_integrity:true,wintun_integrity_scenario:scenario},needs:{changes:{result:'skipped',outputs:{}}},functions:{cancelled:()=>false,success:()=>true,always:()=>true}};
  assert.deepEqual([...jobs].filter(([,j])=>jobRuns(j,context)).map(([n])=>n),['wintun-boundaries']);
 }
 const block=text.split('  wintun-boundaries:\n')[1].split('\n  wintun-payload-pilot:')[0];
 assert.match(block,/runner: \[windows-latest, windows-11-arm\]/);
 const expression=/replica: \$\{\{ fromJSON\((.*)\) \}\}/.exec(block)?.[1];
 assert.ok(expression);
 for(const scenario of [undefined,'proof','boundaries','boundaries-hunt']) {
  for(const count of [undefined,'1','2','5','20']) {
   const replicas=JSON.parse(evaluate(expression,{inputs:{wintun_integrity_scenario:scenario,wintun_boundary_shards:count}}));
   const expected=scenario==='boundaries-hunt'&&['2','5'].includes(count)?Number(count):1;
   assert.deepEqual(replicas,Array.from({length:expected},(_,i)=>i+1));
   assert.ok(replicas.length*2<=10);
  }
 }
 assert.match(text,/wintun_boundary_shards:[\s\S]*?default: '1'/);
 assert.match(block,/max-parallel: 10/);
 assert.doesNotMatch(block,/continue-on-error/);
 assert.match(block,/go test -c -o .\/bin\/wintun-baseline.test.exe/);
 assert.match(block,/go test -tags=wintun_boundaries -c/);
 assert.match(block,/TestWintunBoundaryProof/);
});
