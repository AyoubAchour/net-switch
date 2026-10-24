import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {readWorkflow,jobRuns} from './workflows.mjs';

const text=readFileSync(new URL('../workflows/ci.yml',import.meta.url),'utf8');
const {jobs}=readWorkflow(text);
test('boundary pilot is two jobs; only an explicit hunt selection expands to ten',()=>{
 for(const scenario of ['boundaries','boundaries-hunt']){
  const context={github:{event_name:'workflow_dispatch'},inputs:{regular_jobs:false,control_security:false,wintun_integrity:true,wintun_integrity_scenario:scenario},needs:{changes:{result:'skipped',outputs:{}}},functions:{cancelled:()=>false,success:()=>true,always:()=>true}};
  assert.deepEqual([...jobs].filter(([,j])=>jobRuns(j,context)).map(([n])=>n),['wintun-boundaries']);
 }
 const block=text.split('  wintun-boundaries:\n')[1].split('\n  wintun-payload-pilot:')[0];
 assert.match(block,/runner: \[windows-latest, windows-11-arm\]/);
 assert.match(block,/scenario == 'boundaries' && '\[1\]' \|\| '\[1,2,3,4,5\]'/);
 assert.match(block,/max-parallel: 10/);
 assert.doesNotMatch(block,/continue-on-error/);
 assert.match(block,/go test -c -o .\/bin\/wintun-baseline.test.exe/);
 assert.match(block,/go test -tags=wintun_boundaries -c/);
 assert.match(block,/TestWintunBoundaryProof/);
});
