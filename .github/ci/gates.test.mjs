import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { groups } from './changes.mjs';
import { jobRuns, readWorkflow } from './workflows.mjs';

const workflow = name => readWorkflow(readFileSync(new URL(`../workflows/${name}.yml`, import.meta.url), 'utf8'));

// Which group each job belongs to, written out independently of the files, so
// a moved or new job fails here until someone decides what it depends on.
// investigation: manual-only jobs that existed before gating. oracle: the go
// list check of the drift guard, which must not depend on the classifier.
// manual: jobs a workflow_dispatch input selects and nothing else starts, so
// they depend on no changed file and wait for no classifier.
const expected = {
  ci: {
    'windows-acceptance': 'legacy_windows', testisp: 'testisp', engine: 'legacy_windows',
    'go1-windows': 'go_windows', 'go1-linux': 'go_linux', wintun: 'wintun', linux: 'node',
    'linux-helper': 'helper', 'test-node-22': 'node', 'test-node-24': 'node', installer: 'installer', arm64: 'node',
    'control-security': 'investigation', 'testisp-reproduction': 'investigation', 'golist-oracle': 'oracle',
    'wintun-integrity': 'investigation', 'wintun-payload-pilot': 'investigation', 'wintun-boundaries': 'investigation',
  },
  control: { windows: 'control' },
  'linux-acceptance': { linux: 'acceptance', 'release-gate': 'manual', 'trace-analysis': 'manual' },
};

// A manual Acceptance run is a release-gate check, a saved-trace analysis, or
// the regular engine run, chosen by these two inputs.
const acceptanceInputs = [
  { run: '', release_gate: false, trace_artifact: '' },
  { run: '', release_gate: true, trace_artifact: '' },
  { run: '', release_gate: false, trace_artifact: '123' },
  { run: '', release_gate: true, trace_artifact: '123' },
];

// What each job should do, from the PR's description rather than the files:
// main pushes run everything; a manual CI run starts only the investigation
// unless regular_jobs is set (Control and Acceptance have no other purpose
// for a manual run); a PR job runs unless the classifier succeeded and said
// false for its group; nothing starts in a cancelled run.
function shouldRun(file, group, s) {
  if (s.cancelled) return false;
  // Every push and pull request, whatever the classifier did; manual runs
  // only with the regular jobs.
  if (group === 'oracle') return s.event !== 'workflow_dispatch' || s.inputs.regular_jobs;
  if (group === 'investigation') {
    // Either option replaces the default TestISP investigation.
    if (s.event !== 'workflow_dispatch') return false;
    if (s.job === 'wintun-integrity') return Boolean(s.inputs.wintun_integrity) && !['payload','boundaries','boundaries-hunt'].includes(s.inputs.wintun_integrity_scenario);
    if (s.job === 'wintun-boundaries') return Boolean(s.inputs.wintun_integrity) && ['boundaries','boundaries-hunt'].includes(s.inputs.wintun_integrity_scenario);
    if (s.job === 'wintun-payload-pilot') return Boolean(s.inputs.wintun_integrity) && s.inputs.wintun_integrity_scenario === 'payload';
    if (s.inputs.wintun_integrity) return false;
    return s.job === 'control-security' ? s.inputs.control_security : !s.inputs.control_security && !s.inputs.regular_jobs;
  }
  if (group === 'manual') {
    if (s.event !== 'workflow_dispatch') return false;
    return s.job === 'release-gate' ? Boolean(s.inputs.release_gate) : !s.inputs.release_gate && s.inputs.trace_artifact !== '';
  }
  if (s.event === 'workflow_dispatch' && file === 'ci' && !s.inputs.regular_jobs) return false;
  // The engine run steps aside for the two manual-only jobs.
  if (s.event === 'workflow_dispatch' && file === 'linux-acceptance' && (s.inputs.release_gate || s.inputs.trace_artifact)) return false;
  if (s.event !== 'pull_request') return true;
  return s.changesResult !== 'success' || s.outputs[group] !== 'false';
}

function context(job, s) {
  const needs = Object.fromEntries(job.needs.map(id => [id, { result: s.changesResult, outputs: s.outputs }]));
  const results = Object.values(needs).map(need => need.result);
  return {
    github: { event_name: s.event },
    inputs: s.event === 'workflow_dispatch' ? s.inputs : {},
    needs,
    functions: {
      always: () => true,
      cancelled: () => s.cancelled,
      success: () => !s.cancelled && results.every(result => result === 'success'),
      failure: () => results.includes('failure'),
    },
  };
}

function* scenarios(file, changes) {
  const inputSets = file === 'ci'
    ? [false, true].flatMap(regular_jobs => [false, true].flatMap(control_security => [false, true].flatMap(wintun_integrity => ['x64', 'arm64', 'both'].map(wintun_integrity_arch => ({ regular_jobs, control_security, wintun_integrity, wintun_integrity_arch, packet_capture: false })))))
    : file === 'linux-acceptance' ? acceptanceInputs : [{ run: '' }];
  if (file === 'ci') inputSets.push({ regular_jobs: false, control_security: false, wintun_integrity: true, wintun_integrity_scenario: 'payload' });
  if (file === 'ci') for (const scenario of ['boundaries','boundaries-hunt']) inputSets.push({ regular_jobs:false,control_security:false,wintun_integrity:true,wintun_integrity_scenario:scenario });
  // Every group alone true or alone false, plus all true and all false, so a
  // gate reading another group's output is caught as well as a wrong value.
  // Job outputs are strings; boolean false must not count as 'false', so a
  // gate comparing with a boolean would skip on output it never gets.
  const outputSets = [
    Object.fromEntries(groups.map(group => [group, 'true'])),
    Object.fromEntries(groups.map(group => [group, 'false'])),
    Object.fromEntries(groups.map(group => [group, false])),
    ...groups.flatMap(only => [
      Object.fromEntries(groups.map(group => [group, String(group === only)])),
      Object.fromEntries(groups.map(group => [group, String(group !== only)])),
      Object.fromEntries(groups.map(group => [group, group !== only])),
    ]),
    {},
  ];
  for (const event of ['push', 'pull_request', 'workflow_dispatch']) {
    for (const inputs of event === 'workflow_dispatch' ? inputSets : [{}]) {
      for (const cancelled of [false, true]) {
        const base = { event, inputs, cancelled, outputs: {} };
        // The classifier job's own condition decides whether it ran at all.
        if (!jobRuns(changes, context({ needs: [] }, { ...base, changesResult: 'success' }))) {
          yield { ...base, changesResult: 'skipped' };
          continue;
        }
        // A job that fails after its filter step wrote outputs still exposes
        // them, so failed and cancelled results get every output set too.
        for (const changesResult of ['success', 'failure', 'cancelled']) {
          for (const outputs of outputSets) yield { ...base, changesResult, outputs };
        }
        // Skipped although its condition holds (a re-run of only some jobs,
        // or a future condition): no outputs, and every gated job must run.
        yield { ...base, changesResult: 'skipped', outputs: {} };
      }
    }
  }
}

function checkGates(file, { jobs }) {
  let count = 0;
  const changes = jobs.get('changes');
  assert.ok(changes, 'classifier job');
  assert.deepEqual([...jobs.keys()].filter(id => id !== 'changes').sort(), Object.keys(expected[file]).sort());
  for (const [id, group] of Object.entries(expected[file])) {
    const job = jobs.get(id);
    if (group === 'oracle') {
      assert.deepEqual(job.needs, [], id);
      assert.doesNotMatch(job.if ?? '', /needs\./, id);
    } else if (group === 'manual') {
      assert.deepEqual(job.needs, [], id);
      assert.match(job.if ?? '', /github\.event_name == 'workflow_dispatch'/, id);
      assert.doesNotMatch(job.if, /needs\./, id);
    } else if (group !== 'investigation') {
      assert.deepEqual(job.needs, ['changes'], id);
      // The job must read its own group's output and no other.
      assert.deepEqual([...job.if.matchAll(/needs\.changes\.outputs\.(\w+)/g)].map(match => match[1]), [group], id);
    }
    for (const s of scenarios(file, changes)) {
      assert.equal(jobRuns(job, context(job, { ...s, job: id })), shouldRun(file, group, { ...s, job: id }), `${id} in ${JSON.stringify(s)}`);
      count += 1;
    }
  }
  return count;
}

let checked = 0;
for (const file of Object.keys(expected)) {
  test(`${file}.yml: every job runs exactly when its dependency group needs it`, () => {
    checked += checkGates(file, workflow(file));
  });

  test(`${file}.yml: the classifier job exposes every group and runs the CI tests`, () => {
    const changes = workflow(file).jobs.get('changes');
    assert.deepEqual(changes.outputs, Object.fromEntries(groups.map(group => [group, `\${{ steps.filter.outputs.${group} }}`])));
    assert.deepEqual(changes.needs, []);
    const runs = changes.steps.map(step => step.keys.run?.inline);
    assert.ok(runs.includes('node --test .github/ci/*.test.mjs'), 'runs the classifier, drift and gate tests');
    assert.ok(changes.steps.some(step => step.keys.id?.inline === 'filter' && step.keys.run?.inline === 'node .github/ci/changes.mjs'));
    assert.match(changes.steps[0].text, /fetch-depth: 0/);
    // A default manual CI run stays as cheap as before gating: no classifier.
    const dispatch = regular_jobs => jobRuns(changes, context(changes, { event: 'workflow_dispatch', inputs: { regular_jobs }, cancelled: false }));
    assert.equal(dispatch(false), file !== 'ci');
    assert.equal(dispatch(true), true);
  });

  test(`${file}.yml: label changes start no run`, () => {
    // A label event would share the PR's concurrency group and cancel the
    // PR's own run, or post newer skipped checks over a failure.
    const { header } = workflow(file);
    const trigger = /^ {2}pull_request:(.*)\n((?: {4}.*\n)*)/m.exec(`${header}\n`);
    assert.ok(trigger, 'pull_request trigger');
    assert.doesNotMatch(trigger[1] + trigger[2], /labeled|types/);
  });
}

test('required checks keep their exact names on plain jobs', () => {
  const { jobs } = workflow('ci');
  // Ruleset "Protect main" requires these names. A matrix job skipped by its
  // condition reports a different name, so none of them may use a matrix.
  for (const [id, name] of [['test-node-22', 'Windows / Node 22'], ['test-node-24', 'Windows / Node 24'], ['installer', 'Installer smoke test']]) {
    assert.equal(jobs.get(id).name, name);
    assert.equal(jobs.get(id).hasStrategy, false, id);
  }
  // The two Node jobs differ only in the Node version they set up.
  const steps = id => jobs.get(id).steps.map(step => step.text.replace(/node-version: '2[24]'/, 'node-version: N'));
  assert.deepEqual(steps('test-node-22'), steps('test-node-24'));
  assert.match(jobs.get('test-node-22').steps[1].text, /node-version: '22'/);
  assert.match(jobs.get('test-node-24').steps[1].text, /node-version: '24'/);
});

test('the gate scenarios actually ran', () => {
  // Guards against the loops above silently checking nothing.
  assert.ok(checked > 3000, `only ${checked} gate checks ran`);
  console.log(`# ${checked} gate checks`);
});

test('a broken gate fails the gate check', () => {
  const text = readFileSync(new URL('../workflows/ci.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const gate = "if: ${{ !cancelled() && (github.event_name != 'workflow_dispatch' || inputs.regular_jobs) && (github.event_name != 'pull_request' || needs.changes.result != 'success' || needs.changes.outputs.installer != 'false') }}";
  assert.ok(text.includes(gate), 'installer gate as written today');
  const mutations = {
    'no cancelled check': gate.replace('!cancelled() && ', ''),
    'skips when the classifier fails': gate.replace("needs.changes.result != 'success' || ", ''),
    'filters main pushes': gate.replace("github.event_name != 'pull_request' || ", ''),
    'runs on every manual run': gate.replace("(github.event_name != 'workflow_dispatch' || inputs.regular_jobs) && ", ''),
    'never runs on manual runs': gate.replace('|| inputs.regular_jobs', ''),
    'another group': gate.replace('outputs.installer', 'outputs.node'),
    'two groups': gate.replace("needs.changes.outputs.installer != 'false'", "needs.changes.outputs.installer != 'false' || needs.changes.outputs.node != 'false'"),
    'implicit success()': gate.replace('!cancelled() && ', 'true && '),
    'compares with true': gate.replace("outputs.installer != 'false'", "outputs.installer == 'true'"),
    'compares with boolean false': gate.replace("outputs.installer != 'false'", 'outputs.installer != false'),
    // Differs from the real gate only when the classifier is skipped on a PR.
    'skips when the classifier is skipped': gate.replace('!cancelled() && ', "!cancelled() && needs.changes.result != 'skipped' && "),
  };
  for (const [name, broken] of Object.entries(mutations)) {
    assert.notEqual(broken, gate, name);
    assert.throws(() => checkGates('ci', readWorkflow(text.replace(gate, broken))), assert.AssertionError, name);
  }
  assert.throws(() => checkGates('ci', readWorkflow(text.replace('  installer:\n    needs: changes\n', '  installer:\n'))), assert.AssertionError, 'no needs');
});

test('a broken Acceptance gate fails the gate check', () => {
  const text = readFileSync(new URL('../workflows/linux-acceptance.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const check = broken => checkGates('linux-acceptance', readWorkflow(broken));
  const engine = "!cancelled() && !inputs.release_gate && !inputs.trace_artifact && (github.event_name != 'pull_request'";
  const gate = "if: ${{ github.event_name == 'workflow_dispatch' && inputs.release_gate }}";
  assert.ok(text.includes(engine) && text.includes(gate), 'gates as written today');
  assert.doesNotThrow(() => check(text));
  assert.throws(() => check(text.replace(engine, "!cancelled() && !inputs.trace_artifact && (github.event_name != 'pull_request'")), assert.AssertionError, 'engine run beside the release gate');
  assert.throws(() => check(text.replace(engine, "!cancelled() && !inputs.release_gate && (github.event_name != 'pull_request'")), assert.AssertionError, 'engine run beside a trace analysis');
  assert.throws(() => check(text.replace(gate, "if: ${{ inputs.release_gate }}")), assert.AssertionError, 'release gate on pushes');
  assert.throws(() => check(text.replace(gate, "if: ${{ github.event_name == 'workflow_dispatch' }}")), assert.AssertionError, 'release gate on every manual run');
});
