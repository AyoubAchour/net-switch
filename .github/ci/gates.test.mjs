import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { groups } from './changes.mjs';
import { jobRuns, readWorkflow } from './workflows.mjs';

const workflow = name => readWorkflow(readFileSync(new URL(`../workflows/${name}.yml`, import.meta.url), 'utf8'));

// Which group each job belongs to, written out independently of the files, so
// a moved or new job fails here until someone decides what it depends on.
// investigation: manual-only jobs that existed before gating.
const expected = {
  ci: {
    'windows-acceptance': 'legacy_windows', testisp: 'testisp', engine: 'legacy_windows',
    'go1-windows': 'go_windows', 'go1-linux': 'go_linux', wintun: 'wintun', linux: 'node',
    'linux-helper': 'helper', 'test-node-22': 'node', 'test-node-24': 'node', installer: 'installer', arm64: 'node',
    'control-security': 'investigation', 'testisp-reproduction': 'investigation',
  },
  control: { windows: 'control' },
  'linux-acceptance': { linux: 'acceptance' },
};

// What each job should do, from the PR's description rather than the files:
// main pushes run everything; a manual CI run starts only the investigation
// unless regular_jobs is set (Control and Acceptance have no other purpose
// for a manual run); a PR job runs unless the classifier succeeded and said
// false for its group; nothing starts in a cancelled run.
function shouldRun(file, group, s) {
  if (s.cancelled) return false;
  if (group === 'investigation') {
    // Either option replaces the default TestISP investigation.
    if (s.event !== 'workflow_dispatch') return false;
    return s.job === 'control-security' ? s.inputs.control_security : !s.inputs.control_security && !s.inputs.regular_jobs;
  }
  if (s.event === 'workflow_dispatch' && file === 'ci' && !s.inputs.regular_jobs) return false;
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
    ? [false, true].flatMap(regular_jobs => [false, true].map(control_security => ({ regular_jobs, control_security, packet_capture: false })))
    : [{ run: '' }];
  // Every group alone true or alone false, plus all true and all false, so a
  // gate reading another group's output is caught as well as a wrong value.
  const outputSets = [
    Object.fromEntries(groups.map(group => [group, 'true'])),
    Object.fromEntries(groups.map(group => [group, 'false'])),
    ...groups.flatMap(only => [
      Object.fromEntries(groups.map(group => [group, String(group === only)])),
      Object.fromEntries(groups.map(group => [group, String(group !== only)])),
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
    if (group !== 'investigation') {
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
  };
  for (const [name, broken] of Object.entries(mutations)) {
    assert.notEqual(broken, gate, name);
    assert.throws(() => checkGates('ci', readWorkflow(text.replace(gate, broken))), assert.AssertionError, name);
  }
  assert.throws(() => checkGates('ci', readWorkflow(text.replace('  installer:\n    needs: changes\n', '  installer:\n'))), assert.AssertionError, 'no needs');
});
