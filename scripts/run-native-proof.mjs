import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const containment = ['TestWintunSupervisorContainment', ...['host-child-suspended','host-registrar-suspended','child-registrar-suspended','host-ready','child-ready'].map(name=>`TestWintunSupervisorContainment/${name}`)];
const native = names => ['TestNativeEngineService', ...['installed-native-engine-denies-other-user','service-crash-cleanup','explicit-ctl-removes-real-leftovers',...names].map(name=>`TestNativeEngineService/${name}`)];
const retirementFailure = 'retirement-failure-exits-and-cleans-capture';
// The installed Control proof needs the fault build (injected owner presence and
// crash barriers), so its PASS lines are required in the faults variant only.
const control = ['TestNativeControlCutover', ...['routes-traffic-through-the-native-engine','engine-service-is-never-restarted-by-the-manager','exact-usage-survives-control-crashes-around-the-ack','child-crash-counts-one-failure-and-restarts','adapter-loss-restarts-free-then-counts','control-absent-past-the-lease-then-restored-within-70s'].map(name=>`TestNativeControlCutover/${name}`)];
export const required = {
  'native-product': native(['product-build-ignores-forwarding-fault','control-absent-whole-child','control-absent-host','control-absent-host-and-child']),
  'native-faults': [...control, ...native([retirementFailure,'idle-error-survives-live-lease-backoff','forwarding-health-under-load','slow-start-and-clean-stop','starting-hang-is-bounded','same-child-routing-restart-health','read-deadline-control-with-forwarding-live','totals-capacity-over-installed-transport','startup-death-before-readiness','slow-relay-and-log-readers','control-absent-read-pump','service-outcome-three-cleanup-fails-false','service-outcome-three-cleanup-fails-true'])],
  containment,
  'containment-retry': [...containment,'TestRegistrarBusyRetryOnlyUnclaimedRegistration'],
  launch: ['TestEnvironmentIsExplicitAndBounded','TestRegistrarParentRequiresExplicitGuard',...['DeathAtCreateReturnClosesTheOldOrphanWindow','DeathAtCreateReturnClosesTheOldOrphanWindow/create-window-uncontained','DeathAtCreateReturnClosesTheOldOrphanWindow/create-window','FullOutputPipesDoNotBlockTermination','NaturalExitThreeWinsTerminationRace','OrdinaryChildRefusedAndReplacedImageRejected','RegistrarCapabilityJoinsBeforeChildWaitCompletes','AtomicLaunchAndRawExit','GuardPolicyAndForcedSuspendedExit','CloseFailurePreservesRawExit','HandleListExcludesInheritableDecoy'].map(name=>`TestHosted${name}`)],
};
export function passReader(names) {
  const passed=new Set(); let tail='', overlong=false;
  return {
    push(chunk) {
      for(const part of chunk.toString().split(/(?<=\n)/)) {
        if(tail.length+part.length>8192) overlong=true;
        if(!overlong) tail+=part;
        if(part.endsWith('\n')) {
          const match=!overlong && /^\s*--- PASS: (\S+) \(/.exec(tail);
          if(match) passed.add(match[1]);
          tail='';overlong=false;
        }
      }
    },
    missing() { return names.filter(name=>!passed.has(name)); },
  };
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  const [suite,executable,...args]=process.argv.slice(2);
  if(!required[suite] || !executable || process.env.GITHUB_ACTIONS!=='true' || process.env.RUNNER_ENVIRONMENT!=='github-hosted') throw new Error('native proof runner requires a named suite and disposable hosted CI');
  const proof=passReader(required[suite]);
  const child=spawn(executable,args,{stdio:['ignore','pipe','inherit'],windowsHide:true});
  child.stdout.on('data',chunk=>proof.push(chunk));
  child.stdout.pipe(process.stdout);
  child.on('error',err=>{console.error(err);process.exitCode=1;});
  child.on('close',(code,signal)=>{
    const missing=proof.missing();
    if(code!==0 || signal || missing.length) { console.error(`Native proof failed: exit=${code} signal=${signal} missing PASS=${missing.join(', ')}`);process.exitCode=1; }
  });
}
