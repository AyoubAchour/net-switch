// Brings a startup task from an earlier version up to date. The installer runs
// this, as administrator, after copying the new files: Net Switch 0.3.0's task
// ran node.exe directly, which opened a console window at every sign-in. A
// missing task (starting with Windows is off) is fine.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installedHelper, upgradeAutostart } from '../lib/autostart.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

try {
  const result = await upgradeAutostart({ nodePath: process.execPath, helperPath: installedHelper(root) });
  console.log(`Startup task: ${result}`);
} catch (error) {
  console.error(`Couldn't update Net Switch's startup task: ${error.message}`);
  process.exit(1);
}
