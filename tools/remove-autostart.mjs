// Removes the scheduled tasks that start Net Switch with Windows. The
// uninstaller runs this, as administrator, so nothing starts a program that
// is gone. Tasks that are already gone are fine.
import { disableAutostart } from '../lib/autostart.mjs';

try {
  await disableAutostart();
} catch (error) {
  console.error(`Couldn't remove Net Switch's startup tasks: ${error.message}`);
  process.exit(1);
}
