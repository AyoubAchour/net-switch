// Undoes the Windows settings Net Switch changed, without starting Net Switch.
// The uninstaller runs this (as administrator) before removing the program.
//
//   node tools/restore-windows.mjs [--machine-data <folder>]
//
// The folder defaults to %ProgramData%\Net Switch, where an installed copy
// keeps its undo record.
//
// Exit code 0 means the uninstaller may delete the record: there was no record
// or nothing in it, or everything is back as it was. Any doubt is exit code 1
// and the record stays: something couldn't be undone, or the record is damaged
// and had to be recovered or can't be trusted.
import path from 'node:path';
import { hasChanges, openUndoRecord, undoWindowsChanges, validateUndoRecord } from '../lib/windows-undo.mjs';

const flag = process.argv.indexOf('--machine-data');
const dir =
  flag > 0 && process.argv[flag + 1]
    ? path.resolve(process.argv[flag + 1])
    : path.join(process.env.ProgramData ?? 'C:\\ProgramData', 'Net Switch');

const record = openUndoRecord(dir);
try {
  await record.load();
  // A damaged file is read back from its backup or replaced by an empty
  // record. Either way it isn't the record as written, so this run doesn't
  // decide anything: a person should look at the kept copies first.
  if (record.recovery) {
    console.error(`The undo record in ${dir} was damaged (${record.recovery.reason}). It is kept; nothing was changed.`);
    process.exit(1);
  }
  const problems = validateUndoRecord(record.values);
  if (problems.length > 0) {
    console.error(`The undo record in ${dir} can't be trusted (${problems.join('; ')}). It is kept; nothing was changed.`);
    process.exit(1);
  }
  if (!hasChanges(record.values)) {
    console.log('Nothing to undo.');
    process.exit(0);
  }
  const unreachable = await undoWindowsChanges(record);
  if (unreachable.length > 0) {
    console.log(`Undone, except the settings of ${unreachable.join(' and ')}: connect it again and run this again.`);
    process.exit(1);
  }
  console.log('Windows settings are back as they were before Net Switch changed them.');
  process.exit(0);
} catch (error) {
  console.error(`Couldn't undo the Windows settings: ${error.message}`);
  process.exit(1);
}
