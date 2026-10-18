// How Windows program paths are compared. Kept apart from the rest of the
// Windows platform so app-path can use it without importing the modules that
// import app-path.
const VERSION = '[0-9]+(?:\\.[0-9]+)+';
const VERSION_FOLDER = new RegExp(`^(app-|v)?(${VERSION})$`, 'i');
const STORE_FOLDER = new RegExp(`^([^_]+)_(${VERSION})(_(?:x64|x86|arm64|arm|neutral)__[^_]+)$`, 'i');

export const windowsAppPath = {
  separator: '\\',
  foldCase: (value) => value.toLowerCase(),
  regexFlags: '(?i)',
  versionPattern: VERSION,
  versionFolder(segment) {
    const version = VERSION_FOLDER.exec(segment);
    if (version) return { before: version[1] ?? '', after: '', version: true };
    const store = STORE_FOLDER.exec(segment);
    if (store) return { before: `${store[1]}_`, after: store[3], version: true };
    return null;
  },
};
