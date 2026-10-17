const VERSION = '[0-9]+(?:\\.[0-9]+)+';
const VERSION_FOLDER = new RegExp(`^(app-|v)?(${VERSION})$`, 'i');
const STORE_FOLDER = new RegExp(`^([^_]+)_(${VERSION})(_(?:x64|x86|arm64|arm|neutral)__[^_]+)$`, 'i');

function escapePattern(value) {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
}

// Identity and routing use the same parts, so a saved choice cannot match an
// app in the window but miss it in the engine. Only folder versions vary;
// prefixes, package names, architectures and publishers still identify apps.
function pathParts(programPath) {
  const segments = programPath.split('\\');
  return segments.map((segment, index) => {
    if (index < segments.length - 1) {
      const version = VERSION_FOLDER.exec(segment);
      if (version) return { before: version[1] ?? '', after: '', version: true };
      const store = STORE_FOLDER.exec(segment);
      if (store) return { before: `${store[1]}_`, after: store[3], version: true };
    }
    return { before: segment, after: '', version: false };
  });
}

export function normalizedAppPath(programPath) {
  return pathParts(programPath)
    .map(({ before, after, version }) => `${before}${version ? '*' : ''}${after}`)
    .join('\\').toLowerCase();
}

// Anchored, case-insensitive Go RE2 syntax, as used by sing-box.
export function appPathPattern(programPath) {
  const pattern = pathParts(programPath)
    .map(({ before, after, version }) => `${escapePattern(before)}${version ? VERSION : ''}${escapePattern(after)}`)
    .join('\\\\');
  return `(?i)^${pattern}$`;
}
