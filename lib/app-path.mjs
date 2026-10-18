import { windowsAppPath } from './platform/windows-paths.mjs';

const windows = { appPath: windowsAppPath };

function escapePattern(value) {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
}

// Identity and routing use the same parts, so a saved choice cannot match an
// app in the window but miss it in the engine. Only folder versions vary;
// prefixes, package names, architectures and publishers still identify apps.
function pathParts(programPath, platform) {
  const segments = programPath.split(platform.appPath.separator);
  return segments.map((segment, index) => {
    if (index < segments.length - 1) {
      const version = platform.appPath.versionFolder(segment);
      if (version) return version;
    }
    return { before: segment, after: '', version: false };
  });
}

export function normalizedAppPath(programPath, platform = windows) {
  return platform.appPath.foldCase(pathParts(programPath, platform)
    .map(({ before, after, version }) => `${before}${version ? '*' : ''}${after}`)
    .join(platform.appPath.separator));
}

// Anchored Go RE2 syntax, as used by sing-box.
export function appPathPattern(programPath, platform = windows) {
  const pattern = pathParts(programPath, platform)
    .map(({ before, after, version }) => `${escapePattern(before)}${version ? platform.appPath.versionPattern : ''}${escapePattern(after)}`)
    .join(escapePattern(platform.appPath.separator));
  return `${platform.appPath.regexFlags}^${pattern}$`;
}
