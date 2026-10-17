// Looks for a newer Net Switch on GitHub. It only reads: Net Switch never
// downloads or runs anything by itself, because the server runs as
// administrator. The window offers the installer as a normal browser
// download, and the installer updates the running copy like any upgrade.

export const LATEST_RELEASE_URL = 'https://api.github.com/repos/AyoubAchour/net-switch/releases/latest';
// Links from the answer are used only if they point at this project's own
// release pages, so a wrong or tampered answer can't send anyone elsewhere.
const RELEASE_PAGE_PREFIX = 'https://github.com/AyoubAchour/net-switch/releases/tag/';
const INSTALLER_PREFIX = 'https://github.com/AyoubAchour/net-switch/releases/download/';
const INSTALLER_NAME = /^NetSwitch-Setup-\d+\.\d+\.\d+-x64\.exe$/;

// The first check waits a minute, so starting Net Switch stays quick; after
// that, twice a day is plenty for a program that changes every few weeks.
export const FIRST_CHECK_MS = 60_000;
export const CHECK_EVERY_MS = 12 * 60 * 60 * 1000;
const CHECK_TIMEOUT_MS = 15_000;

// [major, minor, patch] from "1.2.3" or "v1.2.3", or null.
export function parseVersion(text) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(text ?? '').trim());
  return match ? match.slice(1).map(Number) : null;
}

// Whether version a is newer than b. Anything that isn't a plain version is never newer.
export function isNewer(a, b) {
  const [left, right] = [parseVersion(a), parseVersion(b)];
  if (!left || !right) return false;
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return left[i] > right[i];
  }
  return false;
}

// What GitHub's latest-release answer offers, if it is a newer, complete,
// published release: { version, page, installer }. Otherwise null.
export function offerFrom(release, currentVersion) {
  if (!release || typeof release !== 'object' || release.draft || release.prerelease) return null;
  const version = String(release.tag_name ?? '').replace(/^v/, '');
  if (!isNewer(version, currentVersion)) return null;
  const page = String(release.html_url ?? '');
  if (!page.startsWith(RELEASE_PAGE_PREFIX)) return null;
  const asset = (Array.isArray(release.assets) ? release.assets : []).find((item) => INSTALLER_NAME.test(String(item?.name ?? '')));
  const installer = String(asset?.browser_download_url ?? '');
  if (!installer.startsWith(INSTALLER_PREFIX)) return null;
  return { version, page, installer };
}

export class UpdateChecker {
  constructor({
    currentVersion,
    // Whether checking is allowed right now (the person can turn it off).
    enabled = () => true,
    fetch = globalThis.fetch,
    log = () => {},
    firstCheckMs = FIRST_CHECK_MS,
    checkEveryMs = CHECK_EVERY_MS,
  }) {
    this.currentVersion = currentVersion;
    this.enabled = enabled;
    this.fetch = fetch;
    this.log = log;
    this.firstCheckMs = firstCheckMs;
    this.checkEveryMs = checkEveryMs;
    // The newer release found by the last successful check, or null.
    this.offer = null;
    this.timer = null;
    this.checking = null;
    // The last failure, so the same one isn't logged twice a day forever.
    this.lastFailure = null;
  }

  start() {
    this.schedule(this.firstCheckMs);
  }

  stop() {
    clearTimeout(this.timer);
    this.timer = null;
  }

  schedule(ms) {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.check().finally(() => this.schedule(this.checkEveryMs));
    }, ms);
    this.timer.unref?.();
  }

  // Checks now, unless a check is already running; resolves when done.
  check() {
    if (!this.checking) {
      this.checking = this.checkNow().finally(() => {
        this.checking = null;
      });
    }
    return this.checking;
  }

  async checkNow() {
    if (!this.enabled()) return;
    try {
      const response = await this.fetch(LATEST_RELEASE_URL, {
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': `NetSwitch/${this.currentVersion}`,
          'X-GitHub-Api-Version': '2022-11-28',
        },
        signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
      });
      // 404: no published release yet.
      if (response.status === 404) {
        this.offer = null;
        return;
      }
      if (!response.ok) throw new Error(`GitHub answered ${response.status}`);
      const offer = offerFrom(await response.json(), this.currentVersion);
      if (offer && offer.version !== this.offer?.version) this.log(`Net Switch ${offer.version} is available (this is ${this.currentVersion})`);
      this.offer = offer;
      this.lastFailure = null;
    } catch (error) {
      // Offline, blocked or GitHub having a bad day: try again at the next check.
      const reason = error.name === 'TimeoutError' ? 'no answer within 15 seconds' : error.message;
      if (reason !== this.lastFailure) this.log(`could not check for updates: ${reason}`);
      this.lastFailure = reason;
    }
  }
}
