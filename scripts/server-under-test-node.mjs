// Launcher-only dependency injection: the Node factory and Engine are the same
// ones shipped today. This lets both e2e modes choose an exact verified engine
// executable without changing production Node startup or packaging.
import path from 'node:path';
import { createServer } from '../lib/server-factory.mjs';
import { Engine } from '../lib/engine.mjs';
import { platformFor } from '../lib/platform/index.mjs';

const value = (flag) => {
  const i = process.argv.indexOf(flag);
  if (i < 0 || !process.argv[i + 1]) throw new Error(`${flag} is required by the test launcher`);
  return path.resolve(process.argv[i + 1]);
};
const mode = process.argv.includes('--dev-proxy') ? 'proxy' : 'tun';
if (mode === 'tun' && (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted')) {
  throw new Error('TUN control tests require a disposable GitHub-hosted runner.');
}
await createServer({ engine: new Engine({ platform: platformFor(), singBoxPath: value('--engine-executable'), dataDir: value('--machine-data'), mode }) });
