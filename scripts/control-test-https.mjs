// Test-launcher seam only: change the destination before the selected Control
// launches its verified engine. Its startup, process rules and selectors run
// normally. Removing the marker restores ordinary lifecycle configurations.
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { hostedOnly } from '../tests/windows/testisp/harness.mjs';

export const httpsMarker = 'test-local-https.json';

export function installHttpsConfigWriter(directory) {
  const configPath = path.join(directory, 'engine-config.json');
  const write = fs.promises.writeFile;
  fs.promises.writeFile = async (file, data, options) => {
    if (file === configPath) {
      const marker = await fs.promises.readFile(path.join(directory, httpsMarker), 'utf8')
        .catch((error) => { if (error.code === 'ENOENT') return null; throw error; });
      if (marker !== null) {
        hostedOnly();
        const config = JSON.parse(data);
        const rule = JSON.parse(marker);
        await write(path.join(directory, 'traffic-product-config.json'), data);
        config.route.rules.unshift(rule);
        data = JSON.stringify(config, null, 2);
      }
    }
    return write(file, data, options);
  };
  syncBuiltinESMExports();
}
