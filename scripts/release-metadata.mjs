// Validate before building or publishing. Never derive a release version from a tag.
import { readFileSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const { version } = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error('package.json must contain a release version, for example 0.1.0.');
}
const tag = process.env.GITHUB_REF_NAME;
if (tag !== `v${version}`) {
  throw new Error(`Release tag ${JSON.stringify(tag)} must equal v${version} from package.json.`);
}
const changelog = readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8').replace(/\r\n/g, '\n');
const headings = [...changelog.matchAll(/^##[ \t]+\[([^\]\n]+)\][^\n]*$/gm)];
const sections = headings.filter((heading) => heading[1] === version);
if (sections.length !== 1) {
  throw new Error(`CHANGELOG.md must have exactly one ## [${version}] section; found ${sections.length}.`);
}
const heading = sections[0];
const start = heading.index + heading[0].length;
const remainder = changelog.slice(start);
const nextHeading = remainder.search(/^##[ \t]+/m);
const notes = remainder.slice(0, nextHeading === -1 ? undefined : nextHeading).trim();
if (!notes) throw new Error(`CHANGELOG.md section ${version} is empty.`);
const dist = path.join(root, 'dist');
mkdirSync(dist, { recursive: true });
writeFileSync(path.join(dist, 'release-notes.md'), `${notes}\n`);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `version=${version}\n`);
console.log(`Validated ${tag}; extracted its CHANGELOG.md notes.`);
