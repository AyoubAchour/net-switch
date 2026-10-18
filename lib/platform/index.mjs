import { windows } from './windows.mjs';

export function platformFor(name = process.platform) {
  if (name === 'win32') return windows;
  throw new Error(`Net Switch doesn't support ${name} yet`);
}
