// Property order is policy for app pins and port shares, not presentation.
export function orderedPolicy(value, key = '') {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => orderedPolicy(item));
  if (key === 'appLines' || key === 'shares') return Object.entries(value).map(([name, item]) => [name, orderedPolicy(item)]);
  return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, orderedPolicy(item, name)]));
}
