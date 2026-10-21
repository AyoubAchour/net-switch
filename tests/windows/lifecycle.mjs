export async function timedPhase(phases, name, action) {
  const started = performance.now();
  try { return await action(); }
  finally { phases[name] = (phases[name] ?? 0) + performance.now() - started; }
}

export function lifecycleOutput(write) {
  let buffer = '';
  const events = [];
  const output = (chunk) => {
    write(chunk);
    buffer += chunk.toString();
    for (;;) {
      const end = buffer.indexOf('\n');
      if (end < 0) break;
      const line = buffer.slice(0, end);
      buffer = buffer.slice(end + 1);
      const marker = 'WINDOWS LIFECYCLE ';
      const at = line.indexOf(marker);
      if (at >= 0) {
        try { events.push(JSON.parse(line.slice(at + marker.length))); }
        catch (error) { events.push({ parseError: error.message, line }); }
      }
    }
  };
  output.events = events;
  return output;
}
