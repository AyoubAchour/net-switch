// Reporting only: every outcome still fails, with no retry or exemption.
export function publicFailure({ endpoint, phase, status, verified, code, message }) {
  const label = verified && status >= 500 && status < 600 ? 'public target unavailable'
    : code === 'ECONNRESET' ? 'transport reset (origin unproven)'
    : code === 'ERR_STREAM_PREMATURE_CLOSE' || code === 'EOF' ? 'early close (origin unproven)'
    : 'public HTTPS failure (origin unproven)';
  return `${label}: endpoint=${endpoint}; phase=${phase}; ${status ? `HTTP ${status}; ` : ''}${message ?? code ?? ''}`;
}
