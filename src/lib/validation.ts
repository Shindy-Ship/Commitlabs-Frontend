export type Result<T> = { ok: true; value: T } | { ok: false; error: string };
export const MAX_LIMIT = 100;
export function validateWalletAddress(u: unknown): Result<string> {
  return typeof u === 'string' && /^0x[a-fA-F0-9]{40}$/.test(u) ? { ok: true, value: u.toLowerCase() } : { ok: false, error: 'Invalid wallet' };
}
export function validateNetwork(v: unknown): Result<string> {
  return v === 'mainnet' || v === 'sepolia' ? { ok: true, value: v } : { ok: false, error: 'Invalid network' };
}
export function validatePositiveInteger(v: unknown, max = MAX_LIMIT): Result<number> {
  return typeof v === 'number' && Number.isSafeInteger(v) && v > 0 && v <= max ? { ok: true, value: v } : { ok: false, error: 'Invalid int' };
}
export class ReplayGuard {
  private s = new Set<string>();
  assertFresh(id: string, ts: number): void {
    const k = id + ':' + ts;
    if (this.s.has(k)) throw new Error('replay');
    this.s.add(k);
  }
}
