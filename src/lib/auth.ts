export class AuthError extends Error {}
export function getAuthContext(req: Request): { wallet: string } {
  const header = req.headers.get('x-wallet-address');
  if (header) return { wallet: validateWalletAddress(header).value };
  throw new AuthError('Missing auth');
}
export function assertOwnership(ctx: {wallet: string}, expected: string): void {
  if (ctx.wallet !== expected) throw new AuthError('Forbidden');
}
