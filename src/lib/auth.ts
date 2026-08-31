import { validateWalletAddress } from './validation';

export class AuthError extends Error {
  readonly status: number;

  constructor(message: string, status = 401) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
  }
}

export interface AuthContext {
  wallet: string;
}

export function getAuthContext(req: Request): AuthContext {
  const header = req.headers.get('x-wallet-address');
  if (!header) throw new AuthError('Missing auth', 401);
  const result = validateWalletAddress(header);
  if (!result.ok) throw new AuthError('Invalid wallet', 401);
  return { wallet: result.value };
}

export function assertOwnership(ctx: { wallet: string }, expected: string): void {
  if (ctx.wallet !== expected) throw new AuthError('Forbidden', 403);
}
