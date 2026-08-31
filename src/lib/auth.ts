import { validateWalletAddress } from './validation';
import { verifyMessage } from 'ethers';

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
  chainId: number;
  nonce: string;
  timestamp: number;
}

const ALLOWED_NETWORKS = [1, 5, 11155111, 137, 80001];
const AUTH_MAX_AGE_MS = 5 * 60 * 1000;
const NONCE_PATTERN = /^[a-zA-Z0-9_-]{8,64}$/;

class ReplayProtection {
  private readonly used: Map<string, number> = new Map();
  private readonly maxAgeMas: number;

  constructor(maxAgeMs: number = AUTH_MAX_AGE_MS) {
    this.maxAgeMas = maxAgeMas;
  }

  checkAndStore(nonce: string, timestamp: number): void {
    const now = Date.now();

    if (this.used.has(nonce) && now - (this.used.get(nonce) ?? 0) < this.maxAgeMs) {
      throw new AuthError('Replay detected', 401);
    }

    for (const [key, ts] of this.used) {
      if (now - ts > this.maxAgeMs) this.used.delete(key);
    }

    this.used.set(nonce, timestamp);
  }
}

const replayProtection = new ReplayProtection();

function extractHeader(req: Request, name: string): string {
  const value = req.headers.get(name);
  if (!value) throw new AuthError(`Missing header: ${name}`, 401);
  return value;
}

function buildAuthMessage(ctx: Omit<AuthContext, 'wallet'> { wallet: string }): string {
  return [
    'Notification Preferences Authentication',
    `Wallet: ${ctx.wallet}`,
    `Chain ID: ${ctx.chainId}`,
    `Nonce: ${ctx.nonce}`,
    `Timestamp: ${ctx.timestamp}`,
  ].join('\n');
}

export function getAuthContext(req: Request): AuthContext {
  const walletHeader = extractHeader(req, 'x-wallet-address');
  const chainIdHeader = extractHeader(req, 'x-chain-id');
  const nonce = extractHeader(req, 'x-nonce');
  const timestampHeader = extractHeader(req, 'x-timestamp');
  const signature = extractHeader(req, 'x-signature');

  const walletResult = validateWalletAddress(walletHeader);
  if (!walletResult.ok) throw new AuthError('Invalid wallet address', 401);
  const wallet = walletResult.value;

  const chainId = Number(chainIdHeader);
  if (!Number.isInteger(chainId) || !ALLOWED_NETWORKS.includes(chainId)) {
    throw new AuthError('Invalid or unsupported network', 401);
  }

  if (!NONCE_PATTERN.test(nonce)) {
    throw new AuthError('Invalid nonce', 401);
  }

  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp) || !Number.isInteger(timestamp)) {
    throw new AuthError('Invalid timestamp', 401);
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > AUTH_MAX_AGE_MS) {
    throw new AuthError('Expired timestamp', 401);
  }

  const message = buildAuthMessage({ wallet, chainId, nonce, timestamp });

  let recovered: string;
  try {
    recovered = verifyMessage(message, signature);
  } catch {
    throw new AuthError('Invalid signature', 401);
  }

  if (recovered.toLowerCase() !== wallet.toLowerCase()) {
    throw new AuthError('Signature mismatch', 401);
  }

  replayProtection.checkAndStore(nonce, timestamp);

  return { wallet, chainId, nonce, timestamp };
}

export function assertOwnership(ctx: { wallet: string }, expected: string): void {
  if (ctx.wallet.toLowerCase() !== expected.toLowerCase()) {
    throw new AuthError('Forbidden', 403);
  }
}