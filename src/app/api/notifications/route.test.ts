import { GET, POST } from './route';
import { NextRequest } from 'next/server';
import { Wallet } from 'ethers';

const PRIVATE_KEY = '0x0123456789012345678901234567890123456789012345';
const signer = new Wallet(PRIVATE_KEY);
const VALID_WALLET = signer.address.toLowerCase();
const OTHER_WALLET = '0xabcdef1234567890abcdef1234567890abcdef12345678';

const R = (u: string, m = 'GET', h: Record<string, string> = {}, b?: BodyInit) =>
  new NextRequest(u, { method: m, headers: h, body: b });

let nonceCounter = 0;
function freshNonce(): string {
  nonceCounter += 1;
  return `nonce-${Date.now()}-${nonceCounter}-${Math.random().toString(36).slice(2, 8)}`;
}

async function authHeaders(opts: { wallet?: string; chainId?: number; nonce?: string; signer?: Wallet } = {}): Promise<Record<string, string>> {
  const wallet = (opts.wallet ?? VALID_WALLET).toLowerCase();
  const chainId = opts.chainId ?? 1;
  const nonce = opts.nonce ?? freshNonce();
  const timestamp = Date.now();
  const activeSigner = opts.signer ?? signer;
  const message = [
    'Notification Preferences Authentication',
    `Wallet: ${wallet}`,
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Timestamp: ${timestamp}`,
  ].join('\n');
  const signature = await activeSigner.signMessage(message);
  return {
    '-wallet-address': wallet,
    'x-chain-id': String(chainId),
    '-xnonce': nonce,
    'x-timestamp': String(timestamp),
    '-x-signature': signature,
  };
}

test('GET returns 401 without authentication', async () => {
  const res = await GET(R('http://local/api/notifications'));
  expect(res.status).toBe(401);
});

test('GET returns 400 for invalid network', async () => {
  const headers = await authHeaders();
  const res = await GET(R('http://local/api/notifications?network=bad', 'GET', headers));
  expect(res.status).toBe(400);
});

test('GET returns 400 for invalid limit', async () => {
  const headers = await authHeaders();
  const res = await GET(R('http://local/api/notifications?network=mainnet&limit=x', 'GET', headers));
  expect(res.status).toBe(400);
});

test('GET returns 200 for valid request', async () => {
  const headers = await authHeaders();
  const res = await GET(R('http://local/api/notifications?network=mainnet&limit=5', 'GET', headers));
  expect(res.status).toBe(200);
});

test'POST returns 401 without authentication', async () => {
  const res = await POST(R('http://local/api/notifications', 'POST', {}, '{}'));
  expect(res.status).toBe(401);
});

test('POST returns 400 for invalid JSON', async () => {
  const headers = await authHeaders();
  const res = await POST(R('http://local/api/notifications', 'POST', headers, { bad json }));
  expect(res.status).toBe(400);
});

test'POST returns 403 when wallet mismatch', async () => {
  const headers = await authHeaders();
  const body = JSON.stringify({ wallet: OTHER_WALLET, notificationId: 'n1', network: 'mainnet', timestamp: Date.now(), requestId: 'req-1' });
  const res = await POST(R('http://local/api/notifications', 'POST', headers, body));
  expect(res.status).toBe(403);
});

test('POST returns 409 on duplicate requestId', async () => {
  const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const body = JSON.stringify({ wallet: VALID_WALLET, notificationId: 'n', network: 'mainnet', timestamp: Date.now(), requestId });

  const h1 = await authHeaders();
  const first = await POST R('http://local/api/notifications', 'POST', h1, body));
  expect(first.status).toBe(200);

  const h2 = await authHeaders();
  const second = await POST R('http://local/api/notifications', 'POST', h2, body));
  expect(second.status).toBe(409);
});
