import { GET, POST } from './route';
import { NextRequest } from 'next/server';

const WALLET = '0x1234567890abcdef1234567890abcdef12345678';
const OTHER = '0xabcdef1234567890abcdef1234567890abcdef123';

function makeReq(url, options: {method: string; headers?: Record<string, string>; body?: string } = {}) {
  return new NextRequest(url, { method: options.method, headers: options.headers, body: options.body });
}

describe('GET /api/notifications', () => {
  it('returns 200 with auth', async () => {
    const req = makeReq('http://local/api/notifications?network=mainnet', { method: 'GET', headers: { 'x-wallet-address': WALLET } });
    const res = await GET(req);
    expect(res.status).toBe(200);
  });

  it('returns 401 without auth', async () => {
    const req = makeReq('http://local/api/notifications', { method: 'GET' });
    const res = await GET(req);
    expect(res.status).toBe(401);
  });

  it('returns 400 for invalid network', async () => {
    const req = makeReq('http://local/api/notifications?network=bad', { method: 'GET', headers: { 'x-wallet-address': WALLET } });
    const res = await GET(req);
    expect(res.status).toBe(400);
  });
});

describe('POST /api/notifications', () => {
  it('rejects replay', async () => {
    const body = JSON.stringify({ wallet: WALLET, notificationId: 'n1', network: 'mainnet', timestamp: Date.now(), requestId: 'r1' });
    const req1 = makeReq('http://local/api/notifications', { method: 'POST', headers: { 'x-wallet-address': WALLET }, body });
    await POST(req1);
    const req2 = makeReq('http://local/api/notifications', { method: 'POST', headers: { 'x-wallet-address': WALLET }, body });
    const res = await POST(req2);
    expect(res.status).toBe([409, 400]);
  });
});
