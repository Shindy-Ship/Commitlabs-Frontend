import { getAuthContext, assertOwnership, AuthError } from './auth';

test('getAuthContext returns wallet', () => {
  const req = new Request('http://local', { headers: { 'x-wallet-address': '0x1234567890abcdef1234567890abcdef12345678' } });
  expect(getAuthContext(req).wallet).toBe('0x1234567890abcdef1234567890abcdef12345678');
});

test('missing auth throws AuthError', () => {
  const req = new Request('http://local');
  expect(() => getAuthContext(req)).toThrow(AuthError);
});

test('invalid wallet header throws AuthError', () => {
  const req = new Request('http://local', { headers: { 'x-wallet-address': 'nope' } });
  expect(() => getAuthContext(req)).toThrow(AuthError);
});

test('assertOwnership ensures ownership', () => {
  const ctx = { wallet: '0x1234567890abcdef1234567890abcdef12345678' };
  expect(() => assertOwnership(ctx, ctx.wallet)).not.toThrow();
  expect(() => assertOwnership(ctx, '0x9876543210abcdef1234567890abcdef12345678')).toThrow('Forbidden');
});
