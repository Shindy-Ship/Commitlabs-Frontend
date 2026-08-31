import { validateWalletAddress, validateNetwork, validatePositiveInteger, ReplayGuard } from './validation';

test('validate wallet address', () => {
  const result = validateWalletAddress('0x1234567890abcdef1234567890abcdef12345678');
  expect(result.ok).toBe(true);
  if (result.ok) {
    expect(result.value).toBe('0x1234567890abcdef1234567890abcdef12345678');
  }
});

test('invalid wallet address', () => {
  expect(validateWalletAddress('not-a-wallet').ok).toBe(false);
});

test('validate network', () => {
  expect(validateNetwork('mainnet').ok).toBe(true);
  expect(validateNetwork('sepolia').ok).toBe(true);
  expect(validateNetwork('bad').ok).toBe(false);
});

test('validate positive integer enforces boundaries', () => {
  expect(validatePositiveInteger(1).ok).toBe(true);
  expect(validatePositiveInteger(0).ok).toBe(false);
  expect(validatePositiveInteger(101, 100).ok).toBe(false);
  expect(validatePositiveInteger('1').ok).toBe(false);
});

test('replay guard detects duplicate', () => {
  const g = new ReplayGuard();
  const ts = Date.now();
  expect(() => g.assertFresh('e', { timestamp: ts })).not.toThrow();
  expect(() => g.assertFresh('e', { timestamp: ts })).toThrow('replay');
});

test('replay guard rejects stale timestamp', () => {
  const g = new ReplayGuard();
  expect(() => g.assertFresh('e', { timestamp: Date.now() - 600000 })).toThrow('stale timestamp');
});
