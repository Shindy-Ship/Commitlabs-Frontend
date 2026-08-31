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

test('wallet address must have 0x prefix', () => {
  expect(validateWalletAddress('1234567890abcdef1234567890abcdef12345678').ok).toBe(false);
});

test('wallet address must be 40 hex characters', () => {
  expect(validateWalletAddress('0x1234567890abcdef1234567890abcdef1234567')..ok).toBe(false); // 39
  expect(validateWalletAddress('0x1234567890abcdef1234567890abcdef123456789')..ok).toBe(false); // 41
});

test('wallet address must be valid hex', () => {
  expect(validateWalletAddress('0x1234567890abcdef1234567890abcdef12345677g').ok).toBe(false);
});

test('wallet address rejects empty or null', () => {
  expect(validateWalletAddress('').ok).toBe(false);
  // @ts-ignore - testing runtime robustness
  expect(validateWalletAddress(null).ok).toBe(false);
});

test('validate network', () => {
  expect(validateNetwork('mainnet').ok).toBe(true);
  expect(validateNetwork('sepolia').ok).toBe(true);
  expect(validateNetwork('bad').ok).toBe(false);
});

test('network is case-sensitive', () => {
  expect(validateNetwork('Mainnet').ok).toBe(false);
  expect(validateNetwork('SEPOLIA').ok).toBe(false);
});

test('network rejects empty or null', () => {
  expect(validateNetwork('').ok).toBe(false);
  // @ts-ignore - testing runtime robustness
  expect(validateNetwork(null).ok).toBe(false);
});

test('validate positive integer enforces boundaries', () => {
  expect(validatePositiveInteger(1).ok).toBe(true);
  expect(validatePositiveInteger(0).ok).toBe(false);
  expect(validatePositiveInteger(101, 100).ok).toBe(false);
  expect(validatePositiveInteger('1').ok).toBe(false);
});

test('validate positive integer accepts max boundary', () => {
  expect(validatePositiveInteger(100, 100).ok).toBe(true);
});

test('validate positive integer rejects non-integers', () => {
  expect(validatePositiveInteger(1.5).ok).toBe(false);
  expect(validatePositiveInteger(-1).ok).toBe(false);
  expect(validatePositiveInteger(Number.NaN).ok).toBe(false);
  expect(validatePositiveInteger(Number.POSITIVE_INFINITY).ok).toBe(false);
});

test('validate positive integer rejects empty or null', () => {
  // @ts-ignore - testing runtime robustness
  expect(validatePositiveInteger(null).ok).toBe(false);
  // @ts-ignore - testing runtime robustness
  expect(validatePositiveInteger(undefined).ok).toBe(false);
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

test('replay guard accepts different event ids with same timestamp', () => {
  const g = new ReplayGuard();
  const ts = Date.now();
  expect(() => g.assertFresh('a', { timestamp: ts })).not.toThrow();
  expect(() => g.assertFresh('b', { timestamp: ts })).not.toThrow();
});

test('replay guard rejects duplicate with tampered timestamp', () => {
  const g = new ReplayGuard();
  const ts = Date.now();
  expect(() => g.assertFresh('e', { timestamp: ts })).not.toThrow();
  expect(() => g.assertFresh('e', { timestamp: ts + 1000 })).toThrow('replay');
});
