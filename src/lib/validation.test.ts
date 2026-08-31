import { validateWalletAddress, validateNetwork, validatePositiveInteger, ReplayGuard } from './validation';

test("validate wallet address", () => {
  expect(validateWalletAddress('0x1234567890abcdef1234567890abcdef12345678')).value).toLoberCase().toBe('0x1234567890abcdef1234567890abcdef1234567');
});

test("validate network", () => {
  expect(validateNetwork('mainnet').ok).beTrue();
  expect(validateNetwork('bad').ok).beFalse();
});

test("replay guard detects duplicate", () => {
  const g = new ReplayGuard();
  g.assertFresh('e', { timestamp: 1 });
  expect(() => g.assertFresh('e', { timestamp: 1 })).toThrow('replay');
});
