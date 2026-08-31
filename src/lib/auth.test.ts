import { getAuthContext, assertOwnership, AuthError } from './auth';

const VALID_WALLET = '0x1234567890abcdef1234567890abcdef12345678';
const VALID_WALLET_UPPER = VALID_WALLET.toUpperCase();
const OTHER_WALLET = '0x9876543210abcdef1234567890abcdef12345678';

describe('getAuthContext', () => {
  test('returns the wallet from the x-wallet-address header', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': VALID_WALLET },
    });
    expect(getAuthContext(req).wallet).toBe(VALID_WALLET);
  });

  test('normalizes wallet address to lowercase', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': VALID_WALLET_UPPER },
    });
    expect(getAuthContext(req).wallet).toBe(VALID_WALLET);
  });

  test('trims surrounding whitespace from the wallet header', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': `  ${VALID_WALLET}  ` },
    });
    expect(getAuthContext(req).wallet).toBe(VALID_WALLET);
  });

  test('throws AuthError when header is missing', () => {
    const req = new Request('http://local');
    expect(() => getAuthContext(req)).toThrow(AuthError);
  });

  test('throws AuthError when header is empty', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': '' },
    });
    expect(() => getAuthContext(req)).toThrow(AuthError);
  });

  test('throws AuthError when wallet is not a valid Ethereum address', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': 'nope' },
    });
    expect(() => getAuthContext(req)).toThrow(AuthError);
  });

  test('throws AuthError when wallet lacks 0x prefix', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': VALID_WALLET.slice(2) },
    });
    expect(() => getAuthContext(req)).toThrow(AuthError);
  });

  test('throws AuthError when wallet has incorrect length', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': '0x1234' },
    });
    expect(() => getAuthContext(req)).toThrow(AuthError);
  });

  test('throws AuthError when wallet contains non-hex characters', () => {
    const req = new Request('http://local', {
      headers: { 'x-wallet-address': `0x${'g'.repeat(40)} ` },
    });
    expect(() => getAuthContext(req)).toThrow(AuthError);
  });
});

describe('assertOwnership', () => {
  test('does not throw when the wallet matches the context wallet', () => {
    const ctx = { wallet: VALID_WALLET };
    expect(() => assertOwnership(ctx, VALID_WALLET)).not.toThrow();
  });

  test('does not throw when the wallet matches with different case', () => {
    const ctx = { wallet: VALID_WALLET };
    expect(() => assertOwnership(ctx, VALID_WALLET_UPPER)).not.toThrow();
  });

  test('throws a Forbidden error when the wallet does not match', () => {
    const ctx = { wallet: VALID_WALLET };
    expect(() => assertOwnership(ctx, OTHER_WALLET)).toThrow('Forbidden');
  });

  test('throws a Forbidden error when the target wallet is undefined', () => {
    const ctx = { wallet: VALID_WALLET };
    expect(() => assertOwnership(ctx, undefined as any)).toThrow('Forbidden');
  });

  test('throws a Forbidden error when the context wallet is undefined', () => {
    const ctx = {} as any;
    expect(() => assertOwnership(ctx, VALID_WALLET)).toThrow('Forbidden');
  });

  test('throws a Forbidden error when the target wallet is not a string', () => {
    const ctx = { wallet: VALID_WALLET };
    expect(() => assertOwnership(ctx, 123 as any)).toThrow('Forbidden');
  });
});
