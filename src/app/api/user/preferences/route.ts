/**
 * @file /api/user/preferences
 *
 * GET  – Returns the authenticated wallet's current preferences.
 *        Missing preferences are initialised to `DEFAULT_PREFERENCES`.
 *        Supports conditional requests via ETag / If-None-Match for
 *        multi-tab and cross-session consistency.
 *
 * PUT  – Partially updates the authenticated wallet's preferences.
 *        Only supplied fields are written; omitted fields retain their
 *        previous values (deep-merge semantics).
 *
 * State-machine invariants
 * ────────────────────────
 * Preferences have two logical states:
 *   DEFAULT → PERSONALISED
 *
 * Transitions are idempotent and version-protected:
 * • The client may supply an `Idempotency-Key` header. A repeated PUT with
 *   the same key (within 24 h) returns the cached result verbatim — safe
 *   for retries after network interruptions.
 * • The client may supply an `If-Match` header containing the ETag of the
 *   version it last read. If the stored version has changed since then the
 *   request is rejected with 412 Precondition Failed, preventing stale
 *   overwrites across concurrent tabs / sessions.
 * • An interrupted write that committed to the store but never returned a
 *   response to the client is recovered on retry via the Idempotency-Key.
 *
 * Auth
 * ────
 * Both methods require a valid `Authorization: Bearer <sessionToken>` header.
 * Missing / invalid tokens yield 401 Unauthorized.
 *
 * Validation
 * ──────────
 * PUT bodies are validated with `userPreferencesSchema` (Zod).
 * Validation failures yield 400 with field-level error details.
 */

import { NextRequest } from 'next/server';
import { withApiHandler } from '@/lib/backend/withApiHandler';
import { ok } from '@/lib/backend/apiResponse';
import { ValidationError, ConflictError } from '@/lib/backend/errors';
import { generateETag } from '@/lib/backend/etag';
import { IdempotencyService } from '@/lib/backend/idempotency';
import {
  userPreferencesSchema,
  DEFAULT_PREFERENCES,
  jsonFilePreferencesStore,
  requireWalletAuth,
  type PreferencesStore,
  type UserPreferences,
} from '@/lib/backend/preferences';

const MAX_PREFERENCES_BODY_BYTES = 16384;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._~+=-]{1,255}$/;
const IF_MATCH_PATTERN = /^(?:"[A-Za-z0-9._~+-]+"|[A-Za-z0-9._~+-]+)$/;
const WALLET_ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;
const DANGEROUS_KEY_PATTERN = /^(?:__proto__|prototype|constructor)$/;

function assertWalletAddress(address: string): void {
  if (!WALLET_ADDRESS_PATTERN.test(address)) {
    throw new Error('Authenticated wallet identity is invalid.');
  }
}

function validateNetworkHeader(req: NextRequest): void {
  const networkHeader = req.headers.get('x-chain-id') ?? req.headers.get('x-network');
  if (networkHeader === null) return;

  const trimmed = networkHeader.trim();
  const numericChainId = Number(trimmed);
  if (!/^\d+$/.test(trimmed) || !Number.isSafeInteger(numericChainId) || numericChainId <= 0) {
    throw new ValidationError('Network identifier must be a positive integer.');
  }
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function assertSafePreferenceKeys(value: unknown): void {
  if (Array.isArray(value)) {
    for (const entry of value) assertSafePreferenceKeys(entry);
    return;
  }
  if (value === null || typeof value !== 'object') return;

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (DANGEROUS_KEY_PATTERN.test(key)) {
      throw new ValidationError(`Unsupported preference field: ${key}`);
    }
    assertSafePreferenceKeys(child);
  }
}

async function readJsonBody(req: NextRequest): Promise<unknown> {
  const contentType = req.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new ValidationError('Content-Type must be application/json.');
  }

  const contentLength = req.headers.get('content-length');
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_PREFERENCES_BODY_BYTES) {
      throw new ValidationError('Request body exceeds the size limit.');
    }
  }

  const text = await req.text();
  if (text.length > MAX_PREFERENCES_BODY_BYTES) {
    throw new ValidationError('Request body exceeds the size limit.');
  }
  if (text.trim().length === 0) {
    throw new ValidationError('Request body must be valid JSON.');
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new ValidationError('Request body must be valid JSON.');
  }
}

// ─── Store injection (test seam) ─────────────────────────────────────────────

let _store: PreferencesStore = jsonFilePreferencesStore;
export function __setStoreForTesting(store: PreferencesStore): void {
  _store = store;
}
export function __resetStore(): void {
  _store = jsonFilePreferencesStore;
}

// ─── Idempotency service (test seam) ─────────────────────────────────────────

const _defaultIdempotency = new IdempotencyService(undefined, 86400);
let _idempotency: IdempotencyService = _defaultIdempotency;

export function __setIdempotencyForTesting(svc: IdempotencyService): void {
  _idempotency = svc;
}
export function __resetIdempotency(): void {
  _idempotency = _defaultIdempotency;
}

// ─── GET /api/user/preferences ───────────────────────────────────────────────

/**
 * @openapi
 * /api/user/preferences:
 *   get:
 *     summary: Retrieve user preferences
 *     description: >
 *       Returns display and notification preferences for the authenticated wallet.
 *       Defaults are returned when no preferences have been saved yet.
 *       Supports If-None-Match / ETag for efficient polling across tabs.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: User preferences object
 *         headers:
 *           ETag:
 *             description: Opaque version token for conditional PUT requests
 *             schema: { type: string }
 *       304:
 *         description: Preferences unchanged (conditional request, ETag matched)
 *       401:
 *         description: Authentication required
 */
export const GET = withApiHandler(
  async (req: NextRequest) => {
    const address = requireWalletAuth(req.headers.get('authorization'));
    assertWalletAddress(address);
    validateNetworkHeader(req);

    const stored = await _store.get(address);
    let preferences: UserPreferences = { ...DEFAULT_PREFERENCES };
    if (stored !== null && stored !== undefined) {
      const parsed = userPreferencesSchema.safeParse(stored);
      if (!parsed.success) {
        throw new Error('Stored preferences are invalid.');
      }
      preferences = { ...DEFAULT_PREFERENCES, ...parsed.data };
    }

    return ok({ address, preferences });
  },
  { enableETag: true, cachePrivacy: 'private' },
);

// ─── PUT /api/user/preferences ───────────────────────────────────────────────

/**
 * @openapi
 * /api/user/preferences:
 *   put:
 *     summary: Update user preferences
 *     description: >
 *       Partially updates preferences for the authenticated wallet.
 *       Only provided fields are overwritten (deep merge).
 *
 *       Idempotency: supply `Idempotency-Key: <uuid>` to make the operation
 *       safe to retry — the same key within 24h returns the cached result.
 *
 *       Optimistic concurrency: supply `If-Match: "<etag>"` (the ETag from
 *       the most recent GET response) to prevent overwriting a version you
 *       have not seen. Returns 412 if the stored version has changed.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: Idempotency-Key
 *         in: header
 *         schema: { type: string }
 *         description: Optional client-generated unique key for retry safety
 *       - name: If-Match
 *         in: header
 *         schema: { type: string }
 *         description: Optional ETag for optimistic concurrency control
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserPreferencesInput'
 *     responses:
 *       200:
 *         description: Updated preferences
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       412:
 *         description: Precondition failed — stored version changed since If-Match ETag was issued
 */
export const PUT = withApiHandler(async (req: NextRequest) => {
  const address = requireWalletAuth(req.headers.get('authorization'));
  assertWalletAddress(address);
  validateNetworkHeader(req);

  // ── Idempotency key (optional) ────────────────────────────────────────────
  const idempotencyKey = req.headers.get('idempotency-key');
  if (idempotencyKey !== null && !IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
    throw new ValidationError('Invalid Idempotency-Key header.');
  }
  const scopedKey = idempotencyKey ? `prefs:${address}:${idempotencyKey}` : null;

  // ── Parse body ────────────────────────────────────────────────────────────
  const body = await readJsonBody(req);
  assertSafePreferenceKeys(body);

  const result = userPreferencesSchema.safeParse(body);
  if (!result.success) {
    const details = result.error.issues.map((e) => ({
      field: e.path.join('.'),
      message: e.message,
    }));
    throw new ValidationError('Invalid preference data.', details);
  }

  if (Object.keys(result.data).length === 0) {
    throw new ValidationError('Request body must contain at least one preference field.');
  }

  const requestHash = stableStringify(result.data);

  // ── Idempotency replay (after body validation) ────────────────────────────
  if (scopedKey) {
    const cached = await _idempotency.getRecord<{
      address: string;
      preferences: UserPreferences;
      requestHash?: string;
    }>(scopedKey);
    if (cached?.status === 'COMPLETED' && cached.response) {
      if (cached.response.requestHash && cached.response.requestHash !== requestHash) {
        throw new ValidationError('Idempotency-Key was already used with a different request.');
      }
      // Return the previously committed result verbatim
      return ok({
        address: cached.response.address,
        preferences: cached.response.preferences,
        fromCache: true,
      });
    }
  }

  // ── Optimistic concurrency (If-Match) ─────────────────────────────────────
  const ifMatch = req.headers.get('if-match');
  if (ifMatch !== null) {
    const trimmedIfMatch = ifMatch.trim();
    if (trimmedIfMatch.length === 0 || !IF_MATCH_PATTERN.test(trimmedIfMatch)) {
      throw new ValidationError('If-Match header must be a valid entity tag.');
    }

    const current = await _store.get(address);
    const currentPrefs: UserPreferences = current ?? { ...DEFAULT_PREFERENCES };
    const currentETag = generateETag({ address, preferences: currentPrefs });

    // Normalize both sides to bare hash strings for comparison.
    // generateETag returns `"<hash>"` (quoted). The If-Match header value may
    // arrive quoted or bare; strip outer double-quotes for comparison.
    const normalize = (tag: string) => tag.replace(/^"|"$/g, '');
    if (normalize(trimmedIfMatch) !== normalize(currentETag)) {
      throw new ConflictError(
        'Preferences have been modified since your last read. Fetch the current version and retry.',
      );
    }
  }

  // ── Apply update ──────────────────────────────────────────────────────────
  const storedPreferences = await _store.upsert(address, result.data);
  const parsedPreferences = userPreferencesSchema.safeParse(storedPreferences);
  if (!parsedPreferences.success) {
    throw new Error('Preference store returned invalid preferences.');
  }
  const preferences: UserPreferences = { ...DEFAULT_PREFERENCES, ...parsedPreferences.data };

  const responsePayload = { address, preferences, fromCache: false as boolean | undefined };

  // ── Record idempotency result ─────────────────────────────────────────────
  if (scopedKey) {
    // Store without fromCache so the cached version rebuilds it correctly
    await _idempotency.complete(scopedKey, { address, preferences, requestHash }, 200);
  }

  return ok(responsePayload);
});
