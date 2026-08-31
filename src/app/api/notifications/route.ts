/**
 * @file /api/notifications
 *
 * GET   – Returns paginated notifications for the authenticated wallet.
 *         Optional `?unreadOnly=true` filters to unread-only.
 *         Supports If-None-Match / ETag for conditional polling.
 *
 * PATCH – Transitions a notification's state via the deterministic state machine.
 *         Body: { id: string; action: 'mark_read' | 'acknowledge'; idempotencyKey: string }
 *
 * State machine
 * ─────────────
 *   UNREAD ──► READ ──► ACKNOWLEDGED
 *
 * Invariants
 * ──────────
 * • Only the notification's ownerAddress may mutate it.
 * • Transitions are idempotent: replaying the same (idempotencyKey) returns
 *   the cached result without re-applying the transition.
 * • Forward-only: backward transitions are rejected with 409 Conflict.
 * • ACKNOWLEDGED is terminal: further transitions are rejected with 409.
 * • Duplicate submissions (same idempotencyKey) never cause on-store side-effects.
 *
 * Auth
 * ────
 * Both methods require `Authorization: Bearer <sessionToken>`.
 * Missing / invalid tokens yield 401 Unauthorized.
 */

import { NextRequest } from 'next/server';
import { z } from 'zod';
import { withApiHandler } from '@/lib/backend/withApiHandler';
import { ok } from '@/lib/backend/apiResponse';
import { ForbiddenError, ValidationError } from '@/lib/backend/errors';
import { requireWalletAuth } from '@/lib/backend/preferences';
import {
  getNotificationStore,
  setNotificationStoreForTesting,
  resetNotificationStore,
  notificationIdempotency,
  NotificationTransitionService,
  InMemoryNotificationStore,
} from '@/lib/backend/notificationStateMachine';
import { IdempotencyService } from '@/lib/backend/idempotency';

export {
  setNotificationStoreForTesting as __setStoreForTesting,
  resetNotificationStore as __resetStore,
};

// ─── Seeded demo data ─────────────────────────────────────────────────────────
// Populate the singleton store on first import so integration tests and local
// dev always have something to work with. Real deployments replace this with
// DB-backed seeding.

let _seeded = false;
async function ensureSeeded(): Promise<void> {
  if (_seeded) return;
  _seeded = true;

  const store = getNotificationStore();
  if (!(store instanceof InMemoryNotificationStore)) return;

  // Only seed if empty
  const sample = await store.list('SEED_PLACEHOLDER', { page: 1, pageSize: 1 });
  if (sample.total > 0) return;

  await store.seed(
    Array.from({ length: 12 }, (_, i) => ({
      id: `notif-seed-${i + 1}`,
      ownerAddress: '0x1111111111111111111111111111111111111111',
      title: `Demo Notification ${i + 1}`,
      message: `This is demo notification ${i + 1}.`,
      severity: (['info', 'warning', 'critical'] as const)[i % 3],
      type: (['expiry', 'violation', 'health_check', 'marketplace'] as const)[i % 4],
      read: false,
      createdAt: new Date(Date.now() - i * 3_600_000).toISOString(),
    })),
  );
}

// ─── Query validation ─────────────────────────────────────────────────────────

const supportedNetworks = ['mainnet', 'sepolia', 'local'] as const;

const listQuerySchema = z.object({
  page: z.coerce.number().finite().int().min(1).default(1),
  pageSize: z.coerce.number().finite().int().min(1).max(100).default(10),
  unreadOnly: z
    .enum(['true', 'false'])
    .optional()
    .transform((v) => v === 'true'),
  network: z.enum(supportedNetworks).optional(),
}).strict();

// ─── PATCH body validation ────────────────────────────────────────────────────

const patchBodySchema = z.object({
  id: z
    .string()
    .trim()
    .min(1, 'Notification id is required')
    .max(256, 'Notification id is too long')
    .regex(/^[A-Za-z0-9._:-]+$/, 'Notification id contains invalid characters')
    .refine((value) => value.trim().length > 0, 'Notification id cannot be blank'),
  action: z.enum(['mark_read', 'acknowledge'], {
    errorMap: () => ({ message: "action must be 'mark_read' or 'acknowledge'" }),
  }),
  /**
   * Client-supplied idempotency key. Must be unique per intended logical
   * operation. A UUID is recommended. Re-sending the same key within 24h
   * returns the previously committed result without re-executing the transition.
   */
  idempotencyKey: z
    .string()
    .min(1, 'idempotencyKey is required')
    .max(128, 'idempotencyKey must be 128 characters or fewer')
    .regex(/^[A-Za-z0-9._:-]+$/, 'idempotencyKey contains invalid characters'),
  network: z.enum(supportedNetworks).optional(),
}).strict();

// ─── Server response validation ──────────────────────────────────────────────

const walletAddressSchema = z.string().regex(
  /^0x[a-fA-F0-9]{40}$/,
  'Wallet address must be a 40-character hex string starting with 0x',
).transform((value) => value.toLowerCase());

const notificationSchema = z.object({
  id: z.string().min(1).max(256).regex(
    /^[A-Za-z0-9._:-]+$/,
    'Notification id contains invalid characters',
  ),
  ownerAddress: walletAddressSchema,
  read: z.boolean(),
  network: z.enum(supportedNetworks).optional(),
}).passthrough();

const listResponseSchema = z.object({
  items: z.array(notificationSchema),
  total: z.number().finite().int().nonnegative(),
});

const transitionResultSchema = z.object({
  notification: notificationSchema,
  fromCache: z.boolean(),
});

function getAuthenticatedWallet(req: NextRequest): string {
  const address = requireWalletAuth(req.headers.get('authorization'));
  const parsedAddress = walletAddressSchema.safeParse(address);
  if (!parsedAddress.success) {
    throw new ValidationError('Invalid wallet identity.');
  }
  return parsedAddress.data;
}

// ─── Idempotency and transition service ──────────────────────────────────────

let _idempotencyService: IdempotencyService = notificationIdempotency;

/** Replace idempotency service in tests. */
export function __setIdempotencyServiceForTesting(svc: IdempotencyService): void {
  _idempotencyService = svc;
}
export function __resetIdempotencyService(): void {
  _idempotencyService = notificationIdempotency;
}

function getTransitionService(): NotificationTransitionService {
  return new NotificationTransitionService(getNotificationStore(), _idempotencyService);
}

async function assertNotificationOwnership(
  id: string,
  address: string,
  network?: string,
): Promise<void> {
  const store = getNotificationStore();
  const existing = await store.get(id);
  if (!existing) return;

  const parsed = notificationSchema.safeParse(existing);
  if (!parsed.success) {
    throw new Error('Notification store returned a malformed notification.');
  }
  if (parsed.data.ownerAddress.toLowerCase() !== address.toLowerCase()) {
    throw new ForbiddenError('Caller does not own this notification.');
  }
  if (
    network &&
    parsed.data.network &&
    parsed.data.network !== network
  ) {
    throw new ValidationError('Notification does not belong to the requested network.');
  }
}

// ─── GET /api/notifications ───────────────────────────────────────────────────

/**
 * @openapi
 * /api/notifications:
 *   get:
 *     summary: List notifications for the authenticated wallet
 *     description: >
 *       Returns a paginated list of notifications for the authenticated wallet.
 *       Use `?unreadOnly=true` to filter to unread-only items.
 *       Supports conditional requests via ETag / If-None-Match.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: page
 *         in: query
 *         schema: { type: integer, default: 1 }
 *       - name: pageSize
 *         in: query
 *         schema: { type: integer, default: 10, maximum: 100 }
 *       - name: unreadOnly
 *         in: query
 *         schema: { type: boolean }
 *     responses:
 *       200:
 *         description: Paginated notifications
 *       401:
 *         description: Authentication required
 */
export const GET = withApiHandler(
  async (req: NextRequest) => {
    const address = getAuthenticatedWallet(req);
    const { searchParams } = new URL(req.url);
    const duplicateParams = [...new Set(searchParams.keys())].filter(
      (key) => searchParams.getAll(key).length > 1,
    );
    if (duplicateParams.length > 0) {
      throw new ValidationError(
        'Duplicate query parameters are not allowed.',
        duplicateParams.map((field) => ({ field, message: `Duplicate query parameter: ${field}` })),
      );
    }
    const parsed = listQuerySchema.safeParse(Object.fromEntries(searchParams.entries()));
    if (!parsed.success) {
      throw new ValidationError(
        'Invalid query parameters',
        parsed.error.issues.map((e) => ({ field: e.path.join('.'), message: e.message })),
      );
    }

    const { page, pageSize, unreadOnly, network } = parsed.data;
    await ensureSeeded();
    const store = getNotificationStore();
    const { items, total } = await store.list(address, { page, pageSize, unreadOnly });

    const listResult = listResponseSchema.safeParse({ items, total });
    if (!listResult.success) {
      throw new Error('Notification store returned a malformed list response.');
    }
    if (listResult.data.items.some((item) => item.ownerAddress.toLowerCase() !== address.toLowerCase())) {
      throw new Error('Notification store returned notifications for another wallet.');
    }
    if (
      network &&
      listResult.data.items.some(
        (item) => item.network !== undefined && item.network !== network,
      )
    ) {
      throw new Error('Notification store returned notifications for another network.');
    }

    return ok({
      items: listResult.data.items,
      meta: { page, pageSize, total: listResult.data.total, unreadOnly },
    });
  },
  { enableETag: true, cachePrivacy: 'private' },
);

// ─── PATCH /api/notifications ─────────────────────────────────────────────────

/**
 * @openapi
 * /api/notifications:
 *   patch:
 *     summary: Transition a notification state
 *     description: >
 *       Applies a deterministic state-machine transition to a single
 *       notification.  The `idempotencyKey` field makes this operation safe
 *       to retry: a repeated request with the same key returns the cached
 *       result without re-executing the transition.
 *
 *       State machine:
 *         UNREAD → mark_read → READ → acknowledge → ACKNOWLEDGED
 *
 *       ACKNOWLEDGED is terminal; further transitions are rejected (409).
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id, action, idempotencyKey]
 *             properties:
 *               id: { type: string }
 *               action: { type: string, enum: [mark_read, acknowledge] }
 *               idempotencyKey: { type: string }
 *     responses:
 *       200:
 *         description: Notification after transition (or cached result on replay)
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Caller does not own this notification
 *       404:
 *         description: Notification not found
 *       409:
 *         description: Invalid or terminal-state transition
 */
export const PATCH = withApiHandler(async (req: NextRequest) => {
  const address = getAuthenticatedWallet(req);

  // Parse body
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new ValidationError('Request body must be valid JSON.');
  }

  const result = patchBodySchema.safeParse(body);
  if (!result.success) {
    throw new ValidationError(
      'Invalid request body.',
      result.error.issues.map((e) => ({ field: e.path.join('.'), message: e.message })),
    );
  }

  const { id, action, idempotencyKey, network } = result.data;

  // Map action → state machine event
  const event = action === 'mark_read' ? 'MARK_READ' : 'ACKNOWLEDGE';

  // Scope the idempotency key to (caller, notification, event, key) so
  // different wallets, notifications, or actions cannot inadvertently share
  // the same cache slot. The `network` field is validated above and checked
  // against the stored notification by assertNotificationOwnership; it is not
  // part of the cache scope because retries must not be able to bypass the
  // cache by toggling a client-supplied network value.
  const scopedKey = JSON.stringify([
    'notif',
    address,
    id,
    event,
    idempotencyKey,
  ]);

  const svc = getTransitionService();
  await assertNotificationOwnership(id, address, network);
  const { notification, fromCache } = await svc.transition(id, event, address, scopedKey);

  const transitionResult = transitionResultSchema.safeParse({ notification, fromCache });
  if (!transitionResult.success) {
    throw new Error('Notification store returned a malformed transition result.');
  }
  if (transitionResult.data.notification.ownerAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error('Notification transition returned a notification for another wallet.');
  }

  return ok({
    notification: transitionResult.data.notification,
    fromCache: transitionResult.data.fromCache,
  });
});
