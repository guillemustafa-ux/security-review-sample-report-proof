/**
 * Synthetic, non-secret constants for the offline sample app. These are sample keys for a seeded,
 * in-memory target that never leaves the process; they are not credentials for anything real.
 */

export const TOKEN_SECRET = new TextEncoder().encode('sample-signing-key-not-a-secret');
export const TOKEN_AUDIENCE = 'sample-multitenant-api';
export const TOKEN_ISSUER = 'sample-auth';

export const WEBHOOK_SECRET = 'whsec_sample_not_a_real_secret';
/** Replay window for the webhook timestamp, in seconds. */
export const WEBHOOK_WINDOW_SECONDS = 300;

export const ALLOWED_ORIGIN = 'http://localhost:3000';

export const ORG_A = 'org_northwind';
export const ORG_B = 'org_contoso';
