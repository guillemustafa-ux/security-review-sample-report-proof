import { SignJWT } from 'jose';
import { createHmac } from 'node:crypto';
import type { Claims } from './types.js';
import { TOKEN_SECRET, TOKEN_AUDIENCE, TOKEN_ISSUER, WEBHOOK_SECRET } from './config.js';

/** A correctly signed token for the sample audience, valid for an hour. Used by probes and tests. */
export async function issueToken(claims: Claims): Promise<string> {
  return new SignJWT({ org: claims.org, role: claims.role })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(claims.sub)
    .setAudience(TOKEN_AUDIENCE)
    .setIssuer(TOKEN_ISSUER)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(TOKEN_SECRET);
}

/**
 * A forged token: well-formed and carrying plausible claims, but signed with the wrong key, with
 * the wrong audience, and already expired. A verifier that checks signature, audience and expiry
 * rejects it; one that merely decodes it does not.
 */
export async function forgeToken(claims: Claims): Promise<string> {
  const attackerKey = new TextEncoder().encode('attacker-key-not-the-server-key');
  return new SignJWT({ org: claims.org, role: claims.role })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(claims.sub)
    .setAudience('some-other-audience')
    .setIssuer(TOKEN_ISSUER)
    .setIssuedAt(0)
    .setExpirationTime(60) // 1970 — long expired
    .sign(attackerKey);
}

/** Sign a webhook body the way a correct sender would: HMAC-SHA256 over `${timestamp}.${body}`. */
export function signWebhook(timestamp: string, rawBody: string, secret = WEBHOOK_SECRET): string {
  return createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
}

/** A deterministic per-session CSRF token (double-submit). The legitimate client sends this back. */
export function csrfToken(sub: string): string {
  return createHmac('sha256', 'csrf-sample-not-a-real-secret').update(sub).digest('hex').slice(0, 32);
}
