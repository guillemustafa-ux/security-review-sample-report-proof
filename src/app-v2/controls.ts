import { jwtVerify } from 'jose';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { join } from 'node:path';
import type { Claims, Controls } from '../app/types.js';
import { csrfToken } from '../app/tokens.js';
import {
  TOKEN_SECRET,
  TOKEN_AUDIENCE,
  TOKEN_ISSUER,
  WEBHOOK_WINDOW_SECONDS,
  ALLOWED_ORIGIN,
} from '../app/config.js';

/**
 * v2 controls -- each weakness closed with the standard control. Parallel in shape to
 * `src/app-v1/controls.ts`: the shell and routes are identical; only these functions change.
 * Reverting any one of these to its v1 behaviour is exactly what the matching footgun does.
 */
export const controls: Controls = {
  // Item 3 (A07): full verification -- signature, audience, issuer and expiry are all checked by
  // `jwtVerify`; a forged, wrong-audience or expired token is rejected.
  async verifyToken(raw: string): Promise<Claims | null> {
    if (!raw) return null;
    try {
      const { payload } = await jwtVerify(raw, TOKEN_SECRET, {
        audience: TOKEN_AUDIENCE,
        issuer: TOKEN_ISSUER,
      });
      return { sub: String(payload.sub), org: String(payload.org), role: payload.role as Claims['role'] };
    } catch {
      return null;
    }
  },

  // Item 1 (A01): a record is readable only by its owning tenant.
  canReadRecord(claims: Claims, record): boolean {
    return record.ownerOrg === claims.org;
  },

  // Item 2 (A01): authorization uses the server-side role from the verified token; the body is
  // ignored for the decision.
  authorizeAdmin(claims: Claims): boolean {
    return claims.role === 'admin' || claims.role === 'owner';
  },

  // Item 4 (A08): require an HMAC-SHA256 signature over `${timestamp}.${body}`, compared in
  // constant time, and a timestamp inside the replay window.
  verifyWebhook(input, secret): boolean {
    if (!input.signature || !input.timestamp) return false;
    const ts = Number(input.timestamp);
    if (!Number.isFinite(ts)) return false;
    if (Math.abs(input.nowMs / 1000 - ts) > WEBHOOK_WINDOW_SECONDS) return false;
    const expected = createHmac('sha256', secret).update(`${input.timestamp}.${input.rawBody}`).digest('hex');
    const a = Buffer.from(expected);
    const b = Buffer.from(input.signature);
    return a.length === b.length && timingSafeEqual(a, b);
  },

  // Item 5 (A01/A05): normalize and confine -- reject any separator or traversal; allow only a
  // simple file name inside the base directory.
  resolveFilePath(baseDir: string, name: string): string | null {
    if (!/^[\w.-]+$/.test(name) || name.includes('..')) return null;
    return join(baseDir, name);
  },

  // Item 6 (A08): allowlist the writable fields; any other key rejects the whole update.
  vetUpdate(body: Record<string, unknown>): Record<string, unknown> | null {
    const allowed = ['title', 'body'];
    if (Object.keys(body).some((k) => !allowed.includes(k))) return null;
    const patch: Record<string, unknown> = {};
    for (const key of allowed) if (key in body) patch[key] = body[key];
    return patch;
  },

  // Item 7 (A03): keep the untrusted record body in the data channel, separate from the
  // instruction, so a directive planted in the data is not obeyed.
  buildPrompt(record) {
    return { instruction: 'Summarize the note.', data: record.body };
  },

  // Item 8 (A05): attach security headers, require a same-origin request and a matching CSRF token
  // on state-changing routes.
  guardStateChange(input) {
    const headers = {
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    };
    if (input.origin && input.origin !== ALLOWED_ORIGIN) {
      return { allowed: false, headers, reason: 'cross-origin request' };
    }
    if (input.csrfToken !== csrfToken(input.claims.sub)) {
      return { allowed: false, headers, reason: 'missing or invalid CSRF token' };
    }
    return { allowed: true, headers };
  },
};
