import { decodeJwt } from 'jose';
import { join } from 'node:path';
import type { Claims, Controls } from '../app/types.js';

/**
 * v1 controls -- the planted weaknesses. Each function is the smallest handler that exhibits one
 * OWASP category. A reviewer finds these by driving the app, not by reading this banner. See the
 * README for the item-to-OWASP map and `src/app-v2/controls.ts` for the remediation of each.
 */
export const controls: Controls = {
  // Item 3 (A07: Identification and Authentication Failures): the token is only decoded. Its
  // signature, audience and expiry are never checked, so a forged or expired token is accepted.
  async verifyToken(raw: string): Promise<Claims | null> {
    if (!raw) return null;
    try {
      const p = decodeJwt(raw);
      return { sub: String(p.sub), org: String(p.org), role: p.role as Claims['role'] };
    } catch {
      return null;
    }
  },

  // Item 1 (A01: Broken Access Control / object level): any authenticated caller can read any
  // record by id; ownership is never compared against the caller's tenant.
  canReadRecord(_claims: Claims, _record): boolean {
    return true;
  },

  // Item 2 (A01: Broken Access Control / function level): the privileged route trusts a
  // client-supplied `role` field in the body instead of the verified role from the token.
  authorizeAdmin(claims: Claims, body: Record<string, unknown>): boolean {
    const effectiveRole = (body.role as string | undefined) ?? claims.role;
    return effectiveRole === 'admin' || effectiveRole === 'owner';
  },

  // Item 4 (A08: Software and Data Integrity Failures): the webhook is acted on without verifying
  // its signature or its timestamp, so anyone can forge one and there is no replay window.
  verifyWebhook(): boolean {
    return true;
  },

  // Item 5 (A01/A05): the user-supplied name is joined to the base directory with no normalization
  // or confinement, so `../` escapes the attachments directory.
  resolveFilePath(baseDir: string, name: string): string | null {
    return join(baseDir, name);
  },

  // Item 6 (A08): the whole update body is written onto the record, so a protected field such as
  // `ownerOrg` can be reassigned through the update.
  vetUpdate(body: Record<string, unknown>): Record<string, unknown> | null {
    return body;
  },

  // Item 7 (A03-style injection): the untrusted record body is folded into the instruction channel,
  // so a directive planted in synced data is obeyed by the model.
  buildPrompt(record) {
    return { instruction: `Summarize the note.\n${record.body}`, data: '' };
  },

  // Item 8 (A05: Security Misconfiguration): state-changing requests are accepted with no security
  // headers, no CSRF token and no same-origin check.
  guardStateChange() {
    return { allowed: true, headers: {} };
  },
};
