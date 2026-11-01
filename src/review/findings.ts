/**
 * The finding metadata, one entry per weakness, in report order. The CVSS vector and base score are
 * NOT here: they come from `src/scoring.ts`, computed from the vector. These rows are the prose a
 * reviewer writes: what the issue is, where it lives, its impact and its fix.
 */
export interface FindingMeta {
  id: string;
  item: number;
  title: string;
  owasp: string;
  route: string;
  impact: string;
  remediation: string;
}

export const FINDINGS: FindingMeta[] = [
  {
    id: 'object-auth',
    item: 1,
    title: 'Broken object-level authorization (cross-tenant read)',
    owasp: 'A01:2021 Broken Access Control',
    route: 'GET /records/:id',
    impact: 'A token for one tenant reads another tenant\'s record by id; all records are enumerable across tenants.',
    remediation: 'Compare the record\'s owning tenant against the caller\'s tenant on every object fetch; 404 otherwise.',
  },
  {
    id: 'function-auth',
    item: 2,
    title: 'Broken function-level authorization (client-supplied role)',
    owasp: 'A01:2021 Broken Access Control',
    route: 'POST /admin/config',
    impact: 'A non-admin reaches a privileged route by asserting a role in the request body.',
    remediation: 'Authorize from the server-side role in the verified token; never trust a role field in the request.',
  },
  {
    id: 'token-check',
    item: 3,
    title: 'Authentication: token accepted without full verification',
    owasp: 'A07:2021 Identification and Authentication Failures',
    route: 'GET /me (all authenticated routes)',
    impact: 'A forged, wrong-audience or expired token is accepted, so any identity can be impersonated.',
    remediation: 'Verify signature, audience, issuer and expiry with jose jwtVerify; never act on a decoded-only token.',
  },
  {
    id: 'webhook-verify',
    item: 4,
    title: 'Inbound webhook integrity not enforced',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    route: 'POST /webhooks/billing',
    impact: 'An unauthenticated caller changes a tenant\'s billing plan; replays are not bounded.',
    remediation: 'Require an HMAC-SHA256 signature over timestamp+body, compare in constant time, and enforce a replay window.',
  },
  {
    id: 'path-confine',
    item: 5,
    title: 'Path traversal on a file reference',
    owasp: 'A01:2021 Broken Access Control / A05:2021 Security Misconfiguration',
    route: 'GET /files?name=',
    impact: 'A "../" name escapes the attachments directory and reads a file outside it.',
    remediation: 'Normalize and confine the name to the base directory; reject separators and traversal.',
  },
  {
    id: 'field-allowlist',
    item: 6,
    title: 'Mass assignment of a protected field',
    owasp: 'A08:2021 Software and Data Integrity Failures',
    route: 'PATCH /records/:id',
    impact: 'The update body can set a protected field (ownerOrg), moving a record to another tenant.',
    remediation: 'Allowlist the writable fields; reject any update that carries a field outside the allowlist.',
  },
  {
    id: 'prompt-separation',
    item: 7,
    title: 'Untrusted input reaches the model prompt',
    owasp: 'A03:2021 Injection',
    route: 'POST /assistant/summarize',
    impact: 'A directive planted in a synced record body overrides the model instruction.',
    remediation: 'Separate the instruction channel from the untrusted data channel; treat synced text as inert data.',
  },
  {
    id: 'headers',
    item: 8,
    title: 'Missing security headers and CSRF posture',
    owasp: 'A05:2021 Security Misconfiguration',
    route: 'POST /records',
    impact: 'A state-changing request is accepted cross-origin with no CSRF token and no security headers.',
    remediation: 'Attach security headers and require same-origin plus a matching CSRF token on state-changing routes.',
  },
];
