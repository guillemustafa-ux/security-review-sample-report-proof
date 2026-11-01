# Security review (SAMPLE, redacted) - v1

> Sample report on a synthetic, offline multi-tenant API. Tenant names are synthetic
> ("Northwind", "Contoso"), there are no real hosts or client data, and the CVSS scores
> are illustrative on a synthetic target with a finite, planted set of weaknesses.

<!-- review-stats target=v1 findingsOpen=8 retestsClosed=8 total=8 -->

**Verdict (v1): 8 findings open (1 Critical, 2 High, 5 Medium).** Retest against v2: 8 of 8 Closed.

- Severity from CVSS 3.1 base score (Table 14): Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9.
- Verdict: FAIL while any Critical or High finding is open; PASS when all are closed.
- Status = state on this version; Retest = state on v2 (the fixed version).

## Findings

| # | Finding | OWASP | Route | Severity | CVSS base (vector) | Status | Retest | Evidence (observed) | Impact | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Broken object-level authorization (cross-tenant read) | A01:2021 Broken Access Control | `GET /records/:id` | Medium | 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) | Open | Closed | a Contoso token read rec_nw_1 (owner org_northwind); HTTP 200 | A token for one tenant reads another tenant's record by id; all records are enumerable across tenants. | Compare the record's owning tenant against the caller's tenant on every object fetch; 404 otherwise. |
| 2 | Broken function-level authorization (client-supplied role) | A01:2021 Broken Access Control | `POST /admin/config` | High | 8.1 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`) | Open | Closed | a member with body role=admin changed admin config; HTTP 200 | A non-admin reaches a privileged route by asserting a role in the request body. | Authorize from the server-side role in the verified token; never trust a role field in the request. |
| 3 | Authentication: token accepted without full verification | A07:2021 Identification and Authentication Failures | `GET /me (all authenticated routes)` | Critical | 9.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) | Open | Closed | a forged/expired token was accepted at /me; HTTP 200 | A forged, wrong-audience or expired token is accepted, so any identity can be impersonated. | Verify signature, audience, issuer and expiry with jose jwtVerify; never act on a decoded-only token. |
| 4 | Inbound webhook integrity not enforced | A08:2021 Software and Data Integrity Failures | `POST /webhooks/billing` | High | 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`) | Open | Closed | an unsigned webhook set the plan to enterprise; HTTP 200 | An unauthenticated caller changes a tenant's billing plan; replays are not bounded. | Require an HMAC-SHA256 signature over timestamp+body, compare in constant time, and enforce a replay window. |
| 5 | Path traversal on a file reference | A01:2021 Broken Access Control / A05:2021 Security Misconfiguration | `GET /files?name=` | Medium | 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) | Open | Closed | name "../private/credentials.txt" returned a file outside attachments; HTTP 200 | A "../" name escapes the attachments directory and reads a file outside it. | Normalize and confine the name to the base directory; reject separators and traversal. |
| 6 | Mass assignment of a protected field | A08:2021 Software and Data Integrity Failures | `PATCH /records/:id` | Medium | 6.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`) | Open | Closed | ownerOrg was reassigned to org_contoso via the update body; HTTP 200 | The update body can set a protected field (ownerOrg), moving a record to another tenant. | Allowlist the writable fields; reject any update that carries a field outside the allowlist. |
| 7 | Untrusted input reaches the model prompt | A03:2021 Injection | `POST /assistant/summarize` | Medium | 5.4 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`) | Open | Closed | the injected directive controlled the model output ("OWNED") | A directive planted in a synced record body overrides the model instruction. | Separate the instruction channel from the untrusted data channel; treat synced text as inert data. |
| 8 | Missing security headers and CSRF posture | A05:2021 Security Misconfiguration | `POST /records` | Medium | 4.7 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`) | Open | Closed | cross-origin create accepted with no CSRF token; HTTP 201; x-content-type-options=absent | A state-changing request is accepted cross-origin with no CSRF token and no security headers. | Attach security headers and require same-origin plus a matching CSRF token on state-changing routes. |

## Method

- Independent review driving the app through its public HTTP surface; one deterministic probe per finding.
- Manual-style probes, not an automated scanner: each finding is reproduced by a specific request sequence.
- Retest re-runs every probe against v2 (the fixed version) and records the result in the Retest column.
