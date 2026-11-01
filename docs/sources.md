# Sources

Every third-party claim in this repo (CVSS 3.1 definitions, OWASP category ids, `jose` verification
semantics, webhook-signature practice) is quoted from one of the official pages below, each fetched
on 2026-11-01. Quotes are copied from the fetched page; where a claim is about what a page does or
does not say, the method is stated. Anything not backed by a quote here is marked "not verified".

## CVSS 3.1 (FIRST)

**Specification Document**: <https://www.first.org/cvss/v3.1/specification-document>

- Base score formulas (section 7.1), quoted:
  - `ISS = 1 - [ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) ]`
  - Impact, Scope Unchanged: `6.42 × ISS`
  - Impact, Scope Changed: `7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15`
  - `Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction`
  - Base Score: if Impact <= 0 then 0; if Scope Unchanged, `Roundup(Minimum[(Impact + Exploitability), 10])`;
    if Scope Changed, `Roundup(Minimum[1.08 × (Impact + Exploitability), 10])`.
- Roundup (section 7): "Roundup returns the smallest number, specified to 1 decimal place, that is
  equal to or higher than its input." Appendix A: "A suggested approach is for the Roundup function
  to first multiply its input by 100,000 and convert it to the nearest integer." `src/scoring.ts`
  `roundUp1` follows that integer approach.
- Metric weights (Table 16), quoted: Attack Vector N=0.85, A=0.62, L=0.55, P=0.2; Attack Complexity
  L=0.77, H=0.44; Privileges Required (Scope Unchanged) N=0.85, L=0.62, H=0.27, (Scope Changed)
  N=0.85, L=0.68, H=0.5; User Interaction N=0.85, R=0.62; Confidentiality/Integrity/Availability
  H=0.56, L=0.22, N=0.
- Qualitative severity rating scale (Table 14): None 0.0; Low 0.1-3.9; Medium 4.0-6.9; High 7.0-8.9;
  Critical 9.0-10.0.

The per-finding vectors in `src/scoring.ts` are a reviewer's judgement on a synthetic target; the
base scores and severities are computed from those vectors by the formulas above, never hand-typed.

## OWASP Top 10 2021

**Top 10:2021 index**: <https://owasp.org/Top10/> (now redirects to the 2025 edition; the 2021
edition was read at <https://top10.owasp.org/2021/>).

Category identifiers and titles used in this repo, quoted from the 2021 list:

- A01:2021 Broken Access Control
- A03:2021 Injection
- A05:2021 Security Misconfiguration
- A07:2021 Identification and Authentication Failures
- A08:2021 Software and Data Integrity Failures

The item-to-category mapping is the reviewer's classification of each planted weakness; the titles
above are quoted, the assignment of a given handler to a category is this repo's own.

## jose (JWT handling)

**README**: <https://github.com/panva/jose> (`https://raw.githubusercontent.com/panva/jose/main/README.md`)

- `jwtVerify` is listed under "JWT Claims Set Validation & Signature Verification"; the module intro
  describes "signing and verifying tokens, as well as their JWT Claims Set validation."
- `decodeJwt` is listed under "Decoding JWT Claims Set" and described as decoding "prior to its
  validation" — i.e. a decode step, not a verification step.
- Method: the README does not name `exp`, `nbf` or `aud` individually, so which specific claims
  `jwtVerify` checks is backed by RFC 7519 below plus the `audience`/`issuer` options this repo
  passes. v2 relies on `jwtVerify`; v1 uses `decodeJwt`, which per the README does not verify.

**RFC 7519 (JSON Web Token)**: <https://www.rfc-editor.org/rfc/rfc7519>

- `exp` (Expiration Time), section 4.1.4: "...identifies the expiration time on or after which the
  JWT MUST NOT be accepted for processing."
- `aud` (Audience), section 4.1.3: "...identifies the recipients that the JWT is intended for." "If
  the principal processing the claim does not identify itself with a value in the \"aud\" claim ...
  then the JWT MUST be rejected."

## Webhook signature practice

**GitHub — Validating webhook deliveries**:
<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>

- "GitHub recommends that you use the `X-Hub-Signature-256` header, which uses the HMAC-SHA256
  algorithm."
- "The hash signature is generated using your webhook's secret token and the payload contents."
- On comparison: "Never use a plain `==` operator." Use a constant-time comparison such as
  `secure_compare` or `crypto.timingSafeEqual`.

v2's `verifyWebhook` follows this shape: HMAC-SHA256 over `${timestamp}.${body}` with a secret,
compared with `crypto.timingSafeEqual`, plus a replay window on the timestamp. The window bound
(300 s) is this repo's own choice, not quoted from GitHub.
