import { describe, it, expect } from 'vitest';
import { PROBES } from '../src/review/probes.js';
import { buildV1 } from '../src/app-v1/index.js';
import { buildV2 } from '../src/app-v2/index.js';
import { issueToken } from '../src/app/tokens.js';
import { USERS, INJECTION_MARKER, INJECTED_SUMMARY } from '../src/app/seed.js';

// (a) Each planted weakness is demonstrable on v1: the probe observes the issue. Literal statuses.
describe('v1: each weakness is present', () => {
  it('(a1) object-auth: a cross-tenant read returns the record (HTTP 200)', async () => {
    const o = await PROBES['object-auth']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a2) function-auth: a member reaches the admin route via body role (HTTP 200)', async () => {
    const o = await PROBES['function-auth']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a3) token-check: a forged token is accepted (HTTP 200)', async () => {
    const o = await PROBES['token-check']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a4) webhook-verify: an unsigned webhook changes the plan (HTTP 200)', async () => {
    const o = await PROBES['webhook-verify']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a5) path-confine: a traversal name reads an outside file (HTTP 200)', async () => {
    const o = await PROBES['path-confine']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a6) field-allowlist: the update body reassigns ownerOrg (HTTP 200)', async () => {
    const o = await PROBES['field-allowlist']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a7) prompt-separation: the injected directive controls the output', async () => {
    const o = await PROBES['prompt-separation']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(200);
  });
  it('(a8) headers: a cross-origin state change is accepted (HTTP 201)', async () => {
    const o = await PROBES['headers']('v1');
    expect(o.open).toBe(true);
    expect(o.status).toBe(201);
  });
});

// (b) Each weakness is closed on v2: the same probe is blocked. Literal statuses.
describe('v2: each weakness is closed', () => {
  it('(b1) object-auth: the cross-tenant read is blocked (HTTP 404)', async () => {
    const o = await PROBES['object-auth']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(404);
  });
  it('(b2) function-auth: the member is refused the admin route (HTTP 403)', async () => {
    const o = await PROBES['function-auth']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(403);
  });
  it('(b3) token-check: the forged token is rejected (HTTP 401)', async () => {
    const o = await PROBES['token-check']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(401);
  });
  it('(b4) webhook-verify: the unsigned webhook is rejected (HTTP 401)', async () => {
    const o = await PROBES['webhook-verify']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(401);
  });
  it('(b5) path-confine: the traversal is rejected (HTTP 400)', async () => {
    const o = await PROBES['path-confine']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(400);
  });
  it('(b6) field-allowlist: the protected field is rejected (HTTP 400)', async () => {
    const o = await PROBES['field-allowlist']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(400);
  });
  it('(b7) prompt-separation: the injected directive is ignored (HTTP 200, summary)', async () => {
    const o = await PROBES['prompt-separation']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(200);
  });
  it('(b8) headers: the cross-origin state change is refused (HTTP 403)', async () => {
    const o = await PROBES['headers']('v2');
    expect(o.open).toBe(false);
    expect(o.status).toBe(403);
  });
});

// (e) The LLM stub, asserted on literal output: the injection flips v1 and leaves v2 unchanged.
describe('LLM prompt injection, literal output', () => {
  async function summarize(app: ReturnType<typeof buildV1>): Promise<string> {
    const token = await issueToken(USERS.aliceMemberA);
    const res = await app.inject({
      method: 'POST',
      url: '/assistant/summarize',
      headers: { authorization: `Bearer ${token}` },
      payload: { recordId: 'rec_nw_2' },
    });
    return (res.json() as { output: string }).output;
  }

  it('(e) the injected field changes v1 output but not v2 output', async () => {
    const v1 = buildV1();
    const v2 = buildV2();
    try {
      const out1 = await summarize(v1);
      const out2 = await summarize(v2);
      expect(out1).toBe(INJECTION_MARKER); // v1 obeyed the planted directive
      expect(out2).toBe(INJECTED_SUMMARY); // v2 treated it as inert data
      expect(out2).not.toBe(INJECTION_MARKER);
    } finally {
      await v1.close();
      await v2.close();
    }
  });
});
