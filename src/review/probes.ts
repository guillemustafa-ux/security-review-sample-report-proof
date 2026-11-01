import type { FastifyInstance } from 'fastify';
import { buildV1 } from '../app-v1/index.js';
import { buildV2 } from '../app-v2/index.js';
import { issueToken, forgeToken, signWebhook } from '../app/tokens.js';
import { USERS, INJECTION_MARKER } from '../app/seed.js';
import { ORG_A, ORG_B } from '../app/config.js';

export type Version = 'v1' | 'v2';

export interface Observation {
  /** true when the weakness is present (demonstrated) on the probed version. */
  open: boolean;
  status: number;
  /** A short, redacted line of what the response showed. */
  evidence: string;
}

function build(version: Version): FastifyInstance {
  return version === 'v1' ? buildV1() : buildV2();
}

type Probe = (version: Version) => Promise<Observation>;

/** Each probe drives a fresh app through its public HTTP surface and reports what it observed. */
export const PROBES: Record<string, Probe> = {
  // Item 1: a Contoso token asks for a Northwind record by id.
  'object-auth': async (version) => {
    const app = build(version);
    try {
      const token = await issueToken(USERS.carolMemberB);
      const res = await app.inject({
        method: 'GET',
        url: '/records/rec_nw_1',
        headers: { authorization: `Bearer ${token}` },
      });
      const body = res.statusCode === 200 ? (res.json() as { id?: string; ownerOrg?: string }) : {};
      const open = res.statusCode === 200 && body.ownerOrg === ORG_A;
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? `a Contoso token read rec_nw_1 (owner ${ORG_A}); HTTP 200`
          : `cross-tenant read blocked; HTTP ${res.statusCode}`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 2: a member posts to the admin route while asserting role "admin" in the body.
  'function-auth': async (version) => {
    const app = build(version);
    try {
      const token = await issueToken(USERS.aliceMemberA);
      const res = await app.inject({
        method: 'POST',
        url: '/admin/config',
        headers: { authorization: `Bearer ${token}` },
        payload: { setting: 'theme', value: 'dark', role: 'admin' },
      });
      const open = res.statusCode === 200;
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? 'a member with body role=admin changed admin config; HTTP 200'
          : `privileged route refused the member; HTTP ${res.statusCode}`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 3: a forged (wrong key, wrong audience, expired) token is presented.
  'token-check': async (version) => {
    const app = build(version);
    try {
      const token = await forgeToken(USERS.aliceMemberA);
      const res = await app.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` },
      });
      const open = res.statusCode === 200;
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? 'a forged/expired token was accepted at /me; HTTP 200'
          : `forged token rejected; HTTP ${res.statusCode}`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 4: an unsigned webhook tries to upgrade a tenant's plan.
  'webhook-verify': async (version) => {
    const app = build(version);
    try {
      const res = await app.inject({
        method: 'POST',
        url: '/webhooks/billing',
        headers: { 'content-type': 'application/json' },
        payload: { org: ORG_A, plan: 'enterprise' },
      });
      const body = res.statusCode === 200 ? (res.json() as { plan?: string }) : {};
      const open = res.statusCode === 200 && body.plan === 'enterprise';
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? 'an unsigned webhook set the plan to enterprise; HTTP 200'
          : `unsigned webhook rejected; HTTP ${res.statusCode}`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 5: a traversal name escapes the attachments directory.
  'path-confine': async (version) => {
    const app = build(version);
    try {
      const token = await issueToken(USERS.aliceMemberA);
      const res = await app.inject({
        method: 'GET',
        url: '/files',
        query: { name: '../private/credentials.txt' },
        headers: { authorization: `Bearer ${token}` },
      });
      const open = res.statusCode === 200 && res.body.includes('SYNTHETIC-SECRET');
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? 'name "../private/credentials.txt" returned a file outside attachments; HTTP 200'
          : `traversal rejected; HTTP ${res.statusCode}`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 6: the update body carries ownerOrg to move the record to another tenant.
  'field-allowlist': async (version) => {
    const app = build(version);
    try {
      const token = await issueToken(USERS.aliceMemberA);
      const res = await app.inject({
        method: 'PATCH',
        url: '/records/rec_nw_1',
        headers: { authorization: `Bearer ${token}` },
        payload: { ownerOrg: ORG_B },
      });
      const body = res.statusCode === 200 ? (res.json() as { ownerOrg?: string }) : {};
      const open = res.statusCode === 200 && body.ownerOrg === ORG_B;
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? `ownerOrg was reassigned to ${ORG_B} via the update body; HTTP 200`
          : `protected field rejected; HTTP ${res.statusCode}`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 7: a directive planted in a synced record body tries to override the model instruction.
  'prompt-separation': async (version) => {
    const app = build(version);
    try {
      const token = await issueToken(USERS.aliceMemberA);
      const res = await app.inject({
        method: 'POST',
        url: '/assistant/summarize',
        headers: { authorization: `Bearer ${token}` },
        payload: { recordId: 'rec_nw_2' },
      });
      const body = res.json() as { output?: string };
      const open = body.output === INJECTION_MARKER;
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? `the injected directive controlled the model output ("${body.output}")`
          : `injection ignored; model returned a summary ("${body.output}")`,
      };
    } finally {
      await app.close();
    }
  },

  // Item 8: a cross-origin state change with no CSRF token.
  headers: async (version) => {
    const app = build(version);
    try {
      const token = await issueToken(USERS.aliceMemberA);
      const res = await app.inject({
        method: 'POST',
        url: '/records',
        headers: { authorization: `Bearer ${token}`, origin: 'https://evil.example' },
        payload: { title: 'injected', body: 'created cross-origin' },
      });
      const nosniff = res.headers['x-content-type-options'];
      const open = res.statusCode === 201;
      return {
        open,
        status: res.statusCode,
        evidence: open
          ? `cross-origin create accepted with no CSRF token; HTTP 201; x-content-type-options=${nosniff ?? 'absent'}`
          : `state change refused; HTTP ${res.statusCode}; x-content-type-options=${nosniff ?? 'absent'}`,
      };
    } finally {
      await app.close();
    }
  },
};
