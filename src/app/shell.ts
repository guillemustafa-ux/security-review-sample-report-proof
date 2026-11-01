import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Claims, Controls, Store } from './types.js';
import { seed } from './seed.js';
import { llmStub } from './llm-stub.js';
import { WEBHOOK_SECRET } from './config.js';

const ATTACH_DIR = fileURLToPath(new URL('./fixtures/attachments', import.meta.url));

/**
 * The one app shell. Both versions register these exact routes against the same seeded store and
 * differ ONLY in the `controls` they are given. Nothing tenant-specific is decided here; every
 * security decision is delegated to a control so a single revert is enough to reopen one weakness.
 */
export function buildApp(controls: Controls): FastifyInstance {
  const app = Fastify({ logger: false });
  const store: Store = seed();

  // Capture the raw JSON body (needed for the webhook signature) while still parsing it.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    (req as FastifyRequest & { rawBody?: string }).rawBody = body as string;
    try {
      done(null, (body as string).length ? JSON.parse(body as string) : {});
    } catch (err) {
      done(err as Error, undefined);
    }
  });

  async function authed(req: FastifyRequest, reply: FastifyReply): Promise<Claims | null> {
    const header = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
    const claims = await controls.verifyToken(header);
    if (!claims) {
      reply.code(401).send({ error: 'unauthorized' });
      return null;
    }
    return claims;
  }

  // GET /me -- a neutral authenticated endpoint; the token-verification item is observed here.
  app.get('/me', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    reply.send({ sub: claims.sub, org: claims.org, role: claims.role });
  });

  // GET /records/:id -- object-level authorization (item 1).
  app.get('/records/:id', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    const { id } = req.params as { id: string };
    const record = store.records.get(id);
    if (!record) return reply.code(404).send({ error: 'not found' });
    if (!controls.canReadRecord(claims, record)) return reply.code(404).send({ error: 'not found' });
    reply.send(record);
  });

  // PATCH /records/:id -- mass assignment of protected fields (item 6).
  app.patch('/records/:id', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    const { id } = req.params as { id: string };
    const record = store.records.get(id);
    if (!record || record.ownerOrg !== claims.org) return reply.code(404).send({ error: 'not found' });
    const patch = controls.vetUpdate((req.body ?? {}) as Record<string, unknown>);
    if (!patch) return reply.code(400).send({ error: 'invalid update field' });
    Object.assign(record, patch);
    reply.send(record);
  });

  // POST /records -- state-changing route; security headers + CSRF/same-origin posture (item 8).
  app.post('/records', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    const decision = controls.guardStateChange({
      origin: req.headers.origin as string | undefined,
      csrfToken: req.headers['x-csrf-token'] as string | undefined,
      claims,
    });
    for (const [k, v] of Object.entries(decision.headers)) reply.header(k, v);
    if (!decision.allowed) return reply.code(403).send({ error: decision.reason ?? 'forbidden' });
    const body = (req.body ?? {}) as { title?: string; body?: string };
    const id = `rec_new_${store.records.size + 1}`;
    const record = { id, ownerOrg: claims.org, title: body.title ?? 'untitled', body: body.body ?? '' };
    store.records.set(id, record);
    reply.code(201).send(record);
  });

  // POST /admin/config -- function-level authorization (item 2).
  app.post('/admin/config', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    const body = (req.body ?? {}) as Record<string, unknown>;
    if (!controls.authorizeAdmin(claims, body)) return reply.code(403).send({ error: 'forbidden' });
    store.config.set(String(body.setting), String(body.value));
    reply.send({ ok: true, setting: String(body.setting), value: String(body.value) });
  });

  // POST /webhooks/billing -- inbound webhook integrity (item 4). Unauthenticated by design.
  app.post('/webhooks/billing', async (req, reply) => {
    const rawBody = (req as FastifyRequest & { rawBody?: string }).rawBody ?? '';
    const ok = controls.verifyWebhook(
      {
        rawBody,
        signature: req.headers['x-signature'] as string | undefined,
        timestamp: req.headers['x-timestamp'] as string | undefined,
        nowMs: Date.now(),
      },
      WEBHOOK_SECRET,
    );
    if (!ok) return reply.code(401).send({ error: 'invalid signature' });
    const body = (req.body ?? {}) as { org?: string; plan?: string };
    const org = body.org ? store.orgs.get(body.org) : undefined;
    if (!org) return reply.code(404).send({ error: 'unknown org' });
    org.plan = (body.plan as typeof org.plan) ?? org.plan;
    reply.send({ ok: true, org: org.id, plan: org.plan });
  });

  // GET /files?name=... -- path handling on a file reference (item 5).
  app.get('/files', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    const name = (req.query as { name?: string }).name ?? '';
    const path = controls.resolveFilePath(ATTACH_DIR, name);
    if (!path) return reply.code(400).send({ error: 'invalid file name' });
    try {
      const content = readFileSync(path, 'utf8');
      reply.type('text/plain').send(content);
    } catch {
      reply.code(404).send({ error: 'not found' });
    }
  });

  // POST /assistant/summarize -- untrusted input reaching the model prompt (item 7).
  app.post('/assistant/summarize', async (req, reply) => {
    const claims = await authed(req, reply);
    if (!claims) return;
    const { recordId } = (req.body ?? {}) as { recordId?: string };
    const record = recordId ? store.records.get(recordId) : undefined;
    if (!record || record.ownerOrg !== claims.org) return reply.code(404).send({ error: 'not found' });
    const output = llmStub(controls.buildPrompt(record));
    reply.send({ output });
  });

  return app;
}
