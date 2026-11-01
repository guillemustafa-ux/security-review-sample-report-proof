/** Shared types for the synthetic multi-tenant API. v1 and v2 use the exact same shapes. */

export interface Claims {
  sub: string; // user id
  org: string; // tenant id
  role: 'owner' | 'admin' | 'member' | 'viewer';
}

export interface RecordRow {
  id: string;
  ownerOrg: string;
  title: string;
  body: string;
}

export interface OrgRow {
  id: string;
  name: string;
  plan: 'free' | 'pro' | 'enterprise';
}

/** The in-memory store, rebuilt fresh for every app instance from the same deterministic seed. */
export interface Store {
  orgs: Map<string, OrgRow>;
  records: Map<string, RecordRow>;
  config: Map<string, string>;
}

export interface WebhookInput {
  rawBody: string;
  signature: string | undefined;
  timestamp: string | undefined;
  nowMs: number;
}

export interface Prompt {
  instruction: string;
  data: string;
}

export interface StateChangeInput {
  origin: string | undefined;
  csrfToken: string | undefined;
  claims: Claims;
}

export interface StateChangeDecision {
  allowed: boolean;
  headers: Record<string, string>;
  reason?: string;
}

/**
 * The eight controls that differ between v1 (planted weakness) and v2 (remediation). The shell
 * calls these; everything else — routes, seed, token issuance, the LLM stub — is shared. Reverting
 * one v2 control to its v1 behaviour is exactly what each footgun does.
 */
export interface Controls {
  /** Item 3 (A07): turn a raw bearer token into claims, or null to reject. */
  verifyToken(raw: string): Promise<Claims | null>;
  /** Item 1 (A01): may these claims read this record? */
  canReadRecord(claims: Claims, record: RecordRow): boolean;
  /** Item 2 (A01): are these claims allowed to use a privileged route, given the request body? */
  authorizeAdmin(claims: Claims, body: Record<string, unknown>): boolean;
  /** Item 4 (A08): is this inbound webhook authentic and fresh? */
  verifyWebhook(input: WebhookInput, secret: string): boolean;
  /** Item 5 (A01/A05): resolve a user-supplied name to a path inside baseDir, or null to reject. */
  resolveFilePath(baseDir: string, name: string): string | null;
  /** Item 6 (A08): which fields of an update body may be written? Returns the patch to apply, or
   * null to reject the whole update. */
  vetUpdate(body: Record<string, unknown>): Record<string, unknown> | null;
  /** Item 7 (A03): build the model prompt from a record whose body is untrusted synced text. */
  buildPrompt(record: RecordRow): Prompt;
  /** Item 8 (A05): decide a state-changing request and the security headers to attach. */
  guardStateChange(input: StateChangeInput): StateChangeDecision;
}
