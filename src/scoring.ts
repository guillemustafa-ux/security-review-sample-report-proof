/**
 * CVSS 3.1 base score, computed from a vector string. One module, one small weight table.
 *
 * Every number here is from the CVSS v3.1 Specification Document (first.org), fetched for this
 * repo; the metric weights are Table 16, the formulas are section 7.1, and `roundUp1` follows the
 * reference approach described in section 7 / Appendix A (quotes in `docs/sources.md`). Nothing is
 * hand-typed into the report: each finding names a vector, and its base score and severity are
 * computed from it here.
 */

export type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface Score {
  vector: string;
  baseScore: number;
  severity: Severity;
}

// CVSS v3.1 Specification, Table 16 (metric weights).
const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
// Privileges Required weight depends on Scope (Changed raises the L and H weights).
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

const METRIC_ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;

/** Parse "CVSS:3.1/AV:N/AC:L/.../A:N" into its metric map, rejecting anything malformed. */
export function parseVector(vector: string): Record<string, string> {
  const parts = vector.split('/');
  if (parts[0] !== 'CVSS:3.1') throw new Error(`not a CVSS 3.1 vector: ${vector}`);
  const metrics: Record<string, string> = {};
  for (const part of parts.slice(1)) {
    const [key, value] = part.split(':');
    if (!key || !value) throw new Error(`malformed metric "${part}" in ${vector}`);
    metrics[key] = value;
  }
  for (const key of METRIC_ORDER) {
    if (!(key in metrics)) throw new Error(`missing base metric ${key} in ${vector}`);
  }
  return metrics;
}

/**
 * CVSS v3.1 Specification, section 7: "Roundup returns the smallest number, specified to 1 decimal
 * place, that is equal to or higher than its input." Done with integer arithmetic (Appendix A) so
 * that, e.g., 4.02 does not round to 4.0.
 */
export function roundUp1(input: number): number {
  const intInput = Math.round(input * 100_000);
  if (intInput % 10_000 === 0) return intInput / 100_000;
  return (Math.floor(intInput / 10_000) + 1) / 10;
}

/** CVSS v3.1 Specification, Table 14 (qualitative severity rating scale). */
export function severityOf(baseScore: number): Severity {
  if (baseScore === 0) return 'None';
  if (baseScore <= 3.9) return 'Low';
  if (baseScore <= 6.9) return 'Medium';
  if (baseScore <= 8.9) return 'High';
  return 'Critical';
}

export function cvss31(vector: string): Score {
  const m = parseVector(vector);
  const scopeChanged = m.S === 'C';

  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;

  const pr = scopeChanged ? PR_C[m.PR] : PR_U[m.PR];
  const exploitability = 8.22 * AV[m.AV] * AC[m.AC] * pr * UI[m.UI];

  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (scopeChanged) {
    baseScore = roundUp1(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    baseScore = roundUp1(Math.min(impact + exploitability, 10));
  }

  return { vector, baseScore, severity: severityOf(baseScore) };
}

/**
 * The vector per finding. A reviewer's judgement call on a synthetic target; the base score and
 * severity are computed from these, never typed. Keyed by the finding id used across the repo.
 */
export const FINDING_VECTORS: Record<string, string> = {
  'object-auth': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  'function-auth': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
  'token-check': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  'webhook-verify': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
  'path-confine': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  'field-allowlist': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
  'prompt-separation': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
  'headers': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N',
};

export function scoreFor(findingId: string): Score {
  const vector = FINDING_VECTORS[findingId];
  if (!vector) throw new Error(`no vector for finding ${findingId}`);
  return cvss31(vector);
}
