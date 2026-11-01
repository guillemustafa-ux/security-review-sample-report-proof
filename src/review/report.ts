import type { Version } from './probes.js';
import type { ItemResult } from './run.js';
import type { Severity } from '../scoring.js';

const cell = (text: string) => text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'None'];

function severityTally(items: ItemResult[]): string {
  return SEVERITY_ORDER.map((s) => [s, items.filter((i) => i.score.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(', ');
}

/**
 * The ONE sample-report generator, used by the `review` CLI and by the tests. Every number in it is
 * measured by the probes in this run; nothing is typed in. It is a redacted SAMPLE: synthetic tenant
 * names, no real hosts, illustrative CVSS on a synthetic target.
 */
export function renderReport(target: Version, items: ItemResult[]): string {
  const onTarget = (i: ItemResult) => (target === 'v1' ? i.v1 : i.v2);
  const openCount = items.filter((i) => onTarget(i).open).length;
  const retestsClosed = items.filter((i) => !i.v2.open).length;

  const lines: string[] = [];
  lines.push(`# Security review (SAMPLE, redacted) - ${target}`);
  lines.push('');
  lines.push('> Sample report on a synthetic, offline multi-tenant API. Tenant names are synthetic');
  lines.push('> ("Northwind", "Contoso"), there are no real hosts or client data, and the CVSS scores');
  lines.push('> are illustrative on a synthetic target with a finite, planted set of weaknesses.');
  lines.push('');
  lines.push(`<!-- review-stats target=${target} findingsOpen=${openCount} retestsClosed=${retestsClosed} total=${items.length} -->`);
  lines.push('');

  if (target === 'v1') {
    lines.push(`**Verdict (v1): ${openCount} findings open (${severityTally(items)}).** Retest against v2: ${retestsClosed} of ${items.length} Closed.`);
  } else {
    lines.push(`**Verdict (v2): ${openCount} findings open.** Retest of all ${items.length} fixes: ${retestsClosed} Closed.`);
  }
  lines.push('');
  lines.push('- Severity from CVSS 3.1 base score (Table 14): Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9.');
  lines.push('- Verdict: FAIL while any Critical or High finding is open; PASS when all are closed.');
  lines.push('- Status = state on this version; Retest = state on v2 (the fixed version).');
  lines.push('');

  lines.push('## Findings');
  lines.push('');
  lines.push('| # | Finding | OWASP | Route | Severity | CVSS base (vector) | Status | Retest | Evidence (observed) | Impact | Remediation |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |');
  items.forEach((i) => {
    const obs = onTarget(i);
    const status = obs.open ? 'Open' : 'Closed';
    const retest = i.v2.open ? 'Open' : 'Closed';
    lines.push(
      `| ${i.finding.item} | ${cell(i.finding.title)} | ${cell(i.finding.owasp)} | \`${cell(i.finding.route)}\` | ${i.score.severity} | ${i.score.baseScore} (\`${i.score.vector}\`) | ${status} | ${retest} | ${cell(obs.evidence)} | ${cell(i.finding.impact)} | ${cell(i.finding.remediation)} |`,
    );
  });
  lines.push('');
  lines.push('## Method');
  lines.push('');
  lines.push('- Independent review driving the app through its public HTTP surface; one deterministic probe per finding.');
  lines.push('- Manual-style probes, not an automated scanner: each finding is reproduced by a specific request sequence.');
  lines.push('- Retest re-runs every probe against v2 (the fixed version) and records the result in the Retest column.');
  lines.push('');
  return lines.join('\n');
}
