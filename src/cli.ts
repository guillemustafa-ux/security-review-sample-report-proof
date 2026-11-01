import { writeFileSync } from 'node:fs';
import { runAll } from './review/run.js';
import { renderReport } from './review/report.js';
import type { Version } from './review/probes.js';

/**
 * npm run review -- v1|v2
 *
 * Runs every probe against both versions, writes SAMPLE_REPORT.md for the requested target, and
 * prints a per-finding summary. Exit code 0 when the report is produced; the verdict (findings open
 * on v1, all closed on v2) is in the report and the printed summary, not the exit code.
 */
const target = process.argv[2] as Version | undefined;
if (target !== 'v1' && target !== 'v2') {
  console.error('Usage: npm run review -- v1|v2');
  process.exit(2);
}

const items = await runAll();
const report = renderReport(target, items);
writeFileSync('SAMPLE_REPORT.md', report);

const onTarget = (i: (typeof items)[number]) => (target === 'v1' ? i.v1 : i.v2);
const open = items.filter((i) => onTarget(i).open).length;
const closed = items.filter((i) => !i.v2.open).length;

console.log(`Review of ${target}: ${open} finding(s) open, ${closed}/${items.length} closed on v2.`);
for (const i of items) {
  const status = onTarget(i).open ? 'OPEN  ' : 'CLOSED';
  console.log(`  ${status} [${i.score.severity.padEnd(8)} ${String(i.score.baseScore).padEnd(4)}] ${i.finding.route.padEnd(28)} ${i.finding.id}`);
}
console.log('Report written to SAMPLE_REPORT.md');
