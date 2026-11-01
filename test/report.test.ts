import { describe, it, expect, beforeAll } from 'vitest';
import { runAll, type ItemResult } from '../src/review/run.js';
import { renderReport } from '../src/review/report.js';

/**
 * (d) The ONE report generator, asserted on its output. v1 lists exactly 8 open findings; v2 lists
 * 8 retests, all Closed. (d1) reads only the v1 side, so reverting a v2 fix does not touch it;
 * (d2) is the aggregate that must go red the moment any v2 fix is reverted.
 */
describe('sample report', () => {
  let items: ItemResult[];
  beforeAll(async () => {
    items = await runAll();
  });

  it('(d1) v1 report lists exactly 8 findings open', () => {
    const report = renderReport('v1', items);
    expect(report).toContain('target=v1 findingsOpen=8');
    expect(report).toContain('8 findings open');
    const rows = report.match(/^\| \d \| /gm) ?? [];
    expect(rows.length).toBe(8);
  });

  it('(d2) v2 report lists 8 retests all Closed', () => {
    const report = renderReport('v2', items);
    expect(report).toContain('<!-- review-stats target=v2 findingsOpen=0 retestsClosed=8 total=8 -->');
    const rows = report.match(/^\| \d \| /gm) ?? [];
    expect(rows.length).toBe(8);
    // No row is Open on v2 (status and retest columns both Closed).
    expect(report).not.toContain(' Open ');
  });
});
