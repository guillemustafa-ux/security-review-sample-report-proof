import { FINDINGS, type FindingMeta } from './findings.js';
import { PROBES, type Observation } from './probes.js';
import { scoreFor } from '../scoring.js';
import type { Score } from '../scoring.js';

export interface ItemResult {
  finding: FindingMeta;
  score: Score;
  v1: Observation;
  v2: Observation;
}

/**
 * Run every probe against both versions. Each item carries its finding metadata, its computed CVSS
 * score, and what the probe observed on v1 (issue present) and v2 (issue closed). The report and the
 * tests both read these results; nothing is measured twice.
 */
export async function runAll(): Promise<ItemResult[]> {
  const items: ItemResult[] = [];
  for (const finding of FINDINGS) {
    const probe = PROBES[finding.id];
    const v1 = await probe('v1');
    const v2 = await probe('v2');
    items.push({ finding, score: scoreFor(finding.id), v1, v2 });
  }
  return items;
}
