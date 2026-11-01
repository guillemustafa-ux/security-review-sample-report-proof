import { describe, it, expect } from 'vitest';
import { cvss31, scoreFor, roundUp1, severityOf, FINDING_VECTORS } from '../src/scoring.js';

/**
 * (c) Each finding's CVSS 3.1 vector parses and its computed base score matches the documented
 * value. The expected numbers are the ones a reviewer publishes; they are checked against the
 * module's computation, not typed into the report.
 */
const EXPECTED: Record<string, { baseScore: number; severity: string }> = {
  'object-auth': { baseScore: 6.5, severity: 'Medium' },
  'function-auth': { baseScore: 8.1, severity: 'High' },
  'token-check': { baseScore: 9.1, severity: 'Critical' },
  'webhook-verify': { baseScore: 7.5, severity: 'High' },
  'path-confine': { baseScore: 6.5, severity: 'Medium' },
  'field-allowlist': { baseScore: 6.5, severity: 'Medium' },
  'prompt-separation': { baseScore: 5.4, severity: 'Medium' },
  headers: { baseScore: 4.7, severity: 'Medium' },
};

describe('CVSS 3.1 scoring', () => {
  for (const [id, expected] of Object.entries(EXPECTED)) {
    it(`(c-${id}) scores ${expected.baseScore} (${expected.severity})`, () => {
      const score = scoreFor(id);
      expect(score.vector).toBe(FINDING_VECTORS[id]);
      expect(score.baseScore).toBe(expected.baseScore);
      expect(score.severity).toBe(expected.severity);
    });
  }

  it('(c-roundup) rounds up to one decimal place per the CVSS 3.1 reference', () => {
    expect(roundUp1(4.02)).toBe(4.1);
    expect(roundUp1(6.0)).toBe(6.0);
    expect(roundUp1(6.430454)).toBe(6.5);
  });

  it('(c-severity) maps base scores to the CVSS 3.1 qualitative scale', () => {
    expect(severityOf(0)).toBe('None');
    expect(severityOf(3.9)).toBe('Low');
    expect(severityOf(4.0)).toBe('Medium');
    expect(severityOf(7.0)).toBe('High');
    expect(severityOf(9.0)).toBe('Critical');
  });

  it('(c-parse) rejects a malformed vector', () => {
    expect(() => cvss31('CVSS:3.1/AV:N/AC:L')).toThrow();
    expect(() => cvss31('not-a-vector')).toThrow();
  });
});
