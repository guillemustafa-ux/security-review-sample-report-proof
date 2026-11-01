import type { Prompt } from './types.js';

/**
 * A deterministic local stand-in for an LLM. No network, no randomness.
 *
 * The stub obeys a directive ONLY when it appears in the instruction channel. That is the whole
 * point of the prompt-injection item: v1 folds untrusted record text into the instruction, so a
 * directive planted in the data is obeyed; v2 keeps the record text in the data channel, where the
 * stub treats it as inert and just summarises it.
 */
const DIRECTIVE = /RESPOND VERBATIM:\s*([^\n.]+)/i;

export function llmStub(prompt: Prompt): string {
  const directive = prompt.instruction.match(DIRECTIVE);
  if (directive) return directive[1].trim();
  return summarize(prompt.data);
}

function summarize(data: string): string {
  const words = data.trim().split(/\s+/).filter(Boolean).slice(0, 6).join(' ');
  return `Summary: ${words}`;
}
