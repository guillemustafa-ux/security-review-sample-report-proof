import { buildApp } from '../app/shell.js';
import { controls } from './controls.js';

/** v2: the same API with every weakness remediated. */
export function buildV2() {
  return buildApp(controls);
}
