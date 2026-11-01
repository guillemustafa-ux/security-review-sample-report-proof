import { buildApp } from '../app/shell.js';
import { controls } from './controls.js';

/** v1: the synthetic API with all eight weaknesses planted. */
export function buildV1() {
  return buildApp(controls);
}
