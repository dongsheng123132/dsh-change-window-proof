import { readFile } from 'node:fs/promises'
import { computeEventSha256 } from '../lib/change-window-proof.mjs'
export async function fixture() { return JSON.parse(await readFile(new URL('../examples/compliant.json', import.meta.url), 'utf8')) }
export function reseal(manifest) { let previous = '0'.repeat(64); for (const event of manifest.events) { event.previousEventSha256 = previous; event.eventSha256 = computeEventSha256(event); previous = event.eventSha256 } manifest.settlement.ledgerHeadSha256 = previous; return manifest }
