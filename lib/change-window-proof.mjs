import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const ZERO = '0'.repeat(64)
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const hash = (value, label) => { if (typeof value !== 'string' || !HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }
const integer = (value, label, min, max) => { if (!Number.isSafeInteger(value) || value < min || value > max) throw fail('INVALID_MANIFEST', `${label} invalid`) }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|raw|body|content|log|prompt|chat)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `sensitive field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

export function computeEventSha256(event) {
  const { eventSha256: _ignored, occurredMs: _derived, ...body } = event
  return sha256(stable(body))
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest); boundedId(manifest.proofId, 'proofId')
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const change = manifest.change || {}
  for (const key of ['changeReceiptSha256', 'artifactSha256', 'environmentHash', 'policySha256', 'planSha256']) hash(change[key], `change.${key}`)
  const policy = manifest.policy || {}
  integer(policy.maxDurationMs, 'policy.maxDurationMs', 1000, 7 * 86400000)
  integer(policy.cutoffMs, 'policy.cutoffMs', 0, policy.maxDurationMs - 1)
  integer(policy.maxEvidenceAgeMs, 'policy.maxEvidenceAgeMs', 1000, 365 * 86400000)
  integer(policy.minDistinctObservers, 'policy.minDistinctObservers', 1, 100)
  if (!Array.isArray(policy.windows) || !policy.windows.length || policy.windows.length > 100) throw fail('INVALID_MANIFEST', 'policy.windows invalid')
  const windows = new Map()
  for (const [index, window] of policy.windows.entries()) {
    hash(window?.windowIdHash, `windows[${index}].windowIdHash`)
    const opensMs = timestamp(window.opensAt, 'window.opensAt'); const closesMs = timestamp(window.closesAt, 'window.closesAt')
    if (closesMs <= opensMs || closesMs - opensMs > 7 * 86400000) throw fail('INVALID_MANIFEST', 'window duration invalid')
    if (windows.has(window.windowIdHash)) throw fail('INVALID_MANIFEST', 'duplicate window')
    windows.set(window.windowIdHash, { ...window, opensMs, closesMs })
  }
  const settlement = manifest.settlement || {}
  hash(settlement.declaredWindowIdHash, 'settlement.declaredWindowIdHash'); hash(settlement.ledgerHeadSha256, 'settlement.ledgerHeadSha256')
  const startedMs = timestamp(settlement.startedAt, 'settlement.startedAt'); const completedMs = timestamp(settlement.completedAt, 'settlement.completedAt')
  if (!Array.isArray(manifest.events) || manifest.events.length < 2 || manifest.events.length > 10000) throw fail('INVALID_MANIFEST', 'events invalid')
  const eventIds = new Set()
  const events = manifest.events.map((event, index) => {
    for (const key of ['eventIdHash', 'previousEventSha256', 'eventSha256', 'windowIdHash', 'changeReceiptSha256', 'artifactSha256', 'environmentHash', 'actionIdHash', 'observerHash']) hash(event?.[key], `events[${index}].${key}`)
    if (event.sequence !== index + 1) throw fail('INVALID_MANIFEST', 'event sequence must be contiguous')
    if (!['start', 'step', 'finish'].includes(event.phase)) throw fail('INVALID_MANIFEST', 'event phase invalid')
    if (eventIds.has(event.eventIdHash)) throw fail('INVALID_MANIFEST', 'duplicate event id'); eventIds.add(event.eventIdHash)
    return { ...event, occurredMs: timestamp(event.occurredAt, 'event.occurredAt') }
  })
  if (events[0].phase !== 'start' || events.at(-1).phase !== 'finish' || events.slice(1, -1).some(event => event.phase !== 'step')) throw fail('INVALID_MANIFEST', 'event phases must form start/step*/finish')
  return { manifest, evaluationMs, change, policy, windows, settlement, startedMs, completedMs, events }
}

export function inspectChangeWindowManifestJson(manifestJson) {
  const { manifest, change, policy, events } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), artifactSha256: change.artifactSha256, environmentHash: change.environmentHash, declaredWindowIdHash: manifest.settlement.declaredWindowIdHash, windowCount: policy.windows.length, eventCount: events.length, executesChange: false, grantsApproval: false }
}

export function evaluateChangeWindowManifest(manifestJson) {
  const { manifest, evaluationMs, change, policy, windows, settlement, startedMs, completedMs, events } = parseManifest(manifestJson)
  const window = windows.get(settlement.declaredWindowIdHash)
  const declaredWindowExists = Boolean(window)
  const exactSettlementTimes = startedMs === events[0].occurredMs && completedMs === events.at(-1).occurredMs
  const chronologyValid = completedMs >= startedMs && events.every((event, index) => index === 0 || event.occurredMs >= events[index - 1].occurredMs) && completedMs <= evaluationMs
  const durationSatisfied = completedMs - startedMs <= policy.maxDurationMs
  const windowSatisfied = Boolean(window) && startedMs >= window.opensMs && completedMs <= window.closesMs
  const cutoffSatisfied = Boolean(window) && events.filter(event => event.phase !== 'finish').every(event => event.occurredMs <= window.closesMs - policy.cutoffMs)
  const bindingsSatisfied = events.every(event => event.windowIdHash === settlement.declaredWindowIdHash && event.changeReceiptSha256 === change.changeReceiptSha256 && event.artifactSha256 === change.artifactSha256 && event.environmentHash === change.environmentHash)
  let previous = ZERO
  const hashChainValid = events.every(event => { const valid = event.previousEventSha256 === previous && event.eventSha256 === computeEventSha256(event); previous = event.eventSha256; return valid }) && settlement.ledgerHeadSha256 === events.at(-1).eventSha256
  const distinctObserverCount = new Set(events.map(event => event.observerHash)).size
  const observerThresholdSatisfied = distinctObserverCount >= policy.minDistinctObservers
  const evidenceFresh = evaluationMs - completedMs >= 0 && evaluationMs - completedMs <= policy.maxEvidenceAgeMs
  const checks = { declaredWindowExists, exactSettlementTimes, chronologyValid, durationSatisfied, windowSatisfied, cutoffSatisfied, bindingsSatisfied, hashChainValid, observerThresholdSatisfied, evidenceFresh }
  const verified = Object.values(checks).every(Boolean)
  return { schemaVersion: 1, verdict: verified ? 'window-compliant' : 'not-window-compliant', proofIdHash: sha256(manifest.proofId), changeReceiptSha256: change.changeReceiptSha256, artifactSha256: change.artifactSha256, environmentHash: change.environmentHash, policySha256: change.policySha256, planSha256: change.planSha256, declaredWindowIdHash: settlement.declaredWindowIdHash, ledgerHeadSha256: settlement.ledgerHeadSha256, checks, disclosures: { windowCount: policy.windows.length, eventCount: events.length, distinctObserverCount, elapsedMs: completedMs - startedMs }, executesChange: false, grantsApproval: false, grantsWaiver: false, authenticatesReceipts: false, observesLiveSystems: false, provesAbsenceOfUnrecordedActions: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat; const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path contains symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent invalid') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const realRel = relative(await realpath(root), await realpath(absolute)); if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest escapes workspaceRoot')
  return readFile(absolute, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyChangeWindowManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluateChangeWindowManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `change-window-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; if (!(await readFile(output)).equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output); if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
