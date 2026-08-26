import { inspectChangeWindowManifestJson, verifyChangeWindowManifest } from './lib/change-window-proof.mjs'
export const name = 'dsh-change-window-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const define = value => ({ ...value, output: { schema: {}, render: renderJson } })
export function createDefinitions(_ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    define({ name: 'dsh_change_window_inspect', description: 'Inspect bounded hashes and counts from an explicit change-window manifest.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectChangeWindowManifestJson(manifestJson) }),
    define({ name: 'dsh_change_window_verify', description: 'Verify a supplied change event chain and write a redacted content-addressed report.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyChangeWindowManifest({ workspaceRoot, ...args }) })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
