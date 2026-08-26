import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createDefinitions } from '../index.js'
const manifestJson = await readFile(new URL('../examples/compliant.json', import.meta.url), 'utf8'); const tools = createDefinitions(); assert.deepEqual(tools.map(tool => tool.name), ['dsh_change_window_inspect', 'dsh_change_window_verify']); const result = await tools[0].execute({ manifestJson }); assert.equal(result.eventCount, 3); process.stdout.write(`${JSON.stringify({ ok: true, tools: tools.map(tool => tool.name), eventCount: result.eventCount })}\n`)
