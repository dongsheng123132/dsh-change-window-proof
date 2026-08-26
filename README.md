# dsh-change-window-proof

Offline, deterministic evidence for one narrow question: **does the supplied hash-linked change ledger settle inside one declared UTC maintenance window while staying bound to one change receipt, artifact, environment, policy and plan?**

It provides the same headless core through a DSH bundle, standalone MCP stdio server, JavaScript API and CLI. Reports are content-addressed, redacted and verified after writing.

## Why this is separate

AWS models a maintenance window with a schedule, maximum duration, targets and tasks, and defines a cutoff after which new tasks may not start. Azure likewise separates start time, duration, recurrence and disallowed dates. This plugin verifies a supplied settlement against those fixed-window ideas; it is not a scheduler.

It complements rather than duplicates the 2Origin evidence stack:

- `dsh-action-parity` proves interface bindings share one action core.
- `dsh-policy-waiver-proof` verifies an explicit exception chain.
- `dsh-artifact-promotion-proof` verifies immutable digest promotion across stages.
- `dsh-change-window-proof` verifies one supplied action ledger stayed within one declared time boundary and cutoff.

It does **not** approve, grant a waiver, schedule or execute a change; authenticate the recorder or receipts; query live infrastructure; or prove that no unrecorded action occurred.

## Checks

- one declared window exists and contains the exact settlement start/finish;
- contiguous `start → step* → finish` sequence and monotonically ordered UTC timestamps;
- maximum duration and no-new-step cutoff;
- every event binds the same window, change receipt, artifact and environment;
- event SHA-256 chain and declared ledger head;
- observer diversity and evidence freshness;
- secret-shaped values and raw business/log fields are rejected;
- workspace-relative, non-symlink input and output paths; exclusive content-addressed write with read-back.

## Use

```bash
npm test
npm run check
node bin/dsh-change-window-proof.mjs inspect examples/compliant.json
node bin/dsh-change-window-proof.mjs verify examples/compliant.json
```

Install as a DSH bundle from a path or a fixed public commit:

```bash
dsh plugin install /absolute/path/to/dsh-change-window-proof
dsh plugin install github:dongsheng123132/dsh-change-window-proof#<commit>
```

DSH tools:

- `dsh_change_window_inspect` accepts inline `manifestJson` and returns bounded hashes/counts.
- `dsh_change_window_verify` accepts workspace-relative `manifestPath` and `artifactDir`, then writes and re-reads a content-addressed JSON verdict.

MCP tools are `change_window_inspect` and `change_window_verify`; launch with `node mcp-server.mjs` using newline-delimited JSON-RPC.

## Manifest

See [`examples/compliant.json`](examples/compliant.json). Only identifiers, timestamps, counts and SHA-256 bindings belong in the manifest. Do not place credentials, raw logs, prompts, bodies, chat text or source documents in it.

References: [AWS Systems Manager Maintenance Windows](https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows.html), [AWS scheduling and active-period options](https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-schedule-options.html), [Azure AKS maintenance window schema](https://learn.microsoft.com/en-us/rest/api/aks/maintenance-configurations/get?view=rest-aks-2026-03-01).

MIT licensed. See [SECURITY.md](SECURITY.md) for the trust boundary.
