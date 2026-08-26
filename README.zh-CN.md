# dsh-change-window-proof

这是一个离线、确定性的 DSH 证据层，只回答一个窄问题：**显式提供的哈希链变更账本，是否完整落在同一个声明的 UTC 维护窗口内，并始终绑定同一个变更回执、制品、环境、策略和计划？**

同一个无界面核心同时提供 DSH bundle、独立 MCP stdio、JavaScript API 和 CLI。报告按内容寻址写入，并在写后回读核验。

## 互补边界

AWS 把维护窗口定义为 schedule、最大 duration、targets、tasks，并另有禁止新任务启动的 cutoff；Azure 同样拆分 start、duration、recurrence 与禁用日期。本插件只复核已提供的结算证据，不是调度器。

- `dsh-action-parity` 证明多个界面绑定同一个动作核心；
- `dsh-policy-waiver-proof` 复核显式例外链；
- `dsh-artifact-promotion-proof` 复核不可变 digest 的跨阶段晋级；
- 本插件复核一次显式动作账本是否遵守同一个时间窗口与 cutoff。

它不会审批、豁免、调度或执行变更，不认证 recorder/回执，不查询线上系统，也不声称日志之外不存在动作。

## 核验项

- 声明窗口存在，且精确包住结算起止时间；
- 连续 `start → step* → finish` 序列和单调 UTC 时间；
- 最大时长与“停止启动新步骤”的 cutoff；
- 每个事件绑定同一窗口、变更回执、制品与环境；
- 事件 SHA-256 链与声明 ledger head；
- 不同观察者阈值与证据新鲜度；
- 拒绝秘密形态值、原始业务正文和日志字段；
- 输入/输出限于 workspace 相对路径，拒绝 symlink，报告独占写入并回读验证。

## 使用

```bash
npm test
npm run check
node bin/dsh-change-window-proof.mjs inspect examples/compliant.json
node bin/dsh-change-window-proof.mjs verify examples/compliant.json
```

DSH 安装：

```bash
dsh plugin install /absolute/path/to/dsh-change-window-proof
dsh plugin install github:dongsheng123132/dsh-change-window-proof#<commit>
```

DSH 工具是 `dsh_change_window_inspect` 与 `dsh_change_window_verify`；MCP 工具是 `change_window_inspect` 与 `change_window_verify`。完整 manifest 见 [`examples/compliant.json`](examples/compliant.json)。只放哈希、时间、数量和公开 ID，禁止放密钥、原始日志、prompt、body、聊天或原稿。

规范来源：[AWS Maintenance Windows](https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows.html)、[AWS 调度与有效期](https://docs.aws.amazon.com/systems-manager/latest/userguide/maintenance-windows-schedule-options.html)、[Azure AKS maintenance window schema](https://learn.microsoft.com/en-us/rest/api/aks/maintenance-configurations/get?view=rest-aks-2026-03-01)。
