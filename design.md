# trex-cli 设计

状态：v1 已运行；v2 交互设计已确认，分阶段实施
日期：2026-08-15
依据：[goal.md](goal.md)、[first-design.md](first-design.md)

## 1. 摘要

trex-cli 是一套面向隔离实验室的、声明式、可审计、可重复的网络设备流量与性能测试工具。Cisco TRex 是数据面引擎；本项目负责测试意图校验、端口所有权、执行编排、结果有效性判定和证据保存。

v1 交付：

- Python CLI 与 Python Agent；
- 远程控制一个或多个由 Agent 独占的 TRex Server；
- STL 二层、三层无状态流量；
- MAC、IP 与传输层端口的声明式 variation；
- RFC2544 Throughput 与 Frame Loss 的 suite、strict 与 engineering-fast 模式；
- Job 幂等、显式 retry 关系、排队、取消、端口租约、故障恢复和审计；
- JSON 规范结果、Markdown 报告和原始统计 Artifact。

v1 不交付：

- ASTF 有状态 PCAP 会话重建；
- STL PCAP 重放；
- EMU 客户端模拟；
- DNS、DHCP、ARP 风暴；
- RFC2544 Latency、Back-to-back、System Recovery、Reset；
- 任意 Python Profile、Scapy 代码、shell、动态 import 或 `jsonpickle` 输入；
- 多 Agent 主备、分布式租约或主动续跑中断的 trial；
- “RFC2544 认证仪”或认证级绝对时延声明。

这些能力可在不扩大 v1 外部 Interface 的前提下，通过新增声明式 Job kind 和内部执行策略实现。

## 2. 设计原则

### 2.1 深 Module

系统的核心是 `TestJobs` Module。其外部 Interface 只有三个入口：提交、观察、取消。调用者不需要了解：

- STL client 的连接、端口 acquire/reset/start/stop；
- TRex Profile 与 Field Engine；
- 多端口原子租约；
- RFC2544 trial 搜索与确认；
- 统计采样、drain 和结果有效性；
- Agent 重启、远程断连和端口隔离；
- SQLite 事务和 Artifact 布局。

删除 `TestJobs` 后，上述复杂性会重新散落到 CLI、脚本和每种测试命令中。因此该 Module 通过 deletion test，能为调用者提供 Leverage，并把修复与验证集中为 Locality。

### 2.2 Interface 就是测试面

主要行为测试通过 `TestJobs` Interface 运行。测试不得依赖内部状态机类、SQL 表或 TRex 调用顺序；只有 adapter contract tests 可以直接测试内部 seam。

### 2.3 声明式且 fail-closed

- Job 只描述测试意图，不上传代码。
- 所有流量都有 Agent 解析后的硬截止时间。
- 无法证明运行安全或结果有效时，停止或拒绝测试；不得猜测。
- 基础设施失败、样本无效和 DUT 未达标是三类不同结果。

## 3. 系统形状

```text
Human / Automation
        │
        ▼
   Python CLI Adapter
        │ HTTPS + JSON / SSE
        ▼
┌───────────────────────────────────────────┐
│ TestJobs Module                           │
│                                           │
│ validation · policy · job state           │
│ scheduling · leases · RFC2544 engine      │
│ statistics · verdict · audit · recovery   │
│                                           │
│        internal TrafficEngine seam        │
└───────────────────┬───────────────────────┘
                    │
        ┌───────────┴────────────┐
        ▼                        ▼
 RemoteTrexStlAdapter   DeterministicTrexAdapter
        │
        ▼
 Remote, agent-owned TRex Server
```

CLI 是外部 Interface 的 adapter，只做：

- YAML/JSON 读取；
- HTTP 调用和 SSE 断线续接；
- 人类输出、JSON 输出和退出码映射；
- 本地生成并复用幂等键。

CLI 不做 Profile 编译、RFC2544 搜索、端口锁定、统计判定或安全默认值解析。

## 4. TestJobs Interface

逻辑 Interface：

```python
class TestJobs(Protocol):
    async def submit(self, request: SubmitJob) -> JobSnapshot: ...

    def observe(
        self, job_id: JobId, after_revision: int | None = None
    ) -> AsyncIterator[JobSnapshot]: ...

    async def cancel(self, request: CancelJob) -> JobSnapshot: ...
```

`observe` 首先返回完整的当前快照，随后只在 revision 变化时返回新快照；Job 进入终态后流结束。读取状态、等待完成和取得结果都通过同一入口完成。

### 4.1 HTTP adapter

| 行为 | HTTP |
|---|---|
| submit | `POST /v1/jobs` |
| current snapshot | `GET /v1/jobs/{job_id}` |
| observe | `GET /v1/jobs/{job_id}/events?after_revision=N`，SSE |
| cancel | `POST /v1/jobs/{job_id}:cancel` |
| artifact | `GET /v1/artifacts/{sha256}` |
| liveness | `GET /healthz` |
| readiness | `GET /readyz` |
| compatibility discovery | `GET /version` |
| authenticated metrics | `GET /metrics`，Prometheus text format |
| credential reload | `POST /v1/maintenance/auth:reload`，operator-only |

TestControl HTTP adapter 使用 `GET /v1/catalog`、`GET /v1/catalog/{kind}/{ref}`、
`POST /v1/plans`、`POST /v1/plans/{planId}:start`、`GET /v1/tests/{jobId}` 和
`POST /v1/tests/{jobId}:control`。`GET /v1/tests/{jobId}` 的 `afterRevision` 与
`waitSeconds` 实现最长 30 秒的有界 long polling；raw `/v1/jobs` 与 SSE 路径继续作为兼容
Interface。

SSE 的 `id` 等于 snapshot revision。客户端也可通过 `Last-Event-ID` 恢复。事件保留期内，`after_revision` 后的所有变化必须可重放；游标早于保留窗口时返回 `EVENT_CURSOR_EXPIRED`，调用者重新取得完整当前快照。

### 4.2 CLI adapter

```bash
# 常见同步路径：submit → observe → 输出结果
trex-cli run test.yaml

# 自动化
trex-cli run test.yaml --output json

# 异步路径
trex-cli job submit test.yaml --output id
trex-cli job watch <job-id>
trex-cli job result <job-id> --output json
trex-cli job cancel <job-id> --reason "operator request"
```

固定退出码：

| Code | 含义 |
|---:|---|
| 0 | Job `SUCCEEDED`，verdict 为 `PASS` 或 `NO_ASSERTION` |
| 1 | Job `SUCCEEDED`，verdict 为 `FAIL` |
| 2 | 输入、版本、鉴权或安全策略拒绝 |
| 3 | Job `FAILED`，或结果 verdict 为 `INVALID` |
| 130 | Job `CANCELLED`，或前台运行收到中断且取消已提交 |

前台 CLI 收到第一次 SIGINT 时提交 cancel 并继续观察；第二次 SIGINT 只终止本地 CLI，不改变 Agent 中已持久化的取消意图。

#### 4.2.1 面向 Agent 的 TestControl facade（后续 adapter）

最终调用者以自动化 Agent 为主。CLI 与 MCP 不分别发明流量语义，而是共同适配一个
`TestControl` Module；它在现有 `TestJobs` seam 之上隐藏 YAML、HTTP/SSE、TRex 端口号、
FlowStats、租约和校准细节。目标 Interface 为：

```text
search_catalog(query, kinds)
describe_resource(ref)
plan_test(intent) -> resolved plan + safety summary + planId
start_test(planId) -> jobId
get_test(jobId, afterRevision, waitSeconds) -> snapshot
control_test(jobId, action)
```

`plan_test` 只读地解析 named path、packet profile 和 typed overrides，返回最终 Ethernet/IP/
transport headers、variation 范围、负载、预计时长及安全判定。`start_test` 只接受不可变
`planId`，并把它作为幂等身份；MCP adapter 使用有界 long polling 实现 `observe_test`，CLI
adapter 可继续使用 SSE。高级用户仍可使用 `trex-cli run raw-job.yaml`，但 MCP 不接受任意
YAML、Python Profile 或 TRex 原生对象。

第一版 `Profiles` Module 将完整 Job 当作 profile，并允许任意 dotted `--set`。它只保留为迁移期
compatibility adapter，不是目标 Interface。新调用方不得依赖其字段路径。

#### 4.2.2 已确认的意图、资源与执行模型

目标模型把原先的完整 Job 拆成五种输入，由深 `TestPlan` Module 在 Agent 内编译：

| 输入 | 回答的问题 | 所有权 |
|---|---|---|
| `TrafficProfile` | 发送什么流量 | YAML 编写，发布到 Agent 版本目录 |
| `TestMethod` | 如何测试 | Agent 内置、版本化方法 |
| `LabPath` | 在哪条受控路径测试 | Agent 管理员维护 |
| `RunPolicy` | 速率、时长、循环和停止条件 | 调用意图，经 LabPath 约束 |
| `Assertions` | 什么结果算满足要求 | 调用意图或命名策略 |

`TrafficProfile` 不是 Job，不包含真实端口、实验室地址、持续时间、安全声明或验收门槛。它可以包含
多条有名字、有权重的单向 Flow。Flow 使用显式协议栈；删除 IP 层就是纯二层，在 Ethernet 与 IP
之间增加 VLAN 即为单 VLAN。双向流量由两条 Flow 表达，不使用自动反转报文的开关。

Profile 只能暴露声明过的 typed parameters：类型、默认值、范围和说明都是其 Interface 的一部分。
正常 CLI 使用 `--param name=value`；`--rate`、`--duration` 属于 RunPolicy。任意 dotted `--set`
只留在 legacy/raw 入口，MCP 不提供该能力。

MAC、IP 和端口 variation 使用与 TRex 无关的 `fixed`、`increment`、`decrement`、`random` 语义，
TRex Field Engine/VM 只是内部编译目标。Plan 必须显示最终范围、cardinality、校验和修复方式和
实际后端机制。用户声明测量目标（counters、per-flow loss、latency），不直接配置 `pg_id`、
software mode 或 FDIR；普通 traffic 可显式降级为独占端口统计，strict benchmark 不得静默降级。

`LabPath` 支持任意命名角色。TestMethod 再约束本次需要的角色集合；RFC2544 v1 需要一对角色，
Stateful PCAP 使用 client/server 语义映射。Profile 只引用角色名，Plan 只租用实际参与的端口。
L3 默认按 LabPath 自动解析直连邻居或 next-hop MAC，允许类型化手动覆盖；纯 L2 的目的 MAC 必须
显式提供。所有覆盖都必须落在 LabPath 的地址、VLAN、广播、速率、时长和 variation cardinality
限制内。普通 operator 没有通用 `--force`；`--yes` 只跳过交互确认。

RunPolicy 的 `rate` 固定采用 `per-egress` 语义。同一发送角色下的多个 Flow 按 weight 分享该端口
负载；Plan 同时显示每端口和 aggregate 负载。所有用户输入的 frame size 都是包含 4 字节 FCS 的
wire size。编译器同时记录 `wireSizeBytes`、不含 FCS 的 `generatedSizeBytes`，以及加入 8 字节
preamble/SFD 和 12 字节 IFG 的 `l1SizeBytes`。普通 Flow 可定义帧长分布；RFC2544 将选定 Flow
作为报文模板，并由 Method 在 Plan 中覆盖标准 frame sizes。

资源使用 `name@revision` 供发现，digest 保证内容不可变。TrafficProfile 由本地 YAML 编写并发布；
LabPath 只由管理员发布；Plan 固定所有资源 revision 和 digest。未指定 revision 的名字只在创建
Plan 时解析为当前版本，既有 Plan 永不漂移。Plan 有策略规定的有效期，start 时复核 TRex、链路、
端口、能力、校准和授权；实质漂移要求 replan。一个 Plan 最多对应一个 Job，`start_test(planId)`
天然幂等；复测必须 clone/replan。

迁移期未带 `metadata.revision` 的现有 YAML 资源视为 revision 1；新版本使用
`name@revision.yaml`，文件名、`metadata.name` 与 `metadata.revision` 必须一致。目录发现只返回每个
名字的最高 revision，显式 describe 和既有 Plan 仍可读取旧 revision。

CLI 按用户意图组织：

```text
trex-cli traffic plan|run ...
trex-cli traffic storm plan|run arp|dhcp|dns ...
trex-cli benchmark rfc2544 plan|run ...
trex-cli pcap replay plan|run ...
trex-cli plan list|show|start|clone ...
trex-cli job list|show|watch|cancel|report ...
```

`run` 是客户端便利流程：plan、完整展示、确认、start、watch。自动化必须显式 `--yes`。MCP 不提供
一步式 run，只提供两阶段 `plan_test`/`start_test`，并用少量任务级工具而非复制 CLI 命令树。

Job snapshot 使用语义 revision：只有调用者可观察字段变化时才递增，内部心跳不能制造 revision。
`get_test(afterRevision, waitSeconds)` 支持有界 long polling；snapshot 同时提供通用 progress 外壳、
当前 trial 倒计时/预计剩余时间和方法专属搜索区间、已完成 trial。无 assertions 的成功测量保持
`NO_ASSERTION`；state、validity、verdict 是三个独立维度。

#### 4.2.3 RFC2544 suite

RFC2544 的各项测试是独立 TestMethod，外层 suite 负责依赖与编排。首批依次实现 Throughput、
Frame Loss、Latency、Back-to-back；Frame Loss/Latency 可以显式依赖本 suite 的 Throughput 结果。
方向模式不得写成含糊的 `both`：

- `unidirectional`：一条 Flow；
- `bidirectional-simultaneous`：两条显式 Flow 同时发送、分别按 per-egress 加载和统计；
- `unidirectional-each`：两个方向顺序形成两组结果。

RFC2544 不推导 reverse packet。每个子测试有独立状态、有效性、结果和 Artifact，suite 可按策略
stop/continue。只有显式 Assertions 才产生 PASS/FAIL；方法内部的零丢包搜索规则不是 DUT 验收门槛。

#### 4.2.4 PCAP 与 storm 的演进接口

PCAP 先发布到 Agent 命名目录，例如 `regression/http-login@3`，底层以 SHA-256 内容寻址。Plan
可以接受未带 revision 的名字，但会立刻固定 revision 和 digest；不得引用调用者本地路径。
`pcap analyze` 给出协议、端点、时长、安全摘要和推荐模式，但 Plan 必须显式选择 stateless 或
stateful，禁止静默切换。

Stateless replay 默认将抓包端点映射到 LabPath 角色并修复校验和；`preserve` 必须显式选择且全部
原地址/VLAN 通过安全策略。默认 timing 为 capture/1x；fixed-rate 与 top-speed 是互斥显式模式。
Stateful 模式从 PCAP 提取 ASTF 会话模板，保留应用 payload 顺序并按 CPS、duration、最大活动
连接数运行。调用者可以选择单个 Reconstructible Session，或选择 `all-reconstructible` Capture
Workload；后者按模板 digest 合并相同应用交换，以源会话出现次数分配 CPS 和并发，并通过独立
traffic group 报告每个模板。该选择要求分析完整且唯一模板不超过 256 个，不表示还原原连接时间线，
也不承诺逐包 timestamp、ACK、重传和网络抖动的精确复刻。

UDP 使用独立的 `all-datagram-flows` Datagram Workload，而不伪装成 ASTF connection。Capture
Analysis 按双向端点和 30 秒 idle boundary 切分 unicast IPv4 UDP flow；首个发送方是 Initiator，
并保留 flow 内数据报的方向、payload 与相对间隔。相同 Datagram Template 以 occurrence count
合并，Plan 的 FPS 表示 flow instance/s，并冻结派生 PPS 与 L1 bit rate。STL 为每个模板数据报建立
连续 stream，在两个物理方向分别发送并用独立 FlowStats 汇总方向和模板结果。广播、多播、截断
分析、超过 4,096 个 flow、256 个模板或 512 个模板数据报均 fail closed。它不模拟 UDP 连接状态，
也不恢复 capture-wide flow arrival timeline、原 initiator 地址/临时端口或网络抖动。

ARP、DHCP、DNS storm 底层复用 TrafficProfile 与同一 Job lifecycle，但通过
`traffic storm`/`list_storm_types` 提供一等意图入口和更严格的 broadcast、rate、duration 约束。

DNS 首版使用 `PacketStorm/protocol=dns`，只接受 A/AAAA、IN class、递归期望、DNS name、client/
server role、源 UDP port 范围、PPS 和 duration。Plan 规范化 name，冻结完整 question 和端点，
并从 DNS wire length 派生 frame size 与 L1 bit rate。STL 对源 port 和 16-bit transaction ID 做
有界循环，修复 IPv4/UDP checksum，并用硬件 FlowStats 报告 Query Delivery Observation。TRex
对端收到 query 不是 DNS response；没有独立 Response Observation 时必须报告
`responseObservation=unavailable` 和 `NO_ASSERTION`，不得生成 resolver 成功率或响应时延结论。

DHCP 首版使用 `PacketStorm/protocol=dhcp`，只生成 DHCPDISCOVER：Ethernet broadcast、
IPv4 `0.0.0.0 -> 255.255.255.255`、UDP `68 -> 67`、BOOTREQUEST、broadcast reply flag 和
DHCP message-type option。调用者只选择 client/server role、连续 client identity count、PPS 和
duration；Plan 从 client role MAC 派生有界 MAC pool。STL 用同一 VM 值同步 Ethernet source 与
BOOTP `chaddr`，并独立循环 32-bit transaction ID。规划必须同时看到 isolated LabPath、明确的
Layer-2 Broadcast Domain 和 SafetyPolicy `allowBroadcastStorms`；MAC cardinality、前缀、PPS、
派生 L1 bit rate 和 duration 在 Plan 与 Job 两层校验。当前只形成 Discover Delivery Observation，
没有 Offer Observation 时返回 `NO_ASSERTION`，不得声称 offer、lease 或 DHCP 服务性能。

### 4.3 幂等和顺序不变量

- `submit` 要求 `Idempotency-Key`。幂等身份为 `(authenticated_principal, key)`。
- Agent 对输入做 canonical JSON 编码并计算 `spec_digest`。
- 同一身份、同一 key、同一摘要在保留期内返回原 `job_id`；同一 key 配不同摘要返回 `IDEMPOTENCY_CONFLICT`。
- `submit` 只有在 Job、规范化输入、摘要和第一条事件同一事务提交后才成功。
- Job 接受后，其 submitted spec 不可修改；策略解析产生独立的 `resolved_spec`。
- `SubmitJob.retryOf` 可选；它必须引用一个终态 Job，且新旧 `spec_digest` 完全相同。不同 spec 是新测试，不是 retry。
- 每个 Job 的 revision 从 1 开始严格递增；一次状态事务只产生一个新 revision。
- 终态、规范结果和已有 Artifact 不可修改。补充报告必须创建新 Artifact 和追加审计事件。
- `cancel` 要求独立 `cancelRequestId`；相同 ID 重试返回当前快照。
- 首个有效取消意图一旦提交，Job 不得再进入 `SUCCEEDED`；已处于终态时 cancel 返回原终态。

### 4.4 性能特征

- `submit` 只做有界的 envelope、schema、版本、大小和初步策略校验，不等待端口或 TRex。
- v1 单个 Job 文档上限 256 KiB；未知字段一律拒绝。
- snapshot 上限 256 KiB；高频统计写入 Artifact，不通过 SSE 广播。
- `cancel` 只等待取消意图持久化；真正停流异步完成。
- 一个 Job 最多允许 8 个并发观察者；慢消费者断开后使用 revision 续接。
- Job 和事件默认保留 30 天；Artifact 默认保留 90 天。Milestone 1 只记录 `retainUntil` 并提供可测试的清理函数，不启动自动清理 worker；终态结果在保留期内不可变。

## 5. 公共类型

### 5.1 SubmitJob

```yaml
idempotencyKey: "ci-20260806-1842"
retryOf: null
document:
  apiVersion: trex.example.io/v1
  kind: StatelessTraffic | Rfc2544Throughput
  metadata:
    name: optional-human-name
    labels: {}
  spec: {}
```

HTTP adapter 使用 `Idempotency-Key` header；body 不重复该字段，`retryOf` 位于 body envelope。Python in-process adapter 使用上面的逻辑类型。

规范化规则：UTF-8、对象 key 词典序、整数保持整数、duration 转为整数毫秒、MAC/IP 转为规范字符串、拒绝重复 YAML key、NaN、Infinity、YAML tag 和隐式时间类型。

### 5.2 JobSnapshot

```yaml
jobId: job_01J...
revision: 12
state: RUNNING
kind: Rfc2544Throughput
submittedSpecDigest: sha256:...
resolvedSpecDigest: sha256:...
submittedAt: 2026-08-06T10:00:00Z
startedAt: 2026-08-06T10:00:03Z
finishedAt: null
phase:
  name: search
  frameSize: 64
  trial: 4
progress:
  completed: 3
  total: 21
cancelRequested: false
result: null
problem: null
```

所有时间使用 UTC RFC3339，内部存储微秒精度。`progress.total` 无法预先确定时可为 `null`，客户端不得根据百分比推导 deadline。

### 5.3 JobResult

```yaml
verdict: PASS | FAIL | INVALID | NO_ASSERTION
methodology: rfc2544-throughput-strict/v1
summary: {}
artifacts:
  - digest: sha256:...
    mediaType: application/json
    size: 12345
    name: result.json
provenance:
  submittedSpecDigest: sha256:...
  resolvedSpecDigest: sha256:...
  policyVersion: lab-policy-3
  agentVersion: 1.0.0
  trexVersion: v3.xx
  trexClientVersion: v3.xx
  environmentFingerprint: sha256:...
warnings: []
```

语义：

- `PASS`：测试流程成功且所有显式 assertions 满足。
- `FAIL`：测试流程成功且至少一个显式 assertion 不满足。
- `NO_ASSERTION`：测试流程成功，但 Job 未定义合格阈值。
- `INVALID`：流程完成，但一个或多个必要样本不可信，无法形成 DUT 结论。
- `FAILED` 是 Job 状态，不是 verdict；它表示流程未能完成。

### 5.4 Problem

```yaml
code: TARGET_RATE_UNMET
category: INPUT | POLICY | RESOURCE | ENGINE | OBSERVATION | INTERNAL
retryable: false
message: "actual transmit rate did not reach the resolved target"
details: {}
```

外部错误使用 `application/problem+json`，并携带稳定 `code`。稳定错误集合：

| Code | 阶段 | 含义 |
|---|---|---|
| `INVALID_DOCUMENT` | 同步 | YAML/JSON、schema 或规范化失败 |
| `UNSUPPORTED_VERSION` | 同步 | 不支持 apiVersion/kind |
| `UNSAFE_REQUEST` | 同步/异步 | 违反安全策略 |
| `IDEMPOTENCY_CONFLICT` | 同步 | key 已绑定其他输入 |
| `UNAUTHENTICATED` | 同步 | token 缺失或无效 |
| `PERMISSION_DENIED` | 同步 | 角色不允许该操作 |
| `NOT_FOUND` | 同步 | Job 或 Artifact 不存在 |
| `EVENT_CURSOR_EXPIRED` | 同步 | SSE 游标超出保留窗口 |
| `PORT_WAIT_TIMEOUT` | 异步 | 未在期限内取得全部端口 |
| `JOB_TIMEOUT` | 异步 | Job 超过 resolved `jobTimeout` |
| `CAPABILITY_MISMATCH` | 异步 | TRex/NIC 不支持 resolved spec |
| `TREX_UNAVAILABLE` | 异步 | 远程 TRex 不可达 |
| `LINK_DOWN` | 异步 | 必要链路未就绪 |
| `LEASE_LOST` | 异步 | 端口所有权不能证明 |
| `TARGET_RATE_UNMET` | 结果 | 生成器未达到目标，样本 INVALID |
| `RECOVERY_ABORTED` | 异步 | Agent 重启后 fail-closed 终止 |
| `INTERNAL` | 异步 | 未分类实现错误 |

## 6. Job 文档

### 6.1 公共 envelope

```yaml
apiVersion: trex.example.io/v1
kind: StatelessTraffic
metadata:
  name: ipv4-baseline
  labels:
    suite: nightly
spec:
  safety:
    isolatedLab: true
  ports:
    tx: lab-west
    rx: lab-east
    direction: unidirectional
  limits:
    portWaitTimeout: 5m
    jobTimeout: 10m
  # kind-specific fields follow
```

共同不变量：

- `isolatedLab` 必须显式为 `true`，默认缺失不是 true。
- Job 只能引用 Agent 配置中的逻辑端口。
- v1 只支持一对端口；bidirectional 使用同一对端口双向发送。
- `tx` 与 `rx` 必须不同，且必须属于同一受控 TRex Server。
- `jobTimeout` 必须存在于策略允许范围；用户省略时由策略提供有限值并写入 resolved spec。
- direction 为 `bidirectional` 时，配置 rate 表示每个方向的 offered rate；结果同时报告各方向和总量。

### 6.2 StatelessTraffic

示例：

```yaml
apiVersion: trex.example.io/v1
kind: StatelessTraffic
metadata:
  name: ipv4-udp-baseline
spec:
  safety:
    isolatedLab: true
  ports:
    tx: lab-west
    rx: lab-east
    direction: unidirectional
  packet:
    frameSize: 128
    ethernet:
      src: {start: "00:00:00:00:00:01", end: "00:00:00:00:00:fe", mode: increment}
      dst: "00:00:00:00:00:02"
    ipv4:
      src: {start: "198.18.0.1", end: "198.18.0.254", mode: increment}
      dst: "198.19.0.1"
      ttl: 64
    udp:
      srcPort: {start: 1024, end: 65535, mode: increment}
      dstPort: 53
  rate:
    unit: percent_l1
    value: 10
  duration: 30s
  assertions:
    maxLossPercent: 0
```

v1 支持：

- Ethernet II，单层 802.1Q VLAN；
- 裸二层 payload、IPv4、IPv6；
- IPv4/IPv6 上的 UDP、TCP、ICMP/ICMPv6 固定头；
- MAC、IP、端口的 fixed、increment、decrement 和确定性 random 范围；
- 固定帧长；
- `percent_l1`、`bps_l1`、`bps_l2`、`pps`；
- continuous-with-duration 和 fixed-burst 两种发送方式。

不支持：分片生成、任意 header stack、用户表达式、Python 回调和无限时长。字段组合由 schema 封闭定义；新增协议字段需要新 schema 版本或向后兼容的可选字段。

MAC 与 IP 分别受 SafetyPolicy 控制。普通测试只允许 unicast MAC；固定值或 variation 的
完整范围必须落在同一个 `allowedMacPrefixes` 项内。只有实验室显式设置
`allowArbitraryUnicastMac: true` 才可绕过前缀限制。TRex Field Engine 的当前实现保留
MAC 高 16 位并改写低 32 位，因此一个 MAC variation 必须位于同一 16-bit prefix；双向
流量将 source/destination variation 连同字段位置一起交换。

`frameSize` 表示线上 Ethernet frame 长度并包含 4 字节 FCS。TRex packet builder 不提供 FCS，因此编译长度为 `frameSize - 4`。结果同时记录 wire frame size 与 TRex packet size。

为避免交换机 unknown-unicast 抑制影响正式统计，所有 `StatelessTraffic` 与 RFC2544 trial 在清统计前都从
RX 端反向发送有界学习帧，再移除学习流并安装正式 marker 流。学习帧不进入结果；普通裸 Ethernet
在硬件不能提供 FlowStats 时只能使用独占端口计数并标注 `exclusive-port-fallback`，不得作为 strict
RFC2544 的隔离证据。

没有 assertions 时 verdict 为 `NO_ASSERTION`。有 assertions 时全部满足为 `PASS`，否则为 `FAIL`；生成器样本无效优先产生 `INVALID`，不得计算 PASS/FAIL。

### 6.3 Rfc2544Suite 与兼容的 Rfc2544Throughput

新 TestPlan 生成 `Rfc2544Suite`，其 `tests` 是有序、去重的 `throughput`/`frame-loss` 方法列表；
未提供 `--test` 时默认只运行 Throughput。旧 `Rfc2544Throughput` Job kind 继续被 Agent 接受，作为
raw Job 和既有自动化的兼容接口。suite 共用已解析的 packet、方向、端口、帧长与安全上限，但每个
方法分别产生 methodology、validity、verdict 与结果，并聚合在 `summary.tests.<method>` 下。

Strict 示例：

```yaml
apiVersion: trex.example.io/v1
kind: Rfc2544Throughput
metadata:
  name: dut-throughput
spec:
  safety:
    isolatedLab: true
  ports:
    tx: lab-west
    rx: lab-east
    direction: bidirectional
  mode: strict
  packet:
    ethernet:
      src: "00:00:00:00:00:01"
      dst: "00:00:00:00:00:02"
    ipv4:
      src: "198.18.0.1"
      dst: "198.19.0.1"
    udp:
      srcPort: 49152
      dstPort: 7
  limits:
    portWaitTimeout: 10m
    jobTimeout: 8h
  assertion:
    minimumPercentLineRate:
      "64": 70
      "1518": 95
```

Strict 固定规则，调用者不能放宽：

- wire frame sizes：`64, 128, 256, 512, 1024, 1280, 1518`；
- loss tolerance：0 frames；
- rate range：0 到 `min(100% L1, calibration ceiling)`；
- binary search resolution：0.1 percentage point；
- search trial：10 秒；
- final confirmation：每次至少 60 秒，3 次；
- 每轮前执行地址学习/邻居预热；
- 停流后至少 drain 2 秒，或连续两个采样周期计数不再变化，取更长者；
- trial 间至少 rest 5 秒；
- 每个方向分别满足零丢包和生成器有效性。

RFC2544 的 packet 是不含 `frameSize` 的同一份 L2/L3 packet template；每个 trial 只注入
当前标准帧长和搜索速率，再交给统一 packet compiler。因此单 VLAN、IPv4/IPv6、UDP/TCP/
ICMP、payload，以及 MAC/IP/端口 variation 可用于 throughput 测试，不会在 RFC2544 runner
内复制 Field Engine 逻辑。裸 Ethernet 则只用于普通 `StatelessTraffic`：当前 X550 不能为该
格式安装隔离的 hardware FlowStats 规则，普通 Job 在持有独占端口时记录
`exclusive-port-fallback`；RFC2544 必须包含 IPv4 或 IPv6，继续 fail-closed。variation 改变
的是被测流量空间，不改变 strict 的帧长集合、零丢包判据、搜索精度或确认时长。

RFC2544 推荐 Ethernet 帧长为 64、128、256、512、1024、1280、1518，并将 throughput 定义为无丢包的最高速率；搜索可用短 trial，但最终值应以至少 60 秒的完整 trial 确认。参见 [RFC 2544 §9.1、§24、§26.1](https://www.rfc-editor.org/rfc/rfc2544.html)。

Frame Loss 对每个帧长从允许的最高 L1 offered load 开始，按最多 10 percentage points 递减；每个
点记录 `input_count`、`output_count`、loss frames 与
`((input_count-output_count)*100)/input_count`，直到连续两个有效 trial 零丢包。strict 每点 60 秒；
fast 每点 3 秒并使用 `engineering-frame-loss-curve/v1`。安全策略 ceiling 小于 100% 时，strict
结果标记为 `rfc2544-frame-loss-partial-range`，不得声称覆盖完整输入速率范围。参见
[RFC 2544 §24、§26.3](https://www.rfc-editor.org/rfc/rfc2544.html)。

Fast 固定默认：

- methodology：`engineering-throughput-estimate/v1`；
- frame sizes：`64, 512, 1518`，调用者可选择非空子集；
- search trial：3 秒；
- confirmation：10 秒，1 次；
- loss tolerance：仍为 0 frames；
- resolution：0.5 percentage point；
- 报告和 CLI 必须显示“非 RFC2544 Throughput 结果”。

#### 搜索算法

对每个 frame size 独立执行：

1. 以校准 ceiling 为 high，0 为 low；记录当前最高可信零丢包 trial。
2. 运行 candidate `(low + high) / 2`，对齐到 resolution。
3. trial INVALID 时，以相同 candidate 重试一次；再次 INVALID 则该 frame size INVALID，停止该 frame size 搜索。
4. valid 且零丢包时令 low = candidate；valid 且有丢包时令 high = candidate。
5. `high - low <= resolution` 后，对 low 运行 confirmation。
6. 任一 confirmation 有丢包时，将该 candidate 设为 high，并从上一个可信 lower candidate 继续搜索。
7. 所有 confirmation 零丢包后，low 为该 frame size throughput。
8. 如果无法取得任何有效零丢包点，报告 0 或 INVALID：有效 trial 在最低 resolution 仍丢包为 0；生成器/环境不可信为 INVALID。

结果必须提供 fps、percent L1、bps L1、bps L2、理论最大 fps 和每轮原始数据。若 assertion 只覆盖部分帧长，只对指定帧长判定，但仍报告全部 strict 帧长。

## 7. Trial 有效性

每个 trial 先形成 `TrialValidity`，再计算 DUT loss：

```yaml
valid: true
checks:
  ownershipHeld: true
  linksUp: true
  targetRateReached: true
  trexErrorsAbsent: true
  countersMonotonic: true
  receivePathHealthy: true
```

有效条件：

- trial 全程租约 generation 未变化，TRex port owner 与 Agent session 匹配；
- 必要链路全程 up；短暂 flap 也使 trial INVALID；
- steady-state 实际 TX rate 达到 resolved target 的 99.5%，且没有 TRex underrun/queue-full 等错误；
- TX/RX 计数器单调，清零基线成功，无 wrap/reset；
- TRex RX core、NIC 或 driver 没有显示接收测量不可信的错误；
- 停流并 drain 后取得最终稳定计数。

`actual_tx < target * 99.5%` 产生 `TARGET_RATE_UNMET`，只能判 INVALID，不能当作 DUT 零丢包或 DUT 失败。对 bidirectional Job，每个方向独立校验；任一方向无效使整个 trial 无效。

丢包按方向计算：

```text
loss_frames = max(0, tx_test_frames - rx_matching_test_frames)
loss_percent = loss_frames * 100 / tx_test_frames
```

非测试帧不得计入 RX。v1 使用 TRex flow statistics 区分测试流；若能力探测表明无法可靠隔离测试帧，拒绝运行该 spec。

## 8. Job 生命周期、租约和取消

```text
ACCEPTED
  → VALIDATING
  → WAITING_FOR_PORTS
  → PREPARING
  → WARMING_UP
  → RUNNING
  → DRAINING
  → COLLECTING
  → SUCCEEDED

任意非终态 → FAILED
任意非终态收到取消 → DRAINING → COLLECTING → CANCELLED
```

规则：

- 同步 schema 校验后创建 `ACCEPTED`；远程能力、链路、校准和端口检查在持久化 Job 中执行。
- 一个 Job 所需端口在单个 SQLite 事务中全部租用，不能逐个持有等待。
- 冲突 Job 按 `accepted_at, job_id` FIFO；不抢占正在运行的 Job。
- 租约从 `PREPARING` 持有至流量停止、drain、统计采集和端口清理均完成。
- Agent 内部异步任务的每次状态写入和 TRex 操作都校验 fencing generation，旧任务不能操作重新分配的端口。
- `portWaitTimeout` 到期产生 `FAILED/PORT_WAIT_TIMEOUT`。
- cancel 先持久化意图，再触发 graceful stop；5 秒未确认停止则执行 force stop/reset。
- 无法确认端口停止时 Job 可进入 `CANCELLED` 或 `FAILED`，但端口必须进入 `QUARANTINED`，不能重新分配。

## 9. 远程 TRex seam

TRex 是 remote-but-owned dependency。内部 Interface 应表达运行生命周期，而不是复制官方 client 方法：

```python
class TrafficEngine(Protocol):
    async def probe(self) -> EngineCapabilities: ...
    async def prepare(self, intent: ExecutionIntent, fence: FenceToken) -> PreparedRun: ...
    async def start(self, run: PreparedRun) -> RunHandle: ...
    async def sample(self, handle: RunHandle) -> RawSample: ...
    async def stop(self, handle: RunHandle, force: bool = False) -> StopResult: ...
    async def reconcile(self, marker: ExecutionMarker) -> ReconcileResult: ...
```

Adapters：

- `RemoteTrexStlAdapter`：官方 Python STL client；
- `DeterministicTrexAdapter`：内存状态、虚拟时间和故障脚本。

`ExecutionIntent` 只包含领域概念：逻辑端口、packet plan、rate、duration、flow statistics 和采样要求。它不得包含 `STLStream` 等官方 client 类型。

Agent 配置负责映射：

```yaml
trexServers:
  lab-trex-01:
    host: 10.0.0.10
    syncPort: 4501
    asyncPort: 4500
    ports:
      lab-west: 0
      lab-east: 1
    ownershipNamespace: trex-cli-prod
```

Job 不得覆盖该配置。启动时 adapter 必须使用有限 duration；最长单次 STL run 由站点策略限制，v1 默认不超过 120 秒。更长 Job 由多个有界 trial 构成。

官方 STL client 提供连接、端口 acquire、流量启动和统计读取能力，参见 [TRex Stateless Python Interface](https://trex-tgn.cisco.com/trex/doc/cp_stl_docs/) 与 [STLClient reference](https://trex-tgn.cisco.com/trex/doc/cp_stl_docs/api/client_code.html)。

## 10. 持久化与 Artifact

v1 使用单 Agent SQLite/WAL。逻辑记录：

| Record | 作用 |
|---|---|
| `jobs` | 当前 snapshot、spec 摘要、终态和 revision |
| `job_events` | append-only 状态、问题和审计事件 |
| `idempotency_keys` | principal/key 到 job/spec digest 的绑定 |
| `port_leases` | 逻辑端口、job、generation、状态 |
| `execution_markers` | 启动前后持久化的 run/trial/fence 标记 |
| `artifacts` | digest、media type、大小、路径和保留期 |

每次可观察状态改变在一个事务中同时更新 `jobs`、插入 `job_events` 并递增 revision。执行顺序遵循 write-ahead intent：

1. 持久化准备执行的 marker；
2. 调用远程 TRex；
3. 持久化已观察到的远程结果；
4. 发布新 snapshot。

Artifact 使用 SHA-256 内容寻址，本地路径由 digest 派生，不使用用户文件名。写入临时文件、同步并原子 rename 后才登记。规范 Result Bundle：

```text
manifest.json
submitted-spec.json
resolved-spec.json
result.json
trials.ndjson
raw-stats.ndjson.zst
environment.json
report.md
checksums.sha256
```

JSON 是规范结果；Markdown 只从已完成的 `result.json` 确定性渲染，不反向参与 verdict。

## 11. 重启与网络分区

Agent 启动恢复：

1. readiness 保持 false，停止接收新 submit。
2. 读取非终态 Job、租约和 execution markers。
3. 连接相关 TRex Server，核对 session、port owner、active traffic 和 link。
4. `ACCEPTED/VALIDATING/WAITING_FOR_PORTS` Job 恢复排队。
5. 已进入 `PREPARING` 或之后的 Job不透明续跑；等待已设置的有限 duration 到期，并尝试 stop/reset。
6. 保存可取得的部分统计，Job 进入 `FAILED/RECOVERY_ABORTED`。
7. 仅在确认 idle、owner 合法并完成 reset 后释放租约；否则隔离端口。
8. reconciliation 完成后 readiness 才为 true。

运行中与 TRex 断连：

- 不假定 stop 已生效；等待该 run 的远程硬 duration 加安全余量；
- 重连后执行 reconcile 和 stop/reset；
- 当前 trial 与 Job 失败，不自动重试；
- 端口无法确认空闲则隔离并告警。

这种 fail-closed 策略牺牲自动完成率，以换取结果可信性和防止意外持续打流。

## 12. 安全与访问控制

- Agent 只监听专用管理网地址，不监听数据面地址。
- 仅在可信隔离网或 loopback reverse-proxy upstream 使用明文 HTTP；Bearer Token 会明文承载，因此这不是加密链路。
- 原生 TLS 可配置 server certificate/key，并可选以 client CA 强制 mTLS；反向代理模式必须防火墙隔离明文 upstream。
- 启动日志、`/readyz` 与 `/version` 报告 Agent 自身 hop 的 `transportSecurity`，不得把代理外层 TLS 误报为原生 TLS。
- Bearer Token 解析后仅以内存 SHA-256 摘要参与常量时间比较；`0600` 文件凭据支持完整集合原子重载、轮换和吊销。
- `operator`：submit、observe、cancel、artifact read；`read-only`：observe、artifact read。
- 所有鉴权成功和失败、提交、取消与状态转换均记录审计元数据，但不记录 token、文档或 packet payload。
- Agent 配置标记管理口和允许测试的地址范围；Job 不能覆盖。
- `SafetyPolicy` 设置最大 rate、duration、排队时间和并发数；解析后的默认值及 policy version 写入结果。
- strict calibration 默认必须覆盖目标 ceiling；实验室可显式设置 `maxCalibrationGrowthFactor > 1`
  允许渐进升速。目标 ceiling 不得超过七种标准帧长中任一有效校准 ceiling 乘以该因子；默认值 1
  保持完全覆盖语义，缺失、过期或非 marker-isolated FlowStats 校准始终拒绝。
- calibration environment key 包含逻辑端口映射后的协商速率；链路从 10G 改为 1G 等物理变化必须
  形成新环境并重新校准。端口可存在不属于测试 marker 的背景 RX 帧；marker 零丢包时记录为
  `unclassifiedRxFrames`，但 marker 显示丢包而端口总计数显示已收齐时，证据不一致且 trial INVALID。
- 默认拒绝 multicast/broadcast、管理网目的地址和超出白名单的源/目的地址；需要站点策略显式允许。
- Agent 与 TRex 管理端口之间使用隔离网络和防火墙，禁止普通用户直接控制同一 TRex ports。

## 13. 可观测性

结构化日志必须包含 `job_id`、`revision`、`state`、`trex_server`、逻辑端口和 stable problem code；不得包含 token 或完整敏感 DUT 配置。

最小指标：

- Job 数：按 kind/state/verdict；
- submit、排队、运行和取消时长；
- 当前端口租约与隔离端口数；
- TRex 连接状态、重连次数和错误数；
- valid/invalid trial 数及 INVALID 原因；
- SSE 连接数和 cursor expired 数；
- SQLite transaction latency、WAL size；
- Artifact 字节数和写入失败数。

readiness 为 false 的条件：SQLite 不可写、Artifact 库不可写或启动 reconciliation 未完成。单个 TRex 不可达不使整个 Agent unready，但关联逻辑端口标记 unavailable，相关 Job 排队或失败。

## 14. 测试策略

### 14.1 Interface tests

- 相同幂等键和输入返回同一 Job；不同输入冲突。
- 并发 submit 只创建一条 Job。
- observe 首帧是完整 snapshot；revision 单调；断线可续接。
- cancel 与自然完成竞态满足“先提交者决定终态”。
- 终态和 Result Artifact 不可修改。
- operator/read-only 权限和 token 轮换正确。

### 14.2 状态、租约和恢复

- 两个 Job 竞争相同端口时 FIFO 且无部分租约。
- 不冲突端口可并行；同一端口永不出现两个有效 generation。
- stop 超时导致 force stop；仍不可确认时端口隔离。
- 在每个状态点强制终止 Agent，验证 SQLite 恢复、revision、事件和 fail-closed 行为。
- TRex 断连、端口 owner 改变、link flap 和 counter reset 均产生稳定结果。

### 14.3 StatelessTraffic

- 每个支持的 header 组合和字段范围编译成功。
- 未支持 header、非法范围、超短 frame 和白名单外地址拒绝。
- FCS 换算、L1/L2/PPS rate 计算和 bidirectional 语义正确。
- 无 assertion、通过、失败和 INVALID 的优先级正确。

### 14.4 RFC2544 engine

- 对单调 DUT 模型，二分搜索在 resolution 内收敛。
- strict 固定七个 frame sizes、零丢包、60 秒确认和三次重复。
- confirmation 丢包后重新收窄上界。
- invalid trial 只重试一次，不能被当成零丢包。
- 最低速率有效且丢包报告 0；环境无效报告 INVALID。
- fast 使用独立 methodology，不能显示 RFC2544 Throughput。
- assertion 只影响 verdict，不改变测量数据。
- Frame Loss 从 ceiling 按不超过 10% 的粒度递减，连续两个零丢包 trial 后停止。
- Frame Loss 无效 trial 只重试一次；每点报告 offered load、帧计数和 loss percentage。
- suite 按声明顺序运行方法，并在 progress 与结果中保留方法边界。

### 14.5 Adapter 与真实环境

- `TrafficEngine` contract suite 同时运行于 deterministic 和 remote STL adapters。
- 真实 TRex 两端口直连校准覆盖 strict 全部帧长、目标线速和零丢包。
- 模拟 DUT 覆盖确定丢包阈值、双向非对称丢包和流量中断。
- 控制网中断测试证明所有 run 在硬 duration 后终止，恢复前端口不会重分配。

## 15. 版本和演进

- `apiVersion: trex.example.io/v1` 在 v1 生命周期内保持语义兼容；已有字段含义不得改变。
- 新增可选字段必须有安全默认值并写入 resolved spec；删除字段或改变默认语义需要 `v2`。
- 未知字段拒绝，防止拼写错误被静默忽略。
- Agent 至少继续接受最近一个已发布主版本；不支持版本返回明确错误。
- SQLite schema 使用单调 migration version；升级前备份数据库，migration 失败时 Agent 保持 unready，不运行流量。
- Artifact manifest 自带版本，与 Job spec 版本独立演进。

后续能力的预定 kind：

```text
PcapReplay          # stateless 原包重放或 stateful 会话重建
PacketStorm         # DNS/DHCP/ARP 原始报文压力
ClientEmulation     # EMU 客户端状态机
Rfc2544Latency
Rfc9004BackToBack
```

新增 kind 不增加 `TestJobs` 方法。只有当生产与测试至少存在两个实际 Adapter 时才增加新的内部 seam；不得为假想实现建立透传 Module。

## 16. 实施顺序与验收门槛

阶段边界：Milestone 2、3 和 4 构成本阶段一，完成声明式 L2/L3 打流、进阶 Throughput 与
Frame Loss suite。`PcapReplay` 放在阶段二；RFC2544 Latency、Back-to-back 等继续作为独立
TestMethod 演进，不塞入 Throughput 的 mode 或 packet 字段。

### Milestone 1：可信 Job 框架

- HTTP/SSE、Bearer Token、SQLite/WAL、Job 状态机；
- 幂等、端口租约、取消、Artifact、启动恢复；
- deterministic adapter 和完整 Interface tests。

验收：无 TRex 时可确定性验证所有生命周期、并发和崩溃场景。

### Milestone 2：远程 STL 与 StatelessTraffic

- `RemoteTrexStlAdapter`、能力探测、逻辑端口映射；
- 声明式 packet/rate 编译、统计和 validity；
- 真实 TRex 直连校准。

验收：所有支持帧格式可重复运行；断连不会导致无限打流；无效生成器样本不会形成 DUT verdict。

### Milestone 3：RFC2544 Throughput

- strict/fast 引擎、二分搜索、确认和报告；
- 七种标准帧长、双向测试、assertions；
- JSON/Markdown Result Bundle。

验收：确定性模型的结果落在指定 resolution 内；真实直连环境达到校准 ceiling 且零丢包；strict 报告包含完整方法学与原始证据。

### Milestone 4：RFC2544 suite 与 Frame Loss

- `Rfc2544Suite` 有序方法编排，并兼容已有 Throughput Job；
- Frame Loss strict/fast 曲线、连续两次零丢包停止条件和逐点证据；
- suite 级 progress、JSON 结果、Markdown 与 NDJSON Artifact。

验收：确定性与 remote adapter contract 测试覆盖完整 suite；fast 可用于实验室冒烟；只有从 100%
线速开始的 strict 结果才标为完整 Frame Loss 方法范围。

## 17. 规范参考

- [Cisco TRex repository](https://github.com/cisco-system-traffic-generator/trex-core)
- [TRex Stateless documentation](https://trex-tgn.cisco.com/trex/doc/trex_stateless.html)
- [TRex Stateless Python Interface](https://trex-tgn.cisco.com/trex/doc/cp_stl_docs/)
- [RFC 2544 — Benchmarking Methodology for Network Interconnect Devices](https://www.rfc-editor.org/rfc/rfc2544.html)
- [RFC 6815 — Applicability Statement for RFC 2544](https://www.rfc-editor.org/rfc/rfc6815.html)
- [RFC 9004 — Updates for the Back-to-Back Frame Benchmark](https://www.rfc-editor.org/rfc/rfc9004.html)
