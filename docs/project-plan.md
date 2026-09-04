# trex-cli 项目计划

状态：M10.6 软件发布门禁完成，版本定为 1.0.0
更新时间：2026-09-05

本文只记录执行顺序、验收门槛和最终完成定义。系统 Interface、数据模型与设计约束以
[`design.md`](../design.md) 为准；公开的脱敏实验模板及使用边界见
[`testdev/README.md`](../testdev/README.md)；项目目标以 [`goal.md`](../goal.md) 为准。真实环境状态、
访问参数和运行日志只保存在非公开实验室记录中。

## 1. 当前基线

| 能力 | 状态 | 证据入口 |
|---|---|---|
| 持久化 Job、租约、取消、恢复、Artifact | 已实现 | `src/trex_cli/jobs.py`、`storage.py`、Interface tests |
| 声明式 L2/L3 流量、variation、多 Flow | 已实现 | `test_plan.py`、`trex_adapter.py`、`traffic-profiles/` |
| RFC2544 完整四方法 suite | 实现完成，真实发布校准待完成 | `publication.py`、`rfc2544.py`、发布工件 tests |
| 面向 Agent 的稳定 TestControl Interface | M5 核心纵切已实现 | `test_control.py`、HTTP/CLI/MCP adapters |
| PCAP 发布、发现与无状态重放 | M7 已实现并完成真实 TRex 验收 | `pcap_catalog.py`、`pcap_replay.py`、真实 Job 证据 |
| TCP/HTTP 会话提取与 ASTF 状态化重放 | M8/M8.1 已实现并完成真实 TRex 验收 | `session_analysis.py`、`astf_adapter.py`、真实 Job 证据 |
| UDP 全流提取与 STL 双向重放 | M8.2 已实现并完成真实 TRex 验收 | `datagram_analysis.py`、`trex_adapter.py`、真实 Job 证据 |
| DNS/DHCP/ARP storm | DNS、DHCP、ARP 均已实现并完成真实 TRex 验收 | `dns_storm.py`、`dhcp_storm.py`、`arp_storm.py`、`PacketStorm`、真实 Job 证据 |

当前最重要的技术债不是增加更多 CLI 子命令，而是把资源发现、计划、执行和观察收敛到一个深
`TestControl` Module。CLI、未来 MCP 和自动化测试都应穿过同一个 Interface；TRex、YAML、SSE、
FlowStats、端口租约和 Artifact 继续留在其 Implementation 后面。

## 2. 路线图

### M5：TestControl 与资源目录

目标：让自动化 Agent 不需要拼接 YAML、HTTP 或 TRex 参数即可安全完成一次测试。

- 实现 `search_catalog`、`describe_resource`、`plan_test`、`start_test`、`get_test`、
  `control_test` 六个任务级入口。
- 为 `TrafficProfile`、`LabPath` 和后续 PCAP 建立 `name@revision + digest` 资源目录。
- 将现有 CLI intent 命令改为 TestControl adapter；raw Job 入口仅保留兼容用途。
- 增加 MCP adapter，参数使用封闭 schema；不暴露任意 YAML、Python Profile 或 TRex 对象。
- `get_test` 使用 revision 与有界等待，返回完整快照、阶段、剩余时间和 Artifact 引用。

验收门槛：同一组 Interface contract tests 同时覆盖进程内 adapter、HTTP adapter 和 MCP adapter；
重复 `start_test(planId)` 不会创建第二个 Job；Agent 可仅靠目录发现完成一次 L2/L3 和 RFC2544 测试。

### M6：RFC2544 方法完善

目标：从“工程可用”推进到可重复、可审计的完整实验室基准测试。

- 先消除 strict 路径的 `exclusive-port-fallback`：七种标准帧长都必须取得一致的硬件 FlowStats。
- 在可控限速 DUT 上完成 Throughput 与 Frame Loss 全帧长 strict 回归，并固定交换机配置证据。
- 将 Latency 实现为独立 TestMethod，使用可识别标记与硬件时间统计，报告定义和不确定性。
- 按 RFC 9004 实现 Back-to-back；随后评估 System Recovery 与 Reset 是否进入首个完整 suite。
- 每个方法独立记录 methodology、validity、verdict、progress 和原始 trial Artifact。
- 发布判定 fail closed；DUT/拓扑上下文由 LabPath 声明，具体设备控制留在实验室 fixture。
- 生成 JSON、CSV、NDJSON、Markdown、environment、manifest 与 checksum 离线证据包。

验收门槛：确定性模型覆盖阈值、非对称丢包、无效计数与重试；真实 TRex strict 结果不得使用端口
fallback；完整报告可由 manifest 和 checksum 离线复核。

### M7：PCAP 资源与无状态重放

目标：把 PCAP 当作不可变、可发现的资源，而不是调用者机器上的文件路径。

状态：已完成（2026-08-31）。大文件 fixture 已覆盖发布/分析、rewrite、capture timing normalize、
fixed-rate、模拟执行和真实 TRex 执行；preserve、广播/公共地址及非单调时间戳均按策略 fail closed。
分离部署通过 `pcapRemoteRoot` 声明 TRex server 可见目录，文件同步属于明确的部署前提。

- 实现 `pcap publish/list/describe`，内容以 SHA-256 寻址，名称使用 `name@revision`。
- 发布时解析链路类型、协议、端点、VLAN、包数、持续时间和安全风险，拒绝损坏或不支持的文件。
- TestPlan 将 capture 端点显式映射到 LabPath 角色，并支持安全的 MAC/IP/VLAN 重写及校验和修复。
- STL replay 支持 capture timing、倍率和 fixed-rate；所有模式都有包数、速率、时长硬上限。
- 结果区分已发送 capture packets、实际 RX、非测试帧、丢包和 timing 偏差。

验收门槛：再次引用只使用资源名或 digest；Plan 固定 revision；离线 fixture、模拟 adapter 和真实
TRex 均覆盖原地址保留与地址重写路径；任何未通过 SafetyPolicy 的地址都不能发送。

### M8：有状态 PCAP/ASTF

目标：从已发布 PCAP 提取可控的 client/server 会话模板并由 ASTF 执行。

状态：M8 单会话已完成（2026-08-31），M8.1 Capture Workload 已完成（2026-09-01）。Capture
Analysis 提取有界 TCP/HTTP Session Template；Capture Workload 合并相同模板并以源会话出现次数
分配 CPS 与并发。Plan 固定 payload digest、角色、地址/端口池、CPS、并发和 duration；远端 ASTF
通过 traffic group 真实建立、回收并分别统计每个模板。运行中取消会立即打断 Job，所有 ASTF
stop/cleanup 均有硬超时；无法确认清理时保留 execution marker 并隔离端口。

- 明确 client/server 角色映射、连接方向、CPS、并发连接、持续时间和端口池。
- 分析阶段报告可提取会话、无法重建的协议行为以及 capture 与生成流量的语义差异。
- 新增 ASTF adapter，但复用 TestJobs 的租约、取消、恢复、Artifact 和安全策略。
- `all-reconstructible` 只接受完整分析，最多 256 个唯一模板；分析截断或模板超限时 fail closed。
- 不承诺逐包时间、TCP 重传或网络抖动的精确复制；这些差异必须进入 Plan 和报告。

验收门槛：HTTP/TCP fixture 可重复建立并回收会话；取消或控制链路中断后不会无限发流；端口和
地址池耗尽产生稳定 Problem code；真实环境结果包含连接建立率、失败率和吞吐。

#### M8.2：UDP Datagram Workload

状态：实现和真实 STL smoke 均已完成（2026-09-02）。Capture Analysis 以双向端点和 30 秒
idle boundary 提取全部 unicast IPv4 UDP flow，保留 flow 内方向、payload 与相对间隔；相同模板
按出现次数合并并分配 FPS。Plan 固定 Capture revision/digest、角色、模板、派生 PPS/L1 bit rate
和 duration；STL 在两个端口同时发流并以逐数据报 FlowStats 汇总逐方向、逐模板结果。

- `all-datagram-flows` 只接受完整分析；广播、多播、损坏或超出有界容量的 UDP 不允许部分重放。
- 上限为 4,096 个 flow、每 flow 256 个数据报、256 个唯一模板和 512 个模板数据报。
- FPS 表示 flow instance/s；PPS、L1 bit rate、duration、MAC 和 IPv4 均在 Plan 与 Job 两层校验。
- 该模式不声称 UDP 有连接状态，也不恢复 capture-wide flow arrival timeline 或网络抖动。

验收门槛：离线 contract、模拟引擎和 STL adapter 覆盖多 flow、模板权重、双向发送、逐模板统计
与全部 fail-closed 路径；真实双向小流量 smoke 为零丢包且结束后端口可复用。

### M9：DNS、DHCP、ARP storm

目标：以封闭模板提供有界压力测试，不开放任意 Scapy/Python 执行。

- 建立 `PacketStorm` TestMethod 与 DNS、DHCP、ARP 模板；所有字段使用类型化参数。
- 按 LabPath 明确二层广播域、服务器角色、允许的 MAC/IP 池和 VLAN。
- 强制 pps、持续时间、并发、地址 cardinality 和广播比例上限；默认需要显式 isolated-lab 声明。
- 根据协议能力报告发送、响应、超时、重复和无效响应；只在证据可信时形成 assertion verdict。

验收门槛：每种模板都有合法/越权/超限 contract tests；真实小流量 smoke 不影响管理平面；取消、
超时和 Agent 重启均能证明流量停止。

#### M9.1：DNS Query Storm

状态：实现和真实 STL smoke 均已完成（2026-09-02）。DNS 使用一等 `PacketStorm` 文档和
`dns-storm` TestControl intent，支持 A/AAAA、IN class、RD flag、规范化 DNS name、client/server
角色、源 UDP port 范围、PPS 和 duration。CLI 路径为 `traffic storm dns plan|run`，HTTP/MCP
复用同一封闭 intent。

- 只生成单播 DNS query；不开放任意 payload、Scapy 或 Python profile。
- source port 和 transaction ID 在声明范围内循环，并在 VM 写入后修复 UDP checksum。
- Plan 与 Job 双层限制 isolatedLab、PPS、派生 L1 bit rate、duration、端口 cardinality、MAC/IP。
- 当前证据是 Query Delivery Observation；没有响应观察器，因此明确返回 `NO_ASSERTION`，不形成
  resolver 成功率、响应时延、timeout、duplicate 或 invalid-response 结论。

验收门槛已满足：TestControl、CLI/HTTP/MCP、模拟引擎和 STL adapter contract tests 均覆盖；
真实 100 PPS smoke 使用硬件 FlowStats 零丢包；最终多核验证以仅 4 个 source port 运行成功，
结束后逻辑端口恢复 AVAILABLE。

#### M9.2：DHCP Discover Storm

状态：实现和真实 STL smoke 均已完成（2026-09-04）。DHCP 使用同一个一等 `PacketStorm`
Interface 和 `dhcp-storm` TestControl intent；CLI 路径为 `traffic storm dhcp plan|run`，HTTP/MCP
复用相同封闭 intent。

- 只生成最小 DHCPDISCOVER，不开放任意 DHCP option、payload、Scapy 或 Python profile。
- 以 client role MAC 为起点派生连续 Client Identity Pool，并同步写入 Ethernet source 和 BOOTP
  `chaddr`；32-bit transaction ID 独立循环，VM 变量不按 core 拆分。
- 广播必须同时取得 SafetyPolicy `allowBroadcastStorms`、isolated LabPath 和显式
  `broadcastDomain`；client count、MAC prefix、PPS、派生 L1 bit rate 和 duration 双层校验。
- 当前证据是 Discover Delivery Observation；没有 Offer Observation，因此明确返回
  `NO_ASSERTION`，不形成 offer、lease、timeout、duplicate 或 DHCP server 性能结论。

验收门槛已满足：TestControl、CLI/HTTP/MCP、模拟引擎和 STL adapter contract tests 均覆盖；
真实 4-client、100 PPS、3 秒 smoke 使用硬件 FlowStats 301/301、零丢包，结束后端口恢复
AVAILABLE。

#### M9.3：ARP Request Storm

状态：类型化 Interface、TestControl、CLI/HTTP/MCP、模拟引擎、STL adapter 和真实有限流量 smoke
均已完成（2026-09-04）。

- 只生成固定目标 IPv4 的 64-byte ARP Request，不开放任意 opcode、payload、Scapy 或 Python
  profile。
- 以 sender role 的 MAC/IPv4 为起点派生成对连续的 Sender Identity Pool；Ethernet source、ARP
  sender MAC 和 sender IPv4 由不拆 core 的 VM 变量同步循环。
- 广播必须同时取得 `allowBroadcastStorms`、isolated LabPath 与 `broadcastDomain`；identity count、
  MAC prefix、IPv4 CIDR、PPS、派生 L1 bit rate 和 duration 双层校验。
- X550/TRex v3.08 的硬件 packet-group 明确拒绝 ARP L2 header，因此只以独占发送端口计数形成
  Request Transmission Observation；delivery、reply、resolution、loss 和 latency 均为 unavailable，
  结果保持 `NO_ASSERTION`，不使用接收端聚合计数作推断。

验收门槛已满足：X550/TRex v3.08 探针明确返回 `NIC does not support given L2 header type`；最终
4-sender、100 PPS、3 秒 Job `job_A649C57359E9430995D5DE02F406F7B9` 成功发送 301 帧，发送错误
为零，实际 100.33 PPS，`targetRateReached=true`，九项 Artifact 完整。测试后两端口均恢复
AVAILABLE，链路保持 2.5Gbps UP。

### M10：发布与运维收口

目标：形成可部署、可升级、可由 Agent 长期调用的 1.0 版本。

- 建立 CI：Python 3.12、pytest、Ruff、mypy strict、wheel 构建、schema/示例校验。
- 增加数据库 migration、升级备份、Artifact 保留与清理、结构化日志和运行指标。
- 保持内网 HTTP 部署选项，同时提供可选 TLS/reverse-proxy 指南和 token 轮换流程。
- 固定兼容策略、版本化 schema、发布说明和从 0.x 到 1.0 的迁移测试。
- 对 TestControl/MCP 做真实 Agent 任务评测：发现资源、规划、执行、观察、解释结果和安全拒绝。

验收门槛：干净主机可从 wheel 部署；升级失败时 Agent 保持 unready；恢复、限速、权限和保留策略
有运维手册；目标中的四类测试均能通过 TestControl 完成且无需调用者了解 TRex。

#### M10.1：CI 与可安装 wheel 门禁

状态：完成（2026-09-04）。

- GitHub Actions 固定 Python 3.12，安装 `requirements.lock` 后依次执行资源校验、Ruff、strict
  mypy、pytest、wheel 构建与 Artifact 上传。
- `python -m trex_cli.release_validation` 聚合验证示例配置、全部 Job 示例、旧版 profile、
  TrafficProfile、LabPath、四类 JSON Schema 与 `pyproject/package` 版本一致性；任一资源错误均按
  资源类别或文件名 fail-closed。
- wheel 必须在全新 venv 中仅按自身 metadata 安装运行依赖，并通过 `trex-cli --help`、
  `trex-agent --help` 和发布资源校验。

本地复刻使用 Python 3.14（当前主机仅安装该版本）完成；Python 3.12 路径由 CI 固定执行。每次
发布候选的 wheel SHA-256 由 CI Artifact 计算并随发布记录保存，不把自引用 hash 固化进源码。

#### M10.2：数据库迁移与升级恢复

状态：完成（2026-09-04）。

- `SqliteStore.initialize()` 封装 `PRAGMA user_version`、升级前在线 backup、事务化 v0→v1、必需
  表/列校验和未来版本拒绝；调用方不接触迁移步骤。
- v1 增加 `schema_migrations` 审计记录；成功 readiness 报告 `databaseSchemaVersion`。
- 迁移失败回滚原库并返回 backup path；Agent 保持 `/healthz=200`、`/readyz=503`，所有工作接口
  fail-closed 返回 `AGENT_NOT_READY`。
- 运维指南记录停机、`PRAGMA quick_check`、保留 WAL/SHM incident 副本和 SQLite `.backup` 恢复
  流程。

真实升级演练使用 `testdev/.state/astf-jobs-v3.sqlite3` 的只读副本：v0→v1 后 4 个 Job、37 个
事件和 23 个 Artifact 全部保留，并生成一份 v0 backup；原始 testdev 数据库未修改。

#### M10.3：Artifact 保留与清理

状态：完成（2026-09-04）。

- `artifactRetentionDays` 统一控制默认保留期；同一 digest 被再次引用时只延长、不缩短期限。
- operator-only HTTP/CLI 维护入口默认 dry-run；真正删除必须显式 `--apply`，CLI 还要求确认或
  `--yes`，部分失败以退出码 3 告警。
- 先成功删除文件再有条件移除数据库登记；权限或存储错误保留登记供重试，已缺失文件单独计数且
  不虚报回收空间。
- 孤儿文件默认不删除；只有显式 `--delete-orphans`、满足 `artifactOrphanGracePeriod` 且路径严格
  符合 content-addressed 布局时才可删除。
- 单进程内写入与清理串行化，避免相同 digest 延长保留期时与清理竞争；JSON 报告记录候选、删除、
  缺失、回收字节和逐项失败。

验收门槛已满足：contract tests 覆盖 dry-run、apply、缺失文件、删除失败、digest 复用续期、孤儿
grace/显式删除、operator 权限及 CLI 请求语义；完整操作和定时任务建议见 `docs/operations.md`。

#### M10.4：结构化日志与运行指标

状态：完成（2026-09-04）。

- Agent stderr 统一为单行 JSON；HTTP 日志使用校验后的 `X-Request-ID` 关联，Job 日志记录提交与每次
  持久化状态转换，调度器异常不再静默吞掉。
- `/metrics` 使用 Prometheus text format 并要求 reader/operator 认证；HTTP 使用 route template
  标签，Job/端口使用封闭状态标签，不引入 jobId、digest、principal 或错误文本等高基数字段。
- HTTP latency 使用固定累计桶，不按请求保存样本；process counters 重启归零，Job、端口和 Artifact
  gauges 每次从 SQLite 重建，重启后仍反映持久化现状。
- 指标覆盖 engine availability、Job 当前状态与转换、端口状态、Artifact 数量/字节、清理结果、HTTP
  请求数量和时延；运维指南给出抓取、安全边界和首组告警建议。

验收门槛已满足：formatter、request correlation、认证、route cardinality、counter/histogram/gauge
渲染和配置封闭性均有 contract tests；全量 release gate 验证见对应提交。

#### M10.5：部署安全与兼容策略

状态：完成（2026-09-04）。

- 可选原生 TLS 将 certificate/key 交给单 worker Uvicorn，并支持 client CA 强制 mTLS；反向代理模式
  提供 Nginx TLS/SSE/大文件模板，明文 upstream 明确限定于 loopback 或隔离网。
- Bearer Token 在内存中只保存 SHA-256 digest 并常量时间比较；文件 secret 强制 regular file、
  `0600`、单行非空和唯一值，避免同一 token 跨角色产生歧义。
- operator 可通过 HTTP 或 `trex-cli auth reload` 原子重载固定 credential slots；任一来源失败时完整
  保留旧集合，双 slot 流程支持不中断现有 Job 的验证、切换与吊销。
- `/version` 与 `Trex-Agent-Version` 暴露机器可读兼容信息；兼容策略明确 HTTP、Job、TestControl、
  SQLite、Artifact 与 SemVer 的演进/回滚边界。
- systemd hardening、Nginx、运维手册、兼容策略和 changelog 被纳入发布资源校验及 CI 发布 Artifact。

验收门槛已满足：权限、摘要化、重复 token、atomic reload/rollback、旧 token 吊销、TLS/mTLS wiring、
版本发现、CLI adapter 与部署资源均有自动化验证。`v2alpha1` TestControl/Plan 标识稳定化留给最终
1.0 release candidate，不在本阶段伪装为已稳定接口。

#### M10.6：1.0 稳定接口与发布候选

状态：完成（2026-09-04）。

- Catalog 与不可变 Test Plan 分别固定为 `trex.example.io/catalog/v1` 和
  `trex.example.io/test-plan/v1`；所有源码资源和新输出只使用稳定标识。
- 旧 `trex.example.io/v2alpha1` Catalog 资源及 `trex.example.io/plan/v2alpha1` 持久化 Plan
  保持 1.x 只读兼容；读取不会改写历史文件，相同 planId 不产生伪碰撞。
- package、FastAPI metadata、迁移审计、指标与发布验证统一为 `1.0.0`；`/version` 分别公布稳定
  Catalog、TestPlan 及 legacy-read 能力。
- 发布资源校验强制源码 Catalog 使用稳定标识，并纳入兼容策略、变更日志、运维指南、部署模板和
  Agent 任务评估。
- TestControl 任务矩阵覆盖目录发现、计划、幂等启动、有界观察、取消、安全拒绝以及所有测试类别；
  结论与真实实验室证据边界记录在 `docs/release-evaluation.md`。

软件 1.0 发布条件已经封闭。IEEE 1588 校准与超过 12 小时的完整 strict RFC2544 实验仍是独立的
实验室行动项；在完成前不得把 fast 或未校准延迟结果发布为完整 RFC2544 标准符合性证据。

## 3. 近期两个迭代

### Iteration A：可信 Interface

1. 为当前 TestPlan/Jobs 建立 TestControl facade 和进程内 contract tests。（首个纵切完成）
2. 实现 catalog 的只读发现与 revision/digest 固定。（TrafficProfile/LabPath 完成）
3. 将 `traffic`、`benchmark rfc2544` CLI 改为同一 adapter。（完成；无 token 本地路径兼容保留）
4. 加入最小 MCP adapter，先覆盖 plan/start/get/cancel。（完成）

完成条件：一个外部 Agent 能发现 `ipv4-udp` 与 `cc-switch`，规划并运行 fast smoke，期间只接触
TestControl 类型。

### Iteration B：strict 证据与高级 RFC2544

1. 复现并定位 64B 高速 FlowStats 与端口计数不一致，建立固定诊断 fixture。
2. 在 1500 Mbps 可控瓶颈上运行七帧长 Throughput/Frame Loss strict suite。（吞吐已验证；完整重跑待发布环境）
3. Latency 已实现 120 秒、60 秒后单标记、每场景至少 20 次的 IEEE 1588 路径；真实 X550 时间戳能力与校准仍是发布阻塞项。
4. Back-to-back 的确定性模型、独立二分搜索、范围检查与 remote adapter 已完成。

完成条件：软件实现与 contract tests 已满足；真实 `COMPLETE` 报告仍须取得当前 X550/v3.08 的
IEEE 1588 能力探测和可追溯 RFC 1242 校准，再执行预计超过 12 小时的完整 suite。

## 4. 最终完成定义

项目达到 [`goal.md`](../goal.md) 的最终目标，必须同时满足：

- RFC2544、L2/L3 自定义流量、stateless/stateful PCAP、DNS/DHCP/ARP storm 均由声明式 Plan 表达；
- CLI、MCP 和其他自动化只适配 TestControl Interface，不复制测试语义；
- 所有发流受逻辑端口租约、硬时长、速率/地址策略和 fail-closed 恢复约束；
- 每次执行都有不可变输入、环境信息、方法版本、有效性、结果、原始证据和 checksum；
- 模拟 adapter、真实 TRex 和调用方 contract tests 共同证明 Interface；
- 常见测试无需操作者编写 TRex Profile、Scapy、Python 或直接处理 FlowStats。

## 5. 持续风险

- X550/FDIR 与 FlowStats 在高速小帧下仍可能不一致；在解决前只能声明 fast 工程结果。
- TRex STL 与 ASTF client 的部署方式不同，必须通过 adapter 隐藏，不能泄漏到 TestPlan Interface。
- PCAP 和 storm 会显著扩大地址与广播风险，SafetyPolicy 必须先于功能开放。
- 过早增加 CLI/MCP 方法会形成浅 Module；新能力优先扩展 intent/schema 和内部 TestMethod。
- 真实 DUT 配置若不可版本化，strict 结果只能视为环境相关证据，不能跨设备直接比较。
