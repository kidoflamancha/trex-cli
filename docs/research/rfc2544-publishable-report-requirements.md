# RFC 2544 可发布报告：规范与 TRex v3.08 能力基线

日期：2026-08-30

## 结论

本项目若要生成不带保留词的“四项 RFC 2544 报告”，至少必须覆盖 Throughput、Latency、Frame Loss Rate 和经 RFC 9004 更新后的 Back-to-Back，并保存每次 trial 的原始证据。任何缩短最终 trial、截断丢包扫描范围、只做一次 Back-to-Back 搜索，或没有声明 RFC 1242 延迟定义的结果，都只能标成工程性或部分范围结果。

RFC 2544 是设备基准方法，不是认证制度。报告应表述为“按 RFC 2544/RFC 9004 方法测得”，不应表述为 IETF 或 RFC “认证”。测试必须位于隔离测试环境；RFC 6815 明确要求测试流只能沿预期路径传播、非测试流量不得进入测试环境，并禁止在生产网络上运行这些过载测试。[RFC 6815 §§3–5](https://datatracker.ietf.org/doc/html/rfc6815#section-3)

## 术语：结果中必须保持的含义

- **Throughput**：设备不丢弃任何 offered frame 时可达到的最高速率；单位为 N-octet frame/s 或输入 bit/s。[RFC 1242 §3.17](https://www.rfc-editor.org/rfc/rfc1242.html#section-3.17)
- **Frame Loss Rate**：恒定负载下本应转发但因资源不足而未转发的帧比例；单位为丢弃的 N-octet offered frames 百分比。[RFC 1242 §3.6](https://www.rfc-editor.org/rfc/rfc1242.html#section-3.6)
- **Latency**：store-and-forward 设备为“输入帧最后一位到达输入口”至“输出帧第一位出现在输出口”；bit-forwarding 设备为“输入第一位结束到达”至“输出第一位开始出现”。报告必须选定其中一种定义。[RFC 1242 §3.8](https://www.rfc-editor.org/rfc/rfc1242.html#section-3.8)
- **Back-to-Back Frames**：从空闲状态开始，以介质允许的最小合法间隔发送固定长度帧；结果单位为一次 burst 中的 N-octet frame 数。[RFC 1242 §3.1](https://www.rfc-editor.org/rfc/rfc1242.html#section-3.1)
- **Data-link frame size**：从 preamble 后的第一个 octet 到 FCS 末尾；Ethernet 的报告帧长因此包含 4-octet FCS。[RFC 1242 §3.5](https://www.rfc-editor.org/rfc/rfc1242.html#section-3.5)

## 所有方法共同遵守的试验条件

1. DUT 应按用户文档配置，除方法本身要求外，各测试之间不得修改配置。报告必须记录 DUT 软件版本、完整配置和禁用功能。[RFC 2544 §7](https://www.rfc-editor.org/rfc/rfc2544.html#section-7)
2. 报告必须给出实际 test-frame 格式；Ethernet 推荐帧长为 `64, 128, 256, 512, 1024, 1280, 1518` octets，通常每种条件至少测试五个帧长。[RFC 2544 §§8–9.1](https://www.rfc-editor.org/rfc/rfc2544.html#section-9.1)
3. 接收端应排除非测试帧并验证帧长。若加入序列号，应同时报告丢失、乱序、重复和序列缺口。[RFC 2544 §10](https://www.rfc-editor.org/rfc/rfc2544.html#section-10)
4. 每个 trial 应先完成路由/学习稳定，再执行测试，结束后等待 2 秒接收残余帧，并至少等待 5 秒让 DUT 恢复稳定。[RFC 2544 §23](https://www.rfc-editor.org/rfc/rfc2544.html#section-23)
5. 正式 trial 的测试部分应至少 60 秒；二分搜索可用较短 trial，但最终判定应由完整时长 trial 确认。[RFC 2544 §24](https://www.rfc-editor.org/rfc/rfc2544.html#section-24)
6. 单向/双向、单路径/聚合、协议、流数量、地址分布、介质、链路速率、修饰条件以及理论最大帧率均是结果语境，必须在报告中明确，不能只发布 Mbps 数字。[RFC 2544 §§11–16](https://www.rfc-editor.org/rfc/rfc2544.html#section-11)

RFC 2544 的已验证勘误对实现有直接影响：Throughput 在零丢包时应提高 offered rate、发生丢包时降低 rate；BMWG IPv4 测试地址范围为 `198.18.0.0/15`。[Errata 422](https://www.rfc-editor.org/errata/eid422) [Errata 423](https://www.rfc-editor.org/errata/eid423) Frame Loss Rate 对最大帧率的交叉引用应指向 §20，而非 §18。[Errata 5203](https://www.rfc-editor.org/errata/eid5203)

## 四项方法的最低发布门槛

### Throughput

- 对每个帧长搜索 offered rate；只有 TX test-frame count 与 RX forwarded-frame count 完全相等才是零丢包点。Throughput 是满足这一条件的最高速率。[RFC 2544 §26.1](https://www.rfc-editor.org/rfc/rfc2544.html#section-26.1)
- 搜索过程可短，但最终候选必须按 §24 做至少 60 秒完整确认。
- 报告需按帧长给出理论帧率和实测帧率，并注明协议、stream 格式和介质。若宣传单一数字，必须用 frame/s 表示，并附帧长、该帧长的介质理论上限和协议；完整表仍应提供。
- 发布证据至少包含每个搜索/确认 trial 的目标与实测速率、TX/RX、丢包、持续时间、判定、无效原因及计数器健康状态。

### Latency

- 前置条件是先获得每个列出帧长的 Throughput。[RFC 2544 §26.2](https://www.rfc-editor.org/rfc/rfc2544.html#section-26.2)
- 每次以该帧长的 Throughput 发送至少 120 秒；在 60 秒后标记一帧，记录该帧完整发出时刻 A 和收到时刻 B，结果为 `B-A`。
- 每个条件必须至少重复 20 次，发布值是这些记录值的平均数；还应分别覆盖与数据流相同目的地和新目的网络两种情况。
- 报告必须声明采用 RFC 1242 的 store-and-forward 或 bit-forwarding 定义，并按帧长列出测试速率、介质、stream 类型及平均延迟。为了审计，仍应保存 20 个原始样本而不只保存平均数。

### Frame Loss Rate

- 每点计算 `((input_count - output_count) * 100) / input_count`。[RFC 2544 §26.3](https://www.rfc-editor.org/rfc/rfc2544.html#section-26.3)
- 每个帧长从输入介质理论最大帧率的 100% 开始，再测 90%、80%……，直到出现两个连续零丢包 trial；步长不得粗于理论最大速率的 10%，可以更细。
- §24 的正式时长约束仍适用。安全上限导致未从 100% 开始或未达到终止条件时，报告必须标成 `partial-range`，不能发布为完整 Frame Loss Rate 曲线。
- 图的 X 轴是输入速率占理论速率百分比，Y 轴是丢包百分比，两轴范围都必须覆盖 0–100%；可叠加不同帧长、协议或 stream 类型。

### Back-to-Back（RFC 9004 更新）

- 必须先具备 RFC 2544 零丢包 Throughput 的全部推荐帧长结果，并记录 ingress/egress 链路速率、链路层协议和最小 IFG 下的理论最大帧率。Throughput 与 Back-to-Back 的方向性和流数量必须一致。[RFC 9004 §5](https://www.rfc-editor.org/rfc/rfc9004.html#section-5)
- 禁止 IMIX。只测试 `Measured Throughput < Max Theoretical Frame Rate` 的固定帧长；否则 DUT buffer 无法被该测试填满，应将结果标为不适用/无效，而不是报告一个无限大的 burst。[RFC 9004 §§3, 6.1](https://www.rfc-editor.org/rfc/rfc9004.html#section-6.1)
- 每个 trial 从 idle 开始，以最小 IFG 发送 burst，随后等待 DUT 完成转发，再提供至少 2 秒且不与接收阶段重叠的 buffer depletion 时间；若 burst 或 buffer time 超过 2 秒则必须延长。[RFC 9004 §6.2](https://www.rfc-editor.org/rfc/rfc9004.html#section-6.2)
- burst-send 搜索上限必须可配置到至少 30 秒。靠近上限的结果无效，必须提高上限重跑。
- 必须采用 ETSI TST009 的 Binary Search 或 Binary Search with Loss Verification，并报告全部搜索输入和最小 burst step（frames）。
- 每个选定帧长独立执行 N 次完整搜索，N 必须报告，每个原始最长零丢包 burst 都必须保留。[RFC 9004 §6.3](https://www.rfc-editor.org/rfc/rfc9004.html#section-6.3)
- 每帧长计算 average（benchmark）、minimum、maximum、standard deviation、`implied_buffer_time = average_frames / theoretical_fps` 和 `corrected_buffer_time = implied_buffer_time * (1 - measured_throughput_fps / theoretical_fps)`。[RFC 9004 §§6.4–7](https://www.rfc-editor.org/rfc/rfc9004.html#section-6.4)
- 报告表至少包含帧长、平均 burst frames、min/max/stddev、corrected buffer seconds、N、最小 step；若实现设置最大 burst frames/time，也应报告。

## TRex v3.08 STL：可用能力和不能默认作出的声明

### 可用能力

- `STLFlowStats(pg_id)` 提供按 packet-group 隔离的 TX/RX packet、byte、pps、L1/L2 bps；官方文档说明 per-stream statistics 由硬件完成。这适合 Throughput、Frame Loss Rate 和 Back-to-Back 的独立 test-frame 计数。[TRex Stateless Manual：Per-stream statistics](https://trex-tgn.cisco.com/trex/doc/trex_stateless.html#_tutorial_per_stream_statistics) 本仓库固定的 v3.08 client 也列出这些字段：[trex_stl_client.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_client.py#L1582)
- `STLFlowLatencyStats(pg_id)` 在 basic flow stats 上增加 latency、jitter、丢包估计、重复和乱序统计；v3.08 API 会在 `get_stats()` 中同时返回 `flow_stats` 与 `latency`。[trex_stl_streams.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_streams.py#L342) [trex_stl_client.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_client.py#L1488)
- v3.08 的 latency 结果包含微秒单位的 filtered average、histogram、jitter、last/total max、total min，以及 sequence-based error counters；`dropped`、`dup`、`out_of_order` 是启发式推断，不能替代 Throughput 的硬件 TX/RX 精确相等判定。[trex_stl_client.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_client.py#L1629)
- `wait_on_traffic(rx_delay_ms=...)` 能延后移除 flow/latency RX filters；物理端口默认仅 10 ms。RFC 9004 要求的完整接收与至少 2 秒 depletion 阶段必须由测试编排显式实现，不能把该默认值当成 RFC 9004 等待期。[trex_stl_client.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_client.py#L910)

### Latency 的关键限制

TRex 默认 per-stream latency 是软件机制：它修改 IPv4 ID/IPv6 flow label，并占用 payload 最后 16 bytes 存放 stream ID、sequence number 和发送时间戳；输出精度是微秒。它要求至少 16 bytes payload、每个 latency stream 唯一 pg_id，单个 pg_id 不能同时从两个接口发出，最多 128 个并发 latency streams，且全局 multiplier 不作用于该流。[TRex Stateless Manual：Per-stream latency/jitter/packet errors](https://trex-tgn.cisco.com/trex/doc/trex_stateless.html#_tutorial_per_stream_latency_jitter_packet_errors)

因此，实现可以使用它采集工程性单向 latency/jitter 和序列错误，但不能仅凭 `STLFlowLatencyStats.average` 宣称满足 RFC 1242 的 store-and-forward 或 bit-forwarding 定义：官方 API 没有把默认软件时间戳定义为 RFC 所要求的物理边界位时刻，而且 v3.08 的 `average` 是对采样窗口平均值做低通滤波，不是 RFC 2544 指定的至少 20 个 tagged-frame `B-A` 样本的算术平均。[trex_stl_client.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_client.py#L1657)

TRex 也暴露 `ieee_1588=True`，但官方说明硬件时间戳依赖 NIC/driver、编译时启用 DPDK IEEE 1588，且只支持规定的 packet/port 条件；必须在当前 X550/v3.08 实例做 capability probe 和已知链路校准后，才能将它作为 RFC latency 的时间戳基础。[TRex Stateless Manual：IEEE 1588 latency](https://trex-tgn.cisco.com/trex/doc/trex_stateless.html#_ieee_1588_latency) v3.08 client 中该开关只是传入 stream JSON：[trex_stl_streams.py](../../.trex-client/v3.08/interactive/trex/stl/trex_stl_streams.py#L254)

## 建议的发布 Artifact 合约

一份可审计报告应由不可变 manifest 索引以下内容：

- 规范版本与已应用勘误：RFC 1242、RFC 2544 + Errata 422/423/5203、RFC 6815、RFC 9004；
- 测试时间、实验室拓扑、隔离声明、DUT/交换机/TRex/NIC/driver/firmware/Agent 版本；
- DUT 与限速配置快照、端口/VLAN/链路速率、方向、流数量、MAC/IP、协议、frame bytes/FCS/IFG 口径；
- 各方法的 resolved parameters、搜索算法与输入、trial 时长、等待期、重复次数和安全上限；
- 每个 trial 的目标/实际 L1 rate、TX/RX、loss、顺序错误、TRex/port/xstats、校准标识、有效性及失败原因；
- Throughput 和 Frame Loss 图表数据，Latency 的全部原始 tagged-frame 样本，Back-to-Back 的全部独立搜索结果及派生统计；
- 机器可读 JSON/CSV、面向人的 Markdown/PDF、每个文件的 SHA-256，以及生成器版本。

发布总判定应 fail closed：四项中任一项不满足规范时长、范围、重复次数、计数隔离或测量定义，suite 不得显示 `RFC2544 COMPLETE/PASS`；应准确显示 `PARTIAL`、`INVALID` 或具体缺失项。

## 一手资料

- [RFC 1242 — Benchmarking Terminology](https://www.rfc-editor.org/rfc/rfc1242.html)
- [RFC 2544 — Benchmarking Methodology](https://www.rfc-editor.org/rfc/rfc2544.html)
- [RFC 2544 official errata](https://www.rfc-editor.org/errata_search.php?rfc=2544)
- [RFC 6815 — RFC 2544 Applicability Statement](https://datatracker.ietf.org/doc/html/rfc6815)
- [RFC 9004 — Back-to-Back update](https://www.rfc-editor.org/rfc/rfc9004.html)
- [Cisco TRex Stateless Manual](https://trex-tgn.cisco.com/trex/doc/trex_stateless.html)
- [Cisco TRex Stateless Python API](https://trex-tgn.cisco.com/trex/doc/cp_stl_docs/)
