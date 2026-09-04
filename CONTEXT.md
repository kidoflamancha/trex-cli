# TRex Test Control

本上下文描述用户如何声明、运行和审计一次网络流量或性能测试。

## Language

**Job**:
一次不可变的测试请求及其单次执行。终态 Job 不会重新打开；重新执行会创建一个可追溯到原 Job 的新 Job。
_Avoid_: Task, run, 可重置任务

**Verdict**:
测试证据对用户 assertion 的结论：PASS、FAIL、INVALID 或 NO_ASSERTION。Verdict 与 Job 是否完成执行是两个独立维度。
_Avoid_: Job 状态, execution status

**INVALID**:
测试流程已经完成，但证据不足以形成可信的 DUT 结论。它是 Verdict，不表示 Job 执行失败。
_Avoid_: FAILED, DUT failure

**FAILED**:
Job 未能完成测试流程的终态。它描述执行失败，不描述 DUT 是否满足 assertion。
_Avoid_: INVALID, FAIL verdict

**Logical Port**:
Agent 管理并允许 Job 引用的流量端点身份。它在 Job 中保持稳定，不等同于某个引擎的端口编号。
_Avoid_: TRex port index, interface number

**Port Lease**:
一个 Job 在执行期间对一组 Logical Ports 的排他所有权。Job 要么一次取得全部所需租约，要么一个也不取得。
_Avoid_: Lock, partial reservation

**Resource Revision**:
命名资源的一次不可变发布，使用 `name@revision` 标识并由内容 digest 校验。未带 revision 的名字只在创建 Plan 时解析为当前最高版本，Plan 随后固定 revision 与 digest。
_Avoid_: mutable profile, latest pointer in an existing Plan

**Capture Resource**:
一次已发布且不可变的抓包内容，属于 Resource Revision；调用者执行重放时只能引用其名称、revision 或 digest，不能引用本地文件路径。
_Avoid_: PCAP path, upload, mutable capture

**Capture Analysis**:
从 Capture Resource 得到的链路类型、时间范围、协议、端点、VLAN 和安全风险事实；它不授权发送，也不替调用者选择重放模式。
_Avoid_: replay result, safety approval

**Replay Plan**:
把 Capture Resource、LabPath、地址处理和 timing 意图冻结后的不可变执行计划。
_Avoid_: PCAP command, local replay

**Address Mode**:
Replay Plan 对抓包地址的处理方式：`rewrite` 映射到 LabPath 角色，`preserve` 保留原值并要求全部通过 SafetyPolicy。
_Avoid_: automatic fallback, best effort rewrite

**Session Template**:
从 Capture Resource 中一个可重建的 client/server 会话提取出的应用层双向交换序列。它保留 payload 与方向，不保留原 TCP 序号、ACK、重传、逐包时间或网络抖动。
_Avoid_: packet replay, TCP trace clone, ASTF profile

**Reconstructible Session**:
握手、方向和 payload 序列足以生成 Session Template，且未发现会改变应用语义的缺口、乱序或重传的会话。不可重建是分析事实，不是执行失败。
_Avoid_: valid Job, successful connection, supported PCAP

**Stateful Replay Plan**:
把 Capture Resource、Session Template、LabPath client/server 角色、地址池、CPS、并发上限、持续时间和端口池冻结后的不可变执行计划。
_Avoid_: stateful PCAP replay, raw ASTF profile, exact TCP replay

**Capture Workload**:
从一个 Capture Resource 的多个 Reconstructible Session 得到的有界加权组合；相同 Session Template 合并为一个模板并以出现次数表达权重，不表示历史连接时间线。
_Avoid_: every-flow replay, full trace replay, exact capture workload

**Datagram Flow**:
同一双向 UDP 端点对在一个有界空闲间隔内观察到的有序数据报序列；首个发送方是 Initiator，另一方是 Responder，不推断连接状态。
_Avoid_: UDP session, connection, request

**Datagram Template**:
从 Datagram Flow 提取的方向、payload、相对间隔和 Responder 端口组合；它忽略原 Initiator 地址和临时端口，可由 STL 周期性生成。
_Avoid_: UDP connection template, exact UDP trace

**Datagram Workload**:
一个 Capture Resource 中全部已分析 Datagram Flow 的有界加权组合；相同 Datagram Template 合并并以 flow 出现次数表达权重。
_Avoid_: UDP session workload, raw PCAP replay

**Packet Storm**:
在隔离实验室中由封闭协议模板生成的有界报文工作负载；调用者选择类型化字段、速率和时长，不能提供任意报文代码或 payload。
_Avoid_: raw packet generator, arbitrary Scapy, traffic profile

**DNS Query Storm**:
由类型化 DNS Question 生成的单播查询 Packet Storm；没有 Response Observation 时，它只形成 Query Delivery Observation，不形成 DNS 服务性能结论。
_Avoid_: DNS benchmark, resolver test, DNS response storm

**Query Delivery Observation**:
通过隔离 FlowStats 得到的 DNS 查询发送、穿越 DUT 接收和丢失事实；接收查询不等于观察到 DNS Response。
_Avoid_: response rate, resolver success, DNS latency

**Layer-2 Broadcast Domain**:
一个 LabPath 明确声明允许测试广播到达其全部数据面成员的隔离范围。
_Avoid_: subnet, VLAN assumption, isolated lab

**DHCP Discover Storm**:
由有限 Client Identity Pool 生成 DHCPDISCOVER 广播的 Packet Storm；它不代表完整 DHCP 事务或租约测试。
_Avoid_: DHCP benchmark, lease storm, DHCP session replay

**Client Identity Pool**:
DHCP Discover Storm 中一段有界、连续且允许的客户端 MAC 身份集合。
_Avoid_: address pool, IP pool, arbitrary clients

**Discover Delivery Observation**:
通过隔离 FlowStats 得到的 DHCPDISCOVER 发送、穿越 DUT 接收和丢失事实；接收 Discover 不等于观察到 Offer 或 Lease。
_Avoid_: offer rate, lease success, DHCP latency

**ARP Request Storm**:
由有限 Sender Identity Pool 生成以太网广播 ARP Request 的 Packet Storm；它只询问一个固定目标 IPv4，不代表邻居解析成功或 ARP 应答性能。
_Avoid_: ARP benchmark, ARP resolution test, reply-rate test

**Sender Identity Pool**:
ARP Request Storm 中成对递增的一组发送方 MAC 与 IPv4 身份；两个地址范围必须具有相同数量并保持一一对应。

**Request Transmission Observation**:
由发送端独占硬件端口计数器得到的 ARP Request 发送事实；由于当前网卡不支持 ARP packet-group，它不证明请求穿越 DUT，也不证明收到 Reply。
_Avoid_: request delivery, ARP reply, resolution success
