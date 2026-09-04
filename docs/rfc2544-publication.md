# RFC2544 可发布报告运行指南

`publicationStatus: COMPLETE` 是证据完整性判定，不是 IETF 认证。只有真实 TRex、strict 模式、
四种方法和全部发布证据都通过时才会出现；任一条件缺失都会 fail closed 为 `PARTIAL`。

## 发布前置条件

1. `LabPath.reportContext` 必须记录 DUT 名称、硬件、软件版本、配置快照 SHA-256 与快照文件名，
   以及拓扑、介质、协议、stream 类型、隔离声明和测试修饰条件。设备配置由实验室 fixture 获取；
   trex-cli 不包含任何厂商特定 DUT 控制。
2. TRex 两个选定端口必须在 readiness 中显示链路 UP，并报告 NIC、driver、实际线速和
   `ieee1588: true`。
3. `engine.latencyTimestampCalibration` 必须来自当前端口/driver/固件/布线环境的可追溯校准，
   包含校准记录 SHA-256、记录文件名、有效期、不确定度，以及所选 RFC 1242 定义下七种标准帧长
   的 correction。仅填写一个 ID 不能满足发布判定。
4. SafetyPolicy 必须允许 100% L1、至少 120 秒的单次流量，以及足够大的 Back-to-Back burst。
   对需要测试的帧长，`maxBurstPackets` 与 CLI 的 maximum burst frames 至少为
   `theoretical_fps * maximum_burst_seconds`；默认发布范围为 30 秒。
5. TrafficProfile 必须提供正常目的地 flow 和一个同源、不同目的网络的 latency flow。测试路径
   必须隔离，且各方法之间不得改变 DUT 配置。

校准配置示意如下。摘要和值必须来自真实校准记录，不能复制示例占位值：

```yaml
engine:
  mode: remote-trex
  # server/client paths/ports omitted
  latencyTimestampCalibration:
    calibrationId: cal_<lab_record_id>
    calibrationDigest: sha256:<64 lowercase hex characters>
    calibrationArtifact: latency-calibration.json
    timestampMode: ieee1588
    measuredAt: 2026-08-30T00:00:00Z
    validUntil: 2026-09-30T00:00:00Z
    maximumUncertaintyMicroseconds: 0.2
    correctionMicroseconds:
      store-and-forward:
        64: <measured correction>
        128: <measured correction>
        256: <measured correction>
        512: <measured correction>
        1024: <measured correction>
        1280: <measured correction>
        1518: <measured correction>
```

## 完整运行

发布运行固定使用以下方法顺序。`--back-to-back-max-burst-frames` 应按当前最低 ingress 线速和
64-byte 理论帧率计算，不能使用下面的占位符：

```bash
trex-cli benchmark rfc2544 run \
  --profile <profile> --path <lab-path> --forward <normal-flow> \
  --mode strict \
  --test throughput \
  --test latency \
  --test frame-loss \
  --test back-to-back \
  --latency-definition store-and-forward \
  --latency-scenario same-destination \
  --latency-scenario new-destination \
  --latency-new-destination-flow <new-destination-flow> \
  --back-to-back-max-burst-frames <30-second-upper-bound> \
  --back-to-back-repetitions 20 \
  --back-to-back-minimum-step-frames 1 \
  --back-to-back-maximum-burst-seconds 30 \
  --back-to-back-buffer-depletion-seconds 2
```

Latency 单项至少需要 `7 frame sizes * 2 scenarios * 20 repetitions * 120 seconds`，因此完整运行
通常超过 12 小时。Agent 的 `maxJobTimeout`、LabPath 的 `benchmarkJobTimeout` 和持久化运行环境
都必须覆盖这一时长。

## 交付物与验收

最终 bundle 包含 `publication.json`、`measurements.csv`、`trials.ndjson`、`report.md`、
`environment.json`、submitted/resolved specs、`result.json`、`checksums.sha256` 和 manifest。
发布前必须确认：

- `publication.json.status` 为 `COMPLETE` 且 issues 为空；
- manifest 标记非模拟，所有工件摘要可重算；
- Throughput 每帧长存在至少 60 秒零丢包确认；
- Latency 每帧长、每目的场景至少 20 个有效 120 秒 tagged trial；
- Frame Loss 从 100% 开始、步长不大于 10%，并以两个连续零丢包点结束；
- Back-to-Back 每个适用帧长有独立 N 次完整搜索，或有可验证的“不适用”原因。

当前 `testdev` 的 X550T/net_ixgbe 端口均由 TRex v3.08 报告 `ieee1588: false`，所以该环境不能
产出 `COMPLETE`；必须先更换支持的时间戳端口或接入经校准的外部测量 adapter。
