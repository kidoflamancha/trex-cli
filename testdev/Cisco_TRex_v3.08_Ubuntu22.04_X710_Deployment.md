# Cisco TRex v3.08 部署文档

## 1. 部署目标

本文档用于在以下环境部署 Cisco TRex：

| 项目 | 当前配置 |
| --- | --- |
| 虚拟化平台 | Proxmox VE / KVM |
| 虚拟机机型 | Q35 |
| 操作系统 | Ubuntu Server 22.04 LTS（Jammy） |
| TRex | 官方预编译版 v3.08 |
| 测试网卡 | Intel X710 10GbE，PCI 直通，2 个端口 |
| TRex 端口 0 | `0000:06:10.0` |
| TRex 端口 1 | `0000:06:11.0` |
| 管理网卡 | Virtio，`0000:06:12.0` |
| 推荐内存 | 固定 16 GB 或以上，关闭 Balloon |
| 推荐 vCPU | 8 个或以上，CPU 类型为 `host` |

部署原则：

- 使用 Cisco 官方预编译包，不单独安装或编译 DPDK。
- X710 两个端口仅供 TRex 使用。
- Virtio 网卡仅用于 SSH、TRex Console 和 API 管理。
- 优先使用 `vfio-pci`；虚拟机没有 vIOMMU 时回退到 `uio_pci_generic`。
- 首次测试先使用低速环回，确认稳定后再连接 DUT。

---

## 2. 部署前检查

### 2.1 检查操作系统和内核

```bash
cat /etc/os-release
uname -r
uname -m
```

预期：

```text
Ubuntu 22.04 LTS
x86_64
```

建议继续使用 Ubuntu 22.04 的 5.15 GA 内核。若当前内核不同，只要官方 TRex 可以正常绑定并启动，无需为了安装 TRex 主动降级。

### 2.2 确认三块网卡

```bash
lspci -nnk | grep -A3 -E '06:10.0|06:11.0|06:12.0'
ip -br address
```

必须确认：

- `06:10.0`、`06:11.0` 是两个 Intel X710 测试端口。
- `06:12.0` 是 Virtio 管理网卡，并且承载当前 SSH 管理地址。
- 后续所有绑定命令都不能包含 `06:12.0`。

建议记录当前 SSH 所用接口：

```bash
ip route get 192.0.2.12
```

输出中的 `dev <接口名>` 应对应 Virtio 管理网卡。

### 2.3 检查 X710 驱动和固件

TRex 绑定网卡之前，X710 通常由 Linux `i40e` 驱动管理：

```bash
sudo modprobe i40e
lspci -nnk -s 06:10.0
lspci -nnk -s 06:11.0
```

查找 Linux 接口名：

```bash
for dev in /sys/bus/pci/devices/0000:06:1{0,1}.0/net/*; do
    [ -e "$dev" ] && basename "$dev"
done
```

分别查看固件：

```bash
sudo ethtool -i <X710端口1接口名>
sudo ethtool -i <X710端口2接口名>
```

记录 `driver`、`version` 和 `firmware-version`。如果需要升级 X710 NVM/固件，应安排维护窗口并在宿主机侧按 Intel 官方流程完成，不建议在正在运行的 TRex 虚拟机中直接升级。

### 2.4 检查虚拟机资源

```bash
lscpu
free -h
numactl --hardware 2>/dev/null || true
```

建议至少满足：

- 8 个 vCPU；
- 固定 16 GB 内存；
- PVE 已关闭 Balloon；
- CPU 类型设置为 `host`；
- 没有给虚拟机设置 CPU Limit。

---

## 3. 安装系统依赖

```bash
sudo apt update
sudo apt install -y \
    ca-certificates \
    wget \
    tar \
    xz-utils \
    pciutils \
    ethtool \
    numactl \
    python3 \
    python3-distutils
```

TRex 官方包已经包含配套的 DPDK、Python客户端和主要用户态依赖，不要再通过 `apt` 安装另一套 DPDK。

---

## 4. 安装官方 TRex v3.08

### 4.1 下载并解压

```bash
sudo install -d -o trex -g trex /opt/trex
cd /opt/trex

wget https://trex-tgn.cisco.com/trex/release/v3.08.tar.gz
sha256sum v3.08.tar.gz | tee v3.08.tar.gz.sha256
tar -xzf v3.08.tar.gz
```

检查解压结果：

```bash
find /opt/trex -maxdepth 2 -name t-rex-64 -type f -print
```

正常情况下程序目录为 `/opt/trex/v3.08`。统一建立稳定路径：

```bash
sudo ln -sfn /opt/trex/v3.08 /opt/trex/current
sudo chown -R trex:trex /opt/trex/v3.08 /opt/trex/v3.08.tar.gz*
```

验证文件：

```bash
cd /opt/trex/current
ls -l t-rex-64 trex-console dpdk_setup_ports.py
sudo ./t-rex-64 --help >/dev/null
```

> `sha256sum` 在这里用于记录实际安装包摘要，方便后续节点间比对。若 Cisco 另行提供官方摘要，应再与官方值核验。

---

## 5. 配置 HugePage

16 GB 内存的虚拟机建议先给 TRex 预留 4 GB，即 2048 个 2 MB HugePage。

### 5.1 立即配置

```bash
sudo sysctl -w vm.nr_hugepages=2048
```

### 5.2 永久配置

```bash
sudo tee /etc/sysctl.d/80-trex-hugepages.conf >/dev/null <<'EOF'
vm.nr_hugepages = 2048
EOF

sudo sysctl --system
```

### 5.3 挂载 hugetlbfs

```bash
sudo install -d -m 0755 /mnt/huge

grep -qE '^[^#]+[[:space:]]+/mnt/huge[[:space:]]+hugetlbfs' /etc/fstab || \
    echo 'nodev /mnt/huge hugetlbfs defaults 0 0' | sudo tee -a /etc/fstab

sudo mount /mnt/huge 2>/dev/null || true
```

验证：

```bash
grep -E 'HugePages_Total|HugePages_Free|Hugepagesize' /proc/meminfo
mount | grep hugetlbfs
```

预期至少看到：

```text
HugePages_Total: 2048
Hugepagesize:    2048 kB
```

如果 `HugePages_Total` 明显小于 2048，重启虚拟机后再次检查。大规模 ASTF 测试需要更多内存时，再将其提高到 4096；不要在未评估内存占用前盲目增加。

### 5.4 放开锁定内存限制

```bash
sudo tee /etc/security/limits.d/99-trex.conf >/dev/null <<'EOF'
trex soft memlock unlimited
trex hard memlock unlimited
EOF
```

重新登录后检查：

```bash
ulimit -l
```

---

## 6. 选择 DPDK 绑定驱动

### 6.1 检查虚拟机是否暴露 vIOMMU

```bash
find /sys/kernel/iommu_groups/ -type l 2>/dev/null | head
dmesg | grep -Ei 'DMAR|IOMMU' | tail -n 20
```

#### 情况 A：能看到 IOMMU Group

优先使用 `vfio-pci`：

```bash
sudo modprobe vfio-pci
```

#### 情况 B：看不到任何 IOMMU Group

说明 Q35 虚拟机尚未暴露 vIOMMU。当前专用 TRex 虚拟机可回退到：

```bash
sudo modprobe uio
sudo modprobe uio_pci_generic
```

不要启用 `vfio-pci` 的 unsafe no-IOMMU 模式。若希望坚持使用标准 VFIO，应先在 PVE 中为 Q35 虚拟机开启虚拟 IOMMU，再重新检查 IOMMU Group。

### 6.2 配置模块开机加载

使用 VFIO 时：

```bash
echo vfio-pci | sudo tee /etc/modules-load.d/trex.conf
```

使用 UIO 时：

```bash
sudo tee /etc/modules-load.d/trex.conf >/dev/null <<'EOF'
uio
uio_pci_generic
EOF
```

这里只加载驱动模块，不在启动阶段按设备 ID 全局抢占 X710，避免误绑定其他同型号网卡。

---

## 7. 生成 TRex 配置

### 7.1 查看 TRex 识别到的接口

```bash
cd /opt/trex/current
sudo ./dpdk_setup_ports.py -t
```

确认输出中包含：

```text
0000:06:10.0  Intel X710
0000:06:11.0  Intel X710
0000:06:12.0  Virtio management interface
```

### 7.2 自动生成双端口配置

首次按端口互联/环回模式生成：

```bash
sudo ./dpdk_setup_ports.py \
    -c 06:10.0 06:11.0 \
    -o /etc/trex_cfg.yaml
```

检查结果：

```bash
sudo sed -n '1,200p' /etc/trex_cfg.yaml
```

最小配置应类似：

```yaml
- version: 2
  port_limit: 2
  interfaces: ["06:10.0", "06:11.0"]
```

如果生成脚本没有得到正确结果，可手工使用以上最小配置。

### 7.3 可选 CPU 线程配置

在确认虚拟机至少有 8 个 vCPU，并且这些 CPU 都属于虚拟 NUMA Node 0 后，可使用：

```yaml
- version: 2
  port_limit: 2
  interfaces: ["06:10.0", "06:11.0"]
  platform:
    master_thread_id: 0
    latency_thread_id: 1
    dual_if:
      - socket: 0
        threads: [2, 3, 4, 5]
```

部署初期建议先保留自动生成的配置，不要同时手工配置过多核心。稳定运行后，再根据 `lscpu -e=CPU,NODE,SOCKET,CORE` 结果进行核绑定。

### 7.4 三层场景配置说明

如果 DUT 两侧是三层接口，需要为每个 TRex 端口配置 IP和下一跳，例如：

```yaml
  port_info:
    - ip: 192.0.2.13
      default_gw: 192.0.2.14
    - ip: 192.0.2.15
      default_gw: 192.0.2.16
```

这里的地址只是示例，必须替换为实际 DUT 拓扑。纯二层测试可以保持自动生成的端口互联配置，或在流模板中明确指定目的 MAC。

---

## 8. 首次启动

### 8.1 启动前状态检查

```bash
cd /opt/trex/current

sudo ./dpdk_setup_ports.py -s
grep -E 'HugePages_Total|HugePages_Free' /proc/meminfo
sudo cat /etc/trex_cfg.yaml
```

### 8.2 启动 STL 服务

先使用两个数据面核心启动：

```bash
cd /opt/trex/current
sudo ./t-rex-64 -i -c 2 --cfg /etc/trex_cfg.yaml
```

成功启动的关键标志：

- 发现两个 X710 端口；
- 两个端口均为 Link Up；
- 没有 RX/TX queue allocation failed；
- 没有 HugePage、mbuf 或 IOMMU 错误；
- ZMQ服务监听在 4500/4501。

如果配置文件中已经手工定义 `platform` 线程，启动时可以去掉 `-c 2`，避免对核心数量产生歧义。

### 8.3 连接 Console

另开一个 SSH终端：

```bash
cd /opt/trex/current
./trex-console
```

执行：

```text
trex> portattr
trex> stats
```

---

## 9. 环回验证

首次验证建议用线缆直接连接两个 X710 端口：

```text
X710 Port 0  <———— SFP+/DAC ————>  X710 Port 1
```

### 9.1 低速 IMIX 测试

在 Console 中执行：

```text
trex> start -f stl/imix.py -m 1% -d 30
trex> stats
```

检查：

- Port 0 和 Port 1 都有发送、接收计数；
- `ierrors`、`oerrors` 为 0；
- `drop-rate` 为 0 或接近 0；
- 两个方向的包数基本对应。

随后逐步提高：

```text
1% → 10% → 25% → 50% → 100%
```

每档至少运行 30～60 秒。不要在基础环回未通过前连接 DUT 做复杂测试。

### 9.2 停止流量

```text
trex> stop
trex> clear
```

---

## 10. ASTF 启动验证

完成 STL 验证后，再测试有状态模式：

```bash
cd /opt/trex/current
sudo ./t-rex-64 -i --astf -c 2 --cfg /etc/trex_cfg.yaml
```

Console：

```bash
./trex-console
```

简单测试：

```text
trex> start -f astf/http_simple.py -m 1 -d 30
trex> stats
```

ASTF 对内存和 mbuf 的需求高于 STL。如果出现内存不足，先检查 HugePage余量，再考虑增加 HugePage或虚拟机内存。

---

## 11. 远程控制端口

TRex Python客户端远程控制主要使用 TCP 4500 和 4501。若启用了 UFW，只允许管理网段访问，例如：

```bash
sudo ufw allow from <管理网段/CIDR> to any port 4500 proto tcp
sudo ufw allow from <管理网段/CIDR> to any port 4501 proto tcp
```

不要将 TRex控制端口直接暴露到不可信网络。

远程 Console 示例：

```bash
./trex-console -s <TRex管理IP>
```

---

## 12. 可选 systemd 服务

建议先手工运行并完成环回验证，再配置自动启动。

创建服务：

```bash
sudo tee /etc/systemd/system/trex.service >/dev/null <<'EOF'
[Unit]
Description=Cisco TRex Stateless Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/trex/current
ExecStart=/opt/trex/current/t-rex-64 -i -c 2 --cfg /etc/trex_cfg.yaml
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now trex
```

检查：

```bash
systemctl status trex --no-pager
journalctl -u trex -n 100 --no-pager
```

如果启用 ASTF，应单独修改 `ExecStart` 加入 `--astf`；不要同时启动 STL和 ASTF两个实例争用同一组网卡。

---

## 13. 常用运维命令

### 查看端口状态

```bash
cd /opt/trex/current
sudo ./dpdk_setup_ports.py -s
```

### 恢复 X710 到 Linux i40e 驱动

先停止 TRex：

```bash
sudo systemctl stop trex 2>/dev/null || true
sudo pkill -INT t-rex-64 2>/dev/null || true
```

恢复驱动：

```bash
cd /opt/trex/current
sudo ./dpdk_setup_ports.py -l
```

如果自动恢复失败：

```bash
sudo modprobe i40e
sudo ./dpdk_nic_bind.py -u 06:10.0 06:11.0
sudo ./dpdk_nic_bind.py -b i40e 06:10.0 06:11.0
```

### 查看 PCI驱动

```bash
lspci -nnk -s 06:10.0
lspci -nnk -s 06:11.0
```

### 查看 HugePage

```bash
grep -i huge /proc/meminfo
```

### 查看 TRex日志

```bash
journalctl -u trex -f
```

---

## 14. 常见故障处理

### 14.1 `Cannot bind to vfio-pci`

检查：

```bash
find /sys/kernel/iommu_groups/ -type l 2>/dev/null | head
dmesg | tail -n 100
```

处理顺序：

1. 确认 PVE 宿主机已经完成物理 IOMMU和 X710直通；
2. 确认 Q35 虚拟机暴露了 vIOMMU；
3. 若暂不配置 vIOMMU，改用 `uio_pci_generic`；
4. 不建议使用 VFIO unsafe no-IOMMU模式。

### 14.2 `Not enough memory`、mbuf 或 HugePage错误

```bash
grep -i huge /proc/meminfo
free -h
```

确认：

- Balloon已关闭；
- HugePage已经预留；
- 没有其他 DPDK进程占用 HugePage；
- ASTF规模与虚拟机内存相匹配。

### 14.3 网卡 Link Down

检查：

- SFP+/DAC是否与 X710兼容；
- 两端速率和 FEC设置；
- DUT端口是否启用；
- X710固件是否过旧；
- PCI直通后是否对宿主机做过完整关机再开机。

### 14.4 Console连接失败

```bash
ss -lntp | grep -E ':4500|:4501'
systemctl status trex --no-pager
```

远程控制还应检查管理网卡路由和防火墙。不要在 X710测试口配置管理地址。

### 14.5 v3.08 启动异常或性能回退

保留 v3.08配置和日志，再用官方 v3.07做对照：

```bash
sudo ln -sfn /opt/trex/v3.07 /opt/trex/current
```

如果只有 v3.08异常，优先判断为 TRex/DPDK/i40e PMD版本回归；如果两个版本都异常，优先检查 PVE直通、HugePage、X710固件和虚拟机资源配置。

---

## 15. 验收标准

部署完成后应满足：

- [ ] Ubuntu 22.04正常运行，管理连接使用 Virtio网卡。
- [ ] `06:10.0` 和 `06:11.0` 均被 TRex识别。
- [ ] `06:12.0` 未被 DPDK绑定。
- [ ] HugePage总量和空闲量正常。
- [ ] TRex v3.08 STL模式可以启动。
- [ ] Console可以连接并获取端口状态。
- [ ] 双端口低速环回无丢包、无错误计数。
- [ ] 逐步提升至目标速率后运行稳定。
- [ ] ASTF示例能够启动并生成双向流量。
- [ ] 已记录 TRex包摘要、Ubuntu内核、X710固件和最终配置。

建议保存以下基线信息：

```bash
{
    date
    uname -a
    lscpu
    lspci -nnk
    grep -i huge /proc/meminfo
    cat /etc/trex_cfg.yaml
    /opt/trex/current/t-rex-64 --help | head
} | sudo tee /var/log/trex-deployment-baseline.txt
```

---

## 16. 参考资料

- Cisco TRex 官方安装手册：<https://trex-tgn.cisco.com/trex/doc/trex_manual.html>
- Cisco TRex 官方下载目录：<https://trex-tgn.cisco.com/trex/release/>
- Cisco TRex Console：<https://trex-tgn.cisco.com/trex/doc/trex_console.html>
- Cisco TRex Stateless 文档：<https://trex-tgn.cisco.com/trex/doc/trex_stateless.html>
- Cisco TRex ASTF 文档：<https://trex-tgn.cisco.com/trex/doc/trex_astf.html>
- DPDK Linux驱动绑定说明：<https://doc.dpdk.org/guides-25.03/linux_gsg/linux_drivers.html>
