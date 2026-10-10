# HY2 ECN-Aware BBR

[返回功能目录](../features.md) · [配置示例](../config.yaml)

让 Hysteria2 客户端和服务端的既有 `bbr` 直接使用统一的 ECN-aware 状态机：validated ACK_ECN 零 CE 时快速扩张，首次 CE 冻结，持续 CE 按比例与 EWMA 渐进回缩，并在 ECN 不可用时回退到 delivery-rate、RTT 与 loss 控制。路径迁移会重新验证 ECN 并衰减路径相关模型。

## Linux HY2 的内核 pacing

HY2 客户端和服务端安装 BBR 后请求 Linux FQ EDT 后端。quic-go 通过
`SO_TXTIME(CLOCK_MONOTONIC)` 与每数据报的 `SCM_TXTIME` 提供最早出队时刻；
BBR 仍在用户态决定速率和拥塞窗口。依赖补丁为
`patches/quic-go/0007-linux-fq-edt-pacing.patch`，必须使用现有依赖补丁脚本构建。

每连接独立排程，最多提前 1 ms、保留 32 个尚未到时刻的预约。内核模式逐个 UDP
数据报发送，避免一个大 GSO 批次共享同一时刻形成突发；发送线程延迟时仍保留包间距。
QUIC 保留现有入队时间记账，内核提前量不是网卡实发时间，RTT 包含这段受限排队。
握手、ACK-only、PTO 和 PMTU 探测保留原有发送路径。

只有 Linux（不含 Android）且底层 socket 支持相应设置时启用。Windows、macOS、
Android、iOS 以及不支持 OOB/TXTIME 的包装 socket 保留原用户态 pacing/GSO。
该请求不改变 HY2 线协议，也不自动修改出口 qdisc；Linux 出口需已有 FQ。
FQ 的单流限额和物理链路拥塞仍可能导致丢包。

`0008-hy2-bbr-fq-coordination.patch` 与 Xray 的 HY2 BBR/fq 联动修复对齐。
就绪的 EDT 后端只绕过软件 pacing，保留 cwnd、放大保护、PTO 和 tracking 限制；
实际出口须为开启 pacing 的 root fq，或所有叶子均为 fq 的 mq。检查纳入 socket
mark、接口、源地址、UID、UDP 端口与网络命名空间，路由/qdisc 缓存最长 5 秒，
远端地址变化立即重查。端口跳跃保留既有连接语义，出口检查会随地址指针更新。

纯 ACK 立即发送且不消耗 EDT 预约；ACK 等待从首个待确认包计时，BBR 使用
`min(25 ms, max(1 ms, smoothedRTT/4))` 的预算。打包器无数据时才标记应用受限，
控制器替换同步实际 MTU，标准 QUIC 路径迁移重置 MTU、抽样与排程。
软件 pacer 与 EDT 使用同一有效速率，移除 64 KiB/s 的人为下限。发送线程反馈
实际预约进度，按最新速率重算下一间隔；数据队列积压保留 ACK/PTO 的发送机会。

BBR 的 sampler 使用发送前在途字节，loss-only 事件可以进入恢复；ECN floor
不能覆盖 DRAIN、PROBE_RTT、恢复或安全丢包限速。字节/速率/时间换算使用安全
的 128 位中间乘积并饱和，时钟回退不会制造软件 pacing credit。
保留 Mihomo 的可配置初始窗口及现有三档 profile 参数。

最小 RTT 小于 2 ms、非 fq、未知路由或不支持 OOB 的 socket 使用软件 pacing/GSO。
非零 DSCP 与 ECN 控制消息叠加时保守回退；TXTIME 不兼容写错误与内核时钟失败
按原预约时间普通发送，然后关闭该连接的 EDT 后端。环境变量
`QUIC_GO_DISABLE_KERNEL_PACING=1` 可强制软件后端，`Conn.KernelPacingEnabled()`
报告最近发送循环的后端选择。程序不修改宿主 qdisc。

## 对齐验证与部署

2026-10-10 使用本机 i7-12700F 检查 CPU 后构建 `linux-amd64-v3`，保留裁剪
标签、`GOEXPERIMENT=simd`、现有 PGO 和全部依赖补丁。相关 BBR/pacer/ECN、
QUIC pacing、ACK 定时及 MTU 信号测试与 race 检查通过；ACK handler 完整测试
通过。Windows amd64-v3 与 Android arm64 相关包交叉构建通过。

初测中 `TestDial` 与 `TestTransportAndDialConcurrentClose` 失败，在仅含原有
0001–0007 补丁的修复前依赖上也已复现。诊断确认两项都传入空 TLS 配置，而
此 fork 关闭了自动推断 ServerName；TLS 提前拒绝配置，分别导致收包超时和
错误类型断言失败。`0009-tests-use-explicit-tls-server-name.patch` 为这五处
客户端测试配置显式设置 `ServerName: "localhost"`，保留证书验证与原有断言。
修复后完整 QUIC 根包、ACK handler、BBR/pacer 套件及相关完整 race 检查通过，
没有排除测试。隔离网络命名空间中，两路各 10 包的到达
跨度为 17.94/26.95 ms，fq dropped 为 0，删除 fq 后出口检查正确回退。

WAN 对比使用同一 Xray 服务器 UDP443、同一客户端 HY2/TLS 配置和
`aggressive` profile。仅对临时测试服务的 cgroup 添加固定源端口 SNAT，保留
真实网卡 fq 路径；服务器日志确认两版最后 112 个测试请求来自同一个公网
IP/UDP 端口。修复版日志确认 `FQ EDT ready=true, interface=2`。

三轮短测的中位数（下载 16 MiB、上传 8 MiB、四流各下载 4 MiB）：

| 项目 | 修复前 | 修复后 |
| --- | ---: | ---: |
| 单流下载 | 477.7 Mbps | 479.4 Mbps |
| 上传 | 227.7 Mbps | 260.5 Mbps |
| 四流并发下载 | 582.8 Mbps | 577.9 Mbps |
| 小请求首字节 | 80.94 ms | 80.93 ms |

[逐轮数据与限制](../benchmarks/hy2-bbr-fq-alignment-2026-10-10.json)包含 24 项负载。
测试期间观测到宿主 fq 的 flow_limit 由 100 变为 256，该变更不由本任务执行；
因此不能将短测差值全部归因于代码，也没有据此证明 CPU 收益或长期公平性。
本次未在 WAN 人为制造 CE；CE 校验与降速优先级由回归测试覆盖。

实际服务 `/usr/bin/mihomo` 已部署 `a1340e8e-hy2-bbr-fq-aligned`，二进制
SHA-256 为 `9706c1302663075260ff2c686562feb6947b0030fd62a46019d64d76fd99d468`。
旧二进制保留为 `/usr/bin/mihomo.pre-hy2-bbr-fq-01a12406`。
主服务配置保持当前版本，公网 HTTP204 检查通过，实际 HY2 节点测得 HTTP
延迟 86/87/86 ms。服务器原配置已按校验值恢复，临时 SNAT 规则及测试服务已清理。

依赖中包含 `TestKernelPacing*` 测试。`patches/quic-go/test-kernel-pacing.sh`
接收已编译的 quic-go test binary，在隔离网络命名空间的 loopback FQ 上验证共享
UDP socket 的两路独立调度，测试结束删除命名空间，不修改宿主出口队列。

Patches:

- `transport/tuic.patch`
- `../../quic-go/0001-hy2-expose-validated-ack-ecn-deltas.patch`（依赖补丁）

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
