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

依赖中包含 `TestKernelPacing*` 测试。`patches/quic-go/test-kernel-pacing.sh`
接收已编译的 quic-go test binary，在隔离网络命名空间的 loopback FQ 上验证共享
UDP socket 的两路独立调度，测试结束删除命名空间，不修改宿主出口队列。

Patches:

- `transport/tuic.patch`
- `../../quic-go/0001-hy2-expose-validated-ack-ecn-deltas.patch`（依赖补丁）

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
