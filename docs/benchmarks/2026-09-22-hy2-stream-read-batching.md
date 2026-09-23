# HY2 stream 批次通知初版（v2）A/B 实测

测试日期：2026-09-22。在相同源码和构建参数下，仅切换 HY2 客户端的 `EnableStreamReadBatching`，候选版每 MiB 网卡接收对应的 `write` 调用减少 **28.6%**，每 GiB 的进程 CPU 时间减少 **12.1%**。有效下载均值为 **776.4 Mbps**，基线为 **746.1 Mbps**。这是本次四轮公网测试的结果，不能视为固定提速比例，也没有达到配置的 920 Mbps。

本页保留 v2 的原始对照结果。随后在正式服务验证中发现 DIRECT 满载时的并行 HY2 小请求风险，当前实现已收窄为仅对已读取至少 64 KiB 的 stream 合并通知；以下百分比不代表这一后续版本的收益。

最终在线版本及复测结果见 [v3 部署与验证](2026-09-23-hy2-deployment.md)。本页下文的“尚未部署”仅描述初版 A/B 完成时的状态。

## 实现范围

实现见 [HY2 stream 数据通知按收包批次合并](../features/hy2-stream-read-batching.md)。握手后，当接收队列已有多个包时，合并本轮同一 stream 的普通数据通知，在原有收包循环结束时唤醒 reader。保留原来的 32 包上限、队列判空和 ACK 调度，没有新增等待下一包、凑足字节或定时刷新的机制。

FIN、reset、取消、deadline 和关闭保持立即通知；普通 `Read` 仍可短读。优化减少提前唤醒导致的小块写回，不能保证消除所有小写入，也不能保证零额外延迟。DIRECT 和 HY2 UDP datagram 的交付路径未改。

## 对照方法

- 源码基于 `dev` 的 `1c71e73d1d49b7eb33c7a8e8234aa97369d953d7`，包含本次补丁。基线使用相同补丁和构建流程，通过 Go overlay 将 HY2 的开关设为 `false`；候选设为 `true`。
- 两个版本均使用 Go `1.27.1-X:simd`、`GOAMD64=v3`、`CGO_ENABLED=0`、相同 build tags 和 `default.pgo`。先执行仓库依赖补丁脚本。
- 在本机启动独立临时实例，关闭其 TUN，以独立 HTTP 代理端口接收测试请求，使用当前配置中的同一个日本 HY2 节点 `🇯🇵 h4`。生产服务继续运行。
- 顺序为 **A1 → B1 → B2 → A2**。每轮 8 并发，预热 5 秒、正式采样 20 秒。下载源为 Tokyo Linode 大文件和 Google Chrome 安装包；逐秒查询实例 `/connections` 核验真实出站。所有 60 条下载记录均收到 HTTP 200；到测量截止时停止尚未完成的大文件请求。
- 正式窗口同时运行 `perf stat` 和 `perf record -e cpu-clock -F 499 --call-graph fp`。`perf stat` 额外统计 `write` 和 `recvmmsg` 入口事件，包含该进程的所有这类调用，不能等同于仅统计 relay 的成功写入。
- 下载期间另以串行小请求访问 `https://www.gstatic.com/generate_204`，每次请求完成后间隔 0.5 秒。延迟为 curl 的 `time_total`，包含代理连接、TLS 和公网时间；样本覆盖预热和正式窗口，分位数按 nearest rank 计算。

这里的入口是独立实例的 HTTP 代理，前一份 [当前配置实测](2026-09-22-bandwidth-perf.md) 使用正式服务的透明重定向入口。两份报告的绝对 CPU 数值不能直接作为补丁前后对照；以下四轮才是相同入口的 A/B。

## 每轮结果

| 轮次 | 应用下载 Mbps，含预热 | 网卡 RX Mbps，正式窗口 | perf CPU 核数 | write / RX MiB | CPU 秒 / RX GiB | 小请求 p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A1，关闭 | 723.8 | 780.9 | 1.317 | 560.1 | 14.49 | 334.1 |
| B1，启用 | 781.7 | 830.8 | 1.228 | 395.7 | 12.69 | 310.1 |
| B2，启用 | 771.2 | 804.1 | 1.170 | 395.5 | 12.50 | 480.9 |
| A2，关闭 | 768.4 | 806.2 | 1.332 | 548.8 | 14.19 | 351.5 |

合并两轮基线与两轮候选：

| 指标 | 基线 | 候选 | 变化 |
| --- | ---: | ---: | ---: |
| 应用下载均值 | 746.1 Mbps | 776.4 Mbps | +4.1% |
| 网卡 RX | 793.5 Mbps | 817.4 Mbps | +3.0% |
| perf CPU 时间 / 采样时长 | 1.325 核 | 1.199 核 | -9.5% |
| write / RX MiB | 554.4 | 395.6 | -28.6% |
| recvmmsg / RX MiB | 392.2 | 266.7 | -32.0% |
| CPU 秒 / RX GiB | 14.34 | 12.60 | -12.1% |
| 上下文切换 / RX MiB | 634.9 | 602.1 | -5.2% |

归一化使用各轮正式约 20 秒内的网卡接收字节，与 perf 的统计窗口对齐；未用包含预热的 25 秒应用字节作分母。网卡计数仍包含后台流量和协议开销，窗口起止也有很小的采样偏差。CPU 核数以 `task-clock / 20 秒` 计算，1 核表示一个逻辑 CPU 的时间。

基线小请求 70 个、候选 74 个，均成功返回 HTTP 204。合并 p50 为 273.3 → 235.7 ms，p95 为 334.1 → 310.1 ms；但候选 B2 的 p95 达到 480.9 ms，最大值为 507.9 ms，高于基线最大 386.1 ms。样本少且包含公网波动，不能由合并分位数断言尾延迟改善，也不能确认单轮尖峰由补丁导致。因此本次证据支持减少调用和 CPU 开销，**不支持“没有任何副作用”的保证**。

## 验证与交付状态

- 在重新应用最终补丁生成的 quic-go 目录执行 `go test -race -run 'Test(Connection|ReceiveStream|StreamReadBatch|StreamsMap|Config)' -count=1 .`，通过。
- 新增测试覆盖真实 packet-parser 到 stream 的调用链、单包/多包、单向/双向流、错误退出、32 包上限、处理期间追加的包、普通短读、通知去重与复用，以及 FIN/reset/取消/关闭/deadline 和终止后的缺口补齐。
- 使用最终补丁运行 `GOAMD64=v3 GOEXPERIMENT=simd go test -race ./adapter/outbound`，通过。两个用于 A/B 的完整 mihomo 二进制构建成功，配置校验和真实 HY2 HTTPS 流量通过。
- 整个 quic-go 根包和扩展集成测试未全绿：`TestDial` 的部分场景出现 UDP 读超时，`TestTransportAndDialConcurrentClose`、部分 transport/HTTP datagram 测试缺少 TLS `ServerName` 或 `InsecureSkipVerify`。这些失败已在未加入本次补丁的依赖基线上复现，未改动这些无关测试。
- 临时实例已停止，含节点凭据的临时配置已删除，`kernel.kptr_restrict` 已恢复为 2。本次没有替换或重启正式服务。收尾检查正式服务为 active/running、`NRestarts=0`，运行版本仍为 `282258d0`；候选优化尚未部署。

本机原始证据位于 `/home/wudd/文档/mihomo/.git/hy2-read-batch/ab/`，最终四轮为 `v2-a1`、`v2-b1`、`v2-b2`、`v2-a2`；汇总为 `v2-comparison.json`。目录中的更早实验不纳入上述结论。

候选二进制为 `/home/wudd/文档/mihomo/.git/hy2-read-batch/mihomo-candidate`，SHA-256：`77b179d50fb0dae21afa01006d4dde5556e9cd9f7481e0cce66c39eca2707cf9`。基线二进制 SHA-256：`cf29ef157cc41daed40f35523bf7f22fccb5547cde7cbb305d79a323863ad46f`。
