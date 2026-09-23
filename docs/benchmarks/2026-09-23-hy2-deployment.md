# HY2 批次通知 v3 部署与验证

最终在线版本为 `1c71e73d-stream-read-batch-v3`。已替换 `/usr/bin/mihomo` 和 `/usr/local/bin/mihomo`，两处安装文件、构建产物及 `/proc/91115/exe` 的 SHA-256 均为：

```text
19edf5b218258bfe79b41bddbadb7f5a1a95e12c298bc9ed4c8bc349da2a219e
```

服务为 active/running，最终进程 PID 91115，`NRestarts=0`。为做旧版和关闭开关的对照，期间执行过计划内的服务重启；没有自动崩溃重启。配置文件哈希、手动节点选择、运行模式、日志级别和 TUN 设置均与部署前一致。

## 收窄通知合并范围

最初部署 v2 后，HY2 大流量下的并行小请求通过，但 DIRECT 满载、同时发起 HY2 小请求时出现了较多超时。短时同配置对照中：

| 版本 / 轮次 | 小请求成功 / 总数 | 超时 |
| --- | ---: | ---: |
| 原安装版 `282258d0` | 20 / 21 | 1 |
| v2，紧接原版的对照 | 5 / 13 | 8 |
| 同源码，关闭批次通知 | 31 / 32 | 1 |

原版也会出现满载尾延迟，样本不足以确定全部超时的根因，但不能据此接受 v2 对短流的风险。测试期间先恢复原版，再将实现收窄为：**只有应用已经读取至少 64 KiB 的 stream 才允许合并普通数据通知**。初始数据和短流保持每次到达立即通知；64 KiB 不是单次读取目标，也不引入等候。FIN、reset、取消、deadline、关闭仍立即通知。

v3 的针对性 quic-go race 测试、mihomo `adapter/outbound` race 测试、完整构建和当前配置校验均通过。新增测试以真实读取推进 stream 位置，覆盖 0 字节、64 KiB−1 跨界立即通知，以及达到 64 KiB 后的批次通知；原有退出路径和终止事件测试保留。实现说明见 [HY2 stream 批次通知](../features/hy2-stream-read-batching.md)。

## 正式服务负载验证

使用现有透明代理路径，每轮预热 5 秒、采样 30 秒；DIRECT 12 并发、HY2 8 并发。通过下载进程实际持有的 TCP socket 端口匹配 `/connections`，核验 DIRECT 为 `本地直连`、HY2 为 `🇯🇵 h4`。

| 指标 | v3 DIRECT | v3 HY2 |
| --- | ---: | ---: |
| curl 有效下载，含预热共 35 秒 | 816.1 Mbps | 680.4 Mbps |
| 正式窗口网卡 RX 均值 | 960.7 Mbps | 795.6 Mbps |
| perf task-clock / 30 秒 | 0.470 核 | 1.512 核 |
| 下载记录 HTTP 200 | 12 / 12 | 16 / 16 |
| 并行 HY2 小请求成功 | 53 / 53 | 52 / 52 |
| 小请求 p95 总耗时 | 285.5 ms | 260.9 ms |
| 小请求最大总耗时 | 308.4 ms | 285.6 ms |

小请求为 `https://www.gstatic.com/generate_204`，均返回 HTTP 204。每次请求后间隔 0.5 秒，连接超时 3 秒、总超时 5 秒，分位数使用 nearest rank。本轮 105 个请求未复现 v2 的秒级延迟和超时；这不等于保证所有流量和网络条件都没有副作用。传输已经超过 64 KiB 的长连接仍可能承载交互业务。

大文件下载在固定测试截止时间结束，curl 的 28 退出码表示这一人为时限，不代表完整文件校验成功。网卡和进程计数包含正式服务的其他连接；应用吞吐与网卡吞吐的时间窗口也不同，因此以上数值用于描述本次服务负载，不能直接套用初版独立实例的提速比例。

收尾再次验证 DNS 解析成功，DIRECT HTTPS 返回 200，HY2 HTTPS 返回 204。日志仍有部署前已存在的 `pokemen` 订阅源缺少 `proxies` 字段错误；该错误已在原进程日志中核实，本次未改订阅配置。

## v3 长流开销对照

另启两个临时独立实例，使用相同 v3 源码、Go `1.27.1-X:simd`、`GOAMD64=v3`、`CGO_ENABLED=0`、build tags 和 `default.pgo`。唯一功能开关差异是 HY2 的 `EnableStreamReadBatching`。使用独立 HTTP 代理入口和同一个日本节点，仅从 Tokyo Linode 的 1 GB 文件发起 8 并发；每轮预热 5 秒、采样 20 秒。两个实例的 8 条下载均收到 HTTP 200。

| 指标 | 关闭 | v3 启用 | 本轮变化 |
| --- | ---: | ---: | ---: |
| 应用下载，含预热 | 602.0 Mbps | 568.3 Mbps | −5.6% |
| perf CPU 时间 / 20 秒 | 1.273 核 | 0.869 核 | −31.7% |
| write / 网卡 RX MiB | 590.8 | 334.0 | −43.5% |
| CPU 秒 / 网卡 RX GiB | 16.49 | 11.92 | −27.7% |

这是一对公网短时对照：结果支持减少写调用和 CPU 开销，**没有证明带宽提高**。归一化分母为相同正式窗口的物理网卡字节，包含协议开销和后台流量，百分比只能作为本次观测。`write` 入口计数包含进程所有写调用，不等同于仅统计 relay 成功写入。没有用包含预热的应用字节归一化正式窗口的 CPU。

临时实例已停止，含节点凭据的临时配置已删除，`kernel.kptr_restrict` 已恢复为 2。没有改动内核网络参数、拥塞控制配置或代理组选择。

## 证据与备份

本机证据根目录：`/home/wudd/文档/mihomo/.git/hy2-read-batch/deploy-20260923T005955Z/`。

- 最终状态：`installed-v3.json`、`validation-v3.json`、`config-test-v3.log`、`journal-v3-final.json`。
- 正式服务：`load/v3-direct/`、`load/v3-hy2/`、对应的 `*-latency.json` 和汇总 `v3-performance.json`。
- v3 开关对照：`load/v3-isolated-baseline/`、`load/v3-isolated-candidate/`、`v3-isolated-comparison.json`。
- 旧版与 v2 风险对照：`load/old-direct-control/`、`load/candidate-direct-control/`、`load/batch-off-direct-control/` 及对应小请求记录。
- 原 `/usr/bin/mihomo` 备份为 `original-usr-bin-mihomo`，SHA-256 为 `1369e19cf17759928297172ba01bfe246479f6bd006320814c36ae668a373ff7`。
- 原 `/usr/local/bin/mihomo` 备份为 `original-usr-local-bin-mihomo`，SHA-256 为 `68fedb6efa10357ee4c119aec04543d52ab6851aef96a31f829495ec8cc91ff2`。两处原文件原本就是不同版本，已分别保留。

测速脚本也修正了连接识别：原来的端口范围匹配会混入其他应用连接，曾使一次 DIRECT 测试被路由保护中止；该轮不用于最终验收。当前脚本以子进程 socket inode 查实际端口，并已通过 IPv4/IPv6 真实 socket 的隔离验证。
