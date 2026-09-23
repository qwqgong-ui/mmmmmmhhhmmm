# 当前配置下的 DIRECT / HY2 下行 perf 实测

测试日期：2026-09-22（Asia/Singapore）。结论：DIRECT 的网卡接收已达到当前千兆链路的平台期；日本 HY2 在多测速源、4/8/16 并发下，有效下载约 730–749 Mbps，未达到配置的 920 Mbps。没有证据把 HY2 的差额全部归因于本机 CPU，也不能把本次平台期当成线路的绝对上限。

后续已实现 stream 批次通知并完成独立实例 A/B，见 [实现后的对照报告](2026-09-22-hy2-stream-read-batching.md)。本页保留优化前的正式服务测量与当时的建议。

## 测试对象与方法

- 实际服务：`mihomo.service`，PID 863，运行版本 `282258d0`；工作区 HEAD 是 `1c71e73d`。测试没有替换二进制、重启服务或修改代理配置。
- 运行文件 SHA-256：`1369e19cf17759928297172ba01bfe246479f6bd006320814c36ae668a373ff7`，与 `/usr/bin/mihomo` 一致。
- 构建：Go `1.27.1-X:simd`、`GOAMD64=v3`，已使用 `default.pgo` 和依赖补丁。不能把“开启 PGO”当成尚未启用的优化。
- 客户端：i7-12700F，20 个逻辑 CPU；`enp4s0` 实际为 1000 Mbps / Full Duplex，虽然网卡本身支持 2.5 Gbps。
- 配置：TUN system、auto-redirect、GSO；TCP 测试连接实际入口为 `Redir`。因此本报告不能用于声称 TUN 用户态逐包路径、Hybrid QUIC raw 或 UDP reorder 的性能。
- 路由证据：测试进程使用独立源端口段，逐秒从 `/connections` 核验。DIRECT 链为 `本地直连 → 🟢`，HY2 为 `🇯🇵 h4 → 🌐`，没有切换用户的代理组。
- DIRECT 使用清华和中科大镜像；HY2 使用 Tokyo Linode 大文件及 Google Chrome 安装包。HTTP 响应正文丢弃到 `/dev/null`，没有将下载文件写入磁盘。
- 正式两轮均预热 5 秒、采样 45 秒。`perf stat -p 863` 和 `perf record -e cpu-clock -F 499 --call-graph fp -p 863` 同时运行。剥离符号的运行文件通过 `.gopclntab` 生成离线符号副本；未用重新编译的文件替代它。

## 测量结果

| 指标 | DIRECT，12 并发 | HY2，8 并发 |
| --- | ---: | ---: |
| 网卡 RX 平均，正式 45 秒 | 952.5 Mbps | 805.3 Mbps |
| 网卡 RX 中位数 | 968.6 Mbps | 807.6 Mbps |
| 网卡 RX 最高 1 秒 | 970.5 Mbps | 848.6 Mbps |
| curl 有效下载，包含预热共 50 秒 | 891.6 Mbps | 739.6 Mbps |
| `/proc` 进程 CPU 平均 | 0.250 核 | 1.118 核 |
| `perf stat` task-clock / 45 秒 | 0.283 核 | 1.207 核 |
| 上下文切换 / 秒 | 26,356 | 69,327 |
| CPU 迁移 / 秒 | 13,054 | 23,588 |
| perf 样本 | 5,653 | 25,553 |
| perf 丢失样本 | 0 | 0 |
| 全机 UDP 接收缓冲区错误增量 | 0 | 0 |

1 核表示一个逻辑 CPU 的时间。网卡数值包含协议开销和后台流量，不能直接和 curl 的有效字节等同；两列吞吐的时间窗口也不同。空闲基线约 1.14 Mbps RX、0.009 核进程 CPU。HY2 正式轮有一秒额外约 129.5 Mbps 的网卡 TX，因此总网卡计数并非完全隔离的测试流量。

递增并发验证：

| 路径与并发 | 正式窗口网卡 RX 均值 | 包含预热的有效下载 |
| --- | ---: | ---: |
| DIRECT，1 | 244.0 Mbps | 早期脚本未保存完整结束字节 |
| DIRECT，4 | 636.8 Mbps | 早期脚本未保存完整结束字节 |
| DIRECT，12，短轮 | 964.3 Mbps | 906.8 Mbps |
| HY2，4，大文件双源 | 804.0 Mbps | 738.6 Mbps |
| HY2，8，大文件双源 | 801.2 Mbps | 737.8 Mbps |
| HY2，16，大文件双源 | 780.9 Mbps | 730.2 Mbps |
| HY2，8，独立系统调用采样轮 | 817.7 Mbps | 749.4 Mbps |

Cloudflare 短文件测速和 Hetzner 并发请求返回过 HTTP 429，已停止使用，相关轮次不用于判断链路上限。正式 HY2 轮的 3 个 HTTP 0 都是测试截止前新请求仅剩 100–239 ms，按统一截止时间超时且没有下载字节；它们不是已经下载中的服务端失败。

另外通过现有 `ssh proxy` 对同一日本服务器读取 `/proc`，与 HY2 正式轮重叠的 18 个高流量秒中，Xray 平均约 0.682 核、整机忙碌约 0.948 核、steal 约 0.012 核，机器有 2 个逻辑 CPU。这不能排除单 goroutine、拥塞控制或线路限制，但没有整机 CPU 持续耗尽的证据。远端 sudo 需要密码，未修改远端状态，也未取得远端特权 perf 或服务配置。

## perf 热点与含义

下列累计百分比包含子调用，不能相加。

**DIRECT：** `bufio.splice` 累计 47.80%，`__schedule` 自身 13.14%，`runtime.findRunnable` 自身 9.36%。内核样本合计约 69.82%。实际已经走 `copyDirect → splice → splice_to_socket`，没有证据需要再改一套用户态拷贝；在接近千兆时，进程仅消耗约 0.28 核。

**HY2：** `CopyExtendedWithPool` 累计 27.04%，TCP `Write` 累计 20.25%，QUIC `Conn.run` 累计 20.92%，`oobConn.ReadPacket` 累计 11.45%，其中 `ReadBatch` 累计 10.21%。`runtime.findRunnable` 自身 6.82%、`__schedule` 5.91%、AES-GCM 解密主函数 1.93%、`runtime.memmove` 1.08%；按函数名归类的 AES 相关总和约 2.88%，GC/分配相关约 1.46%。主要机会在调用、调度和批量交付，当前证据不支持优先改加密算法或 GC。

为了分清“大缓冲区未填满”和“缓冲区太小”，另外做了 5 秒系统调用追踪：

- `write` 共 298,503 次，合计返回 475,224,257 字节，平均 **1,592 字节/次**。
- **83.97% ≤ 2 KiB，95.18% ≤ 4 KiB**；整块 32 KiB 仅 3 次。主要 8 个高流量 FD 各自平均约 1.66–1.70 KiB。统计包含其他存量写调用，以及约 15,588 次 8 字节 eventfd 写入。
- `recvmmsg` 请求批量大小是 8，成功调用平均 **2.60 包/次**；满 8 包的仅占成功调用约 **2.94%**，另有 129,046 次 `EAGAIN`。
- 这轮追踪与正式 CPU 采样分开；它会增加观测开销，只用于说明系统调用的大小和分布。

源码也符合这个现象：通用 relay 默认缓冲区为 32 KiB，但 QUIC `ReceiveStream.readImpl` 会在暂时没有更多 frame 时返回已经读到的少量数据；relay 随即写回本地 TCP。UDP socket 已经有 `ReadBatch`，不能把“增加批读”作为尚未实现的功能。

## 优化方案，按优先级

1. **先做 HY2 stream 的批量交付 A/B。** 现有 `readChan` 容量为 1，已经合并尚未消费的通知；`Conn.handlePackets` 也已经每批最多处理 32 个 packet，不能重复“增加批处理”。可先验证把当前已收到的一批 frame 处理完后，再统一通知对应 stream reader，是否能减少 reader 提前读空队列的情况。若仍然大量短读，再考虑仅供 HY2 bulk relay 使用的批量读取接口，保留普通 `Read` 立即返回的语义；任何跨到达时刻的等待都需要极小且有界的预算，不能按固定最小字节数无限等候。FIN、错误、取消、低速流和交互流必须及时返回，限制内存与单批工作量。切点是 `ReceiveStream.readImpl` 的“已有部分数据但没有下一 frame 就返回”分支，以及 `handleStreamFrameImpl → signalRead` 的通知时机。验收指标是每 MiB 的 `write`/唤醒次数、CPU 秒/GiB、吞吐，以及并发交互请求的 p95/p99 延迟。此为候选改造，尚未实现，不能承诺会从 740 升到 920 Mbps。
2. **用双方 QUIC 运行数据确认 920 Mbps 差额。** 记录实际协商的拥塞控制、服务端带宽上限、RTT、丢包/重传、cwnd 和 pacing rate。客户端 `down: 920 Mbps` 只是传给服务端的接收带宽请求；不能据此认定服务端最终发送策略。本轮 4→8→16 并发没有增长，单纯继续加连接收益不足。服务器特权观测本轮未完成，应在这一点补齐后再调限速/拥塞参数。
3. **将 Go 调度参数作为后续可回退实验。** 高上下文切换和迁移已被 perf 观察到，可对 `GOMAXPROCS=4/8/20`、仅 P 核等设置做独立 A/B；必须同时看 CPU/吞吐/尾延迟，不能只因机器有 20 个线程就认定多开或少开更快。当前服务参数没有调整。
4. **DIRECT 保持当前 splice 路径。** 其 CPU 开销已低且网卡接近千兆；若目标超过千兆，先确认路由器/交换机/线缆/网卡整条链路能协商更高速度，以及宽带本身是否支持。保留已开启的 TSO/GSO/GRO。Linux 文档说明这些功能负责分段与聚合，不能用关闭卸载来作为无证据的常规优化：[Linux segmentation offloads](https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html)。

不建议现在单独把 32 KiB buffer 改成 128 KiB：当前绝大部分读取尚未填满旧缓冲区。也不优先增大 UDP socket buffer：现有接收缓冲区没有错误增量，且批读平均远未填满。PGO 已开启；后续只有结合代表性新 profile 更新和对照构建才有意义，参见 [Go PGO 文档](https://go.dev/doc/pgo)。

## 复现与证据位置

- 脚本：`scripts/perf-bandwidth.py`；离线符号辅助：`scripts/perf-go-symbols.go`。
- 命令与测量口径：`scripts/README.perf-bandwidth.md`。
- 本机原始证据：`/home/wudd/文档/mihomo/.git/perf-bandwidth-20260922/`。正式结果位于 `direct-profile/` 与 `hy2-profile/`，包含 `summary.json`、`samples.json`、`routes.json`、`transfers.json`、`perf-stat.csv`、`perf.data`、函数平面与调用图报告。
- 系统调用追踪：`hy2-syscalls.data`、`hy2-syscalls.txt.gz`、`hy2-syscalls-summary.json`。符号副本位于 `symbols/`。
- 采样后 `kernel.kptr_restrict` 恢复为 2；服务仍为 PID 863、active/running、`NRestarts=0`。

范围边界：本次为**当前配置的 TCP 下行**。未测上传、HTTP/3、Hybrid QUIC raw、普通 HY2 UDP 或 UDP reorder，也没有部署候选优化。保留了原有未跟踪 `.codex/` 内容。
