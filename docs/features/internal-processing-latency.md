# 内部处理延迟修复

[返回功能目录](../features.md)

最初的修改减少 UDP 目的地准备、缓存失效、TCP 首包等待、缓存连接重拨、网络接口采样和 DEBUG 输出带来的内部等待。基线为 `ed291e18`，修复源码为 `42f36d99`；下面分别记录后续持久化修复和缓存命中路径的局部优化。

## 同条件计时

下表来自同一台 CachyOS、Intel 6 核 12 线程、8 GB 内存机器，Go 1.27.1，计时测试使用 GOMAXPROCS=3。除本地 VLESS 链路外，网络延迟由测试替身控制；这些数字不代表公网网页加载速度。测试耗时和请求处理耗时分别记录。

| 场景 | 修复前 | 修复后 | 测量边界 |
| --- | --- | --- | --- |
| 同 UDP association 中，慢目标 DNS 阻塞 100 ms，已准备的其他目标发包 | 100.31–100.56 ms | 0.09–0.22 ms | 三次相同输入；socket WriteTo 的到达时间 |
| Clear、退休 scope、MarkStale 唤醒旧查询等待者 | 约 3.00 s | 0.8–4.4 μs | 三次；旧 worker 的原始超时为 3 s |
| 本地 VLESS，客户端等待服务端先发 banner | 中位数 200.87 ms | 中位数 0.29 ms | SOCKS 请求到 banner；关闭嗅探，五次有效样本 |
| 相同链路带客户端首包 | 中位数 0.36 ms | 中位数 0.18 ms | 相同本地服务和配置 |
| 缓存预算 30 ms，实际连接需 35 ms | 约 65.6 ms，拨号两次 | 35.48–35.76 ms，拨号一次 | 三次；原连接继续参加竞争 |
| 桌面来源 DNS 缓存命中 | 34–38 μs，约 30 KB / 109 次分配 | 1.02–1.11 μs，656 B / 14 次分配 | 三轮 benchmark，双方每次上游查询数都是零 |
| DEBUG 控制台每条写入耗时 20 ms，模拟连接约 1.1 ms | 返回约 82 ms，缓存 RTT 约 21.3 ms | 返回 1.13–1.25 ms，RTT 1.09–1.15 ms | 三次；日志在连接计时之后排队 |

真实服务另测 `www.bilibili.com` 的本地 UDP Fake-IP 查询，每个地址族 2000 次。旧版 warning 模式中位数 A=31.94 μs、AAAA=30.97 μs；新源码 warning 模式 A=31.07 μs、AAAA=31.53 μs。此路径不经过真实来源 DNS 缓存，应视为中位数相近，不能套用上述来源缓存的提升倍数。公网 HTTPS 验证中 `bbs.pcbeta.com`、`www.bilibili.com`、Cloudflare trace 均返回 200。

## 行为与边界

- UDP 将地址准备和 socket 写入分开。DIRECT 每个 association 最多同时准备 8 个目标；其他适配器默认串行解析。准备好的目标不等待新目标 DNS。同一目标保持包序，所有 socket 写入仍由同一个循环执行。总待发包预算为 128，关闭取消准备并逐包释放。精确映射包含目的端口，保留 ICMP 差错回报。
- 第一次 UDP association 创建仍按真实目的地址选接口并登记防回环；这次优化针对 association 建立后的目的地准备，不把未解析 Fake-IP 用于提前选择 socket。
- 显式缓存失效立即发布 ErrInvalidated 并取消旧 worker。取消某一个等待者仍不取消其他人的共享刷新；旧 worker 即使忽略取消，也不能覆盖新结果、移除新 flight 或写入失败退避。
- 出站需要协议握手时，立即结束可选的首字节 Peek，发送已经缓冲的数据或空握手；成功后才消费缓冲。后续数据继续通过 relay。嗅探仍在规则选择之前执行，TLS 分片和域名选路所需等待保持原语义。
- 缓存连接预算到期后，释放其他候选并保留已有尝试，每个地址最多拨号一次。普通双栈偏好窗口保持从完整竞争开始计算。失败退避排除调用者取消；未交付 socket 和 held fallback 在结束时关闭。单缓存目标的 TFO 语义保留。
- 网络采样按接口合并并缓存最多 250 ms；事件和接口身份变化触发重采样。Linux 地址事件也参与失效。平台提供的网络身份优先，稳定桌面缓存仍采用原 `/16` 分区；持续切网使用独立 transition scope，避免复用旧分区。
- DEBUG 控制台只有一个 worker、256 项队列，满队列计数并丢弃。事件时间和 fields 在产生时保存；INFO/WARNING/ERROR 输出及日志订阅接口保持原语义。RTT 在日志之前测量，未完成 TFO 握手时标记未知，不保存伪造的零耗时样本。

## 验证

新增回归测试覆盖 UDP 同目标包序、不同端口、单 socket 写入、128 项总预算、并发 Send/Close 的一次释放、ICMP 包装、无首包握手、迟到首包、失败重试缓冲、共享等待者取消、忽略取消的旧缓存 worker、接口采样合并/切网、双方地址族偏好、偏好窗口先于成功到期、held 连接取消，以及慢 DEBUG 输出和队列溢出。

依赖补丁链通过。受影响的 dev_cache、dialer、DNS、tunnel、sniffer、common/net、log、controller 和 outbound 测试通过 `-race -short -p 2`；sing-tun、ping、sing-mux 的对应检查通过。`-short` 排除原有运行数分钟的 Wi-Fi 分布模拟，本次直接使用定向延迟对照。amd64-v3 release 构建和原配置校验通过，本地服务经包管理器替换，配置校验和保持不变。

按仓库要求从已提交的修复版本采集 300 秒真实服务 CPU profile，并更新 `default.pgo`。启动时启用 profiler，随后把运行日志恢复为 warning；profile 包含开始阶段的 DEBUG 检查及真实代理流量。CPU 样本合计 3.99 秒，占该采样时段 1.33%；负载与之前采样不同，不据此宣称 CPU 占用下降。

## Fake-IP 持久化查询

后续修复针对 `store-fake-ip: true`：分配器原先持锁执行两次 `DB.Batch`，每次等待默认 10 ms 合并窗口。现在一次 `DB.Update` 原子写入正反映射，循环复用时在同一事务删除旧映射。已有持久化映射的 Lookup、LookBack、Exist 使用数据库读快照，不再争用分配锁；内存模式保留原有池锁和容量规则。

新映射仍在事务提交完成后返回，没有异步写入队列。提交失败会恢复分配器游标及循环标志；A/AAAA 返回 DNS 错误，不会发布仍属于旧域名的地址。HTTPS/SVCB 删除分配失败地址族的 hint 及对应 mandatory 引用，保留其他参数。清理和保存状态与分配串行，重开数据库验证旧映射清理及双栈恢复。

数据库写入 meta 页后、最后一次磁盘同步结束前，新读事务可能已经看到这次写入。因此持久化 store 仅为受写入影响的键暂存此前已确认的值；提交结果返回前，正向和反向查询使用这些旧值，其他键继续读取数据库。确认成功后再发布新值；同步失败时继续隐藏未确认值，下一次成功写入、保存状态或清理会在同一事务修复它们。保护锁不会跨越磁盘同步或 Batch 合并等待。同一缓存文件、同一地址族的多个 store 调用共享保护，内存池和 IPv4/IPv6 存储隔离保持原有行为。数据库重映射及元数据锁仍可能引入短暂等待，这项修复不承诺所有数据库读操作零等待。保护作用于运行中的映射可见性；若同步失败后立即异常退出且未完成后续修复，重启恢复仍受数据库实际落盘内容影响。

同机临时数据库的三轮新映射计时从 20.46–20.55 ms 降为 21.7–27.5 μs；这个存储位置不能代表实际服务磁盘的提交成本。故意阻塞写事务时，已有映射的三种读操作合计 12–56 μs，且新映射仍须等写事务释放。真实 DNS 总耗时还可能包含域名 bundle 查询、磁盘提交和调度等待，不能把本地分配耗时当成完整 DNS 耗时。

回归测试覆盖 IPv4/IPv6 读快路径、绕过 Batch 定时器、循环复用的完整读快照、事务失败回滚、清理后重开、正常保存后重开和分配/清理/保存的并发竞争，并覆盖 meta 已可见但提交结果未返回、同步失败后的重试/保存/清理及重开、连续失败的临时键数量。另用临时依赖副本向 bbolt 最终同步注入暂停和 EIO，核对实际失败阶段；生产依赖不含故障注入。Fake-IP、cachefile、DNS、tunnel 的 `-race -short` 检查通过。

## 2026-10-04：缓存命中与连接日志的小改动

基线是 `6dfe9f92` 的生产源码。改动只涉及三处：

- domain bundle 命中复用第一次缓存读取，跳过普通记录缓存及 question key 的构造；A/AAAA 只深拷贝返回的 Additional，HTTPS 只深拷贝返回的 Answer/Authority。完整 bundle 仍保存在缓存中，调用者不能通过修改回复污染缓存。TTL、缺少地址族时的 Fake-IP TTL、过期后台刷新和旧服务端回退保持原行为。
- UDP 准备缓存直接使用可比较的 `netip.Addr`，不再每包将 IP 转成字符串。Host 仍优先于 IP，目的端口仍参与区分；socket 写入、准备并发度和队列预算未调整。
- `logMetadata` 在格式化连接 INFO 参数前检查 `log.Enabled(INFO)`。warning 控制台没有 INFO 消费者时跳过格式化，存在 INFO 订阅者时照常发送事件。

两侧均应用同一依赖补丁、使用 trimmed tags、Go 1.27.1、GOAMD64=v3、GOEXPERIMENT=simd 和同一 `default.pgo` 编译。仍是 CachyOS、Intel 6 核 12 线程、8 GB 内存，GOMAXPROCS=3，测试进程绑定 CPU 0/1/2。保存修改前后的测试二进制后，交替执行五轮，每场景每轮 100000 次；第二、四轮先执行修改版，其他轮次先执行基线。所有轮次均纳入下表，单位为 **μs**。

avg 和 p99 是五轮各自统计的中位数；p100 是五轮全部 500000 个样本中的最大值，不能当作未来请求的延迟上界。每次操作的计时包含函数调用边界，`ns/op` 则还包含采样循环成本。并发场景的 avg 测量每次调用的耗时，不能用 Go benchmark 的吞吐 `ns/op` 代替。

| 场景 | avg 前 → 后 | p99 前 → 后 | p100 前 → 后 |
| --- | --- | --- | --- |
| bundle A，串行 | 1.526 → 0.791 | 3.582 → 1.434 | 193.319 → 359.217 |
| bundle AAAA，串行 | 1.529 → 0.801 | 3.588 → 2.502 | 282.567 → 169.185 |
| bundle HTTPS，串行 | 1.458 → 0.767 | 3.520 → 2.419 | 420.147 → 172.192 |
| bundle A，3 worker | 2.547 → 1.343 | 7.664 → 4.601 | 1837.057 → 2769.916 |
| bundle AAAA，3 worker | 2.507 → 1.275 | 7.423 → 4.645 | 1766.012 → 1800.973 |
| bundle HTTPS，3 worker | 2.455 → 1.301 | 7.319 → 4.857 | 3401.234 → 2777.651 |
| 已准备 UDP IPv4 | 0.243 → 0.184 | 0.468 → 0.225 | 129.582 → 143.046 |
| 已准备 UDP IPv6 | 0.365 → 0.183 | 0.597 → 0.227 | 86.230 → 72.130 |
| 已准备 UDP FQDN | 0.228 → 0.217 | 0.265 → 0.259 | 142.404 → 154.583 |
| 无 INFO 消费者的连接日志 | 0.558 → 0.024 | 0.873 → 0.026 | 217.832 → 19.491 |

串行 bundle A/AAAA 从 1120 B、28 次分配降至 608 B、14 次，HTTPS 从 1104 B、27 次降至 632 B、15 次。UDP IPv4/IPv6 每次分配从 4 次降至 2 次；禁用的连接 INFO 格式化从 232 B、16 次降为零分配。

测量边界：bundle benchmark 用替身选择固定节点并命中预填缓存，保留双栈地址、HTTPS ALPN/hint/ECH 和 EDNS option，不测真实规则匹配、上游 DNS、持久化 Fake-IP 或客户端 socket。UDP benchmark 覆盖已准备目标的两次查找和 `processPacket`，WriteTo 使用内存替身，不包含发送队列调度和内核网络。日志 benchmark 使用 warning 控制台且没有日志订阅者。**这些结果确认 avg/p99 的下降；p100 有场景升高，尚未确认整体最大延迟改善。** 本轮没有为异常最大值分别采集 GC/调度证据，也没有测公网端到端延迟。

benchmark 保存在 `dns/domain_client_bench_test.go`、`tunnel/internal_latency_bench_test.go`。可在两个版本各自编译测试二进制后交替重跑以下命令（先按根目录 `SKILL.md` 应用依赖补丁并使用上述构建参数）：

```bash
GOMAXPROCS=3 taskset -c 0,1,2 ./dns.test -test.run '^$' \
  -test.bench '^BenchmarkDomainBundleCacheHit$' -test.benchtime 100000x
GOMAXPROCS=3 taskset -c 0,1,2 ./tunnel.test -test.run '^$' \
  -test.bench '^(BenchmarkPreparedUDP|BenchmarkConnectionLogDisabled)$' \
  -test.benchtime 100000x
```

DNS、tunnel、Fake-IP、dev_cache、log 的 `-race -short -p 2` 检查通过。新增回归验证回复中的 IP、ECH、hint、EDNS option 和 TTL 修改不污染完整缓存，IPv4/IPv6/zone/mapped IP 的 UDP 端口身份，以及 warning 控制台下 INFO 订阅者的事件交付。amd64-v3 release 构建通过；首轮仅构建，后续替换见下一节。

## 继续检查与本机替换

用户授权替换后，继续做了四项局部修改：

- Sing UDP waiter 在构造包装器时初始化一次，避免每次读取重建底层回调；读取错误、空包和正常包的 buffer 释放规则保持一致。
- 原生 UDP 仅在实际收到非空数据后创建交付给调用者的释放回调。EAGAIN、空数据报和截断直接归还 buffer，不跨 netpoll 等待持有 buffer。
- domain bundle 日志的 scope 提取改为 `strings.Cut`，省掉 `strings.SplitN` 每次命中的临时 slice 分配。
- DNS 选路 metadata 直接设置 TCP/INNER/443，省掉 host:port 的拼接、拆分和固定端口解析。IP literal 仍通过 `netip.ParseAddr` 并执行 `Unmap()`；含括号的罕见输入保留原解析路径，覆盖大小写、尾点、IPv4、IPv6、mapped IP、zone 和异常输入的兼容测试。

首次优化后的并发 bundle profile 显示：约 7.4% 的采样分配对象来自 `strings.genSplit`；约 180 ms 的累计 mutex delay 主要位于缓存读取及网络 scope 读取。后者是多个调用的累计等待，不是某个请求的 p100，也不能据此解释真实服务的 15.7 ms 样本。本轮没有改缓存锁结构、调度策略或缓冲区大小，诊断 profile 没有写入 `default.pgo`。

追加对照与上一节使用相同构建条件和采样方式，基线为首轮优化后的代码；UDP 读取基线仍使用该路径原有源码。正式五轮计时没有并行运行构建或回归测试。新增 benchmark 位于 `common/net/packet/packet_read_bench_test.go`、`packet_posix_bench_test.go`，以及 `tunnel/internal_latency_bench_test.go` 的 `BenchmarkTunnelDNSMatchTarget`。下表单位为 **μs**，avg/p99 为五轮中位数，p100 为全部 500000 个样本的最大值。

| 场景 | avg 前 → 后 | p99 前 → 后 | p100 前 → 后 | 分配次数前 → 后 |
| --- | --- | --- | --- | --- |
| Sing callback-backed UDP 读取 | 0.213 → 0.192 | 0.476 → 0.448 | 444.916 → 546.009 | 5 → 4 |
| 原生 UDP，先 EAGAIN 再收到包 | 3.697 → 3.675 | 6.249 → 6.133 | 633.969 → 656.289 | 11 → 10 |
| DNS 选路 metadata，域名 | 0.234 → 0.177 | 0.734 → 0.912 | 606.286 → 606.568 | 3 → 2 |
| DNS 选路 metadata，IPv4 | 0.215 → 0.150 | 0.950 → 0.809 | 545.806 → 415.890 | 2 → 1 |
| DNS 选路 metadata，IPv6 | 0.241 → 0.173 | 0.810 → 0.702 | 203.509 → 476.364 | 2 → 1 |
| bundle A 串行，scope 提取 | 0.847 → 0.812 | 2.178 → 1.748 | 747.675 → 688.346 | 14 → 13 |
| bundle AAAA 串行，scope 提取 | 0.867 → 0.841 | 2.637 → 2.581 | 806.500 → 562.946 | 14 → 13 |
| bundle HTTPS 串行，scope 提取 | 0.807 → 0.804 | 2.471 → 2.552 | 668.422 → 564.353 | 15 → 14 |

Sing 读取从 148 B 降至 132 B；原生冷读 benchmark 从约 289 B 降至 256 B。冷读测试在第一次 EAGAIN 后才向本地 socket 写入 1200 B，包含真实系统调用和测试注入器的成本，不能当成生产读循环的完整分配数量。scope 提取每次少 32 B；3 worker 下 A/AAAA/HTTPS 的 avg 分别为 1.402→1.371、1.437→1.430、1.407→1.350 μs，p99 为 5.022→4.880、5.220→4.943、5.125→5.069 μs；三者 p100 都没有下降。追加改动的主要确定收益是减少分配和局部平均耗时，尚不能确认普遍降低 p100。

### 真实服务 DNS 与部署验证

通过 pacman 安装本地包 `9999:dev.r6dfe9f92.latency-5`，运行版本标记为 `6dfe9f92-latency`，来自当前 dev 工作区源码，包含两轮修改；版本标记不代表新增 Git 提交。包使用 canonical 依赖补丁、trimmed tags、GOAMD64=v3、GOEXPERIMENT=simd 和原 `default.pgo` 构建。安装后二进制校验和与构建产物一致，服务及 TPROXY 正常。

`config.yaml`、`tproxy.toml`、`direct4.cidr`、`direct6.cidr` 的内容、uid/gid 和权限与替换前一致。pacman 完整性检查仅报告原有的自定义 `config.yaml` 与包默认值不同，二进制及其余文件一致；没有把配置改成包默认值。候选二进制先在隔离的配置资源副本上通过原配置校验，旧二进制保存在本机私有临时目录用于回退。

向 `127.0.0.1:53` 连续发送 `www.bilibili.com` 的 A/AAAA UDP 查询，使用同一 Python socket 计时实现、同一运行配置和 warning 日志。每组先预热 100 次，再记录 4000 次，共三轮，每地址族每侧 12000 个样本；此计时包含客户端、内核、透明代理路径及 DNS 服务，不是单个函数的耗时。表中 avg/p99 为三轮中位数，p100 为三个轮次的最大值，单位为 **μs**。

| 地址族/状态 | avg | p99 | p100 |
| --- | --- | --- | --- |
| A，替换前 | 44.137 | 105.209 | 867.092 |
| A，替换后首次采样 | 46.733 | 115.970 | 969.462 |
| A，替换后稳定状态复测 | 45.828 | 104.178 | 823.371 |
| AAAA，替换前 | 45.895 | 106.495 | 15709.111 |
| AAAA，替换后首次采样 | 46.850 | 113.965 | 763.898 |
| AAAA，替换后稳定状态复测 | 45.311 | 101.358 | 551.053 |

首次替换后采样与安装完整性检查有短暂重叠，因此在服务稳定且无构建/检查并行后又完整测了三轮，上表同时保留两组结果。所有样本的 DNS RCODE 为成功且包含答案。真实 DNS avg 大体相近，不能据此宣称整体平均延迟明显下降；稳定状态下 p99 小幅下降，未重现基线的一次 15.7 ms 尖峰，但不承诺未来最大值或将其消失归因于某项改动。

追加的 common/net/packet、common/net、DNS、tunnel、log `-race -short -p 2` 检查通过；安装包管理脚本的 5 项测试通过。替换前后，经原 mixed 入口访问 Cloudflare trace、Bilibili 均返回 HTTP 200。未修改节点选择、规则、DNS 设置或进程调度配置。
