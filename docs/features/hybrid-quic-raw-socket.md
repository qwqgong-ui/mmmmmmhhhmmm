# Hybrid QUIC raw 路径的连接化与零分配

[返回功能目录](../features.md) · [专题](../hybrid-quic.md)

raw 路径只搬运内层 QUIC 的短包头数据报，收发在每个包上重复同样的工作。本次只改这条路径的开销和可观测性，不动它的状态机：探测超时、raw socket 失败和 15 秒静默仍是永久回退的唯一原因，raw 仍不会自动恢复。

## socket 连接化

raw socket 仍按节点原有的 interface/routing-mark 选项监听，之后 connect 到终端返回的 relay。内核因此把路由留在 socket 上而不必逐包查找，在包进入接收循环前丢掉其他来源，并回报这条路径的 ICMP 差错；发送不再附目的地址，接收不再比较来源。connect 失败的平台保留原来的未连接 socket，改为按 addr:port 比较来源，不再格式化成字符串。

ICMP 差错只计数，不作为回退依据：未连接 socket 原本看不到它们，把它们当作 socket 失效会让 raw 在本可继续工作时提前放弃。

收发缓冲区各请求 1 MiB，由内核上限（Linux 的 `net.core.rmem_max`）裁剪，设不上去时维持系统默认。

## 每包分配

接收一个数据报原本要 9 次分配、约 1.5 KiB：6 次把来源和 relay 分别格式化成字符串来比较，1 次复制给读取方，2 次构造随包返回的地址。现在来源比较无分配，复制改用缓冲池并在 `ReadFrom` 拷出后归还，地址在注册时构造一次、只读共享；流方向的 2 字节封帧同样改用缓冲池。

同机基准（amd64，1350 字节数据报）：来源比较 113.6 ns / 6 allocs → 4.0 ns / 0；复制 132.2 ns / 1 alloc → 20.4 ns / 0；封帧 139.0 ns / 1 alloc → 24.7 ns / 0。这是单个操作的微基准，不是端到端吞吐或 CPU 结论。

## 锁

raw 的禁用状态、活动标记和最后一次 raw 回包时间改为原子量，接收路径不再为记录活动而等待发送路径的锁。发送仍由单个 writeMu 串行化，回退通知与流写入的顺序不变；读取方一律先看禁用状态，因此与回退竞争的激活不会让 raw 复活。

## 计数

`GET /hybrid-quic/flows` 的每条 flow 与 `GET /hybrid-quic/stats` 的进程累计值新增 `counters`：raw 与 stream 两条路径各自的收发包数和字节数、`rawDropped`（来源不符或不是短包头而丢弃）、`rawErrors`（连接化 socket 收到的 ICMP 差错）。flow 另有 `rawConnected` 表示该 socket 是否连接成功。

这些是诊断计数，不是账目：flow 关闭时把计数折算进进程累计值，此刻仍在其 goroutine 上投递的数据报不再计入。raw 路径看不到内层 QUIC 的包号（短包头的包号是加密的），因此客户端无法据此统计 raw 的丢包或乱序。

## 实现与验证入口

- [raw socket](../../component/hybrid/rawsock.go)、[connect](../../component/hybrid/connect_unix.go)、[收发与状态](../../component/hybrid/client.go)、[计数](../../component/hybrid/diagnostics.go)
- [回归测试](../../component/hybrid/raw_test.go)
