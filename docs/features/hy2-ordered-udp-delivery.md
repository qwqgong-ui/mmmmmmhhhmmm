# HY2 UDP 按序交付

[返回功能目录](../features.md)

sing-quic 的 HY2 客户端原本为每个收到的 QUIC datagram 启动一个 goroutine 解码和投递。同一批到达的连发包由不同 goroutine 并发写入会话队列，先后取决于调度，经 TUN 写回应用时顺序被调换。游戏等对乱序敏感的 UDP 应用会把迟到的旧包计为丢包。

补丁改为在接收循环内依次处理 datagram。投递不会阻塞接收：会话队列满时照旧丢弃，分片重组只持有短暂的锁。

2026-09-17 以战争雷霆实测，同时在本机 TUN、本机网卡和 HY2 服务器网卡抓包并按载荷逐包比对。修复前游戏包上下行均未丢失，但下行 8.3% 乱序，其中 149 对调换发生在本机；修复后本机造成的调换为 0，剩余乱序来自线路。游戏内显示的丢包率从约 50% 降至 0–16%。两次测量连接的游戏服务器不同，线路侧数值不可直接比较。

服务器网卡抓包会被 GRO 合并连发包，比对前须排除 IP 总长超过 MTU 或由多个包合成的记录，否则会误判为截断或拆包。

实现：`patches/sing-quic/0003-hysteria2-deliver-received-datagrams-in-order.patch`。构建前通过 `sh patches/apply-dependency-patches.sh` 应用依赖补丁。
