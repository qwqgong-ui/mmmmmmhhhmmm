# HY2 stream 数据通知按收包批次合并

HY2 TCP 下行在 QUIC STREAM 数据到达时唤醒 reader，再由 relay 写回本地 TCP。即使 relay 使用 32 KiB 缓冲区，reader 也可能只读到一两个 frame 就返回，形成大量小块 `write`。

当前实现仅对 HY2 客户端启用 `quic.Config.EnableStreamReadBatching`。握手完成后，如果一轮 `handlePackets` 开始时已有多个包排队，且该 stream 已被应用读取至少 64 KiB，就对本轮同一 stream 的普通数据通知去重，退出本轮时统一发出。保留原来的收包循环：只取当前已排队的包，队列一空立即结束，最多处理 32 包，不改变 ACK 发送调度。没有新增定时器、最小读取字节数或等待下一包的逻辑。

64 KiB 是基于已读取字节的优化资格判断，不是要求单次读取凑满 64 KiB。初始交换和短流的每次数据到达仍立即通知；跨过这一门槛的那次通知也不会被收回或延后。

## 行为边界

- 只调整已经收到的数据的通知时机，不改变 QUIC 包大小、加密、拥塞控制、ACK 规则或线上协议。
- 普通 `Read` 的语义不变：已经运行的 reader 有数据即可读取，数据不足时仍可短读。这个优化不能消除所有小块写回。
- FIN、reset、取消、deadline 变化和连接关闭仍立即通知。已知 FIN 或可靠 reset 之后，补齐缺口的数据也立即通知。
- 空队列不开始批次；正常结束、处理错误或达到包数上限都会释放已积累的通知。对同一 stream 的重复通知不新增分配，批次结束清理链表引用。
- 握手阶段不启用批次通知；其他 QUIC 客户端默认关闭这一开关。DIRECT、HY2 UDP datagram 和 Hybrid raw 的交付路径不经过此优化。

“不等待下一包”不等于零额外延迟：符合资格的阻塞 reader 的通知最多推迟到当前收包批次结束。32 包是数量上限，不是严格的耗时上限；已经传输较多数据的长连接仍需观察交互延迟与多 stream 公平性。

## 实现与验证

- HY2 启用点：`adapter/outbound/hysteria2.go`。
- quic-go 修改：`patches/quic-go/0005-batch-stream-read-notifications.patch`。
- 批次队列：`patches/quic-go/_files/stream_read_batch.go`。
- 回归测试：`patches/quic-go/_files/stream_read_batch_test.go`，覆盖真实 packet-parser 调用链、正常/错误退出、32 包限制、追加新包、单向/双向流、初始/门槛边界数据立即通知、普通读取、FIN/reset 缺口、取消、关闭、deadline，以及队列复用。

须先执行 `sh patches/apply-dependency-patches.sh <env-file>` 并使用输出的 `GOFLAGS`，再测试或构建。A/B 时应保持源码、Go 工具链、PGO 和协议配置一致，只改变 `EnableStreamReadBatching`，同时比较每 MiB 写调用次数、CPU、吞吐和交互延迟。

[2026-09-22 初版 A/B 实测](../benchmarks/2026-09-22-hy2-stream-read-batching.md)记录了未限制初始数据时的结果。当前版本已增加短流保护，不能直接套用初版的量化收益。

受限版本已替换本机正式服务；[v3 部署与验证](../benchmarks/2026-09-23-hy2-deployment.md)包含最终运行哈希、短请求测试、长流对照和原版本备份位置。
