# HY2 叶节点跨连接 MTU 缓存

[返回功能目录](../features.md)

每个实际 HY2 代理实例保留一份内存中的 QUIC MTU 探测结果，选择组和不同节点不共享。无需配置，不持久化，也不按定时 TTL 反复清空。同一节点重连及端口跳跃可以复用；服务器 IP 改变时换成空缓存。

握手仍使用保守的初始包大小。握手完成后，优先发一个缓存大小的确认探测包；收到 ACK 后扩大业务包大小。已完成的探测结果经过这一次确认即可恢复，不再重复二分搜索；未完成的结果则从已确认大小继续探测。缓存探测丢失时清除提示，保持初始业务包大小并恢复常规探测。QUIC 路径迁移也使旧提示失效。

桌面系统网络事件、TUN 默认接口变化以及 Android 宿主的网络环境更新或接口刷新递增网络代际。下一次拨号替换该叶节点的缓存对象，旧连接迟到的 ACK 无法污染新网络的结果。桌面网络监控在 `ipv6: false` 时也运行；IPv6 开关语义不变。

这是 mihomo 到 HY2 节点的外层 QUIC 优化。Hybrid raw 转发的浏览器 QUIC 仍由浏览器与目标站维护，BrowserLeaks 的 MTU 估算不能直接当作外层缓存值。

实现：`adapter/outbound/hysteria2.go`、`transport/tuic/common/mtu_cache.go`、`patches/quic-go/0002-reuse-leaf-path-mtu-discovery.patch` 及 `patches/quic-go/_files/`。构建前通过 `sh patches/apply-dependency-patches.sh` 应用依赖补丁。

回归测试覆盖缓存隔离、网络刷新、迟到 ACK、并发更新、peer 上限及缓存失败回退；真实 UDP/QUIC 集成测试比较首次连接与重连的探测次数，并模拟路径变窄。
