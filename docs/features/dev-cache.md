# dev_cache 统一缓存

普通 DNS 应答、DIRECT 各来源候选、`server-dns.invalid:53` 的节点域名 bundle/记录、TCP winner 共用 `component/dev_cache` 的存储、刷新协调和持久化生命周期。

## 使用与刷新

- TTL/refresh deadline 只表示应该刷新，不代表旧值不可用；不设最大陈旧年龄。
- 命中旧值立即返回；到刷新时间才异步查询。同键工作合并，单个调用者取消不取消共享刷新。
- 上游超时、SERVFAIL、REFUSED、截断/不完整 bundle 不覆盖旧值；失败后退避 3 秒再尝试，旧值持续可用。
- 成功结果原子替换。同一 bundle 的 HTTPS/ECH、A、AAAA 一起替换，包含某个地址族为空的结果，不混用不同节点或不同批次。
- 陈旧 DNS 回复的客户端 TTL 为 3 秒。这个 TTL 不延长内部刷新期限。
- TCP winner 的 30 分钟期限也不删除记录。真实连接失败只暂缓优先尝试，保留地址；连接成功更新 RTT 和记录。winner 必须仍在当前候选集中，才进入快速拨号路径。
- 连接成功不延长 DNS TTL，也不把完整 DNS 答案改写成单个 winner。
- 仍使用现有容量和 LRU/ARC 冷条目替换。明确清理、网络退休或冷数据淘汰可以删除条目。
- 首次查询没有任何旧值时仍需要成功的上游应答；缓存不能凭空生成地址。

## 隔离

桌面网络 scope 只取当前物理接口的 RFC1918 内网 IPv4，统一使用 `255.255.0.0`（`/16`）掩码。忽略 IPv6、接口名字和 IPv4 主机位；例如 `192.168.1.2` 与 `192.168.200.9` 共享分区，`10.1.x.x` 与 `10.2.x.x` 分开。无法发现内网 IPv4 时 scope 为 `ipv4-private|unknown`。

Android 保留宿主 Wi-Fi/SIM 加物理路径指纹，通过现有 JNI 网络身份接口传入。切网选择不同分区，切回可复用；IPv6 可用性重建 resolver 时重新附着同一配置 namespace。网络退休统一删除 DNS、bundle 和 winner，并使该分区未完成的刷新无法写回。

DNS 按网络 scope、resolver/配置、域名、QTYPE/QCLASS 隔离；A/AAAA 分开。代理域名额外包含实际叶子节点，完整 bundle 内保留两个地址族。TCP key 包含网络 scope、域名、端口、TCP 地址族约束及配置的 DIRECT 出站/路由标记。

## 持久化与诊断

所有上述运行时缓存写入 `cache.db` 的版本化 `dev_cache_v1` bucket，每小时及正常退出时同步事务保存。恢复保留原刷新期限，过期条目仍可用；各类型使用独立 namespace/编码。旧版 `dnscache` 缺少可靠网络身份，保留原 bucket，但不自动混入新分区。

- `/dns/cache?name=example.com`：`state=stale`、`refreshDue=true` 与 `usable=true` 可以同时存在；`refreshing` 表示正在刷新，`retryAfter` 表示失败退避。`expiresAt` 为兼容字段，含义是刷新期限。
- `/direct/winners?host=example.com`：保留过期 winner 的快照，并显示刷新期限和失败重试时间；这不是连接可达性证明。
- `/network`：显示实际使用的网络 scope；IPv6 可用性信息不会参与桌面 scope。
- `/stats/downstream`：`dev_cache.refresh.*` 计数器。
- `/logs?format=structured&level=debug&subsystem=dev_cache`：`refresh_succeeded`、`refresh_failed`、`refresh_invalidated`，附带 `cache_kind`、`network_scope`、`retained`。

DEBUG 日志按控制台或订阅者需求启用，结构化日志的 `fields` 是 `key/value` 数组。诊断快照不主动查询上游、不改变 LRU 顺序。手动 DNS flush 同时清理统一缓存和磁盘快照；刷新中的旧代次不能撤销清理。
