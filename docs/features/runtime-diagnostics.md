# 运行时诊断与结构化状态日志

[返回功能目录](../features.md)

External controller 提供以下诊断接口；配置 `secret` 时均要求 Bearer 认证。诊断信息含域名、节点及接口信息，不应把无认证的 controller 暴露到公网。

- `GET /network`：物理接口、network scope、IPv4/IPv6 可用性，以及 Auto ECS 的脱敏前缀、来源和 generation。
- `GET /dns/cache[?name=]`：普通、DIRECT、逐上游缓存及服务器 domain bundle 的 fresh/stale、剩余 TTL、到期时间、scope、节点与记录摘要。最多返回 2000 条，提供 total/truncated；按域名查询可避免全量输出。
- `GET /dns/server-capabilities`：server-dns 与 domain-bundle 分别记录 supported/unsupported/expired、最近探测时间；未列出的节点是 unknown，不等于支持。
- `GET /direct/winners[?host=]`：TCP winner/RTT/scope，以及经 QUIC server CID + 1-RTT 确认的 UDP/QUIC warm winner。
- `GET /hybrid-quic/stats`：当前 registering/tunnel/probing/raw 数量与生命周期累计值。successRate = 曾进入 raw 的 flow 数 / 已开始的 flow 数；fallback 原因每个 flow 只计第一次，关闭后不保留活动记录。`counters` 是活动 flow 与已关闭 flow 计数之和。
- `GET /hybrid-quic/flows[?host=&port=&proxy=]`：活动 flow 的状态、目标、raw endpoint、raw socket 是否已连接、应用数据 idle 时间、probe 次数和最近一次 fallback 原因（回到 raw 时清空，`rawPermanent` 表示是否还能恢复）。keepalive 不刷新应用 idle。`counters` 分 raw 与 stream 两条路径统计收发包数和字节数，另有来源不符而丢弃的数据报数、raw socket 收到的 ICMP 差错数、回到可靠流的次数和进入 raw 的次数（超过 1 即为恢复）；短包头的包号是加密的，客户端无法据此统计 raw 的丢包或乱序。
- `GET /stats/downstream`：已接入的 DNS、DIRECT TCP、ICMP 报告、进程归属累计计数，另含 Hybrid 计数和慢日志订阅者丢弃数。计数随进程重启归零，不代表所有下游功能均已埋点。
- `GET /debug/path?host=example.com&port=443&network=tcp`：默认不发起 DNS 或目标连接，汇总规则预览、缓存来源、ECS、真实候选、缓存中的 HTTPS/SVCB/ECH 摘要、winner 与该目标的 Hybrid 活动状态。

## 主动检查与结果边界

追加 `resolve=true` 才主动查询。使用实际 DNS service 查询 A/AAAA/HTTPS/SVCB，因此能看到客户端收到的 Fake-IP hint，而不是绕过改写的默认 resolver 响应。仅确定为 DIRECT 的目标额外查询 direct-nameserver；代理目标不会因此额外向 DIRECT DNS 泄露域名。查询并行、有请求超时、最多同时处理 4 次主动诊断，逐项返回错误和耗时。主动查询会使用并更新正常 DNS 缓存，已有共享解析可能在请求结束后完成。

规则结果始终是 preview：请求没有真实客户端的源地址、进程、入站和嗅探信息；需额外 DNS 才能判断的 IP 规则会标记 complete=false。预览不增加规则命中/未命中计数。DNS service 的服务器节点选择仍按实际服务的 TCP/443 语义运行，不是假装能重放任意客户端连接。

候选采用当前网络分区中适用的 DIRECT 或选定节点缓存；[dev_cache](dev-cache.md) 的陈旧答案仍可使用，`refreshDue` 不等于不可用。无记录返回 candidatesKnown=false。旧网络记录不会自动视为当前候选。TCP winner 附自己的端口、scope、排序和重试退避；QUIC warm cache 原本不保留 RTT、端口、scope，接口明确标记未知，不能据此认定当前连接一定可用。每条 DNS 缓存不保存 ECS generation，因此 ecsGenerationKnown=false；顶层 ECS 是当前状态，不倒推历史值。

ECH 仅表示是否携带配置，不输出密钥材料，也不证明握手成功。AD/RRSIG 是观测值，不是诊断接口做了独立 DNSSEC 验证。

## 日志与开销

`GET /logs?format=structured` 现在携带事件时间及结构字段；可追加
`subsystem=dns`（或 direct/hybrid/network/provider/tun/process）精确过滤；也支持 event、flow_id、network_scope、host、proxy、reason。多个字段同时指定时全部满足才输出。默认格式仍为 type/payload，结构化格式保留 time/level/message/fields。

新增 INFO 集中记录状态转换、缓存加载/写盘结果和失效事件，不把每次缓存命中升级为 INFO。DEBUG 解释 DNS 缓存/上游/TC 重试、Fake-IP hint 与 DNSSEC 改写、DIRECT TCP 候选/预算/连接结果、QUIC 确认、Hybrid 注册/探测/回退、ICMP 报告结果和进程筛选。

控制台 INFO 与 `/logs?level=debug` 独立；仅有 DEBUG 消费者时才启用详细诊断。新增昂贵 DEBUG 参数受 Enabled 检查保护，无消费者时不构造详情；普通连接的既有日志保持兼容。慢订阅者使用有界队列，丢弃事件而不阻塞转发；HTTP 取消和 WebSocket 关闭会释放订阅。没有新增周期探测或诊断定时器，计数使用固定原子变量；快照按 API 请求生成。

这些措施限制软件层面的额外成本，不等于已完成设备功耗测试。尚未覆盖的细粒度信息包括所有 DIRECT QUIC CID 分歧/确认超时原因、ICMP 底层最终写入的 type/code，以及全部下游功能的 hit/miss 计数；接口不伪造这些数据。
