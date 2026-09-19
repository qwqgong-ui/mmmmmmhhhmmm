# Mihomo dev 下游修改索引

本文档记录 `dev` 分支相对上游 `Alpha` 保留的定制功能，按 2026-09-09 的源码整理。
配置示例见 [config.yaml](config.yaml)，专题见 [Hybrid QUIC](hybrid-quic.md) 和
[服务端域名 DNS bundle](domain-dns-bundle.md)。历史测试数据只代表对应修改时的结果，不代表本次重新验证。

Mihomo 补丁已在
2026-08-26 完整展开到 `dev` 源码，不再需要构建前应用 `patches/mihomo/series`。
各功能文档中的 `Patches` 列表仅保留为迁移前的源码分组索引，实际实现以
`dev` 分支中的 Go 源码和测试为准。quic-go、sing-quic、sing-tun 和 sing-mux 仍是外部
Go module，因此它们的补丁继续保存在 `patches/` 下并由构建流程应用。

## 功能目录

- [DNS 上游主机名优先使用 IPv6（DNS Upstream Hostname IPv6 Preference）](features/dns-upstream-hostname-ipv6-preference.md)
- [Linux 基于连接端点的进程归属识别（Linux Endpoint-Aware Process Attribution）](features/linux-endpoint-aware-process-attribution.md)
- [远端 UDP 目的地身份保留（Remote UDP Destination Identity）](features/remote-udp-destination-identity.md)
- [可选协议构建标签（Optional Protocol Build Tags）](features/optional-protocol-build-tags.md)
- [DIRECT 双栈竞争（DIRECT Dual-Stack Race）](features/direct-dual-stack-race.md)
- [direct-nameserver 渐进解析与网络缓存](features/direct-nameserver-progressive-cache.md)
- [DIRECT QUIC 胜出路径确认](features/direct-quic-winner-confirmation.md)
- [Fake-IP ICMP 处理（Fake-IP ICMP Handling）](features/fake-ip-icmp-handling.md)
- [直连 UDP 的 ICMP 差错回报（Direct UDP ICMP Errors）](features/direct-udp-icmp-errors.md)
- [运行时 IPv6 可用性管理（Runtime IPv6 Availability Handling）](features/runtime-ipv6-availability-handling.md)
- [Fake-IP 主机名校验（Fake-IP Host-Name Validation）](features/fake-ip-host-name-validation.md)
- [Fake-IP HTTPS/SVCB 地址提示合成（Fake-IP HTTPS/SVCB Hint Synthesis）](features/fake-ip-https-svcb-hint-synthesis.md)
- [内置 Fake-IP 服务记录解析器（Built-in Fake-IP Service Record Resolver）](features/built-in-fake-ip-service-record-resolver.md)
- [Fake-IP 完整域名路由（Fake-IP FQDN Routing）](features/fake-ip-fqdn-routing.md)
- [直连 DNS 自动添加 ECS（Direct-Nameserver Auto ECS）](features/direct-nameserver-auto-ecs.md)
- [进程规则候选的文件描述符扫描过滤（Process-Rule Candidate FD Filtering）](features/process-rule-candidate-fd-filtering.md)
- [物理网络 DNS 拨号（Physical-Network DNS Dialing）](features/physical-network-dns-dialing.md)
- [TCP 并发胜出地址缓存（TCP Concurrent Winner Cache）](features/tcp-concurrent-winner-cache.md)
- [代理提供者健康检查探测间隔控制（Provider Health-Check Probe Pacing）](features/provider-health-check-probe-pacing.md)
- [通用混合 QUIC（Generic Hybrid QUIC）](features/generic-hybrid-quic.md)
- [Hybrid QUIC raw 路径的连接化与零分配](features/hybrid-quic-raw-socket.md)
- [运行时诊断与结构化状态日志](features/runtime-diagnostics.md)
- [dev_cache 统一缓存、刷新与网络隔离](features/dev-cache.md)
- [AndroidCyaml 集成（AndroidCyaml Integration）](features/androidcyaml-integration.md)
- [HY2 支持 ECN 反馈的 BBR（HY2 ECN-Aware BBR）](features/hy2-ecn-aware-bbr.md)
- [HY2 使用 QUIC v2（HY2 QUIC v2）](features/hy2-quic-v2.md)
- [HY2 叶节点跨连接 MTU 缓存](features/hy2-leaf-mtu-cache.md)
- [HY2 UDP 按序交付（HY2 Ordered UDP Delivery）](features/hy2-ordered-udp-delivery.md)
- [拒绝规则提前结束处理（Reject-Rule Short-Circuit）](features/reject-rule-short-circuit.md)
- [DNS 默认超时 3 秒（3s Default DNS Timeout）](features/3s-default-dns-timeout.md)
- [扩大 DNS 缓存并延长乐观缓存 TTL（Larger DNS Cache and Softer Optimistic TTL）](features/larger-dns-cache-and-softer-optimistic-ttl.md)
- [DNS 应答缓存持久化（Persisted DNS Answer Cache）](features/persisted-dns-answer-cache.md)
- [sing-tun 系统协议栈（sing-tun System Stack）](features/sing-tun-system-stack.md)
- [sing-tun ICMP 探测（sing-tun ICMP Ping）](features/sing-tun-icmp-ping.md)
- [Go 1.26 语言版本（Go 1.26 Language Version）](features/go-1-26-language-version.md)
- [MPTCP 监听器防护（MPTCP Listener Guards）](features/mptcp-listener-guards.md)
- [恢复 GODEBUG 默认行为（GODEBUG Defaults Released）](features/godebug-defaults-released.md)
- [依赖安全升级（Dependency Security Upgrades）](features/dependency-security-upgrades.md)
- [sing-mux h2mux 兼容性修复（sing-mux h2mux）](features/sing-mux-h2mux.md)
