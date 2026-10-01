# DIRECT Dual-Stack Race

[返回功能目录](../features.md) · [配置示例](../config.yaml)

重叠执行 DIRECT 的 A/AAAA 查询与 IPv4/IPv6 TCP、UDP 竞争，并接入近期 winner、resolver 超时和运行时 IPv6 能力门控。
DIRECT UDP/QUIC 在首批可用地址到达后即可建立关联、发送首包，不等待另一地址族完成；`direct-nameserver` 的保留候选也可直接启动。
后续地址仅在竞争尚未结束时加入。解析期间暂存最多 4 个、合计 16 KiB 的开场报文，向新候选补发时仍受原竞争字节预算约束；已有 winner 后不再加入或补发。
解析工作受关联关闭和 DNS 超时约束，建立关联后取消 setup context 不会中断后续候选。QUIC 仍由应用发出的服务器 CID 选择路径，并以 1-RTT CID 确认 warm winner。
Fake-IP ICMP 按目标 Fake-IP 的地址族查询 A 或 AAAA，仅在同族真实地址之间竞争，不进行 IPv4/IPv6 跨族竞争或回退。

Patches:

- `adapter/outbound.patch`
- `component/dialer.patch`
- `component/directrace.patch`
- `component/resolver.patch`
- `config.patch`
- `dns.patch`
- `listener/sing_tun.patch`
- `tunnel.patch`

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。

相关功能：[渐进解析与网络缓存](direct-nameserver-progressive-cache.md)、[DIRECT QUIC 胜出路径确认](direct-quic-winner-confirmation.md)。
