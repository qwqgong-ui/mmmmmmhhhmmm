# direct-nameserver 渐进解析与网络缓存

[返回功能目录](../features.md) · [配置示例](../config.yaml)

仅为 `direct-nameserver` 提供渐进候选接口。冷缓存按配置顺序查询，前一个失败或无地址才尝试下一个；
有效应答缓存命中时不发新查询。应答到刷新期限后，先交付保留的来源候选，再独立刷新到期来源，
任意来源返回地址即可交给 DIRECT TCP 开始竞争，不必等待全部 DNS 查询结束。
来源候选不设最大陈旧年龄，刷新失败继续保留，成功才替换；这些候选用于连接尝试，不表示 DNS 应答仍然新鲜。统一生命周期见 [dev_cache](dev-cache.md)。
`direct-nameserver-follow-policy` 命中策略时按策略解析。

候选缓存按物理网络分区；桌面只使用内网 IPv4 `/16` 子网，忽略 IPv6 和主机位变化，Android 由宿主指定网络身份。
网络切换可重新选择已有分区，宿主淘汰网络时可单独删除对应候选。
实现入口：[DNS 候选](../../dns/direct_candidates.go)、[渐进拨号](../../component/dialer/direct_progressive.go)、
[网络作用域](../../component/dialer/direct_scope.go)。
