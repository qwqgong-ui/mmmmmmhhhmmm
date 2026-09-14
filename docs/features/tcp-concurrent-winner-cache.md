# TCP Concurrent Winner Cache

[返回功能目录](../features.md) · [配置示例](../config.yaml)

缓存 `tcp-concurrent` 最近成功连接的至多两个地址，按连接耗时排序；确认地址仍属于当前 DNS 候选后同时尝试，并在失败或超时后回退正常并发连接。默认最多 4096 个目的地，30 分钟为刷新期限，不因时间到期删除；失败地址保留但暂缓优先尝试，成功连接才更新记录。渐进式 DIRECT 也使用同一缓存。存储、分区和持久化统一由 [dev_cache](dev-cache.md) 管理。命中地址的 RTT 用于自适应 fast-path 超时；TCP 并发拨号不使用 TFO，以获得真实连接结果。手动 flush DNS 缓存会一并清理该缓存。

Patches:

- `component/dialer.patch`
- `hub/route.patch`

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
