# Persisted DNS Answer Cache

[返回功能目录](../features.md) · [配置示例](../config.yaml)

DNS、代理域名 bundle 和 TCP winner 由 [dev_cache](dev-cache.md) 写入 `cache.db` 的 `dev_cache_v1` bucket，每小时及正常退出时 flush，启动载回。每条保留刷新期限，过期不删除；刷新失败继续使用旧值，成功才替换。旧 `dnscache` bucket 不自动迁移，因为无法可靠判断其物理网络来源。

载入必须由 `hub/executor` 在 DNS 就绪之后调用 `dns.LoadPersistentCache()` 触发，
**不能在 resolver 构造期间碰 `cachefile.Cache()`** —— 那是个单例，会把首次看到的路径永久锁定，
而此时运行时还没把 `C.Path` 指向 `-d` 目录，结果整个进程改去打开
`$HOME/.config/mihomo/cache.db`；在 systemd 下 root 无 HOME，打开失败、`DB` 为 nil，
fake-ip 池连带失去存储，所有 fake IP 反查失败。

写入用 `DB.Update` 而非 `DB.Batch`：`Batch` 会延迟提交以合并调用者，而关机路径在那之前就退出了。

`arc` 和 `lru` 两种 `cache-algorithm` 都支持，各自加了 `Snapshot()`：ARC 跳过 ghost 条目，
LRU 按最近最少使用顺序返回以便恢复时重放同样的 recency。两者在 `component/dev_cache` 归一化。

不同 resolver/配置、代理节点、网络和地址族的条目使用独立 namespace/key；完整 bundle 原子保存。

Patches:

- `common/arc.patch`
- `common/lru.patch`
- `component/profile.patch`
- `dns.patch`
- `hub/executor.patch`

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
