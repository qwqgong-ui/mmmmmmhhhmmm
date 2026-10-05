# Reject-Rule Short-Circuit

[返回功能目录](../features.md) · [配置示例](../config.yaml)

命中 REJECT 或 REJECT-DROP 的连接在规则匹配后直接短路，不再拨出站、不再包装 deadline conn、traffic tracker 和双向 relay。TCP REJECT 立即关闭客户端连接；TCP REJECT-DROP 交给共享 parker 挂起，由单个按截止时间排序的 goroutine 统一释放，队列有上限以免洪水堆积 fd；UDP 在 nat 表中吸收整个会话，后续报文由已关闭的 sender 直接丢弃，不再重复匹配规则、拨号和打日志。`reject` 出站自身的 dropConn 同时成为真正的黑洞：写入被吞掉而不是报错。

TCP `REJECT` 还带有 failban 拒绝缓存：同一来源 IP 访问同一目标域名/IP 和端口，在任意 10 秒内累计被拒绝 10 次后，记录截止时间并封禁 1 分钟。源端口不计入缓存键，换端口重连仍会命中；不同入站类型、地址、名称、用户、指定代理/规则和 DSCP 分别计数。封禁针对来源和目标，不按进程区分。

封禁期间仍然立即关闭连接，不进入 `REJECT-DROP` 的挂起流程，也不重复匹配规则、启动连接 peek 或输出连接日志。计时从第 10 次拒绝开始，后续尝试不延长封禁；到期后恢复正常规则匹配，从零重新计数。触发时输出一条包含封禁截止时间的 INFO 日志。

计数和封禁合计最多保存 4096 个键，超限按 LRU 淘汰，不为每条记录创建计时器或 goroutine。规则、代理、模式、嗅探或进程查找设置更新会清空缓存；rule-provider 内容更新同步清空缓存，旧匹配结果不能在更新后重建封禁。命中缓存时会重新检查当前代理组的最终叶子，选择变成可用代理或 `REJECT-DROP` 时解除旧封禁。UDP 继续使用会话吸收机制。

Patches:

- `adapter/outbound.patch`
- `tunnel.patch`

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
