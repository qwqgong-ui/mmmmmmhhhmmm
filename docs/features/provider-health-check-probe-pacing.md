# Provider Health-Check Probe Pacing

[返回功能目录](../features.md) · [配置示例](../config.yaml)

在 provider、手动单节点 API 和整组测速之间共享启动节拍，以随机 15–50 ms 间隔错开 probe，同时保留既有并发上限。provider 在排队后才启动单次探测超时；同一次探测只等待一次偏移。排队期间取消的测速不会将节点标记为不可用。

Patches:

- `adapter/provider.patch`

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
