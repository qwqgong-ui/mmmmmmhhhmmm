# Runtime IPv6 Availability Handling

[返回功能目录](../features.md) · [配置示例](../config.yaml)

配置 `ipv6: true` 时，Linux、Windows 与 macOS 监听接口和路由变化，事件静默 500ms 后复检物理网络 IPv6；不再是仅在配置解析时单向关闭。检测排除 Mihomo TUN、ULA、链路本地、Teredo、6to4 和已知隧道接口，配置解析与运行时监控共用同一份检测实现（`config.SystemIPv6Available`）。检测到可用时自动恢复运行时 IPv6，检测到失效时自动关闭，并保留 DNS、Fake-IP 与 TUN 的原始 IPv6 配置供之后恢复，无需重新加载配置。

状态切换通过 `hub/executor` mux 与 `resolver.DisableIPv6`（`atomic.Bool`）原子完成，重建对应 DNS 路径，并对 Mihomo 自建 TUN 增删 IPv6 配置。Android 核心不启动网络监听，由宿主的网络切换流程负责重新加载；外部传入文件描述符的 TUN（Android 等）不会被重启，以免关闭宿主 VPN 会话。REST API 的 `PATCH /configs` 的 `ipv6`/`tun` 字段现在都经过该控制器，而不是直接改写 resolver 或监听器。

桌面网络监听也负责刷新 HY2 叶节点的 MTU 缓存，因此 `ipv6: false` 时仍监听网络事件，但不会启用 IPv6。

Patches:

- `component/dialer.patch`
- `component/resolver.patch`
- `config.patch`
- `hub/executor.patch`
- `hub/route.patch`

> `Patches` 为迁移前的源码分组索引；实现与依赖补丁边界见[功能目录说明](../features.md)。
