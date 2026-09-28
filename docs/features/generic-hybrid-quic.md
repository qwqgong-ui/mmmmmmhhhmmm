# Generic Hybrid QUIC

[返回功能目录](../features.md) · [配置示例](../config.yaml)

在支持保留域名的代理节点上设置 `hybrid-quic: true`，默认关闭；支持 VLESS、Trojan、
Shadowsocks、HY2 等流代理，DIRECT、REJECT 和仅承载 IP 的隧道不能启用。
只接管以 QUIC Initial 开始的公网 UDP 443 流，其他 UDP 使用节点原生能力。

握手、控制和回退数据经所选节点的可靠流传输；终端 Xray 返回 raw UDP 端点，raw 收到有效回复后启用。
探测超时或 15 秒没有 raw 回复后本会话回到可靠流，但会重新探测；raw socket 失败仍然永久关闭。
观察到零长度客户端 QUIC SCID 时（例如部分 Chrome 连接），该会话直接保持可靠流，
不探测 raw：共享端口上的首个 raw 回包无法通过客户端连接 ID 验证，强行切换会造成丢包和超时。
这不影响其他使用非空客户端连接 ID 的会话启用 raw；运行诊断中原因显示为 `zero_client_cid`。
协议为 `HQS1`，不兼容旧 HY2 `HQV3`，两端需配套升级。

raw socket 的连接化、缓冲区、每包分配和计数见
[raw 路径的连接化与零分配](hybrid-quic-raw-socket.md)；
回退后的恢复与重新探测见
[raw 路径的恢复与重新探测](hybrid-quic-raw-recovery.md)。

配置、Xray 多跳转发、源地址限制和 TCP 队头阻塞说明见 [Hybrid QUIC](../hybrid-quic.md)。
