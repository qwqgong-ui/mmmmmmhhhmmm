# Generic Hybrid QUIC

[返回功能目录](../features.md) · [配置示例](../config.yaml)

在支持保留域名的代理节点上设置 `hybrid-quic: true`，默认关闭；支持 VLESS、Trojan、
Shadowsocks、HY2 等流代理，DIRECT、REJECT 和仅承载 IP 的隧道不能启用。
只接管以 QUIC Initial 开始的公网 UDP 443 流，其他 UDP 使用节点原生能力。

握手、控制和回退数据经所选节点到 `hybrid-quic.invalid:443` 的可靠流传输；只有这个入口
登记成功的会话才能建立 raw UDP 443 绑定，登记失败不会绕过入口改走原生 UDP。
终端 Xray 返回 raw UDP 端点；客户端通过可靠流登记实际探测包的 SHA-256 摘要，
终端匹配该原始 UDP 包及入口确认的来源 IP，绑定实际观察到的来源地址和端口。
终端先通过可靠流确认临时绑定，再选定一个真实 QUIC 回包作为反向探测；
同一轮保持该包不变，最多每 250 毫秒发送一次 raw 副本，业务数据继续走可靠流。
客户端只对 raw 实际收到的回包报告摘要，终端核对后才确认启用双向 raw。
没有反向确认时数据仍走可靠流；暂停或确认超时立即停止探测副本。
上行探测包已通过可靠流转发，不重复投递。
探测超时或 15 秒没有 raw 回复后本会话回到可靠流，但会重新探测；raw socket 失败仍然永久关闭。
零长度 CID 使用同样的地址和端口绑定，不修改 QUIC 数据、不添加 UDP 标记。
租约每次最多到服务器当前时间起 30 秒；客户端每 10 秒通过可靠流续约，可持续续约但不能累加。
raw 包和普通 keepalive 都不能续约；到期或可靠流关闭后绑定失效，到期数据回退可靠流。
协议为 `HQS2`，两端需配套升级；终端仍接受旧 `HQS1` 客户端，其行为不变。

raw socket 的连接化、缓冲区、每包分配和计数见
[raw 路径的连接化与零分配](hybrid-quic-raw-socket.md)；
回退后的恢复与重新探测见
[raw 路径的恢复与重新探测](hybrid-quic-raw-recovery.md)。

配置、Xray 多跳转发、源地址限制和 TCP 队头阻塞说明见 [Hybrid QUIC](../hybrid-quic.md)。
