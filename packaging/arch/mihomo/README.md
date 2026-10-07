# Arch/CachyOS Mihomo dev 包

包名是 `mihomo`，构建当前 dev 的 x86-64-v3 内核，替换 `mihomo-bin`。
它保留 `/usr/bin/mihomo`、`mihomo.service`、`/etc/mihomo/config.yaml` 的路径。
已有 `config.yaml` 在安装前备份、事务后恢复，不写入你的节点/订阅凭据。
`epoch=9999` 防止普通发行版本覆盖本地 dev 包。
安装且配置就绪后自动启用/重启 `mihomo.service`；systemd drop-in 在服务启动后
注册双栈 TCP/UDP TPROXY，在停止、升级重启和卸载时清理它拥有的规则。
默认使用纯 TPROXY，不要求开启 TUN。规则注册失败会使服务启动失败并输出错误。

## 配置前提

现有 `/etc/mihomo/config.yaml` 需要：

```yaml
tproxy-port: 17894
routing-mark: 666
```

`tun` 可以省略或设为 `enable: false`；同时开启 TUN 时必须关闭 `auto-redirect`。
升级保留已有配置，不自动改变用户的 TUN 开关。

不需要固定 `interface-name`。53 端口优先接管；DNS 请求的处理策略仍由
Mihomo 配置决定，例如 `DST-PORT,53,dns` 和 `type: dns` 出站。
Mihomo 自身的上游连接排除，避免 DNS 回环；systemd-resolved 的 TCP/UDP 53
查询照常接管，使用 NSS `resolve` 的程序也能收到 Fake-IP。
策略表同时注册 `lo` 和已配置地址的出口接口的本地路由，避免 resolved 的
`IP_UNICAST_IF`/`IPV6_UNICAST_IF` 接口约束绕过接管。IPv6 link-local DNS 的
原始作用域和回包接口保留，不把接口名当成无作用域地址。
`mihomo-tproxy-watch.service` 随主服务运行，监听接口/地址变化并更新自己拥有的
路由；注册或更新后清理 resolved 缓存，避免继续使用接管前的错误结果。
这不修改 NetworkManager、resolved、NSS 或现有 Mihomo DNS 上游配置。
包只接管本机流量，不接管其他设备的转发流量。

## 确定直连绕过

把确定可以直接访问的**真实目标 IP/CIDR**分别加入 `/etc/mihomo/direct4.cidr`
和 `/etc/mihomo/direct6.cidr`。放行时设置 `routing-mark` 相同的标记，由更优先
的 `ip rule` 查询 `main` 表。局域网/组播默认放行。
只有在主路由表本身没有指向代理/VPN 的路由时，`main` 才是物理直连出口。
不确定的地址保持接管；列表留空不会自动把中国 IP 或 Mihomo 的 DIRECT 规则导出。

**域名被返回 Fake-IP 时，仅排除真实 IP 列表不起作用。** 对确定直连的域名，
还需让现有 `fake-ip-filter` 返回 `real-ip`，并选择能返回真实地址的 DNS 上游。
不能排除 Fake-IP 网段；无论 CIDR 列表怎么配置，Fake-IP 和 53 端口都先接管。
共享 CDN 的 IP 不能仅因一个域名走 DIRECT 就全局排除。域名/进程/动态组规则
不能无条件转换为内核 IP 集合；本包不会这样做。

修改 CIDR 列表后用 `sudo systemctl restart mihomo` 应用。内核绕过的流量不会
出现在 Mihomo 连接列表、规则计数或流量统计里。

## 构建和安装

```bash
cd packaging/arch/mihomo
makepkg -s
sudo pacman -U "$(makepkg --packagelist)"
```

包使用本目录中版本控制的源文件；pacman 的 backup 机制保留已有 CIDR/TOML。
版本包含 dev 提交计数和短哈希，连续更新时能正常比较新旧版本。
`tproxy.toml` 可调整标记、路由表和优先级。启动前检查冲突，避免覆盖其他规则。
内核需支持 nftables TPROXY/socket、IPv4/IPv6 策略路由以及 cgroup v2 socket 匹配。

安装脚本会迁移旧 `30-transparent.conf`，保留备份并撤下旧规则。

## 检查和清理

```bash
sudo /usr/lib/mihomo-tproxy/manage validate
systemctl status mihomo-tproxy-watch.service
sudo nft list table inet mihomo_tproxy
ip rule
ip -6 rule
sudo /usr/lib/mihomo-tproxy/manage stop
```

`stop` 撤下 TPROXY 接管；恢复时调用 `manage start` 或重启服务。
它只删除 `/run/mihomo-tproxy/state.json` 记录的规则
及接口路由和自己的 nft 表，不 flush 全局防火墙、其他路由表或 conntrack。
