# Arch/CachyOS Mihomo dev 包

包名是 `mihomo`，构建当前 dev 的 x86-64-v3 内核，替换 `mihomo-bin`。
它保留 `/usr/bin/mihomo`、`mihomo.service`、`/etc/mihomo/config.yaml` 的路径。
已有 `config.yaml` 在安装前备份、事务后校验保留，不写入你的节点/订阅凭据。
`epoch=9999` 防止普通发行版本覆盖本地 dev 包。
安装且配置就绪后自动启用/重启 `mihomo.service`；systemd drop-in 在服务启动后
注册双栈 TCP/UDP TPROXY，在停止、升级重启和卸载时清理它拥有的规则。
注册失败不会阻止内核启动，配置中的 TUN 保留兜底。它不是上游故障自动切换器。

## 配置前提

现有 `/etc/mihomo/config.yaml` 需要：

```yaml
tproxy-port: 17894
routing-mark: 666
tun:
  enable: true
  auto-route: true
  auto-detect-interface: true
  auto-redirect: false
```

不需要固定 `interface-name`。53 端口优先接管；DNS 请求的处理策略仍由
Mihomo 配置决定，例如 `DST-PORT,53,dns`、`dns` 组及 `type: dns` 出站。
Mihomo 和 systemd-resolved 的上游连接排除，避免系统 DNS 回环。
包只接管本机流量，不接管其他设备的转发流量。

## 确定直连绕过

把确定可以直接访问的**真实目标 IP/CIDR**分别加入 `/etc/mihomo/direct4.cidr`
和 `/etc/mihomo/direct6.cidr`。放行时设置 `routing-mark` 相同的标记，由更优先
的 `ip rule` 查询 `main` 表，因此不会再被 TUN 接管。局域网/组播默认放行。
只有在主路由表本身没有指向代理/VPN 的路由时，`main` 才是物理直连出口。
不确定的地址保持接管；列表留空不会自动把中国 IP 或 Mihomo 的 DIRECT 规则导出。

**域名被返回 Fake-IP 时，仅排除真实 IP 列表不起作用。** 对确定直连的域名，
还需让现有 `fake-ip-filter` 返回 `real-ip`，并选择能返回真实地址的 DNS 上游。
不能排除 Fake-IP 网段；无论 CIDR 列表怎么配置，Fake-IP 和 53 端口都先接管。
共享 CDN 的 IP 不能仅因一个域名走 DIRECT 就全局排除。域名/进程/动态组规则
不能无条件转换为内核 IP 集合；本包不会这样做。

修改 CIDR 列表后用 `sudo systemctl restart mihomo` 应用。内核绕过的流量不会
出现在 Mihomo 连接列表、规则计数或流量统计里。

## 按 config.yaml 的 DIRECT 自动导出

当前包的 CIDR 列表是显式的内核放行策略，**尚未实现自动读取核心规则导出**。
不能用 grep 搜索 `DIRECT` 或把某个走直连的规则集整个复制到 nft 集合：

1. 核心规则按顺序第一次命中生效；必须检查候选前面的代理/拒绝规则。
2. `🟢 -> 本地直连(type: direct)` 这种单成员组可以静态确定；多成员组需要
   跟踪当前选择以及切换、reload、规则集更新，不能假定永远 DIRECT。
3. 纯 IP/端口/协议条件可以编译成有序的内核条件；域名、嗅探、进程或其他
   无法在内核证明的条件需要继续交给 Mihomo。遇到前序不确定条件时必须
   保守保留接管，而不是无条件放行后面的 CIDR。
4. MRS 规则集需要由核心解码，不能当文本 IP 列表读取。Fake-IP 必须留给
   核心映射，实际直连域名需要 real-IP DNS 策略。

例如当前用户配置中 `i-cn -> 🟢` 前面有拒绝规则和 `g-google -> 🌐`。
因此全量导出 `i-cn` 会改变分流行为；靠前的 `i-private -> 🟢` 才可以在
保留 53 端口规则后确定放行。若扩展自动导出，应从核心编译后的规则和
规则集做保守分析，再原子更新 nft 集合，同时保留无法证明的流量走核心。

## 构建和安装

```bash
cd packaging/arch/mihomo
makepkg -s
sudo pacman -U "$(makepkg --packagelist)"
```

包使用本目录中版本控制的源文件；pacman 的 backup 机制保留已有 CIDR/TOML。
`tproxy.toml` 可调整标记、路由表和优先级。启动前检查冲突，避免覆盖其他规则。
内核需支持 nftables TPROXY/socket、IPv4/IPv6 策略路由以及 cgroup v2 socket 匹配。

当前手动部署使用 `30-transparent.conf`。安装脚本会清理它注册的规则，并把旧
drop-in 移到 `/etc/mihomo/30-transparent.conf.manual-backup` 后启动包内的集成。
旧脚本和 nft 文件保留用于回滚，不同时注册两套接管。

## 检查和清理

```bash
sudo /usr/lib/mihomo-tproxy/manage validate
sudo nft list table inet mihomo_tproxy
ip rule
ip -6 rule
sudo /usr/lib/mihomo-tproxy/manage stop
```

`stop` 撤下 TPROXY，剩余流量交给已启用的 TUN；无需改核心配置。恢复时调用
`manage start` 或重启服务。它只删除 `/run/mihomo-tproxy/state.json` 记录的规则
和自己的 nft 表，不 flush 全局防火墙、其他路由表或 conntrack。
