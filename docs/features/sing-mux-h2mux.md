# sing-mux h2mux

[返回功能目录](../features.md) · [配置示例](../config.yaml)

依赖 `github.com/metacubex/sing-mux` v0.3.12 已包含此修复，不再应用本地补丁。
以下保留原问题与修复原因。

x/net **v0.54.0** 起 `x/net/http2` 在 **Go 1.27 工具链**下会走 net/http 的请求
校验（`//go:build go1.27 && !http2legacy`），而 sing-mux 的 h2mux 客户端为每条
流构造的 `http.Request` 字面量没有 `Header` 字段，于是 `RoundTrip` 直接返回
`http: nil Request.Header`，每条流都开不起来 —— 调用方看到请求体上的 closed
pipe 和等响应头的超时。表现是
`TestInboundVless_Encryption/**/singmux/h2mux/Sequential` 96 条全部挂 60s。

`http.Request` 的 `Header` 本来就不允许为 nil，只是旧版 `x/net/http2` 没去看它。
补上一个空 map 即可，对新旧两种实现都成立。

排查过程中试过另外两条路，都比这个差：把 x/net 钉在 v0.53.0（最后一个可用版本）
需要 `replace` 压过 x/crypto、miekg/dns 和 x/text 声明的 v0.57.0，且拿不到
v0.55.0 的 idna 修复；用上游的 `http2legacy` 构建标签则要求每条构建命令都别忘了
带，漏了就静默坏掉。补 sing-mux 一行两者都不需要。
