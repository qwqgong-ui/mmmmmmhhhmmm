# Generic hybrid QUIC

Enable hybrid on the already selected proxy node:

```yaml
proxies:
  - name: first-xray
    type: vless
    server: FIRST_XRAY_ADDRESS
    port: 443
    uuid: YOUR_UUID
    udp: true
    hybrid-quic: true
    # Keep this node's existing TLS/transport settings.
```

The option is disabled by default and is shared by domain-preserving stream
proxies, including VLESS, Trojan, Shadowsocks and HY2. It is no longer a HY2
option. IP-only tunnels and direct/reject nodes cannot enable it.

Rules select this node using the application's real target. The wrapper then
opens `hybrid-quic.invalid:443` through the node's existing stream dialer without
running rules on the marker. QUIC handshakes and fallback datagrams travel over
that stream, with their UDP boundaries preserved. Raw short-header packets go
directly to the endpoint returned by the terminal Xray, using the node's normal
interface/routing-mark options. Raw never uses a dialer-proxy.

For `mihomo -> Xray -> Xray`, configure the first Xray's `forwardOutbounds` and
the terminal's `trustedForwardInbounds`, `listen` and `advertise` as described in
[Xray's configuration guide](https://github.com/qwqgong-ui/Xray-core/blob/claude/hy2-hybrid-review-c2jv99/docs/hybrid-quic.md).
The terminal supplies the raw endpoint and learns the original client address
through the explicitly trusted chain. The intermediate Xray routes on the real
UDP target, including its domain, and does not terminate the flow when forwarding.

Only public UDP 443 targets beginning with a QUIC Initial use hybrid. Other UDP
uses the node's native datagram support. Fake-IP names stay names until the
terminal resolves them. DNS mapping/hosts mode retains a selected real IP.

A successful raw reply activates raw. A probe timeout, or 15 seconds without a
raw reply, returns both directions to the stream; the timeout also applies to
idle raw flows. That is not the end of raw. A flow that was carrying nothing
when raw went quiet keeps its binding and probes again on its next packet; one
that was busy tells the terminal to stop sending raw, then probes again after 30
seconds, doubling to at most 10 minutes and giving raw up after eight attempts.
A raw packet arriving in the meantime resumes the flow with no probe at all.
A raw socket failure on either side is still permanent. A 30-second stream
keepalive protects against proxy idle timeouts; closing the packet connection
closes all its streams and the terminal releases their targets/CIDs/raw bindings
immediately.

Where the platform allows it the raw socket is connected to the endpoint, so the
kernel drops every other source and reports this path's ICMP errors. Those errors
are counted, not acted on: the timeouts above stay the only reasons to fall back.
`/hybrid-quic/flows` reports each flow's raw and stream packet and byte counts,
the datagrams dropped as foreign, the ICMP reports, and whether its socket is
connected.

This wire protocol is `HQS1` and is incompatible with the removed `HQV3` HY2
control protocol. Upgrade both sides and explicitly enable the option. There is
no independent flow ID, registration retry, TTL-based flow cleanup or automatic
raw recovery. TCP-based fallback has TCP head-of-line blocking. Transparent
proxies/NATs that give raw a different source IP from the first tunnel connection
cannot bind raw and continue using the reliable stream.
