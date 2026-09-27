# Ready DATAGRAM batching

The QUIC dependency patch coalesces up to four already queued DATAGRAM frames
into one packet. It introduces no timer and never waits to fill a packet.
The existing first-DATAGRAM, ACK, retransmission and STREAM scheduling is
preserved; extra DATAGRAMs use only the remaining payload space.

Each original message remains a separate length-bearing RFC 9221 frame. There
is no private envelope, negotiation, padding, or receive-side protocol change.
An unmodified QUIC DATAGRAM peer can receive the packets, and mixed versions
work in either direction. The shared QUIC packer applies this behavior to all
DATAGRAM users of this dependency, not just Hysteria2.

Frames that do not fit the remaining space stay queued for the next packet.
DATAGRAM order is preserved during payload serialization, and batch dequeue
notifications allow blocked senders to use all newly available queue slots.
ACK-only packets stay ACK-only. DATAGRAMs remain unreliable and are not
retransmitted by the outer QUIC connection.

One lost outer packet can lose up to four application datagrams together.
Sparse traffic gains little because there may be nothing else queued. The
four-frame limit bounds loss grouping; it does not promise a particular PPS
reduction on a real path.

## Validation

Apply the dependency patches and export the generated GOFLAGS before testing:

```sh
sh patches/apply-dependency-patches.sh /tmp/mihomo-datagram.env
set -a
. /tmp/mihomo-datagram.env
set +a
CGO_ENABLED=1 go test -race github.com/metacubex/quic-go -run 'Test(Datagram|Pack)' -count=1
```

Tests cover single-message immediate packing, batch bounds, MTU remainder,
ACK-only traffic, retransmission/STREAM space, preserved message order and
boundaries, lengthless STREAM tails, and blocked sender wakeups.

A localhost interop test using these pinned MetaCubeX and apernet dependencies
passed QUIC v1 and v2 with both patched, client-only patched, server-only patched,
and neither patched. Each side verified 256 echoed datagrams of 32/64/128/256
bytes. In that queued-burst workload, patched senders used 64 data packets and
unmodified senders used 256, confirmed by QUIC packet-sent tracing. This is a
synthetic packet count, not a production PPS or game-latency measurement.

Full-binary localhost HY2/SOCKS5 UDP echo tests also passed for the new Mihomo
and the previously installed Mihomo against the new Xray. Each completed 128
round trips with 32 through 4000 byte payloads, including HY2 fragmentation
and reassembly. No production services were replaced during these tests.

## Production rollback comparison (2026-09-27)

Both endpoints were rolled back to their saved pre-batching binaries, tested,
then restored to the batching binaries and tested again. Each run used 60
seconds of Pion WebRTC: 3000 unordered, zero-retransmission DataChannel
messages and 3000 synthetic Opus RTP packets, echoed through the private HY2
path. ICE, DTLS and SCTP stayed connected in both runs.

| Measurement | Saved binaries | Batching binaries |
|---|---:|---:|
| DataChannel round trips | 3000/3000 | 2999/3000 |
| RTP round trips | 2999/3000 | 3000/3000 |
| RTT median / P95 | 70.55 / 72.56 ms | 67.68 / 70.88 ms |
| HY2 uplink packets | 18605 | 12231 |
| HY2 downlink packets | 21202 | 15691 |

Packet counts include setup/control/ACK traffic for the isolated test
connection over approximately 62.9 seconds. There were no captured payloads
over 1472 bytes and tcpdump reported zero kernel drops. Combined packet count
fell from 39807 to 27922 (29.9%). No obvious connection or latency regression
was observed in this short public-network sample; it is not a loss-free or
long-term guarantee. The saved Xray was a13779b-dirty and the new Xray used
the latest SingleUser base 2bc25f8, so this compares the deployed versions,
not the batching patch in complete isolation. The new binaries were restored
after the test; configuration hashes remained unchanged.
