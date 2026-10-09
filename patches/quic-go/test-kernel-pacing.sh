#!/bin/sh
# Run compiled quic-go tests against Linux fq in an isolated network namespace.
set -eu
left="hy2-edt-$$-l"
receiver=""
state=$(mktemp -d "$PWD/.git/kernel-pacing-test.XXXXXX")
cleanup() {
 [ -z "$receiver" ] || kill "$receiver" 2>/dev/null || true
 ip netns del "$left" 2>/dev/null || true
 rm -rf -- "$state"
}
trap cleanup EXIT INT TERM
ip netns add "$left"
ip -n "$left" link set lo up txqueuelen 1000
ip netns exec "$left" tc qdisc replace dev lo root fq
ip netns exec "$left" python3 -u -c '
import select,socket,struct,time
sockets=[]
for port in (34567,34568):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 s.bind(("127.0.0.1",port))
 sockets.append(s)
print("ready",flush=True)
while True:
 for s in select.select(sockets,[],[])[0]:
  data,peer=s.recvfrom(2048)
  arrival=time.monotonic_ns()
  s.sendto(data+struct.pack("!Q",arrival),peer)
' >"$state/receiver.log" 2>&1 &
receiver=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 [ -s "$state/receiver.log" ] && break
 sleep 0.05
done
for binary in "$@"; do
 ip netns exec "$left" env QUIC_KERNEL_PACING_PEER=127.0.0.1 "$binary" -test.run '^TestKernelPacingFQIntegration$' -test.v
done
ip netns exec "$left" tc -s qdisc show dev lo
