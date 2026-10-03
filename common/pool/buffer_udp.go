package pool

// UDPBufferSize must hold a complete UDP datagram after IP reassembly.
// This also applies to low-memory builds: the link MTU does not bound a
// reassembled datagram, and a short receive buffer silently discards its tail.
const UDPBufferSize = 64 * 1024
