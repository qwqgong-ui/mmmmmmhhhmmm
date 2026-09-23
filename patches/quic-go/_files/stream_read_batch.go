package quic

import "github.com/metacubex/quic-go/internal/protocol"

// Keep initial exchanges and short streams on the immediate notification path.
// This is an eligibility threshold on bytes already read, never a read target
// or a reason to wait for additional data.
const minStreamReadBatchReadPos protocol.ByteCount = 64 * 1024

// streamReadBatch collects ordinary data wakeups during one bounded pass over
// the connection's receive queue. All fields, including the intrusive links in
// ReceiveStream, are owned by that connection goroutine. Readers keep their
// normal semantics and terminal events bypass this list via signalRead.
type streamReadBatch struct {
	active bool
	head   *ReceiveStream
	tail   *ReceiveStream
}

func (b *streamReadBatch) add(s *ReceiveStream) {
	if s.readBatchQueued {
		return
	}
	s.readBatchQueued = true
	if b.tail == nil {
		b.head = s
	} else {
		b.tail.readBatchNext = s
	}
	b.tail = s
}

func (b *streamReadBatch) flush() {
	b.active = false
	for s := b.head; s != nil; {
		next := s.readBatchNext
		s.readBatchNext = nil
		s.readBatchQueued = false
		s.signalRead()
		s = next
	}
	b.head = nil
	b.tail = nil
}
