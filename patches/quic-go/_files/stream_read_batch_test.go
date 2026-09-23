package quic

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func primeStreamReadBatch(t *testing.T, s *ReceiveStream, size protocol.ByteCount) {
	t.Helper()
	data := make([]byte, size)
	require.NoError(t, s.handleStreamFrame(&wire.StreamFrame{Data: data}, monotime.Now()))
	n, err := io.ReadFull(s, data)
	require.NoError(t, err)
	require.EqualValues(t, size, n)
	select {
	case <-s.readChan:
	default:
	}
}

func TestConnectionStreamReadBatchFlushesOnEveryExit(t *testing.T) {
	for _, scenario := range []string{"disabled", "normal", "short", "unidirectional", "single", "malformed", "limit", "new-arrival", "handshake"} {
		t.Run(scenario, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			unpacker := NewMockUnpacker(ctrl)
			enabled := scenario != "disabled"
			tc := newServerTestConnection(t, ctrl, &Config{
				EnableStreamReadBatching: enabled, DisablePathMTUDiscovery: true,
			}, false, connectionOptUnpacker(unpacker))
			tc.conn.handshakeComplete = scenario != "handshake"
			tc.conn.peerParams = &wire.TransportParameters{}
			// Create an incoming stream before the batch so we can observe its
			// data notifications between two real packet-parser calls.
			var id protocol.StreamID
			if scenario == "unidirectional" {
				id = 2
			}
			require.NoError(t, tc.conn.streamsMap.HandleStreamFrame(&wire.StreamFrame{StreamID: id}, monotime.Now()))
			var stream *ReceiveStream
			if scenario == "unidirectional" {
				s, err := tc.conn.streamsMap.AcceptUniStream(context.Background())
				require.NoError(t, err)
				stream = s
			} else {
				s, err := tc.conn.streamsMap.AcceptStream(context.Background())
				require.NoError(t, err)
				stream = s.receiveStr
			}
			<-stream.readChan
			if scenario != "short" {
				primeStreamReadBatch(t, stream, minStreamReadBatchReadPos)
			}
			base := stream.readPos
			queued := 2
			wantProcessed := queued
			if scenario == "single" {
				queued = 1
				wantProcessed = 1
			}
			if scenario == "new-arrival" {
				wantProcessed = 3
			}
			if scenario == "limit" {
				queued = maxPacketsToProcess + 1
				wantProcessed = maxPacketsToProcess
			}
			processed := 0
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
				func(monotime.Time, []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
					if processed > 0 && enabled && scenario != "handshake" && scenario != "short" {
						require.Empty(t, stream.readChan, "ordinary data woke the reader before the batch ended")
					}
					if processed == 1 && (!enabled || scenario == "handshake" || scenario == "short") {
						require.Len(t, stream.readChan, 1)
					}
					if scenario == "new-arrival" && processed == 0 {
						tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 3, []byte{0}))
					}
					frame := wire.StreamFrame{StreamID: id, Offset: base + protocol.ByteCount(processed), Data: []byte{'x'}, DataLenPresent: true}
					data, err := frame.Append(nil, protocol.Version1)
					require.NoError(t, err)
					processed++
					if scenario == "malformed" && processed == 2 {
						data = []byte{0xff} // truncated frame type
					}
					return protocol.PacketNumber(processed), protocol.PacketNumberLen2, protocol.KeyPhaseZero, data, nil
				},
			).Times(wantProcessed)
			for i := 0; i < queued; i++ {
				tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i+1), []byte{0}))
			}
			_, err := tc.conn.handlePackets()
			if scenario == "malformed" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, wantProcessed, processed)
			require.Len(t, stream.readChan, 1)
			require.False(t, tc.conn.streamsMap.readBatch.active)
			require.Nil(t, tc.conn.streamsMap.readBatch.head)
			require.False(t, stream.readBatchQueued)
			remaining := 0
			if scenario == "limit" {
				remaining = 1
				require.Len(t, tc.conn.notifyReceivedPacket, 1)
			}
			require.Equal(t, remaining, tc.conn.receivedPackets.Len())
			for !tc.conn.receivedPackets.Empty() {
				p := tc.conn.receivedPackets.PopFront()
				p.buffer.Decrement()
			}
		})
	}
}

func TestStreamReadBatchCombinesQueuedFramesWithoutWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newReceiveStream(42, nil, newTestStreamFlowController(42))
		primeStreamReadBatch(t, s, minStreamReadBatchReadPos)
		batch := streamReadBatch{active: true}
		read := make(chan string, 1)
		go func() {
			p := make([]byte, 32*1024)
			n, err := s.Read(p)
			if err != nil {
				read <- err.Error()
				return
			}
			read <- string(p[:n])
		}()
		synctest.Wait() // the reader is blocked before the first frame arrives
		start := time.Now()
		for i, data := range []string{"abc", "def", "ghi"} {
			require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{
				Offset: minStreamReadBatchReadPos + protocol.ByteCount(i*3), Data: []byte(data),
			}, monotime.Now(), &batch))
			synctest.Wait()
			require.Empty(t, read)
		}
		batch.flush()
		synctest.Wait()
		require.Len(t, read, 1)
		require.Equal(t, "abcdefghi", <-read)
		require.Equal(t, start, time.Now(), "batching must not introduce a timer or minimum-size wait")
		require.Nil(t, batch.head)
		require.Nil(t, batch.tail)
		require.False(t, s.readBatchQueued)
		require.Nil(t, s.readBatchNext)
	})
}

func TestStreamReadBatchDoesNotGateReadableData(t *testing.T) {
	s := newReceiveStream(42, nil, newTestStreamFlowController(42))
	primeStreamReadBatch(t, s, minStreamReadBatchReadPos)
	batch := streamReadBatch{active: true}
	defer batch.flush()
	require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{Offset: minStreamReadBatchReadPos, Data: []byte("a")}, monotime.Now(), &batch))
	// A reader that is already running keeps ordinary Read semantics: no
	// artificial block until a batch, a full buffer, or more data arrives.
	p := make([]byte, 32*1024)
	n, err := s.Read(p)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte('a'), p[0])
}

func TestStreamReadBatchKeepsInitialDataImmediate(t *testing.T) {
	for _, alreadyRead := range []protocol.ByteCount{0, minStreamReadBatchReadPos - 1} {
		synctest.Test(t, func(t *testing.T) {
			s := newReceiveStream(42, nil, newTestStreamFlowController(42))
			if alreadyRead > 0 {
				primeStreamReadBatch(t, s, alreadyRead)
			}
			batch := streamReadBatch{active: true}
			defer batch.flush()
			done := make(chan string, 1)
			go func() {
				p := make([]byte, 3)
				n, err := s.Read(p)
				if err != nil {
					done <- err.Error()
					return
				}
				done <- string(p[:n])
			}()
			synctest.Wait()
			require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{
				Offset: alreadyRead, Data: []byte("abc"),
			}, monotime.Now(), &batch))
			synctest.Wait()
			require.Len(t, done, 1, "initial data must not wait for batch flush, even when crossing the threshold")
			require.Equal(t, "abc", <-done)
			require.False(t, s.readBatchQueued)
		})
	}
}

func TestStreamReadBatchDeduplicatesAndReusesStreams(t *testing.T) {
	batch := streamReadBatch{active: true}
	streams := []*ReceiveStream{
		newReceiveStream(0, nil, newTestStreamFlowController(0)),
		newReceiveStream(4, nil, newTestStreamFlowController(4)),
	}
	for pass := 0; pass < 2; pass++ {
		batch.active = true
		for i := 0; i < 4; i++ {
			for _, s := range streams {
				batch.add(s)
			}
		}
		batch.flush()
		for _, s := range streams {
			require.Len(t, s.readChan, 1)
			<-s.readChan
			require.Nil(t, s.readBatchNext)
			require.False(t, s.readBatchQueued)
		}
	}
	batch.flush()
	for _, s := range streams {
		require.Empty(t, s.readChan)
	}
}

func TestStreamReadBatchTerminalEventsWakeImmediately(t *testing.T) {
	for _, event := range []string{"fin", "reset", "cancel", "shutdown", "deadline"} {
		t.Run(event, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				sender := NewMockStreamSender(ctrl)
				sender.EXPECT().onStreamCompleted(gomock.Any()).AnyTimes()
				sender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
				s := newReceiveStream(42, sender, newTestStreamFlowController(42))
				primeStreamReadBatch(t, s, minStreamReadBatchReadPos)
				batch := streamReadBatch{active: true}
				defer batch.flush()
				done := make(chan error, 1)
				go func() {
					_, err := s.Read(make([]byte, 100))
					done <- err
				}()
				synctest.Wait()
				require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{Offset: minStreamReadBatchReadPos, Data: []byte("abc")}, monotime.Now(), &batch))
				synctest.Wait()
				require.Empty(t, done)
				shutdownErr := errors.New("shutdown")
				switch event {
				case "fin":
					require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{Offset: minStreamReadBatchReadPos + 3, Fin: true}, monotime.Now(), &batch))
				case "reset":
					require.NoError(t, s.handleResetStreamFrame(&wire.ResetStreamFrame{FinalSize: minStreamReadBatchReadPos + 3, ErrorCode: 7}, monotime.Now()))
				case "cancel":
					s.CancelRead(7)
				case "shutdown":
					s.closeForShutdown(shutdownErr)
				case "deadline":
					require.NoError(t, s.SetReadDeadline(time.Now().Add(-time.Second)))
				}
				synctest.Wait()
				require.Len(t, done, 1, "terminal notification must bypass the unflushed batch")
				err := <-done
				switch event {
				case "fin":
					require.ErrorIs(t, err, io.EOF)
				case "reset", "cancel":
					var streamErr *StreamError
					require.ErrorAs(t, err, &streamErr)
					require.EqualValues(t, 7, streamErr.ErrorCode)
				case "shutdown":
					require.ErrorIs(t, err, shutdownErr)
				case "deadline":
					require.ErrorIs(t, err, errDeadline)
				}
			})
		})
	}
}

func TestStreamReadBatchFINAndReliableResetGapFillWakeImmediately(t *testing.T) {
	for _, reset := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sender := NewMockStreamSender(ctrl)
			sender.EXPECT().onStreamCompleted(gomock.Any()).AnyTimes()
			s := newReceiveStream(42, sender, newTestStreamFlowController(42))
			primeStreamReadBatch(t, s, minStreamReadBatchReadPos)
			batch := streamReadBatch{active: true}
			defer batch.flush()
			if reset {
				require.NoError(t, s.handleResetStreamFrame(&wire.ResetStreamFrame{FinalSize: minStreamReadBatchReadPos + 6, ReliableSize: minStreamReadBatchReadPos + 6, ErrorCode: 7}, monotime.Now()))
			} else {
				require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{Offset: minStreamReadBatchReadPos + 6, Fin: true}, monotime.Now(), &batch))
			}
			done := make(chan error, 1)
			go func() {
				p := make([]byte, 6)
				_, err := io.ReadFull(s, p)
				if err == nil && string(p) != "abcdef" {
					err = errors.New("wrong gap-fill data")
				}
				done <- err
			}()
			synctest.Wait()
			require.Empty(t, done)
			require.NoError(t, s.handleStreamFrameWithReadBatch(&wire.StreamFrame{Offset: minStreamReadBatchReadPos, Data: []byte("abcdef")}, monotime.Now(), &batch))
			synctest.Wait()
			require.Len(t, done, 1)
			require.NoError(t, <-done)
		})
	}
}
