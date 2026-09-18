package self_test

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/quic-go"

	"github.com/stretchr/testify/require"
)

// Conn.MaxDatagramPayloadSize lets a caller that fragments its own payloads
// size the fragments to what the connection will actually take, instead of
// pinning them to a conservative constant. It is only useful if it agrees
// exactly with SendDatagram, so assert it against SendDatagram's own boundary
// rather than against a recomputed number.
func TestMaxDatagramPayloadSize(t *testing.T) {
	t.Run("peer without datagram support", func(t *testing.T) {
		serverConn, _ := newDatagramConnPair(t, false, 0)
		require.Zero(t, serverConn.MaxDatagramPayloadSize())
		require.Error(t, serverConn.SendDatagram([]byte("foo")))
	})

	t.Run("bounded by the peer's max_datagram_frame_size", func(t *testing.T) {
		const peerFrameSize = 512
		serverConn, clientConn := newDatagramConnPair(t, true, peerFrameSize)

		size := serverConn.MaxDatagramPayloadSize()
		require.Positive(t, size)
		require.Less(t, size, int64(peerFrameSize), "payload must leave room for the frame header")

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// A payload of exactly this size goes through and arrives intact.
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i)
		}
		require.NoError(t, serverConn.SendDatagram(payload))
		received, err := clientConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, payload, received)

		// One byte more is rejected, and the error reports the same limit.
		var tooLarge *quic.DatagramTooLargeError
		err = serverConn.SendDatagram(make([]byte, size+1))
		require.ErrorAs(t, err, &tooLarge)
		require.Equal(t, size, tooLarge.MaxDatagramPayloadSize)
	})
}

// newDatagramConnPair returns the server-side and client-side connections of a
// handshaked pair. The client advertises datagram support according to
// clientEnableDatagrams, and clientFrameSize (when non-zero) caps the
// max_datagram_frame_size it advertises, which is what bounds the server's
// sends.
func newDatagramConnPair(t *testing.T, clientEnableDatagrams bool, clientFrameSize int64) (server, client *quic.Conn) {
	t.Helper()

	ln, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		ln.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			EnableDatagrams:      clientEnableDatagrams,
			MaxDatagramFrameSize: clientFrameSize,
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.CloseWithError(0, "") })

	// Accept returns a handshaked connection, so the server already holds the
	// client's transport parameters.
	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { serverConn.CloseWithError(0, "") })
	require.Equal(t, clientEnableDatagrams, serverConn.ConnectionState().SupportsDatagrams.Remote)

	return serverConn, clientConn
}
