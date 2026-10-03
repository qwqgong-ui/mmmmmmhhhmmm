//go:build !with_low_memory

package pool

const (
	// RelayBufferSize using for tcp
	// io.Copy default buffer size is 32 KiB
	RelayBufferSize = 32 * 1024
)
