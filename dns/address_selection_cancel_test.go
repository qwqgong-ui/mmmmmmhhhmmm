package dns

import (
	"context"
	"errors"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestAddressSelectionWaitIsCancelable(t *testing.T) {
	c := &addressRaceClient{selection: make(chan struct{}, 1)}
	// Another query owns the cold selection gate.
	c.selection <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		q := new(D.Msg)
		q.SetQuestion("example.test.", D.TypeA)
		_, err := c.ExchangeContext(ctx, q)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled query waited for unrelated selector")
	}
}
