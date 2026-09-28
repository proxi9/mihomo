package dns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type fakeClient struct {
	addr  string
	delay time.Duration
	err   error
}

func (c fakeClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.err != nil {
		return nil, c.err
	}
	return new(D.Msg).SetReply(m), nil
}

func (c fakeClient) Address() string  { return c.addr }
func (c fakeClient) ResetConnection() {}

// A failing nameserver is logged by address; one that lost the race to a faster answer is not.
func TestBatchExchangeLogsFailedNameserver(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	m := new(D.Msg).SetQuestion("example.com.", D.TypeA)
	clients := []dnsClient{
		fakeClient{addr: "10.0.0.1:53", err: errors.New("connection refused")},
		fakeClient{addr: "10.0.0.2:53", delay: 20 * time.Millisecond},
		fakeClient{addr: "10.0.0.3:53", delay: time.Second},
	}
	if _, _, err := batchExchange(context.Background(), clients, m); err != nil {
		t.Fatal(err)
	}

	var failed []string
	timeout := time.After(200 * time.Millisecond)
	for done := false; !done; {
		select {
		case e := <-sub:
			if strings.Contains(e.Payload, " failed: ") {
				failed = append(failed, e.Payload)
			}
		case <-timeout:
			done = true
		}
	}

	if len(failed) != 1 || failed[0] != "[DNS] 10.0.0.1:53 failed: connection refused" {
		t.Fatalf("failed lines: %q", failed)
	}
}
