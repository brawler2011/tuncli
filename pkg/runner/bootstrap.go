package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Race independent DNS servers and transports: a silently dropped UDP packet
// must not consume the entire startup deadline before TCP can be attempted.
func lookupBootstrap(ctx context.Context, host string, dial func(context.Context, string, string) (net.Conn, error)) ([]net.IP, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		ips []net.IP
		err error
	}
	results := make(chan result, 4)
	for _, address := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		for _, network := range []string{"udp", "tcp"} {
			go func() {
				resolver := newBootstrapResolver(dial, address, network == "tcp")
				ips, err := resolver.LookupIP(ctx, "ip", host)
				if err == nil && len(ips) == 0 {
					err = fmt.Errorf("empty DNS answer from %s", address)
				}
				results <- result{ips, err}
			}()
		}
	}
	var failures []error
	for range 4 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			if r.err == nil {
				return r.ips, nil
			}
			failures = append(failures, r.err)
		}
	}
	return nil, errors.Join(failures...)
}

// Preserve the resolver's TCP retry on truncated UDP replies. The parallel TCP
// resolver additionally handles UDP packets dropped without any reply.
func newBootstrapResolver(dial func(context.Context, string, string) (net.Conn, error), address string, forceTCP bool) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if forceTCP {
			network = "tcp"
		}
		return dial(ctx, network, address)
	}}
}
