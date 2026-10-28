package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

// Hysteria2 allows 15 seconds for its transport handshake. Leave time for the
// HTTPS check after it, rather than cancelling a valid startup after 5 seconds.
const StartupProbeTimeout = 20 * time.Second

// Dialing an outbound includes the VPN transport's own TLS/REALITY handshake.
// It must be distinguished from TLS to the probe site inside that transport.
func probeHTTPS(ctx context.Context, url string, tlsConfig *tls.Config, dial func(context.Context, string, string) (net.Conn, error)) error {
	var stage atomic.Int32
	stages := []string{"VPN transport connection/handshake", "probe TLS handshake", "probe HTTP response"}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { stage.Store(1) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				stage.Store(2)
			}
		},
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: StartupProbeTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", stages[stage.Load()], err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("VPN probe HTTP %d", response.StatusCode)
	}
	if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); err != nil {
		return fmt.Errorf("probe HTTP body: %w", err)
	}
	return nil
}

// A single unavailable check site is not evidence that the VPN is down.
// Every request uses the VPN outbound and verifies the site's TLS certificate.
func probeVPN(ctx context.Context, urls []string, tlsConfig *tls.Config, dial func(context.Context, string, string) (net.Conn, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(urls))
	for _, url := range urls {
		go func() { results <- probeHTTPS(ctx, url, tlsConfig, dial) }()
	}
	var failures []error
	for range urls {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-results:
			if err == nil {
				return nil
			}
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
