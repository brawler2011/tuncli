package runner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProbeDistinguishesTransportFromInnerTLS(t *testing.T) {
	t.Run("VPN transport", func(t *testing.T) {
		err := probeHTTPS(context.Background(), "https://1.1.1.1/", nil, func(context.Context, string, string) (net.Conn, error) {
			return nil, context.DeadlineExceeded
		})
		require.ErrorContains(t, err, "VPN transport connection/handshake")
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("probe TLS", func(t *testing.T) {
		err := probeHTTPS(context.Background(), "https://1.1.1.1/", nil, func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() { _ = server.Close() }()
			return client, nil
		})
		require.ErrorContains(t, err, "probe TLS handshake")
	})
}

func TestProbeHTTPSResponses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := probeHTTPS(ctx, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig, (&net.Dialer{}).DialContext)
			if status == http.StatusOK {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "VPN probe HTTP")
			}
		})
	}
}

func TestProbeHTTPResponseTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := probeHTTPS(ctx, server.URL, server.Client().Transport.(*http.Transport).TLSClientConfig, (&net.Dialer{}).DialContext)
	require.ErrorContains(t, err, "probe HTTP response")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestProbeSurvivesOneUnavailableSite(t *testing.T) {
	healthy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer healthy.Close()
	blocked := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer blocked.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := probeVPN(ctx, []string{blocked.URL, healthy.URL}, healthy.Client().Transport.(*http.Transport).TLSClientConfig, (&net.Dialer{}).DialContext)
	require.NoError(t, err)
	require.NoError(t, ctx.Err(), "successful alternate probe should finish before the deadline")
}
func TestProbeAllSitesFail(t *testing.T) {
	err := probeVPN(context.Background(), []string{"https://1.1.1.1/", "https://example.com/"}, nil, func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded })
	require.ErrorContains(t, err, "VPN transport connection/handshake")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
