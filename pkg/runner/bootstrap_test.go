package runner

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBootstrapRetriesTruncatedDNSOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
	require.NoError(t, err)
	var udpQueries, tcpQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		if w.LocalAddr().Network() == "udp" {
			udpQueries.Add(1)
			response.Truncated = true
		} else {
			tcpQueries.Add(1)
			if r.Question[0].Qtype == dns.TypeA {
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")}}
			}
		}
		_ = w.WriteMsg(response)
	})
	udp := &dns.Server{PacketConn: packet, Handler: handler}
	tcp := &dns.Server{Listener: listener, Handler: handler}
	udpDone, tcpDone := make(chan error, 1), make(chan error, 1)
	go func() { udpDone <- udp.ActivateAndServe() }()
	go func() { tcpDone <- tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		require.NoError(t, udp.Shutdown())
		require.NoError(t, tcp.Shutdown())
		require.NoError(t, <-udpDone)
		require.NoError(t, <-tcpDone)
	})
	var wrongResolver atomic.Bool
	resolver := newBootstrapResolver(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "1.1.1.1:53" {
			wrongResolver.Store(true)
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}, "1.1.1.1:53", false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip", "vpn.example.")
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.ParseIP("192.0.2.7").To4()}, ips)
	require.Positive(t, udpQueries.Load())
	require.Positive(t, tcpQueries.Load())
	require.False(t, wrongResolver.Load())
}

func TestBootstrapSurvivesDroppedUDPAndPrimaryResolver(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")}}
		}
		_ = w.WriteMsg(response)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := lookupBootstrap(ctx, "vpn.example.", func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "1.1.1.1:53" || network == "udp" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})
	require.NoError(t, err)
	require.Equal(t, []net.IP{net.ParseIP("192.0.2.7").To4()}, ips)
	require.NoError(t, ctx.Err())
}
