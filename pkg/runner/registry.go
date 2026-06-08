package runner

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/redirect"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
)

func singboxContext(ctx context.Context) context.Context {
	return box.Context(ctx, inboundRegistry(), outboundRegistry(), endpointRegistry(), dnsTransportRegistry(), serviceRegistry())
}

func inboundRegistry() *inbound.Registry {
	r := inbound.NewRegistry()
	tun.RegisterInbound(r)
	redirect.RegisterRedirect(r)
	redirect.RegisterTProxy(r)
	direct.RegisterInbound(r)
	socks.RegisterInbound(r)
	http.RegisterInbound(r)
	mixed.RegisterInbound(r)
	vless.RegisterInbound(r)
	return r
}

func outboundRegistry() *outbound.Registry {
	r := outbound.NewRegistry()
	direct.RegisterOutbound(r)
	block.RegisterOutbound(r)
	group.RegisterSelector(r)
	group.RegisterURLTest(r)
	socks.RegisterOutbound(r)
	http.RegisterOutbound(r)
	vless.RegisterOutbound(r)
	return r
}

func endpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

func dnsTransportRegistry() *dns.TransportRegistry {
	r := dns.NewTransportRegistry()
	transport.RegisterTCP(r)
	transport.RegisterUDP(r)
	transport.RegisterTLS(r)
	transport.RegisterHTTPS(r)
	hosts.RegisterTransport(r)
	local.RegisterTransport(r)
	fakeip.RegisterTransport(r)
	return r
}

func serviceRegistry() *service.Registry {
	return service.NewRegistry()
}
