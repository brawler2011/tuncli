package udpnat

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type sessionKey struct {
	Source      netip.AddrPort
	Destination M.Socksaddr
}

type Service struct {
	cache   freelru.Cache[sessionKey, *natConn]
	handler N.UDPConnectionHandlerEx
	prepare PrepareFunc
}

type PrepareFunc func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc)

func New(handler N.UDPConnectionHandlerEx, prepare PrepareFunc, timeout time.Duration, shared bool) *Service {
	if timeout == 0 {
		panic("invalid timeout")
	}
	var cache freelru.Cache[sessionKey, *natConn]
	if !shared {
		cache = common.Must1(freelru.NewSynced[sessionKey, *natConn](1024, maphash.NewHasher[sessionKey]().Hash32))
	} else {
		cache = common.Must1(freelru.NewSharded[sessionKey, *natConn](1024, maphash.NewHasher[sessionKey]().Hash32))
	}
	cache.SetLifetime(timeout)
	cache.SetHealthCheck(func(_ sessionKey, conn *natConn) bool {
		select {
		case <-conn.doneChan:
			return false
		default:
			return true
		}
	})
	cache.SetOnEvict(func(_ sessionKey, conn *natConn) {
		conn.Close()
	})
	return &Service{
		cache:   cache,
		handler: handler,
		prepare: prepare,
	}
}

func (s *Service) NewPacket(bufferSlices [][]byte, source M.Socksaddr, destination M.Socksaddr, userData any) {
	key := sessionKey{Source: source.AddrPort(), Destination: destination}
	conn, _, ok := s.cache.GetAndRefreshOrAdd(key, func() (*natConn, bool) {
		ok, ctx, writer, onClose := s.prepare(source, destination, userData)
		if !ok {
			return nil, false
		}
		newConn := &natConn{
			cache:        s.cache,
			key:          key,
			writer:       writer,
			localAddr:    source,
			packetChan:   make(chan *N.PacketBuffer, 64),
			doneChan:     make(chan struct{}),
			readDeadline: pipe.MakeDeadline(),
		}
		go s.handler.NewPacketConnectionEx(ctx, newConn, source, destination, onClose)
		return newConn, true
	})
	if !ok {
		return
	}
	conn.handlerAccess.RLock()
	readWaitOptions := conn.readWaitOptions
	handler := conn.handler
	buffer := readWaitOptions.NewPacketBuffer()
	for _, bufferSlice := range bufferSlices {
		buffer.Write(bufferSlice)
	}
	if handler != nil {
		conn.handlerAccess.RUnlock()
		handler.NewPacketEx(buffer, destination)
		return
	}
	packet := N.NewPacketBuffer()
	*packet = N.PacketBuffer{
		Buffer:      buffer,
		Destination: destination,
	}
	select {
	case conn.packetChan <- packet:
	default:
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
	conn.handlerAccess.RUnlock()
}

func (s *Service) Purge() {
	s.cache.Purge()
}

func (s *Service) PurgeExpired() {
	s.cache.PurgeExpired()
}
