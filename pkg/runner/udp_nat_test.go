package runner

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type udpNATSession struct {
	conn        N.PacketConn
	destination M.Socksaddr
}
type udpNATHandler struct{ sessions chan udpNATSession }

func (h *udpNATHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	h.sessions <- udpNATSession{conn, destination}
}

type udpNATWriter struct{}

func (udpNATWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}
func TestUDPNATSeparatesDestinations(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "synced", true: "sharded"}[shared], func(t *testing.T) {
			handler := &udpNATHandler{sessions: make(chan udpNATSession, 10)}
			service := udpnat.New(handler, func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
				return true, context.Background(), udpNATWriter{}, nil
			}, time.Minute, shared)
			t.Cleanup(service.Purge)
			source := M.ParseSocksaddr("172.19.0.1:20000")
			destinations := []M.Socksaddr{M.ParseSocksaddr("198.18.0.2:8081"), M.ParseSocksaddr("198.18.0.3:8081"), M.ParseSocksaddr("198.18.0.2:53")}
			sessions := make([]udpNATSession, 0, len(destinations))
			for _, destination := range destinations {
				service.NewPacket([][]byte{[]byte("first")}, source, destination, nil)
				var session udpNATSession
				select {
				case session = <-handler.sessions:
				case <-time.After(time.Second):
					t.Fatal("different UDP destination reused an existing NAT session")
				}
				assert.Equal(t, destination, session.destination)
				buffer := buf.New()
				peer, err := session.conn.ReadPacket(buffer)
				require.NoError(t, err)
				assert.Equal(t, destination, peer)
				assert.Equal(t, "first", string(buffer.Bytes()))
				buffer.Release()
				natConn, ok := session.conn.(udpnat.Conn)
				require.True(t, ok)
				assert.Positive(t, natConn.Timeout())
				assert.True(t, natConn.SetTimeout(2*time.Minute))
				sessions = append(sessions, session)
			}
			// Repeated packets to the same full tuple retain their original session.
			for i, destination := range destinations {
				service.NewPacket([][]byte{[]byte("second")}, source, destination, nil)
				buffer := buf.New()
				peer, err := sessions[i].conn.ReadPacket(buffer)
				require.NoError(t, err)
				assert.Equal(t, destination, peer)
				assert.Equal(t, "second", string(buffer.Bytes()))
				buffer.Release()
			}
			select {
			case <-handler.sessions:
				t.Fatal("same UDP tuple created an extra session")
			default:
			}
		})
	}
}

// Switching from queued packets to a direct handler must deliver the first
// packet even when the handler is installed concurrently with packet copying.
type udpCallbackHandler struct{ packets chan int }

func (h *udpCallbackHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.(udpnat.Conn).SetHandler(h)
}
func (h *udpCallbackHandler) NewPacketEx(buffer *buf.Buffer, _ M.Socksaddr) {
	h.packets <- buffer.Len()
	buffer.Release()
}
func TestUDPNATFirstPacketDuringHandlerInstall(t *testing.T) {
	handler := &udpCallbackHandler{packets: make(chan int, 1)}
	service := udpnat.New(handler, func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
		return true, context.Background(), udpNATWriter{}, nil
	}, time.Minute, true)
	t.Cleanup(service.Purge)
	payload := make([]byte, 8000)
	destination := M.ParseSocksaddr("198.18.0.2:8081")
	for i := range 1000 {
		source := M.Socksaddr{Addr: destination.Addr, Port: uint16(20000 + i)}
		service.NewPacket([][]byte{payload}, source, destination, nil)
		select {
		case size := <-handler.packets:
			assert.Len(t, payload, size)
		case <-time.After(time.Second):
			t.Fatalf("first UDP packet lost while installing handler, iteration %d", i)
		}
	}
}
