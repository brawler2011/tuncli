package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

const StateDir = "/var/lib/tuncli"
const Socket = "/run/tuncli/control.sock"
const ManifestPath = "/etc/tuncli-owner.json"

type Manifest struct {
	UID int `json:"uid"`
}
type Request struct {
	Operation    string   `json:"operation"`
	Args         []string `json:"args,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	Node         string   `json:"node,omitempty"`
	Subscription string   `json:"subscription,omitempty"`
}
type Response struct {
	Error   string   `json:"error,omitempty"`
	Output  string   `json:"output,omitempty"`
	Status  *Status  `json:"status,omitempty"`
	Choices []Choice `json:"choices,omitempty"`
}
type Choice struct {
	Subscription string `json:"subscription"`
	Name         string `json:"name"`
}
type Status struct {
	State      string `json:"state"`
	Desired    bool   `json:"desired"`
	Node       string `json:"node"`
	Mode       string `json:"mode"`
	Protection bool   `json:"protection"`
	LastError  string `json:"last_error,omitempty"`
}

func Installed() bool { _, err := os.Stat(ManifestPath); return !os.IsNotExist(err) }
func Call(ctx context.Context, request Request) (Response, error) {
	return CallSocket(ctx, Socket, request)
}
func CallSocket(ctx context.Context, path string, request Request) (Response, error) {
	var result Response
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return result, fmt.Errorf("tuncli service unavailable (no foreground fallback): %w", err)
	}
	defer func() { _ = conn.Close() }()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return result, err
	}
	if err = json.NewDecoder(io.LimitReader(conn, 4<<20)).Decode(&result); err != nil {
		return result, err
	}
	if result.Error != "" {
		return result, fmt.Errorf("%s", result.Error)
	}
	return result, nil
}
func Authorized(uid, owner uint32) bool { return uid == 0 || uid == owner }
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		sockErr = e
		if e == nil {
			uid = cred.Uid
		}
	})
	if err != nil {
		return 0, err
	}
	return uid, sockErr
}
func ServeConnection(conn *net.UnixConn, owner uint32, handle func(Request) Response) {
	ServeConnectionContext(conn, owner, func(_ context.Context, r Request) Response { return handle(r) })
}
func ServeConnectionContext(conn *net.UnixConn, owner uint32, handle func(context.Context, Request) Response) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	uid, err := peerUID(conn)
	if err != nil || !Authorized(uid, owner) {
		_ = json.NewEncoder(conn).Encode(Response{Error: "permission denied"})
		return
	}
	var request Request
	decoder := json.NewDecoder(io.LimitReader(conn, 64<<10))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid request"})
		return
	}
	if request.Operation == "logs" {
		if len(request.Args) > 1 || (len(request.Args) == 1 && request.Args[0] != "-f") {
			_ = json.NewEncoder(conn).Encode(Response{Error: "invalid log arguments"})
			return
		}
		_ = conn.SetDeadline(time.Time{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		args := []string{"-u", "tuncli.service", "--no-pager", "-n", "100", "-o", "short-iso"}
		if len(request.Args) == 1 {
			args = append(args, "-f")
		}
		command := exec.CommandContext(ctx, "/usr/bin/journalctl", args...)
		pipe, e := command.StdoutPipe()
		if e != nil {
			_ = json.NewEncoder(conn).Encode(Response{Error: e.Error()})
			return
		}
		if e = command.Start(); e != nil {
			_ = json.NewEncoder(conn).Encode(Response{Error: e.Error()})
			return
		}
		go func() { var b [1]byte; _, _ = conn.Read(b[:]); cancel() }()
		encoder := json.NewEncoder(conn)
		b := make([]byte, 8192)
		for {
			n, e := pipe.Read(b)
			if n > 0 {
				if e = encoder.Encode(Response{Output: string(b[:n])}); e != nil {
					cancel()
					break
				}
			}
			if e != nil {
				break
			}
		}
		if e = command.Wait(); e != nil && ctx.Err() == nil {
			_ = encoder.Encode(Response{Error: e.Error()})
		}
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The client closes its socket on Ctrl+C. Cancel DNS/download/probe work too.
	go func() { var b [1]byte; _, _ = conn.Read(b[:]); cancel() }()
	_ = json.NewEncoder(conn).Encode(handle(ctx, request))
}
func Logs(ctx context.Context, follow bool, out io.Writer) error {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", Socket)
	if err != nil {
		return fmt.Errorf("tuncli service unavailable: %w", err)
	}
	defer func() { _ = conn.Close() }()
	request := Request{Operation: "logs"}
	if follow {
		request.Args = []string{"-f"}
	}
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	decoder := json.NewDecoder(conn)
	for {
		var response Response
		if err = decoder.Decode(&response); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if response.Error != "" {
			return fmt.Errorf("%s", response.Error)
		}
		if _, err = io.WriteString(out, response.Output); err != nil {
			return err
		}
	}
}
