package p2p

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	rtsnap "github.com/thebadinteger/rtsnap"
)

func (t *PTCPTunnel) ForwardToLocal(camPort int) (addr string, stop func(), err error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	var connsMu sync.Mutex
	conns := make(map[net.Conn]struct{})
	halt := func() {
		stopOnce.Do(func() {
			close(stopCh)
			ln.Close()
			connsMu.Lock()
			for c := range conns {
				c.Close()
			}
			connsMu.Unlock()
		})
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			conns[conn] = struct{}{}
			connsMu.Unlock()
			t.serveForwardConn(conn, camPort, stopCh)
			connsMu.Lock()
			delete(conns, conn)
			connsMu.Unlock()
		}
	}()
	return ln.Addr().String(), halt, nil
}

func (t *PTCPTunnel) serveForwardConn(conn net.Conn, camPort int, stopCh <-chan struct{}) {
	defer conn.Close()
	realm := rand.Uint32()
	if err := t.DoBindToPort(realm, camPort); err != nil {
		return
	}
	defer t.DisconnectRealm(realm)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := t.SendDataWithRealm(buf[:n], realm); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-stopCh:
			return
		case <-done:
			return
		default:
		}
		data, err := t.ReadDataForRealm(realm, time.Second)
		if err != nil {
			select {
			case <-stopCh:
				return
			case <-done:
				return
			default:
			}
			if strings.Contains(strings.ToLower(err.Error()), "disconnect") {
				return
			}
			continue
		}
		if len(data) == 0 {
			continue
		}
		if _, err := conn.Write(data); err != nil {
			return
		}
	}
}

func (t *PTCPTunnel) RTSPSnapshot(channel int, timeout time.Duration) ([]byte, error) {
	if channel <= 0 {
		channel = 1
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var lastErr error
	for _, port := range RTSPTryPorts(t.serial()) {
		addr, stop, err := t.ForwardToLocal(port)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := rtspSnapshotVia(addr, channel, t.user, t.pass, timeout)
		stop()
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("rtsp: no route")
	}
	return nil, lastErr
}

func rtspSnapshotVia(addr string, channel int, user, pass string, timeout time.Duration) ([]byte, error) {
	var lastErr error
	for _, subtype := range []int{1, 0} {
		u := fmt.Sprintf("rtsp://%s/cam/realmonitor?channel=%d&subtype=%d", addr, channel, subtype)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		data, err := rtsnap.SnapshotJPEG(ctx, u, 85,
			rtsnap.WithAuth(user, pass),
			rtsnap.WithTimeout(timeout),
		)
		cancel()
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("rtsp: snapshot failed")
	}
	return nil, lastErr
}
