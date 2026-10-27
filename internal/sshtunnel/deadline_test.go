package sshtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// noDeadlineConn mimics ssh's chanConn, whose deadline methods always fail.
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.New("deadline not supported") }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.New("deadline not supported") }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.New("deadline not supported") }

func pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return newDeadlineConn(noDeadlineConn{a}), b
}

func TestDeadlineInterruptsBlockedRead(t *testing.T) {
	conn, _ := pipe(t)
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline must succeed (amqp091 stops heartbeats otherwise): %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline error, got %v", err)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatal("deadline error must be a net.Error timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read deadline did not interrupt a blocked read")
	}
}

func TestExtendedDeadlineKeepsConnection(t *testing.T) {
	conn, peer := pipe(t)
	go func() {
		time.Sleep(250 * time.Millisecond)
		_, _ = peer.Write([]byte("ok"))
	}()
	// Heartbeat-style: keep pushing the deadline forward while reading.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			}
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("extended deadline should not interrupt the read: %q %v", buf, err)
	}
}

func TestExpiredDeadlineDoesNotCloseIdleConnection(t *testing.T) {
	conn, peer := pipe(t)
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	time.Sleep(80 * time.Millisecond)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected immediate deadline error, got %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	go func() { _, _ = peer.Write([]byte("x")) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("connection should remain usable after clearing the deadline: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("read after clearing the deadline did not complete")
	}
}
