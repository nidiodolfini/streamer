package sshtunnel

import (
	"net"
	"os"
	"sync"
	"time"
)

// deadlineConn adds read/write deadline support to SSH channel connections,
// whose SetDeadline methods always fail. Clients such as amqp091 stop their
// heartbeat loop when SetReadDeadline fails, which makes brokers close idle
// connections for missed client heartbeats.
//
// An expired deadline makes subsequent operations fail without closing the
// connection, as with net.TCPConn. An operation already blocked when its
// deadline expires can only be interrupted by closing the SSH channel.
type deadlineConn struct {
	net.Conn
	mu          sync.Mutex
	read, write deadline
}

type deadline struct {
	at     time.Time
	timer  *time.Timer
	active int
}

func newDeadlineConn(c net.Conn) net.Conn { return &deadlineConn{Conn: c} }

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.set(&c.read, t)
	c.set(&c.write, t)
	return nil
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error  { c.set(&c.read, t); return nil }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error { c.set(&c.write, t); return nil }

func (c *deadlineConn) set(d *deadline, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d.at = t
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if t.IsZero() {
		return
	}
	d.timer = time.AfterFunc(time.Until(t), func() {
		c.mu.Lock()
		expired := d.active > 0 && !d.at.IsZero() && !time.Now().Before(d.at)
		c.mu.Unlock()
		if expired {
			_ = c.Conn.Close()
		}
	})
}

func (c *deadlineConn) begin(d *deadline) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !d.at.IsZero() && !time.Now().Before(d.at) {
		return false
	}
	d.active++
	return true
}

// end reports whether the deadline had expired, so errors caused by closing
// the channel are reported as timeouts.
func (c *deadlineConn) end(d *deadline) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	d.active--
	return !d.at.IsZero() && !time.Now().Before(d.at)
}

func timeoutError(op string) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.ErrDeadlineExceeded}
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if !c.begin(&c.read) {
		return 0, timeoutError("read")
	}
	n, err := c.Conn.Read(p)
	if c.end(&c.read) && err != nil {
		err = timeoutError("read")
	}
	return n, err
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	if !c.begin(&c.write) {
		return 0, timeoutError("write")
	}
	n, err := c.Conn.Write(p)
	if c.end(&c.write) && err != nil {
		err = timeoutError("write")
	}
	return n, err
}

func (c *deadlineConn) Close() error {
	c.mu.Lock()
	for _, d := range []*deadline{&c.read, &c.write} {
		if d.timer != nil {
			d.timer.Stop()
			d.timer = nil
		}
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
