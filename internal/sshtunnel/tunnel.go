// Package sshtunnel provides a persistent SSH connection to a bastion (jump)
// host and dials remote TCP endpoints through it, mirroring the SSH tunnel
// feature of JetBrains DataGrip. It is pure Go (zero CGO) and only depends on
// golang.org/x/crypto/ssh.
package sshtunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"streamer/internal/storage"

	"golang.org/x/crypto/ssh"
)

// Config carries the SSH bastion connection settings.
type Config struct {
	Host          string // bastion hostname or IP
	Port          int    // bastion SSH port (default 22)
	User          string // SSH username
	AuthMethod    string // "password" or "key"
	Password      string
	KeyFile       string // path to OpenSSH private key (.pem, .key, or id_*)
	KeyPassphrase string // passphrase for the private key, if encrypted
}

// Tunnel maintains a persistent SSH client connected to the bastion host and
// dials outbound TCP connections through it using SSH direct-tcpip channels.
type Tunnel struct {
	cfg    Config
	addr   string
	mu     sync.Mutex
	client *ssh.Client
	stopCh chan struct{}
	doneCh chan struct{}
}

// New dials the bastion, authenticates, and starts a background keepalive
// loop that transparently reconnects when the SSH link drops.
func New(cfg Config) (*Tunnel, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return nil, fmt.Errorf("SSH bastion host is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	userName := strings.TrimSpace(cfg.User)
	if userName == "" {
		userName = localUsername()
	}
	if userName == "" {
		return nil, fmt.Errorf("SSH username is required")
	}

	authMethods, err := buildAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	t := &Tunnel{
		cfg:    cfg,
		addr:   net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Port)),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	clientConfig := &ssh.ClientConfig{
		User:            userName,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // first-connect trust; like many desktop DB GUIs
		Timeout:         15 * time.Second,
	}

	if err := t.connect(clientConfig); err != nil {
		return nil, err
	}

	go t.keepAlive(clientConfig)
	return t, nil
}

// NewForProfile builds a Tunnel from the SSH fields of a connection profile.
// The profile's SSHEnabled flag must be true.
func NewForProfile(p *storage.ConnectionProfile) (*Tunnel, error) {
	return New(Config{
		Host:          p.SSHHost,
		Port:          p.SSHPort,
		User:          p.SSHUser,
		AuthMethod:    p.SSHAuthMethod,
		Password:      p.SSHPassword,
		KeyFile:       p.SSHKeyFile,
		KeyPassphrase: p.SSHKeyPassphrase,
	})
}

// localUsername returns the current OS user name, stripped of any
// Windows domain prefix (e.g. "DOMAIN\\alice" -> "alice").
func localUsername() string {
	u, err := user.Current()
	if err != nil || u == nil {
		return ""
	}
	name := u.Username
	if i := strings.LastIndexAny(name, `\/`); i >= 0 && i+1 < len(name) {
		name = name[i+1:]
	}
	return strings.TrimSpace(name)
}

// buildAuthMethods translates the profile auth settings into SSH auth methods.
func buildAuthMethods(cfg Config) ([]ssh.AuthMethod, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.AuthMethod)) {
	case "", "password":
		if strings.TrimSpace(cfg.Password) == "" {
			return nil, fmt.Errorf("SSH password is empty")
		}
		pass := cfg.Password
		return []ssh.AuthMethod{
			ssh.Password(pass),
			// Fall back to keyboard-interactive for servers that only offer it.
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pass
				}
				return answers, nil
			}),
		}, nil

	case "key", "keypair", "private_key":
		keyFile := strings.TrimSpace(cfg.KeyFile)
		if keyFile == "" {
			return nil, fmt.Errorf("SSH private key file path is empty")
		}
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH private key %q: %w", keyFile, err)
		}
		var signer ssh.Signer
		if cfg.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(cfg.KeyPassphrase))
			// Some callers provide a passphrase even for unencrypted keys.
			if err != nil && strings.Contains(err.Error(), "not password protected") {
				signer, err = ssh.ParsePrivateKey(data)
			}
		} else {
			signer, err = ssh.ParsePrivateKey(data)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH private key %q (OpenSSH PEM / PKCS#8 formats supported): %w", keyFile, err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	default:
		return nil, fmt.Errorf("unsupported SSH auth method %q", cfg.AuthMethod)
	}
}

// connect establishes (or re-establishes) the SSH client to the bastion.
func (t *Tunnel) connect(clientConfig *ssh.ClientConfig) error {
	conn, err := net.DialTimeout("tcp", t.addr, clientConfig.Timeout)
	if err != nil {
		return fmt.Errorf("failed to reach SSH bastion %s: %w", t.addr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, t.addr, clientConfig)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SSH handshake/authentication with bastion %s failed: %w", t.addr, err)
	}
	client := ssh.NewClient(c, chans, reqs)

	t.mu.Lock()
	if t.isClosed() {
		t.mu.Unlock()
		_ = client.Close()
		return fmt.Errorf("SSH tunnel already closed")
	}
	old := t.client
	t.client = client
	t.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return nil
}

// keepAlive periodically probes the SSH link and reconnects when it drops.
func (t *Tunnel) keepAlive(clientConfig *ssh.ClientConfig) {
	defer close(t.doneCh)

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.mu.Lock()
			cl := t.client
			t.mu.Unlock()
			if cl == nil {
				continue
			}
			if _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				_ = t.connect(clientConfig)
			}
		}
	}
}

// Dial opens a TCP connection to addr (host:port) through the SSH bastion.
// It can be plugged directly into http.Transport.DialContext, kgo.Dialer, etc.
func (t *Tunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	t.mu.Lock()
	cl := t.client
	t.mu.Unlock()
	if cl == nil {
		return nil, fmt.Errorf("SSH bastion tunnel is not connected")
	}

	var (
		conn net.Conn
		err  error
	)
	if ctx != nil {
		conn, err = cl.DialContext(ctx, network, addr)
	} else {
		conn, err = cl.Dial(network, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("SSH tunnel dial %s failed: %w", addr, err)
	}
	return conn, nil
}

func (t *Tunnel) isClosed() bool {
	select {
	case <-t.stopCh:
		return true
	default:
		return false
	}
}

// Close terminates the keepalive loop and closes the SSH connection.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	cl := t.client
	t.client = nil
	t.mu.Unlock()

	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	<-t.doneCh

	if cl != nil {
		return cl.Close()
	}
	return nil
}
