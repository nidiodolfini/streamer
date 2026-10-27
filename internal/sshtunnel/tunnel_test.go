package sshtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBuildAuthMethodsPassword(t *testing.T) {
	methods, err := buildAuthMethods(Config{AuthMethod: "password", Password: "s3cret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("expected password + keyboard-interactive fallback, got %d methods", len(methods))
	}
}

func TestBuildAuthMethodsPasswordEmpty(t *testing.T) {
	if _, err := buildAuthMethods(Config{AuthMethod: "password"}); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestBuildAuthMethodsUnsupported(t *testing.T) {
	if _, err := buildAuthMethods(Config{AuthMethod: "magic"}); err == nil {
		t.Fatal("expected error for unsupported auth method")
	}
}

func TestBuildAuthMethodsKey(t *testing.T) {
	// Generate a key and marshal it as an OpenSSH private key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "streamer-test")
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	methods, err := buildAuthMethods(Config{AuthMethod: "key", KeyFile: keyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(methods))
	}

	// The parsed signer must be usable: sign a payload and verify it.
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to re-parse key: %v", err)
	}
	sig, err := signer.Sign(rand.Reader, []byte("hello bastion"))
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if err := signer.PublicKey().Verify([]byte("hello bastion"), sig); err != nil {
		t.Fatalf("signature failed verification: %v", err)
	}
}

func TestBuildAuthMethodsKeyMissingFile(t *testing.T) {
	if _, err := buildAuthMethods(Config{AuthMethod: "key", KeyFile: filepath.Join(t.TempDir(), "nope.pem")}); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty host")
	}
}

// TestTunnelEndToEnd spins up an in-memory SSH server (with direct-tcpip
// support) plus a TCP echo server, and verifies that Tunnel.Dial reaches the
// echo server through the SSH connection — the exact path used in production.
func TestTunnelEndToEnd(t *testing.T) {
	sshAddr, stopSSH := startTestSSHServer(t, "supersecret")
	defer stopSSH()

	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	tunnel, err := New(Config{
		Host:       "127.0.0.1",
		Port:       sshAddr.port,
		User:       "tester",
		AuthMethod: "password",
		Password:   "supersecret",
	})
	if err != nil {
		t.Fatalf("failed to create tunnel: %v", err)
	}
	defer tunnel.Close()

	conn, err := tunnel.Dial(context.Background(), "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("failed to dial through tunnel: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello bastion")); err != nil {
		t.Fatalf("failed to write through tunnel: %v", err)
	}
	buf := make([]byte, len("hello bastion"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read echo through tunnel: %v", err)
	}
	if string(buf) != "hello bastion" {
		t.Fatalf("unexpected echo payload: %q", string(buf))
	}
}

func TestTunnelBadPassword(t *testing.T) {
	sshAddr, stopSSH := startTestSSHServer(t, "correct-password")
	defer stopSSH()

	_, err := New(Config{
		Host:       "127.0.0.1",
		Port:       sshAddr.port,
		User:       "tester",
		AuthMethod: "password",
		Password:   "wrong-password",
	})
	if err == nil {
		t.Fatal("expected authentication failure for wrong password")
	}
}

// --- test helpers ---

type sshServerAddr struct {
	host string
	port int
}

func startTestSSHServer(t *testing.T, password string) (sshServerAddr, func()) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create host signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for user %q", c.User())
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(conn, config)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return sshServerAddr{host: "127.0.0.1", port: addr.Port}, func() { _ = listener.Close() }
}

func handleTestSSHConn(nConn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		_ = nConn.Close()
		return
	}
	defer sConn.Close()

	// Reply positively to keepalives; reject everything else.
	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				_ = req.Reply(true, nil)
				continue
			}
			_ = req.Reply(false, nil)
		}
	}()

	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		var msg struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
			_ = newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
			continue
		}

		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}

		target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", msg.DestAddr, msg.DestPort), 5*time.Second)
		if err != nil {
			_ = ch.Close()
			continue
		}

		go ssh.DiscardRequests(chReqs)
		go func() {
			_, _ = io.Copy(target, ch)
			_ = target.Close()
		}()
		go func() {
			_, _ = io.Copy(ch, target)
			_ = ch.Close()
		}()
	}
}

func startEchoServer(t *testing.T) (net.Addr, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return listener.Addr(), func() { _ = listener.Close() }
}
