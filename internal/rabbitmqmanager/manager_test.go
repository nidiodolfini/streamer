package rabbitmqmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"streamer/internal/sshtunnel"
	"streamer/internal/storage"

	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/crypto/ssh"
)

func TestParseConnectionInfo(t *testing.T) {
	mgr := NewRabbitMQManager()

	tests := []struct {
		name        string
		profile     storage.ConnectionProfile
		expectedURL string
		expectedMgt string
		expectedVH  string
		expectedTLS bool
	}{
		{
			name: "Standard default localhost",
			profile: storage.ConnectionProfile{
				URL:      "amqp://localhost:5672",
				Username: "guest",
				Password: "guest",
			},
			expectedURL: "amqp://guest:guest@localhost:5672/",
			expectedMgt: "http://localhost:15672",
			expectedVH:  "/",
			expectedTLS: false,
		},
		{
			name: "Custom VHost in URL path",
			profile: storage.ConnectionProfile{
				URL: "amqp://admin:secret123@rabbit.company.internal:5672/sales",
			},
			expectedURL: "amqp://admin:secret123@rabbit.company.internal:5672/sales",
			expectedMgt: "http://rabbit.company.internal:15672",
			expectedVH:  "sales",
			expectedTLS: false,
		},
		{
			name: "Management URL is derived even when legacy override exists",
			profile: storage.ConnectionProfile{
				URL:           "amqp://myuser:mypass@10.0.0.5:5672",
				ManagementURL: "http://10.0.0.5:18000/",
				VHost:         "analytics",
			},
			expectedURL: "amqp://myuser:mypass@10.0.0.5:5672/analytics",
			expectedMgt: "http://10.0.0.5:15672",
			expectedVH:  "analytics",
			expectedTLS: false,
		},
		{
			name: "Amazon MQ auto-management HTTPS on 443",
			profile: storage.ConnectionProfile{
				URL:      "amqps://b-123.mq.us-east-1.amazonaws.com:5671",
				Username: "clouduser",
				Password: "cloudpass",
			},
			expectedURL: "amqps://clouduser:cloudpass@b-123.mq.us-east-1.amazonaws.com:5671/",
			expectedMgt: "https://b-123.mq.us-east-1.amazonaws.com",
			expectedVH:  "/",
			expectedTLS: true,
		},
		{
			name: "Self-hosted AMQPS retains plugin port",
			profile: storage.ConnectionProfile{
				URL: "amqps://rabbit.internal:5671/",
			},
			expectedURL: "amqps://guest:guest@rabbit.internal:5671/",
			expectedMgt: "https://rabbit.internal:15671",
			expectedVH:  "/",
			expectedTLS: true,
		},
		{
			name: "Amazon MQ with whitespace management URL uses automatic",
			profile: storage.ConnectionProfile{
				URL:           "amqps://b-123.mq.sa-east-1.amazonaws.com/",
				ManagementURL: "  ",
				Username:      "clouduser",
				Password:      "cloudpass",
			},
			expectedURL: "amqps://clouduser:cloudpass@b-123.mq.sa-east-1.amazonaws.com:5671/",
			expectedMgt: "https://b-123.mq.sa-east-1.amazonaws.com",
			expectedVH:  "/",
			expectedTLS: true,
		},
		{
			name: "Amazon MQ ignores stale management overrides",
			profile: storage.ConnectionProfile{
				URL:           "amqps://b-123.mq.sa-east-1.amazonaws.com/",
				ManagementURL: " https://management.internal:8443/rabbit/ ",
				Username:      "clouduser",
				Password:      "cloudpass",
			},
			expectedURL: "amqps://clouduser:cloudpass@b-123.mq.sa-east-1.amazonaws.com:5671/",
			expectedMgt: "https://b-123.mq.sa-east-1.amazonaws.com",
			expectedVH:  "/",
			expectedTLS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			amqpURL, mgtURL, vhost, _, _, isTLS, err := mgr.parseConnectionInfo(&tt.profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if amqpURL != tt.expectedURL {
				t.Errorf("expected amqpURL %q, got %q", tt.expectedURL, amqpURL)
			}
			if mgtURL != tt.expectedMgt {
				t.Errorf("expected mgtURL %q, got %q", tt.expectedMgt, mgtURL)
			}
			if vhost != tt.expectedVH {
				t.Errorf("expected vhost %q, got %q", tt.expectedVH, vhost)
			}
			if isTLS != tt.expectedTLS {
				t.Errorf("expected isTLS %v, got %v", tt.expectedTLS, isTLS)
			}
		})
	}
}

func TestAmazonMQNormalizesTLS(t *testing.T) {
	const host = "b-123.mq.sa-east-1.amazonaws.com"
	for _, endpoint := range []string{
		"amqp://" + host + ":5671/", // The frame_max error reported in the UI.
		"amqp://" + host + ":5672/",
		"amqp://" + host,
		"amqps://" + host + ":5672/",
		host + ":5671/",
		host,
	} {
		t.Run(endpoint, func(t *testing.T) {
			p := storage.ConnectionProfile{URL: endpoint, Username: "clouduser", Password: "cloudpass"}
			uri, management, _, _, _, isTLS, err := NewRabbitMQManager().parseConnectionInfo(&p)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := amqp.ParseURI(uri)
			if err != nil {
				t.Fatal(err)
			}
			if !isTLS || parsed.Scheme != "amqps" || parsed.Port != 5671 || parsed.Host != host {
				t.Fatal("expected an AMQPS connection to the original host on port 5671")
			}
			if management != "https://"+host {
				t.Fatalf("unexpected management endpoint: %s", management)
			}
		})
	}
}

func TestConnectionConfigurationErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		profile storage.ConnectionProfile
		message string
	}{
		{"Plaintext on TLS port", storage.ConnectionProfile{URL: "amqp://rabbit.internal:5671/"}, "change amqp:// to amqps://"},
		{"Amazon MQ missing credentials", storage.ConnectionProfile{URL: "amqp://b-123.mq.sa-east-1.amazonaws.com:5671/"}, "Authentication > User / Password"},
		{"Amazon MQ missing password", storage.ConnectionProfile{URL: "amqps://b-123.mq.sa-east-1.amazonaws.com/", Username: "alice"}, "Authentication > User / Password"},
		{"Wrong scheme", storage.ConnectionProfile{URL: "https://rabbit.internal/"}, "amqp:// or amqps://"},
		{"Missing host", storage.ConnectionProfile{URL: "amqps:///"}, "hostname is required"},
		{"Malformed credential URL", storage.ConnectionProfile{URL: "amqp://alice:private-secret%zz@host/"}, "invalid RabbitMQ URL"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, _, _, err := NewRabbitMQManager().parseConnectionInfo(&tt.profile)
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("expected actionable error containing %q, got %v", tt.message, err)
			}
			if strings.Contains(err.Error(), "private-secret") {
				t.Fatal("configuration error exposed a password")
			}
		})
	}
}

func TestAMQPCredentialsRoundTrip(t *testing.T) {
	p := storage.ConnectionProfile{
		URL:      "amqps://old:old@b-123.mq.sa-east-1.amazonaws.com/",
		Username: "alice+test", Password: " a+b@c:/?#% ", VHost: "team/queues",
	}
	uri, _, _, user, pass, _, err := NewRabbitMQManager().parseConnectionInfo(&p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := amqp.ParseURI(uri)
	if err != nil {
		t.Fatal("the AMQP client could not parse the generated URI")
	}
	if parsed.Username != p.Username || parsed.Password != p.Password || parsed.Vhost != p.VHost || user != p.Username || pass != p.Password {
		t.Fatal("credentials or vhost changed while constructing the connection URI")
	}
}

func TestDialErrorOmitsCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 8)
		_, _ = io.ReadFull(conn, header)
		// Close before the AMQP handshake to exercise the UI's connection error.
	}()
	p := storage.ConnectionProfile{URL: "amqp://" + listener.Addr().String(), Username: "private-user", Password: "private-secret"}
	_, _, _, _, _, _, err = NewRabbitMQManager().buildClients(&p, nil)
	if err == nil || !strings.Contains(err.Error(), listener.Addr().String()) {
		t.Fatalf("expected a connection error identifying the endpoint, got %v", err)
	}
	if strings.Contains(err.Error(), p.Username) || strings.Contains(err.Error(), p.Password) {
		t.Fatal("connection error exposed credentials")
	}
}

func TestBrokerHandshakeTimeoutThroughSSH(t *testing.T) {
	// A real SSH transport whose target accepts TCP but never replies to TLS or
	// AMQP. SSH channel SetDeadline is unsupported: cancellation must close the
	// underlying tunnel, not merely reset the UI's spinner.
	for _, scheme := range []string{"amqp", "amqps"} {
		t.Run(scheme, func(t *testing.T) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			config := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
			config.AddHostKey(signer)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				socket, err := listener.Accept()
				if err != nil {
					return
				}
				defer socket.Close()
				server, channels, requests, err := ssh.NewServerConn(socket, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					go ssh.DiscardRequests(requests)
					go func() { _, _ = io.Copy(io.Discard, channel); _ = channel.Close() }()
				}
			}()
			tunnel, err := sshtunnel.New(sshtunnel.Config{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
				User: "tester", AuthMethod: "password", Password: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			profile := storage.ConnectionProfile{URL: scheme + "://broker.internal/", SSHEnabled: true}
			_, _, _, _, _, _, err = NewRabbitMQManager().buildClientsContext(ctx, &profile, tunnel)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected TLS/AMQP deadline through SSH, got %v", err)
			}
			select {
			case <-serverDone:
			case <-time.After(time.Second):
				t.Fatal("timed-out broker handshake left the SSH transport open")
			}
		})
	}
}

func TestIsAmazonMQHost(t *testing.T) {
	for _, host := range []string{
		"b-123.mq.sa-east-1.amazonaws.com",
		"b-123.mq.cn-north-1.amazonaws.com.cn",
		"B-123.MQ.US-EAST-1.AMAZONAWS.COM.",
	} {
		if !isAmazonMQHost(host) {
			t.Errorf("expected Amazon MQ endpoint: %s", host)
		}
	}
	for _, host := range []string{
		"localhost", "rabbit.internal", "10.0.0.5",
		"b-123.mq.us-east-1.amazonaws.com.example.org",
		"b-123.us-east-1.amazonaws.com", "b-123.ec2.us-east-1.amazonaws.com",
	} {
		if isAmazonMQHost(host) {
			t.Errorf("unexpected Amazon MQ endpoint: %s", host)
		}
	}
}

func TestBuildTLSConfig(t *testing.T) {
	mgr := NewRabbitMQManager()

	p := storage.ConnectionProfile{
		TLSInsecure: true,
		TLSSNI:      "rabbit.mydomain.com",
	}

	cfg, err := mgr.buildTLSConfig(&p)
	if err != nil {
		t.Fatalf("unexpected error building TLS config: %v", err)
	}

	if !cfg.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify=true")
	}
	if cfg.ServerName != "rabbit.mydomain.com" {
		t.Errorf("expected ServerName='rabbit.mydomain.com', got %q", cfg.ServerName)
	}
}
