package rabbitmqmanager

import (
	"testing"

	"streamer/internal/storage"
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
			name: "Explicit Management URL and VHost",
			profile: storage.ConnectionProfile{
				URL:           "amqp://myuser:mypass@10.0.0.5:5672",
				ManagementURL: "http://10.0.0.5:18000/",
				VHost:         "analytics",
			},
			expectedURL: "amqp://myuser:mypass@10.0.0.5:5672/analytics",
			expectedMgt: "http://10.0.0.5:18000",
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
			},
			expectedURL: "amqps://guest:guest@b-123.mq.sa-east-1.amazonaws.com:5671/",
			expectedMgt: "https://b-123.mq.sa-east-1.amazonaws.com",
			expectedVH:  "/",
			expectedTLS: true,
		},
		{
			name: "Amazon MQ explicit management override takes priority",
			profile: storage.ConnectionProfile{
				URL:           "amqps://b-123.mq.sa-east-1.amazonaws.com/",
				ManagementURL: " https://management.internal:8443/rabbit/ ",
			},
			expectedURL: "amqps://guest:guest@b-123.mq.sa-east-1.amazonaws.com:5671/",
			expectedMgt: "https://management.internal:8443/rabbit",
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
