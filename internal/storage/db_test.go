package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageProtocols(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "streamer_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	// 1. Save NATS Profile
	natsProf := ConnectionProfile{
		ID:         "nats-1",
		Protocol:   "nats",
		Name:       "Test NATS",
		URL:        "nats://localhost:4222",
		AuthType:   "none",
		ClientName: "StreamerNATS",
	}
	if err := s.SaveConnection(natsProf); err != nil {
		t.Fatalf("failed to save NATS profile: %v", err)
	}

	// 2. Save Kafka Profile
	kafkaProf := ConnectionProfile{
		ID:          "kafka-1",
		Protocol:    "kafka",
		Name:        "Test Kafka",
		URL:         "localhost:9092,localhost:9093",
		AuthType:    "scram256",
		Username:    "alice",
		Password:    "secret",
		TLSSNI:      "kafka.internal",
		TLSInsecure: true,
		ClientName:  "StreamerKafka",
	}
	if err := s.SaveConnection(kafkaProf); err != nil {
		t.Fatalf("failed to save Kafka profile: %v", err)
	}

	// 3. Save RabbitMQ Profile
	rmqProf := ConnectionProfile{
		ID:            "rmq-1",
		Protocol:      "rabbitmq",
		Name:          "Test RabbitMQ",
		URL:           "amqp://guest:guest@localhost:5672/",
		ManagementURL: "http://localhost:15672",
		VHost:         "/",
		AuthType:      "userpass",
		Username:      "guest",
		Password:      "guest",
		ClientName:    "StreamerRMQ",
	}
	if err := s.SaveConnection(rmqProf); err != nil {
		t.Fatalf("failed to save RabbitMQ profile: %v", err)
	}

	// 4. Query All Connections
	conns, err := s.GetAllConnections()
	if err != nil {
		t.Fatalf("failed to get all connections: %v", err)
	}

	if len(conns) != 3 {
		t.Fatalf("expected 3 connections, got %d", len(conns))
	}

	foundNats := false
	foundKafka := false
	foundRabbitMQ := false
	for _, c := range conns {
		if c.ID == "nats-1" {
			foundNats = true
			if c.Protocol != "nats" {
				t.Errorf("expected protocol 'nats', got %q", c.Protocol)
			}
		}
		if c.ID == "kafka-1" {
			foundKafka = true
			if c.Protocol != "kafka" {
				t.Errorf("expected protocol 'kafka', got %q", c.Protocol)
			}
			if c.Username != "alice" || c.Password != "secret" {
				t.Errorf("mismatched Kafka credentials: %s / %s", c.Username, c.Password)
			}
			if c.TLSSNI != "kafka.internal" {
				t.Errorf("expected TLSSNI 'kafka.internal', got %q", c.TLSSNI)
			}
			if !c.TLSInsecure {
				t.Errorf("expected TLSInsecure to be true")
			}
		}
		if c.ID == "rmq-1" {
			foundRabbitMQ = true
			if c.Protocol != "rabbitmq" {
				t.Errorf("expected protocol 'rabbitmq', got %q", c.Protocol)
			}
			if c.ManagementURL != "http://localhost:15672" {
				t.Errorf("expected ManagementURL 'http://localhost:15672', got %q", c.ManagementURL)
			}
			if c.VHost != "/" {
				t.Errorf("expected VHost '/', got %q", c.VHost)
			}
		}
	}

	if !foundNats || !foundKafka || !foundRabbitMQ {
		t.Errorf("expected to find NATS, Kafka, and RabbitMQ profiles, foundNats=%v, foundKafka=%v, foundRMQ=%v", foundNats, foundKafka, foundRabbitMQ)
	}
}

func TestStorageSSHFields(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "streamer_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	db, err := sql.Open("sqlite", filepath.Join(tempDir, "test.db"))
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	prof := ConnectionProfile{
		ID:               "kafka-ssh",
		Protocol:         "kafka",
		Name:             "Private Kafka via Bastion",
		URL:              "kafka-0.internal:9092,kafka-1.internal:9092",
		AuthType:         "scram512",
		Username:         "alice",
		Password:         "secret",
		SSHEnabled:       true,
		SSHHost:          "bastion.example.com",
		SSHPort:          2222,
		SSHUser:          "ec2-user",
		SSHAuthMethod:    "key",
		SSHPassword:      "",
		SSHKeyFile:       `C:\Users\alice\.ssh\id_ed25519`,
		SSHKeyPassphrase: "hunter2",
	}
	if err := s.SaveConnection(prof); err != nil {
		t.Fatalf("failed to save SSH profile: %v", err)
	}

	got, err := s.GetConnection("kafka-ssh")
	if err != nil {
		t.Fatalf("failed to get SSH profile: %v", err)
	}
	if !got.SSHEnabled {
		t.Error("expected SSHEnabled true")
	}
	if got.SSHHost != "bastion.example.com" {
		t.Errorf("expected SSHHost 'bastion.example.com', got %q", got.SSHHost)
	}
	if got.SSHPort != 2222 {
		t.Errorf("expected SSHPort 2222, got %d", got.SSHPort)
	}
	if got.SSHUser != "ec2-user" {
		t.Errorf("expected SSHUser 'ec2-user', got %q", got.SSHUser)
	}
	if got.SSHAuthMethod != "key" {
		t.Errorf("expected SSHAuthMethod 'key', got %q", got.SSHAuthMethod)
	}
	if got.SSHKeyFile != `C:\Users\alice\.ssh\id_ed25519` {
		t.Errorf("mismatched SSHKeyFile: %q", got.SSHKeyFile)
	}
	if got.SSHKeyPassphrase != "hunter2" {
		t.Errorf("mismatched SSHKeyPassphrase: %q", got.SSHKeyPassphrase)
	}
}
