package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestBastionPersistenceAndProfileIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "streamer.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		t.Fatal(err)
	}
	p := ConnectionProfile{ID: "broker", Name: "Existing broker", URL: "amqp://broker/", AuthType: "userpass", SSHHost: "original"}
	if err := s.SaveConnection(p); err != nil {
		t.Fatal(err)
	}
	b := SSHBastion{ID: "bastion-1", Name: "Production", Host: "jump.internal", User: "ec2-user",
		AuthMethod: "key", KeyFile: `C:\keys\jump.pem`, KeyPassphrase: " significant spaces "}
	if err := s.SaveSSHBastion(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	s = &Storage{db: db}
	defer s.Close()
	if err := s.initSchema(); err != nil {
		t.Fatal(err)
	}
	list, err := s.GetSSHBastions()
	if err != nil || len(list) != 1 {
		t.Fatalf("expected saved bastion after reopening DB, count=%d err=%v", len(list), err)
	}
	b.Port = 22
	if list[0] != b {
		t.Fatal("saved SSH settings changed after reopening DB")
	}
	b.AuthMethod, b.Password = "password", " secret "
	if err := s.SaveSSHBastion(b); err != nil {
		t.Fatal(err)
	}
	list, err = s.GetSSHBastions()
	if err != nil || len(list) != 1 || list[0].Password != b.Password || list[0].KeyFile != "" || list[0].KeyPassphrase != "" {
		t.Fatal("updating a bastion must replace, preserve password whitespace and clear unused key credentials")
	}
	if err := s.DeleteSSHBastion(b.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetConnection(p.ID)
	if err != nil || got.SSHHost != p.SSHHost {
		t.Fatal("editing/deleting a reusable bastion changed an existing connection")
	}
}
