package storage

import (
	"fmt"
	"strings"
)

// SSHBastion is a reusable set of SSH settings, independent of broker profiles.
// Applying it copies the settings into a connection so existing profiles remain
// usable even if the saved bastion is later edited or deleted.
type SSHBastion struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	AuthMethod    string `json:"authMethod"`
	Password      string `json:"password,omitempty"`
	KeyFile       string `json:"keyFile,omitempty"`
	KeyPassphrase string `json:"keyPassphrase,omitempty"`
}

func (s *Storage) initBastionSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ssh_bastions (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 22,
		username TEXT NOT NULL,
		auth_method TEXT NOT NULL,
		password TEXT NOT NULL DEFAULT '',
		key_file TEXT NOT NULL DEFAULT '',
		key_passphrase TEXT NOT NULL DEFAULT ''
	)`)
	return err
}

func (s *Storage) GetSSHBastions() ([]SSHBastion, error) {
	rows, err := s.db.Query(`SELECT id, name, host, port, username, auth_method,
		password, key_file, key_passphrase FROM ssh_bastions ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []SSHBastion{}
	for rows.Next() {
		var b SSHBastion
		if err := rows.Scan(&b.ID, &b.Name, &b.Host, &b.Port, &b.User, &b.AuthMethod,
			&b.Password, &b.KeyFile, &b.KeyPassphrase); err != nil {
			return nil, err
		}
		list = append(list, b)
	}
	return list, rows.Err()
}

func (s *Storage) SaveSSHBastion(b SSHBastion) error {
	b.Name = strings.TrimSpace(b.Name)
	b.Host = strings.TrimSpace(b.Host)
	b.User = strings.TrimSpace(b.User)
	b.KeyFile = strings.TrimSpace(b.KeyFile)
	if b.ID == "" || b.Name == "" || b.Host == "" || b.User == "" {
		return fmt.Errorf("bastion name, host and username are required")
	}
	if b.Port == 0 {
		b.Port = 22
	}
	if b.Port < 1 || b.Port > 65535 {
		return fmt.Errorf("SSH port must be between 1 and 65535")
	}
	switch b.AuthMethod {
	case "key":
		if b.KeyFile == "" {
			return fmt.Errorf("SSH private key file path is required")
		}
		b.Password = ""
	case "password":
		if b.Password == "" {
			return fmt.Errorf("SSH password is required")
		}
		b.KeyFile, b.KeyPassphrase = "", ""
	default:
		return fmt.Errorf("select SSH key or password authentication")
	}
	_, err := s.db.Exec(`INSERT INTO ssh_bastions
		(id, name, host, port, username, auth_method, password, key_file, key_passphrase)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host,
		port=excluded.port, username=excluded.username, auth_method=excluded.auth_method,
		password=excluded.password, key_file=excluded.key_file, key_passphrase=excluded.key_passphrase`,
		b.ID, b.Name, b.Host, b.Port, b.User, b.AuthMethod, b.Password, b.KeyFile, b.KeyPassphrase)
	return err
}

func (s *Storage) DeleteSSHBastion(id string) error {
	_, err := s.db.Exec("DELETE FROM ssh_bastions WHERE id = ?", id)
	return err
}
