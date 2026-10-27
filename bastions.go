package main

import (
	"context"
	"fmt"
	"time"

	"streamer/internal/sshtunnel"
	"streamer/internal/storage"
)

func (a *App) GetSSHBastions() ([]storage.SSHBastion, error) {
	if a.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}
	return a.storage.GetSSHBastions()
}

func (a *App) SaveSSHBastion(b storage.SSHBastion) error {
	if a.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return a.storage.SaveSSHBastion(b)
}

func (a *App) DeleteSSHBastion(id string) error {
	if a.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return a.storage.DeleteSSHBastion(id)
}

// TestSSHBastion authenticates a temporary SSH connection without touching the
// active broker connection. Returns elapsed connection/authentication time in ms.
func (a *App) TestSSHBastion(b storage.SSHBastion) (float64, error) {
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	start := time.Now()
	tunnel, err := sshtunnel.NewContext(ctx, sshtunnel.Config{
		Host: b.Host, Port: b.Port, User: b.User, AuthMethod: b.AuthMethod,
		Password: b.Password, KeyFile: b.KeyFile, KeyPassphrase: b.KeyPassphrase,
	})
	if err != nil {
		return 0, err
	}
	defer tunnel.Close()
	return float64(time.Since(start).Microseconds()) / 1000, nil
}
