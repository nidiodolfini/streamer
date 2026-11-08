package rabbitmqmanager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
)

// RMQUserInfo deliberately excludes password hashes returned by Management API.
type RMQUserInfo struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type CreateUserParams struct {
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Tags     []string `json:"tags"`
}

type RMQUserPermissions struct {
	User      string `json:"user"`
	VHost     string `json:"vhost"`
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

func normalizeUserTags(tags []string) []string {
	result := []string{}
	seen := make(map[string]bool)
	for _, value := range tags {
		for _, tag := range strings.Split(value, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" && !seen[tag] {
				result = append(result, tag)
				seen[tag] = true
			}
		}
	}
	return result
}

func (m *RabbitMQManager) ListUsers(ctx context.Context) ([]RMQUserInfo, error) {
	client, err := m.GetHTTPClient()
	if err != nil {
		return nil, err
	}
	users, err := client.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to list users (RabbitMQ administrator access required): %w", err)
	}
	result := make([]RMQUserInfo, 0, len(users))
	for _, user := range users {
		result = append(result, RMQUserInfo{Name: user.Name, Tags: normalizeUserTags(user.Tags)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (m *RabbitMQManager) CreateUser(ctx context.Context, params CreateUserParams) (*RMQUserInfo, error) {
	params.Name = strings.TrimSpace(params.Name)
	if params.Name == "" {
		return nil, fmt.Errorf("username is required")
	}
	if params.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	client, err := m.GetHTTPClient()
	if err != nil {
		return nil, err
	}
	// PUT is an upsert. Check first so Add a user does not normally reset an
	// existing user's password/tags. The API has no atomic create-only operation.
	_, err = client.GetUser(params.Name)
	if err == nil {
		return nil, fmt.Errorf("user %q already exists; select the user to set permissions", params.Name)
	}
	var apiError rabbithole.ErrorResponse
	if !errors.As(err, &apiError) || apiError.StatusCode != http.StatusNotFound {
		return nil, fmt.Errorf("failed to check user %q: %w", params.Name, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tags := normalizeUserTags(params.Tags)
	response, err := client.PutUser(params.Name, rabbithole.UserSettings{
		Name: params.Name, Password: params.Password, Tags: rabbithole.UserTags(tags),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user %q: %w", params.Name, err)
	}
	defer response.Body.Close()
	return &RMQUserInfo{Name: params.Name, Tags: tags}, nil
}

func (m *RabbitMQManager) ListUserPermissions(ctx context.Context, username string) ([]RMQUserPermissions, error) {
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	client, err := m.GetHTTPClient()
	if err != nil {
		return nil, err
	}
	permissions, err := client.ListPermissionsOf(username)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions for %q: %w", username, err)
	}
	result := make([]RMQUserPermissions, 0, len(permissions))
	for _, permission := range permissions {
		result = append(result, RMQUserPermissions{
			User: permission.User, VHost: permission.Vhost,
			Configure: permission.Configure, Write: permission.Write, Read: permission.Read,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].VHost < result[j].VHost })
	return result, nil
}

func (m *RabbitMQManager) SetUserPermissions(ctx context.Context, params RMQUserPermissions) error {
	if strings.TrimSpace(params.User) == "" || params.VHost == "" {
		return fmt.Errorf("username and virtual host are required")
	}
	client, err := m.GetHTTPClient()
	if err != nil {
		return err
	}
	// Keep regexps verbatim, including empty patterns. RabbitMQ validates its
	// own regexp syntax, which differs from Go's and JavaScript's engines.
	response, err := client.UpdatePermissionsIn(params.VHost, params.User, rabbithole.Permissions{
		Configure: params.Configure, Write: params.Write, Read: params.Read,
	})
	if err != nil {
		return fmt.Errorf("failed to set permissions for %q in vhost %q: %w", params.User, params.VHost, err)
	}
	defer response.Body.Close()
	return nil
}
