package rabbitmqmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	rabbithole "github.com/michaelklishin/rabbit-hole/v3"
)

type userAPIRoundTripper struct {
	openBodies atomic.Int32
}

func (transport *userAPIRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		transport.openBodies.Add(1)
		response.Body = &userAPIResponseBody{ReadCloser: response.Body, openBodies: &transport.openBodies}
	}
	return response, err
}

type userAPIResponseBody struct {
	io.ReadCloser
	openBodies *atomic.Int32
}

func (body *userAPIResponseBody) Close() error {
	body.openBodies.Add(-1)
	return body.ReadCloser.Close()
}

func newUserAPIManager(t *testing.T, handler http.HandlerFunc) *RabbitMQManager {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "admin-secret" {
			t.Error("Management credentials were not used")
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
		// Drain even rejected PUT requests before closing the connection, so
		// Windows does not reset the socket with an unread request body.
		io.Copy(io.Discard, r.Body)
	}))
	t.Cleanup(server.Close)
	transport := &userAPIRoundTripper{}
	client, err := rabbithole.NewTLSClient(server.URL, "admin", "admin-secret", transport)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewRabbitMQManager()
	mgr.httpCli = client
	t.Cleanup(func() {
		if count := transport.openBodies.Load(); count != 0 {
			t.Errorf("%d response bodies left open (or closed twice)", count)
		}
	})
	return mgr
}

func TestListUsersOmitsSecretsAndSupportsTagFormats(t *testing.T) {
	mgr := newUserAPIManager(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/users/" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		io.WriteString(w, `[{"name":"z-user","password_hash":"sensitive-hash","tags":"management, monitoring"},{"name":"a-user","tags":["administrator"]},{"name":"none","tags":""}]`)
	})
	users, err := mgr.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[0].Name != "a-user" || !reflect.DeepEqual(users[2].Tags, []string{"management", "monitoring"}) || len(users[1].Tags) != 0 {
		t.Fatalf("unexpected users: %#v", users)
	}
	encoded, _ := json.Marshal(users)
	if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "sensitive-hash") {
		t.Fatalf("user DTO exposed password data: %s", encoded)
	}
}

func TestCreateUserEscapesNameAndPreservesPassword(t *testing.T) {
	name := "team/user ?#% ç"
	password := "  complex-password  "
	puts := 0
	mgr := newUserAPIManager(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/users/"+url.PathEscape(name) || r.URL.RawQuery != "" {
			t.Errorf("incorrect user path: %s", r.URL)
		}
		if r.Method == "GET" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"not_found","reason":"No such user"}`)
			return
		}
		if r.Method != "PUT" {
			t.Errorf("unexpected method %s", r.Method)
		}
		puts++
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload["password"] != password || payload["tags"] != "management,monitoring" || payload["name"] != name {
			t.Error("unexpected user payload")
		}
		w.WriteHeader(http.StatusCreated)
	})
	user, err := mgr.CreateUser(context.Background(), CreateUserParams{Name: name, Password: password, Tags: []string{" management ", "monitoring,management", ""}})
	if err != nil || user == nil || user.Name != name || puts != 1 {
		t.Fatalf("create result: user=%#v err=%v puts=%d", user, err, puts)
	}
}

func TestCreateUserRejectsExistingAndFailedChecks(t *testing.T) {
	for _, status := range []int{200, 401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			mgr := newUserAPIManager(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("must not overwrite user after existing/failed preflight")
				}
				w.WriteHeader(status)
				if status == 200 {
					io.WriteString(w, `{"name":"existing","tags":[]}`)
				} else {
					io.WriteString(w, `{"error":"denied","reason":"Cannot inspect users"}`)
				}
			})
			_, err := mgr.CreateUser(context.Background(), CreateUserParams{Name: "existing", Password: "new-password"})
			if err == nil {
				t.Fatal("expected creation to fail")
			}
			if status == 200 && !strings.Contains(err.Error(), "already exists") {
				t.Fatal(err)
			}
		})
	}
}

func TestUserPermissionsRequests(t *testing.T) {
	for _, vhost := range []string{"/", "team/vhost ?#% ç"} {
		t.Run(vhost, func(t *testing.T) {
			name := "team/user ?#% ç"
			// PCRE lookahead and empty patterns must reach RabbitMQ unchanged.
			params := RMQUserPermissions{User: name, VHost: vhost, Configure: "^(?!private).*", Write: "", Read: "^orders\\..*$"}
			mgr := newUserAPIManager(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case "GET":
					if r.URL.EscapedPath() != "/api/users/"+url.PathEscape(name)+"/permissions" {
						t.Errorf("incorrect permission listing path: %s", r.URL)
					}
					json.NewEncoder(w).Encode([]RMQUserPermissions{params})
				case "PUT":
					if r.URL.EscapedPath() != "/api/permissions/"+url.PathEscape(vhost)+"/"+url.PathEscape(name) || r.URL.RawQuery != "" {
						t.Errorf("incorrect permission update path: %s", r.URL)
					}
					var payload rabbithole.Permissions
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					if payload.Configure != params.Configure || payload.Write != params.Write || payload.Read != params.Read {
						t.Errorf("patterns were modified: %#v", payload)
					}
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected method: %s", r.Method)
				}
			})
			permissions, err := mgr.ListUserPermissions(context.Background(), name)
			if err != nil || len(permissions) != 1 || permissions[0] != params {
				t.Fatalf("unexpected permissions: %#v, err=%v", permissions, err)
			}
			if err := mgr.SetUserPermissions(context.Background(), params); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUserAPIFailures(t *testing.T) {
	mgr := newUserAPIManager(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/users/new" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"not_found","reason":"No such user"}`)
			return
		}
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"bad_request","reason":"Broker validation failed"}`)
	})
	_, listErr := mgr.ListUsers(context.Background())
	_, createErr := mgr.CreateUser(context.Background(), CreateUserParams{Name: "new", Password: "secret"})
	_, permissionsErr := mgr.ListUserPermissions(context.Background(), "new")
	setErr := mgr.SetUserPermissions(context.Background(), RMQUserPermissions{User: "new", VHost: "/", Read: "["})
	for _, err := range []error{listErr, createErr, permissionsErr, setErr} {
		if err == nil || !strings.Contains(err.Error(), "Broker validation failed") {
			t.Errorf("missing API failure reason: %v", err)
		}
	}
}

func TestUserAPIValidationAndUnavailableManagement(t *testing.T) {
	mgr := NewRabbitMQManager()
	ctx := context.Background()
	_, nameErr := mgr.CreateUser(ctx, CreateUserParams{Password: "secret"})
	_, passwordErr := mgr.CreateUser(ctx, CreateUserParams{Name: "new"})
	_, listNameErr := mgr.ListUserPermissions(ctx, "")
	setNameErr := mgr.SetUserPermissions(ctx, RMQUserPermissions{VHost: "/"})
	setVhostErr := mgr.SetUserPermissions(ctx, RMQUserPermissions{User: "new"})
	_, listErr := mgr.ListUsers(ctx)
	_, createErr := mgr.CreateUser(ctx, CreateUserParams{Name: "new", Password: "secret"})
	_, permissionsErr := mgr.ListUserPermissions(ctx, "new")
	setErr := mgr.SetUserPermissions(ctx, RMQUserPermissions{User: "new", VHost: "/"})
	for _, err := range []error{nameErr, passwordErr, listNameErr, setNameErr, setVhostErr, listErr, createErr, permissionsErr, setErr} {
		if err == nil {
			t.Error("expected validation or Management API availability error")
		}
	}
}
