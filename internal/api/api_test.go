package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	hotboxnostr "github.com/zapstore/hotbox/internal/nostr"
	"github.com/zapstore/hotbox/internal/vault"
)

func TestDecodeRejectsUnknownAndTrailingJSON(t *testing.T) {
	server := &Server{sign: make(chan struct{}, 1)}
	for _, body := range []string{
		`{"input":"app.apk","unexpected":true}`,
		`{"input":"app.apk"} {"input":"other.apk"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/sign-apk", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.routes().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d", body, response.Code)
		}
	}
}

func TestDecodeRequiresJSONContentType(t *testing.T) {
	server := &Server{sign: make(chan struct{}, 1)}
	request := httptest.NewRequest(http.MethodPost, "/v1/sign-apk", strings.NewReader(`{"input":"app.apk"}`))
	response := httptest.NewRecorder()
	server.routes().ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestStatusExposesOnlyPublicIdentityMetadata(t *testing.T) {
	server := &Server{
		key:      vault.Keystore{Aliases: []string{"calendar", "reader"}, Bytes: []byte("private keystore")},
		password: "private password",
		root:     "/projects/calendar",
		aliases:  []Alias{{Name: "calendar", CertificateDN: "CN=calendar", CertificateSHA256: "abc"}},
		sign:     make(chan struct{}, 1),
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	response := httptest.NewRecorder()
	server.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var status statusResponse
	body := response.Body.Bytes()
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if !status.OK || status.Bunker || strings.Join(status.Aliases, ",") != "calendar,reader" ||
		status.Npub != "" || status.Workspace != "/projects/calendar" {
		t.Fatalf("status = %+v", status)
	}
	if len(status.Certificates) != 1 || status.Certificates[0].CertificateDN != "CN=calendar" {
		t.Fatalf("certificates = %+v", status.Certificates)
	}
	if strings.Contains(string(body), "private") {
		t.Fatalf("status exposed private material: %q", body)
	}
}

func TestBunkerSessionEndpointIsUnavailable(t *testing.T) {
	server := &Server{
		key:      vault.Keystore{Bytes: []byte("private keystore")},
		password: "private password",
		sign:     make(chan struct{}, 1),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/bunker-session", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.routes().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if body := response.Body.String(); strings.Contains(body, "private") {
		t.Fatalf("removed endpoint exposed private material: %q", body)
	}
}

func TestNostrSignAndSessionAPI(t *testing.T) {
	bunker, err := hotboxnostr.Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{bunker: bunker, sign: make(chan struct{}, 1)}
	signRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/nostr/sign",
		strings.NewReader(`{"event":{"kind":99999,"created_at":1,"tags":[],"content":"test"}}`),
	)
	signRequest.Header.Set("Content-Type", "application/json")
	signResponse := httptest.NewRecorder()
	server.routes().ServeHTTP(signResponse, signRequest)
	if signResponse.Code != http.StatusOK {
		t.Fatalf("sign status = %d: %s", signResponse.Code, signResponse.Body.String())
	}
	var signed nostr.Event
	if err := json.NewDecoder(signResponse.Body).Decode(&signed); err != nil {
		t.Fatal(err)
	}
	valid, err := signed.CheckSignature()
	if err != nil || !valid || signed.Kind != 99999 {
		t.Fatalf("signed event = %+v", signed)
	}

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"/v1/nostr/sessions",
		strings.NewReader(`{"ttl":"1m","uses":2}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	server.routes().ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", createResponse.Code, createResponse.Body.String())
	}
	var session hotboxnostr.SessionInfo
	if err := json.NewDecoder(createResponse.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	if session.ID == "" || session.URL == "" {
		t.Fatalf("session = %+v", session)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/v1/nostr/sessions", nil)
	listResponse := httptest.NewRecorder()
	server.routes().ServeHTTP(listResponse, listRequest)
	if strings.Contains(listResponse.Body.String(), "bunker://") {
		t.Fatalf("session list exposed capability: %s", listResponse.Body.String())
	}

	revokeRequest := httptest.NewRequest(http.MethodDelete, "/v1/nostr/sessions/"+session.ID, nil)
	revokeRequest.SetPathValue("id", session.ID)
	revokeResponse := httptest.NewRecorder()
	server.routes().ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusOK {
		t.Fatalf("revoke status = %d: %s", revokeResponse.Code, revokeResponse.Body.String())
	}
}

func TestAPKSignRejectsNonWorkspacePathsBeforeSigning(t *testing.T) {
	server := &Server{
		root: t.TempDir(),
		key:  vault.Keystore{Aliases: []string{"punch"}},
		sign: make(chan struct{}, 1),
	}
	for _, apk := range []string{"/tmp/app.apk", "../app.apk"} {
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/apk/sign",
			strings.NewReader(`{"apk":`+fmt.Sprintf("%q", apk)+`}`),
		)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.routes().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("apk %q status = %d", apk, response.Code)
		}
	}
}

func TestServeRefusesNonSocketRuntimePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hotbox.sock")
	if err := os.WriteFile(path, []byte("do not remove"), 0600); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	if err := server.Serve(context.Background(), path); err == nil {
		t.Fatal("Serve removed a non-socket runtime path")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("runtime path was removed: %v", err)
	}
}

func TestSameUserListenerAcceptsCurrentUID(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "hb-peer-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "s.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener = sameUserListener(listener)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			err = connection.Close()
		}
		accepted <- err
	}()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestSigningHint(t *testing.T) {
	if got := signingHint("refusing to overwrite existing output", "/workspace"); !strings.Contains(got, "overwrite") {
		t.Fatalf("overwrite hint = %q", got)
	}
	if got := signingHint("input must be inside the configured workspace (/workspace)", "/workspace"); !strings.Contains(got, "/workspace") {
		t.Fatalf("workspace hint = %q", got)
	}
}
