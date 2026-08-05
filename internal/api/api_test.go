package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
