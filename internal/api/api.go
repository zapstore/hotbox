package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/zapstore/hotbox/internal/android"
	hotboxnostr "github.com/zapstore/hotbox/internal/nostr"
	"github.com/zapstore/hotbox/internal/vault"
)

type Server struct {
	key    vault.Keystore
	bunker *hotboxnostr.Service
	root   string
	sign   chan struct{}
}

func New(key vault.Keystore, bunker *hotboxnostr.Service, workspace string) (*Server, error) {
	root, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}
	return &Server{key: key, bunker: bunker, root: root, sign: make(chan struct{}, 1)}, nil
}

func (s *Server) Serve(ctx context.Context, socket string) error {
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove non-socket runtime path")
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0600); err != nil {
		_ = listener.Close()
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socket)
	}()
	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		Handler:           s.routes(),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	return httpServer.Serve(listener)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{"ok": true, "bunker": s.bunker != nil})
	})
	mux.HandleFunc("POST /v1/sign-apk", s.signAPK)
	mux.HandleFunc("POST /v1/bunker-url", s.bunkerURL)
	return mux
}

type signRequest struct {
	Input  string `json:"input"`
	Output string `json:"output,omitempty"`
}

func (s *Server) signAPK(w http.ResponseWriter, r *http.Request) {
	select {
	case s.sign <- struct{}{}:
		defer func() { <-s.sign }()
	default:
		write(w, http.StatusTooManyRequests, errorResponse{Error: "a signing operation is already running"})
		return
	}
	var request signRequest
	if !decode(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := android.SignAPK(ctx, s.root, request.Input, request.Output, s.key)
	if err != nil {
		slog.Warn("APK signing rejected", "error", err)
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	slog.Info("APK signed", "certificate_sha256", result.CertificateSHA256)
	write(w, http.StatusOK, result)
}

type bunkerRequest struct {
	TTL string `json:"ttl,omitempty"`
}

func (s *Server) bunkerURL(w http.ResponseWriter, r *http.Request) {
	if s.bunker == nil {
		write(w, http.StatusConflict, errorResponse{Error: "Nostr identity is unavailable"})
		return
	}
	var request bunkerRequest
	if !decode(w, r, &request) {
		return
	}
	ttl := 15 * time.Minute
	if request.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(request.TTL)
		if err != nil || ttl <= 0 || ttl > time.Hour {
			write(w, http.StatusBadRequest, errorResponse{Error: "ttl must be greater than zero and no more than one hour"})
			return
		}
	}
	url, err := s.bunker.URL(ttl)
	if err != nil {
		slog.Error("could not issue bunker capability", "error", err)
		write(w, http.StatusInternalServerError, errorResponse{Error: "could not issue bunker URL"})
		return
	}
	slog.Info("bunker capability issued", "ttl", ttl)
	write(w, http.StatusOK, bunkerResponse{URL: url})
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		write(w, http.StatusUnsupportedMediaType, errorResponse{Error: "Content-Type must be application/json"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON request"})
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		write(w, http.StatusBadRequest, errorResponse{Error: "request must contain exactly one JSON object"})
		return false
	}
	return true
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func IsClosed(err error) bool {
	return errors.Is(err, http.ErrServerClosed)
}

type errorResponse struct {
	Error string `json:"error"`
}

type bunkerResponse struct {
	URL string `json:"url"`
}
