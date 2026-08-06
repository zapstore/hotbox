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
	"strings"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/zapstore/hotbox/internal/android"
	hotboxidentity "github.com/zapstore/hotbox/internal/identity"
	hotboxnostr "github.com/zapstore/hotbox/internal/nostr"
	"github.com/zapstore/hotbox/internal/toolchain"
	"github.com/zapstore/hotbox/internal/vault"
)

type Server struct {
	key      vault.Keystore
	password string
	bunker   *hotboxnostr.Service
	root     string
	aliases  []Alias
	sign     chan struct{}
	zsp      toolchain.Executable
	keytool  toolchain.Executable
	relays   []string
}

type Alias struct {
	Name              string `json:"name"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	CertificateDN     string `json:"certificate_dn,omitempty"`
}

func New(
	key vault.Keystore,
	password string,
	bunker *hotboxnostr.Service,
	workspace string,
	aliases []Alias,
	zsp, keytool toolchain.Executable,
	relays []string,
) (*Server, error) {
	root, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}
	return &Server{
		key: key, password: password, bunker: bunker, root: root,
		aliases: aliases, sign: make(chan struct{}, 1),
		zsp: zsp, keytool: keytool, relays: relays,
	}, nil
}

func (s *Server) Workspace() string {
	return s.root
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
	listener = sameUserListener(listener)
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
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("POST /v1/apk/sign", s.signAPKRelative)
	mux.HandleFunc("POST /v1/apk/identity", s.linkAPKIdentity)
	mux.HandleFunc("POST /v1/nostr/sign", s.signNostrEvent)
	mux.HandleFunc("POST /v1/nostr/sessions", s.createNostrSession)
	mux.HandleFunc("GET /v1/nostr/sessions", s.listNostrSessions)
	mux.HandleFunc("DELETE /v1/nostr/sessions/{id}", s.revokeNostrSession)
	mux.HandleFunc("POST /v1/sign-apk", s.signAPK)
	return mux
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	status := statusResponse{
		OK: true, Bunker: s.bunker != nil,
		IdentityLinking: s.zsp.Valid() && s.keytool.Valid(),
		Aliases:         s.key.Aliases, Certificates: s.aliases, Workspace: s.root,
	}
	if s.bunker != nil {
		status.Npub, _ = nip19.EncodePublicKey(s.bunker.PublicKey())
	}
	write(w, http.StatusOK, status)
}

type apkIdentityRequest struct {
	Alias string `json:"alias,omitempty"`
}

type apkIdentityResponse struct {
	OK      bool     `json:"ok"`
	Status  string   `json:"status"`
	EventID string   `json:"event_id"`
	Relays  []string `json:"relays"`
}

func (s *Server) linkAPKIdentity(w http.ResponseWriter, r *http.Request) {
	if s.bunker == nil || !s.zsp.Valid() || !s.keytool.Valid() {
		write(w, http.StatusConflict, errorResponse{Error: "APK identity linking is unavailable"})
		return
	}
	var request apkIdentityRequest
	if !decode(w, r, &request) {
		return
	}
	alias, err := s.selectAlias(request.Alias)
	if err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Hint: "set alias to one of the aliases from GET /v1/status"})
		return
	}
	select {
	case s.sign <- struct{}{}:
		defer func() { <-s.sign }()
	default:
		write(w, http.StatusTooManyRequests, errorResponse{Error: "a signing operation is already running"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	result, err := hotboxidentity.Link(
		ctx, s.zsp, s.keytool, s.key, s.password, alias, s.bunker, s.relays,
	)
	if err != nil {
		slog.Warn("APK identity linking failed", "error", err)
		write(w, http.StatusBadGateway, errorResponse{Error: err.Error(), Hint: "check zsp and relay availability"})
		return
	}
	slog.Info("APK identity linked", "alias", alias, "event", result.EventID)
	write(w, http.StatusOK, apkIdentityResponse{
		OK: true, Status: "linked", EventID: result.EventID, Relays: result.Relays,
	})
}

type nostrSignRequest struct {
	Event nostr.Event `json:"event"`
}

func (s *Server) signNostrEvent(w http.ResponseWriter, r *http.Request) {
	if s.bunker == nil {
		write(w, http.StatusConflict, errorResponse{Error: "Nostr identity is unavailable"})
		return
	}
	var request nostrSignRequest
	if !decodeLimit(w, r, &request, 512<<10) {
		return
	}
	event, err := s.bunker.SignEvent(r.Context(), request.Event)
	if err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	slog.Info("Nostr event signed", "kind", event.Kind, "event", event.ID)
	write(w, http.StatusOK, event)
}

type nostrSessionRequest struct {
	TTL  string `json:"ttl,omitempty"`
	Uses int    `json:"uses,omitempty"`
}

type nostrSessionListResponse struct {
	OK       bool                      `json:"ok"`
	Sessions []hotboxnostr.SessionInfo `json:"sessions"`
}

func (s *Server) createNostrSession(w http.ResponseWriter, r *http.Request) {
	if s.bunker == nil {
		write(w, http.StatusConflict, errorResponse{Error: "Nostr identity is unavailable"})
		return
	}
	var request nostrSessionRequest
	if !decode(w, r, &request) {
		return
	}
	ttl := 15 * time.Minute
	if request.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(request.TTL)
		if err != nil {
			write(w, http.StatusBadRequest, errorResponse{Error: "invalid ttl"})
			return
		}
	}
	session, err := s.bunker.NewSession(ttl, request.Uses)
	if err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	slog.Info("Nostr signing session issued", "session", session.ID, "ttl", ttl, "uses", session.UsesRemaining)
	write(w, http.StatusCreated, session)
}

func (s *Server) listNostrSessions(w http.ResponseWriter, _ *http.Request) {
	if s.bunker == nil {
		write(w, http.StatusConflict, errorResponse{Error: "Nostr identity is unavailable"})
		return
	}
	write(w, http.StatusOK, nostrSessionListResponse{OK: true, Sessions: s.bunker.ListSessions()})
}

func (s *Server) revokeNostrSession(w http.ResponseWriter, r *http.Request) {
	if s.bunker == nil {
		write(w, http.StatusConflict, errorResponse{Error: "Nostr identity is unavailable"})
		return
	}
	id := r.PathValue("id")
	if id == "" || !s.bunker.RevokeSession(id) {
		write(w, http.StatusNotFound, errorResponse{Error: "Nostr signing session not found"})
		return
	}
	slog.Info("Nostr signing session revoked", "session", id)
	write(w, http.StatusOK, map[string]bool{"ok": true})
}

type signRequest struct {
	Input     string `json:"input"`
	Output    string `json:"output,omitempty"`
	Alias     string `json:"alias"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

type apkSignRequest struct {
	APK       string `json:"apk"`
	Output    string `json:"output,omitempty"`
	Alias     string `json:"alias,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty"`
}

type apkSignResponse struct {
	OK                bool   `json:"ok"`
	Output            string `json:"output"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

func (s *Server) signAPKRelative(w http.ResponseWriter, r *http.Request) {
	var request apkSignRequest
	if !decode(w, r, &request) {
		return
	}
	input, err := s.workspaceInput(request.APK)
	if err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Hint: "use a workspace-relative APK path"})
		return
	}
	output, err := s.workspaceOutput(request.Output, input)
	if err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Hint: "use a workspace-relative output beside the input APK"})
		return
	}
	alias, err := s.selectAlias(request.Alias)
	if err != nil {
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Hint: "set alias to one of the aliases from GET /v1/status"})
		return
	}
	select {
	case s.sign <- struct{}{}:
		defer func() { <-s.sign }()
	default:
		write(w, http.StatusTooManyRequests, errorResponse{Error: "a signing operation is already running"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	result, err := android.SignAPK(ctx, s.root, input, output, s.key, alias, s.password, request.Overwrite)
	if err != nil {
		slog.Warn("APK signing rejected", "error", err)
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Hint: signingHint(err.Error(), s.root)})
		return
	}
	relative, err := filepath.Rel(s.root, result.Output)
	if err != nil {
		write(w, http.StatusInternalServerError, errorResponse{Error: "could not format signed APK path"})
		return
	}
	write(w, http.StatusOK, apkSignResponse{
		OK:                true,
		Output:            filepath.ToSlash(relative),
		CertificateSHA256: result.CertificateSHA256,
	})
}

func (s *Server) selectAlias(requested string) (string, error) {
	if requested != "" {
		for _, alias := range s.key.Aliases {
			if alias == requested {
				return requested, nil
			}
		}
		return "", fmt.Errorf("unknown signing alias")
	}
	if len(s.key.Aliases) != 1 {
		return "", fmt.Errorf("signing alias is ambiguous")
	}
	return s.key.Aliases[0], nil
}

func (s *Server) workspaceInput(relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("apk must be a relative path")
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("apk must be inside the configured workspace")
	}
	path, err := filepath.EvalSymlinks(filepath.Join(s.root, clean))
	if err != nil {
		return "", fmt.Errorf("resolve APK: %w", err)
	}
	if !pathWithin(s.root, path) {
		return "", fmt.Errorf("apk must be inside the configured workspace")
	}
	return path, nil
}

func (s *Server) workspaceOutput(relative, input string) (string, error) {
	if relative == "" {
		return "", nil
	}
	if filepath.IsAbs(relative) {
		return "", fmt.Errorf("output must be a relative path")
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output must be inside the configured workspace")
	}
	path := filepath.Join(s.root, clean)
	if !pathWithin(s.root, path) || filepath.Dir(path) != filepath.Dir(input) {
		return "", fmt.Errorf("output must be beside the input APK")
	}
	return path, nil
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
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
	result, err := android.SignAPK(ctx, s.root, request.Input, request.Output, s.key, request.Alias, s.password, request.Overwrite)
	if err != nil {
		slog.Warn("APK signing rejected", "error", err)
		write(w, http.StatusBadRequest, errorResponse{Error: err.Error(), Hint: signingHint(err.Error(), s.root)})
		return
	}
	slog.Info("APK signed", "certificate_sha256", result.CertificateSHA256)
	write(w, http.StatusOK, result)
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	return decodeLimit(w, r, target, 16<<10)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) bool {
	defer r.Body.Close()
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		write(w, http.StatusUnsupportedMediaType, errorResponse{Error: "Content-Type must be application/json"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
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
	Hint  string `json:"hint,omitempty"`
}

type statusResponse struct {
	OK              bool     `json:"ok"`
	Bunker          bool     `json:"bunker"`
	IdentityLinking bool     `json:"identity_linking"`
	Aliases         []string `json:"aliases"`
	Certificates    []Alias  `json:"certificates"`
	Npub            string   `json:"npub,omitempty"`
	Workspace       string   `json:"workspace"`
}

func signingHint(message, workspace string) string {
	switch {
	case strings.Contains(message, "configured workspace"):
		return "restart Hotbox from the project workspace, or sign an APK under " + workspace
	case strings.Contains(message, "refusing to overwrite existing output"):
		return "choose a new output path or set overwrite to true"
	case strings.Contains(message, "unknown signing alias"):
		return "query GET /v1/status and select one of its aliases"
	case strings.Contains(message, "apksigner not found"):
		return "install Android SDK Build Tools or set ANDROID_HOME"
	default:
		return ""
	}
}
