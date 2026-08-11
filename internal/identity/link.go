// Package identity creates and publishes Android certificate identity proofs
// without exposing keystore material to API clients.
package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"
	hotboxnostr "github.com/zapstore/hotbox/internal/nostr"
	"github.com/zapstore/hotbox/internal/toolchain"
	"github.com/zapstore/hotbox/internal/vault"
)

type Result struct {
	EventID string   `json:"event_id"`
	Relays  []string `json:"relays"`
}

func Link(
	ctx context.Context,
	zsp, keytool toolchain.Executable,
	key vault.Keystore,
	password, alias string,
	signer *hotboxnostr.Service,
	relays []string,
) (Result, error) {
	event, err := generate(ctx, zsp, keytool, key, password, alias, signer)
	if err != nil {
		return Result{}, err
	}
	if len(relays) == 0 {
		return Result{}, fmt.Errorf("no identity relays configured")
	}
	pool := nostr.NewSimplePool(ctx)
	defer pool.Close("identity linking complete")
	var published []string
	for result := range pool.PublishMany(ctx, relays, event) {
		if result.Error == nil {
			published = append(published, result.RelayURL)
		}
	}
	if len(published) == 0 {
		return Result{}, fmt.Errorf("identity proof was rejected by every relay")
	}
	return Result{EventID: event.ID, Relays: published}, nil
}

func generate(
	ctx context.Context,
	zsp, keytool toolchain.Executable,
	key vault.Keystore,
	password, alias string,
	signer *hotboxnostr.Service,
) (nostr.Event, error) {
	if !zsp.Valid() {
		return nostr.Event{}, fmt.Errorf("zsp is unavailable")
	}
	if !keytool.Valid() {
		return nostr.Event{}, fmt.Errorf("keytool is unavailable")
	}
	scratch, err := os.MkdirTemp("", "hotbox-identity-*")
	if err != nil {
		return nostr.Event{}, err
	}
	defer os.RemoveAll(scratch)
	if err := os.Chmod(scratch, 0700); err != nil {
		return nostr.Event{}, err
	}
	source := filepath.Join(scratch, "source.jks")
	defer os.Remove(source)
	if err := os.WriteFile(source, key.Bytes, 0600); err != nil {
		return nostr.Event{}, err
	}
	keystore := filepath.Join(scratch, "release.jks")
	defer os.Remove(keystore)
	transientPassword, err := rekey(ctx, keytool, source, keystore, alias, password)
	if err != nil {
		return nostr.Event{}, err
	}
	if err := os.Remove(source); err != nil {
		return nostr.Event{}, fmt.Errorf("remove source keystore: %w", err)
	}
	defer clear(transientPassword)

	session, err := signer.NewSession(15*time.Minute, 1)
	if err != nil {
		return nostr.Event{}, err
	}
	defer signer.RevokeSession(session.ID)

	command := toolchain.Command(ctx, zsp,
		"identity", "--link-key", keystore, "--key-alias", alias,
		"--offline", "--json",
	)
	command.Dir = scratch
	command.Env = childEnvironment(scratch,
		"SIGN_WITH="+session.URL,
		"KEYSTORE_PASSWORD="+string(transientPassword),
		"KEYSTORE_KEY_PASSWORD="+string(transientPassword),
	)
	passwordInput := append(append([]byte(nil), transientPassword...), '\n')
	defer clear(passwordInput)
	command.Stdin = bytes.NewReader(passwordInput)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nostr.Event{}, fmt.Errorf("zsp identity failed: %w: %s", err, sanitized(stderr.String()))
	}
	if err := os.Remove(keystore); err != nil {
		return nostr.Event{}, fmt.Errorf("remove transient keystore: %w", err)
	}
	var event nostr.Event
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&event); err != nil {
		return nostr.Event{}, fmt.Errorf("zsp identity returned invalid event: %w", err)
	}
	if event.Kind != 30509 || event.PubKey != signer.PublicKey() {
		return nostr.Event{}, fmt.Errorf("zsp identity returned an unexpected event")
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid {
		return nostr.Event{}, fmt.Errorf("zsp identity returned an invalid signature")
	}
	return event, nil
}

func rekey(
	ctx context.Context,
	keytool toolchain.Executable,
	source, destination, alias, sourcePassword string,
) ([]byte, error) {
	transient := make([]byte, 32)
	if _, err := rand.Read(transient); err != nil {
		return nil, err
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(transient)))
	base64.RawURLEncoding.Encode(encoded, transient)
	clear(transient)
	command := toolchain.Command(ctx, keytool,
		"-importkeystore",
		"-srckeystore", source,
		"-srcstoretype", "JKS",
		"-srcalias", alias,
		"-srcstorepass:file", "/dev/fd/3",
		"-srckeypass:file", "/dev/fd/4",
		"-destkeystore", destination,
		"-deststoretype", "JKS",
		"-destalias", alias,
		"-deststorepass:env", "HOTBOX_TRANSIENT_PASSWORD",
		"-destkeypass:env", "HOTBOX_TRANSIENT_PASSWORD",
		"-noprompt",
	)
	command.Env = append(command.Env, "HOTBOX_TRANSIENT_PASSWORD="+string(encoded))
	storePassword, err := passwordPipe(sourcePassword)
	if err != nil {
		clear(encoded)
		return nil, err
	}
	defer storePassword.Close()
	keyPassword, err := passwordPipe(sourcePassword)
	if err != nil {
		clear(encoded)
		return nil, err
	}
	defer keyPassword.Close()
	command.ExtraFiles = []*os.File{storePassword, keyPassword}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		clear(encoded)
		return nil, fmt.Errorf("prepare transient JKS: %w: %s", err, sanitized(stderr.String()))
	}
	if err := os.Chmod(destination, 0600); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

func passwordPipe(password string) (*os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(writer, password+"\n"); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		_ = reader.Close()
		return nil, err
	}
	return reader, nil
}

func childEnvironment(home string, extra ...string) []string {
	environment := toolchain.Environment()
	filtered := environment[:0]
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "HOME=") {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, append([]string{"HOME=" + home}, extra...)...)
}

func sanitized(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
