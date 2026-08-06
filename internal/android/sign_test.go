package android

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zapstore/hotbox/internal/vault"
)

func TestSignAPKPassesPasswordsOnlyOnStdin(t *testing.T) {
	sdk := t.TempDir()
	toolsDir := filepath.Join(sdk, "build-tools", "1.0.0")
	if err := os.MkdirAll(toolsDir, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case "$1" in
verify)
	if [ "$2" = "--verbose" ]; then
		echo "Signer #1 certificate SHA-256 digest: abc123"
		exit 0
	fi
	exit 1
	;;
sign)
case " $* " in
*"store secret"*) exit 70 ;;
	esac
	IFS= read -r store
	IFS= read -r key
	[ "$store" = "store secret" ] || exit 71
[ "$key" = "store secret" ] || exit 72
	out=
	last=
	shift
	while [ "$#" -gt 0 ]; do
		if [ "$1" = "--out" ]; then
			shift
			out="$1"
		fi
		last="$1"
		shift
	done
	/bin/cp "$last" "$out"
	;;
*) exit 73 ;;
esac
`
	apksigner := filepath.Join(toolsDir, "apksigner")
	if err := os.WriteFile(apksigner, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANDROID_HOME", sdk)
	t.Setenv("ANDROID_SDK_ROOT", "")

	dir := t.TempDir()
	input := filepath.Join(dir, "app.apk")
	output := filepath.Join(dir, "app-signed.apk")
	if err := os.WriteFile(input, []byte("test APK"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := SignAPK(context.Background(), dir, input, output, vault.Keystore{
		Bytes:   []byte("test keystore"),
		Aliases: []string{"release"},
	}, "release", "store secret", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.CertificateSHA256 != "abc123" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(result.Output); err != nil {
		t.Fatalf("signed output: %v", err)
	}
}

func TestPublishFileRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.apk")
	destination := filepath.Join(dir, "destination.apk")
	if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := publishFile(source, destination, false)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("publishFile error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("destination changed to %q", got)
	}
}

func TestPublishFileOverwritesWhenExplicit(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.apk")
	destination := filepath.Join(dir, "destination.apk")
	if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishFile(source, destination, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("destination = %q", got)
	}
}

func TestCheckOutputAllowsExplicitOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.apk")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkOutput(path, true); err != nil {
		t.Fatalf("explicit overwrite rejected: %v", err)
	}
	if err := checkOutput(path, false); err == nil {
		t.Fatal("implicit overwrite was allowed")
	}
}

func TestSignAPKReportsConfiguredWorkspace(t *testing.T) {
	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(outside, []byte("test APK"), 0600); err != nil {
		t.Fatal(err)
	}
	resolvedWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignAPK(t.Context(), workspace, outside, "", vault.Keystore{Aliases: []string{"app"}}, "app", "password", false)
	if err == nil || !strings.Contains(err.Error(), "configured workspace ("+resolvedWorkspace+")") {
		t.Fatalf("SignAPK error = %v", err)
	}
}

func TestCertificateDigestSupportsAnySignerNumber(t *testing.T) {
	output := "Signer #2 certificate SHA-256 digest: abc123\n"
	if got := certificateDigest(output); got != "abc123" {
		t.Fatalf("certificateDigest() = %q", got)
	}
}
