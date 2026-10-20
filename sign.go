package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/zapstore/hotbox/profile"
)

const signHelp = `Usage:
  hotbox sign <app-unsigned.apk>...

Signs each APK with the Android key of a running hotbox. It reads
HOTBOX_SOCKET and HOTBOX_PIN from the environment, then from .env in the
current directory. Paste the block hotbox prints at startup into .env.
.env must not be readable by other users (chmod 600 .env).

app-release-unsigned.apk is written as app-release.apk beside it. Any other
name is written as <name>-signed.apk. An existing output is replaced.

Requires zipalign and apksigner from Android build-tools, on PATH or under
$ANDROID_HOME. Hotbox never reads the APK; apksigner asks it to sign.
`

func runSign(args []string) error {
	if len(args) == 0 || slices.Contains(args, "-h") || slices.Contains(args, "--help") {
		fmt.Print(signHelp)
		if len(args) == 0 {
			return errors.New("an APK is required")
		}
		return nil
	}
	env, err := signEnv()
	if err != nil {
		return err
	}
	tools, err := findBuildTools()
	if err != nil {
		return err
	}
	for _, apk := range args {
		out, digest, err := signAPK(tools, env, apk)
		if err != nil {
			return fmt.Errorf("%s: %w", apk, err)
		}
		fmt.Printf("%s\n  certificate SHA-256 %s\n", displayPath(out), digest)
	}
	return nil
}

type hotboxEnv struct {
	socket string
	config string
	pin    string
}

// signEnv reads HOTBOX_SOCKET and HOTBOX_PIN from the environment, then .env.
func signEnv() (hotboxEnv, error) {
	file, err := readDotEnv(".env")
	if err != nil {
		return hotboxEnv{}, err
	}
	get := func(name string) string {
		if value, ok := os.LookupEnv(name); ok {
			return value
		}
		return file[name]
	}
	env := hotboxEnv{socket: get("HOTBOX_SOCKET"), pin: get("HOTBOX_PIN")}
	if env.socket == "" || env.pin == "" {
		return hotboxEnv{}, errors.New("HOTBOX_SOCKET and HOTBOX_PIN are not set; paste the block hotbox printed at startup into .env")
	}
	info, err := os.Stat(env.socket)
	if err != nil || info.Mode()&fs.ModeSocket == 0 {
		return hotboxEnv{}, fmt.Errorf("hotbox is not listening on %s; start it and paste the block it prints into .env", env.socket)
	}
	env.config = strings.TrimSuffix(env.socket, ".sock") + ".pkcs11.cfg"
	if _, err := os.Stat(env.config); err != nil {
		return hotboxEnv{}, fmt.Errorf("missing %s; rebuild hotbox with make and restart it", env.config)
	}
	return env, nil
}

// readDotEnv parses KEY=value lines. A missing file is empty. A file that
// other users can read is refused, since it holds signing grants.
func readDotEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; run chmod 600 %s", path, path)
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[strings.TrimSpace(key)] = value
	}
	return values, scanner.Err()
}

type buildTools struct {
	zipalign  string
	apksigner string
}

// findBuildTools prefers PATH, then the newest build-tools under the usual SDK roots.
func findBuildTools() (buildTools, error) {
	zipalign, zErr := exec.LookPath("zipalign")
	apksigner, aErr := exec.LookPath("apksigner")
	if zErr == nil && aErr == nil {
		return buildTools{zipalign: zipalign, apksigner: apksigner}, nil
	}
	var roots []string
	for _, name := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if value := os.Getenv(name); value != "" {
			roots = append(roots, value)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if runtime.GOOS == "darwin" {
			roots = append(roots, filepath.Join(home, "Library", "Android", "sdk"))
		} else {
			roots = append(roots, filepath.Join(home, "Android", "Sdk"))
		}
	}
	roots = append(roots, "/opt/homebrew/share/android-commandlinetools", "/usr/local/share/android-commandlinetools")
	for _, root := range roots {
		entries, err := os.ReadDir(filepath.Join(root, "build-tools"))
		if err != nil {
			continue
		}
		versions := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				versions = append(versions, entry.Name())
			}
		}
		slices.SortFunc(versions, compareVersions)
		for i := len(versions) - 1; i >= 0; i-- {
			dir := filepath.Join(root, "build-tools", versions[i])
			tools := buildTools{zipalign: filepath.Join(dir, "zipalign"), apksigner: filepath.Join(dir, "apksigner")}
			if executable(tools.zipalign) && executable(tools.apksigner) {
				return tools, nil
			}
		}
	}
	return buildTools{}, errors.New("zipalign and apksigner were not found; put Android build-tools on PATH or set ANDROID_HOME")
}

func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x - y
		}
	}
	return strings.Compare(a, b)
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

// displayPath drops the working-directory prefix when the path is inside it.
// Abs and Getwd use the same logical path, so a symlink such as macOS /var
// is not rewritten out from under the comparison.
func displayPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	working, err := os.Getwd()
	if err != nil {
		return absolute
	}
	relative, err := filepath.Rel(working, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return absolute
	}
	return relative
}

// signOutput names the signed APK beside the input.
func signOutput(in string) (string, error) {
	dir, base := filepath.Dir(in), strings.TrimSuffix(filepath.Base(in), ".apk")
	if !strings.HasSuffix(strings.ToLower(in), ".apk") {
		return "", errors.New("input is not an .apk file")
	}
	if trimmed, ok := strings.CutSuffix(base, "-unsigned"); ok && trimmed != "" {
		return filepath.Join(dir, trimmed+".apk"), nil
	}
	return filepath.Join(dir, base+"-signed.apk"), nil
}

func signAPK(tools buildTools, env hotboxEnv, apk string) (out, digest string, err error) {
	in, err := filepath.Abs(apk)
	if err != nil {
		return "", "", err
	}
	if info, err := os.Stat(in); err != nil {
		return "", "", err
	} else if info.IsDir() {
		return "", "", errors.New("input is a directory")
	}
	out, err = signOutput(in)
	if err != nil {
		return "", "", err
	}
	aligned, err := os.CreateTemp(filepath.Dir(in), ".hotbox-align-*.apk")
	if err != nil {
		return "", "", err
	}
	alignedPath := aligned.Name()
	_ = aligned.Close()
	defer os.Remove(alignedPath)

	if output, err := exec.Command(tools.zipalign, "-f", "-p", "4", in, alignedPath).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("zipalign: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	// The apksigner wrapper takes -J options before the subcommand and adds one leading dash.
	sign := exec.Command(tools.apksigner,
		"-J-add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
		"sign",
		"--provider-class", "sun.security.pkcs11.SunPKCS11",
		"--provider-arg", env.config,
		"--ks", "NONE",
		"--ks-type", "PKCS11",
		"--ks-key-alias", profile.AndroidAlias,
		"--ks-pass", "env:HOTBOX_PIN",
		"--in", alignedPath,
		"--out", out,
	)
	sign.Env = append(os.Environ(), "HOTBOX_TOKEN="+env.socket, "HOTBOX_PIN="+env.pin)
	if output, err := sign.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("apksigner sign: %w (the hotbox log has the reason)\n%s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command(tools.apksigner, "verify", "--print-certs", out).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("apksigner verify: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		if _, value, ok := strings.Cut(line, "certificate SHA-256 digest: "); ok {
			return out, strings.TrimSpace(value), nil
		}
	}
	return out, "unknown", nil
}
