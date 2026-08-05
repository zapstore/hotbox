# Hotbox

Hotbox is a local Android signing daemon and Nostr bunker. It does not make
outbound connections or run Gradle. Read [SECURITY.md](SECURITY.md) before
using a production key.

## Build and enroll

```sh
go build -trimpath -o hotbox ./cmd/hotbox
mkdir -m 700 -p "$HOME/.hotbox"
```

Start Hotbox from the project it may sign. The current directory becomes the
allowed APK workspace.

```sh
./hotbox "$HOME/.hotbox/my-app.hotbox"
```

The vault must be outside that workspace. With no path argument, Hotbox asks
for a `.hotbox` filename and stores it in `~/.hotbox`.

The first run asks for a Hotbox password, Android key details, and an optional
Nostr private key. Press Enter at the Android keystore password prompt to reuse
the Hotbox password. New vault passwords must contain at least 12 characters.
Leave the keystore path blank to create a 4096-bit RSA JKS with `keytool`.
Leave the Nostr key blank to generate one.

An imported keystore remains at its original path. Move that file to offline
backup or remove it after checking that the new vault opens correctly.

Vaults are immutable. Stop Hotbox and create a new vault when replacing an
identity.

## Export a keystore

To export the password-protected Android keystore from a vault, supply both
the vault and a new destination file. Hotbox prompts for the vault password
again and refuses to replace an existing destination.

```sh
./hotbox export "$HOME/.hotbox/my-app.hotbox" "$HOME/release.jks"
```

The exported file is mode 0600. Store it securely and remove it when it is no
longer needed.

## Sandboxed launch

Use an absolute binary path, vault path, and workspace path.

Linux with a systemd user manager:

```sh
./scripts/run-hotbox-linux \
  "$PWD/hotbox" \
  "$HOME/.hotbox/my-app.hotbox" \
  "$PWD"
```

The Linux wrapper blocks `connect` for Hotbox and every child process. It keeps
the Unix API and local NIP-46 listener reachable. It also provides private
temporary storage and makes the rest of the home directory read-only. If the
required systemd controls cannot be installed, launch fails. Before unlocking
the vault, it checks the systemd version, cgroup mode, user manager, loopback
binding, and denied external connection behavior.

macOS:

```sh
./scripts/run-hotbox-macos \
  "$PWD/hotbox" \
  "$HOME/.hotbox/my-app.hotbox" \
  "$PWD"
```

The macOS wrapper uses Seatbelt to allow loopback traffic and deny other IP
destinations. `sandbox-exec` is deprecated and may be unavailable inside an
existing sandbox. Before unlocking the vault, it proves that loopback
round-trips work and an external connection returns `EPERM`. The wrapper exits
if either check fails. Use a no-network VM when Seatbelt is unavailable or when
the signing boundary must survive future macOS changes.

Run Gradle, `ngit`, and `zsp` outside the Hotbox wrapper. They need network or
project access that Hotbox does not need.

## Agent API

Set the private socket path once:

```sh
HOTBOX_RUNTIME="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/hotbox-$(id -u)"
HOTBOX_SOCKET="$HOTBOX_RUNTIME/hotbox.sock"
```

Sign a completed APK inside the workspace:

```sh
curl --unix-socket "$HOTBOX_SOCKET" \
  --fail-with-body \
  -X POST http://localhost/v1/sign-apk \
  -H 'Content-Type: application/json' \
  --data '{"input":"/absolute/project/app-release-build.apk","output":"/absolute/project/app-release.apk"}'
```

Hotbox copies the input to private scratch storage, signs the copy, verifies
the certificate, and publishes the output without replacing an existing file.

Capture a short-lived bunker URL without printing it:

```sh
BUNKER_URL="$(
  curl --silent --show-error --fail-with-body \
    --unix-socket "$HOTBOX_SOCKET" \
    -X POST http://localhost/v1/bunker-url \
    -H 'Content-Type: application/json' \
    --data '{"ttl":"15m"}' |
  jq -er '.url'
)"
```

Pass `BUNKER_URL` directly to the intended client. Do not print it, export it,
write it to `.env`, or place it in shell history. The first NIP-46 client to
bind consumes the token.
