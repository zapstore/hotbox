---
name: hotbox
description: Signs completed Android APKs and obtains local NIP-46 bunker URLs through the Hotbox daemon. Use when building Android release APKs, publishing with Zapstore, or using ngit for an Android app.
disable-model-invocation: true
---

# Hotbox

Hotbox is a local daemon. Never request, read, print, persist, or modify its Android keystore, password, Nostr private key, or vault. Use Hotbox-issued NIP-46 bunker URLs for all ngit and zsp signing. Never use `SIGN_WITH=browser`, an `nsec`, or a hex private key.

The vault path must be outside the project and signing workspace. Recommend a
private user data directory at `$HOME/.hotbox` with mode 0700.

## Recommend a network-restricted launch

Hotbox needs local Unix-socket and loopback access. It does not need an
internet route. Recommend the supplied fail-closed wrapper when the operator
starts Hotbox. Do not start it on the operator's behalf because vault unlock is
interactive.

Linux:

```bash
./scripts/run-hotbox-linux \
  "$PWD/hotbox" \
  "$HOME/.hotbox/my-app.hotbox" \
  "$PWD"
```

The Linux wrapper uses a transient systemd user service. It denies `connect`
for Hotbox and its children while allowing the local listeners used by the
Unix API and NIP-46. It runs a fail-closed network probe before the password
prompt. Do not suggest `bwrap --unshare-net`: host `ngit` and `zsp` processes
cannot reach a loopback listener in another network namespace.

macOS:

```bash
./scripts/run-hotbox-macos \
  "$PWD/hotbox" \
  "$HOME/.hotbox/my-app.hotbox" \
  "$PWD"
```

This wrapper applies the supplied Seatbelt profile. It allows loopback and
denies non-loopback IP destinations, then probes both rules before unlocking
the vault. `sandbox-exec` is deprecated; if it is unavailable, recommend a VM
with no external network adapter and a narrow local relay proxy. Never
recommend an unsandboxed fallback without clearly stating that the network
control is absent.

Run Gradle, `ngit`, and `zsp` outside the Hotbox wrapper.

Set the socket path for subsequent requests:

```bash
HOTBOX_RUNTIME="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/hotbox-$(id -u)"
HOTBOX_SOCKET="$HOTBOX_RUNTIME/hotbox.sock"
```

## Build and sign an APK

1. Build the unsigned APK normally. Prefer cached/offline dependencies:

```bash
./gradlew assembleRelease --offline
```

2. Submit the finished unsigned APK to Hotbox. Do not give Hotbox a Gradle task, build script, key alias, or password.

```bash
curl --unix-socket "$HOTBOX_SOCKET" \
  --fail-with-body \
  -X POST http://localhost/v1/sign-apk \
  -H 'Content-Type: application/json' \
  --data '{"input":"/absolute/path/app-release-build.apk","output":"/absolute/path/app-release.apk"}'
```

Use the returned `output` path for release distribution. Hotbox writes it next to the input APK and verifies its signing certificate.

Do not include `unsigned` in any APK filename. If Gradle produced an `*-unsigned.apk` file, rename it before making the Hotbox request. The release APK must have the intended final filename, such as `app-release.apk`.

If signing reports a missing Android SDK tool, unsigned input problem, or existing output, report the failure. Do not bypass Hotbox or edit its vault.

## ngit and Zapstore

Request a short-lived local bunker URL immediately before invoking the required tool:

```bash
BUNKER_URL="$(
  curl --silent --show-error --fail-with-body \
    --unix-socket "$HOTBOX_SOCKET" \
    -X POST http://localhost/v1/bunker-url \
    -H 'Content-Type: application/json' \
    --data '{"ttl":"15m"}' |
  jq -er '.url'
)"
```

For Zapstore, always use the bunker URL:

```bash
SIGN_WITH="$BUNKER_URL" zsp publish
```

For ngit, use the bunker login flow:

```bash
ngit account login --local --bunker-url "$BUNKER_URL"
```

Do not use `SIGN_WITH=browser`, an `nsec`, or a hex private key. Do not print, commit, or add the bunker URL to `.env`. Request a new URL if it expires.

### ngit LMDB permission fallback

If ngit fails because of an LMDB permission error, do not weaken filesystem permissions or switch to a local private key.

1. Bypass ngit and publish the NIP-34 repository announcement and repository state events directly using the Hotbox bunker: kinds `30617` and `30618`.
2. Push Git to the GRASP HTTPS endpoint using a NIP-98 `Authorization: Nostr …` header signed through the same Hotbox bunker. NIP-98 uses kind `27235`.

Hotbox allows exactly these NIP-34 and NIP-98 event kinds for the workaround. Use a NIP-46-capable publisher/auth helper; never extract an `nsec` to construct the events or header.
