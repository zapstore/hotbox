# Hotbox

Local Android signing daemon and Nostr signer. It never runs Gradle. Read
[SECURITY.md](SECURITY.md) before using a production key.

## Quickstart

Use Hotbox if you want agents or local tools to sign APKs and Nostr events
without holding the vault password, JKS, or `nsec`. You unlock it, agents get
only a Unix socket path. Ideal for publishing Android apps to [Zapstore](https://zapstore.dev).

Skip it if you need CI signing, multi-user access, or a Gradle plugin.

```sh
go build -trimpath -o hotbox ./cmd/hotbox
mkdir -m 700 -p "$HOME/.hotbox"
cd /path/to/android/project   # becomes the allowed APK workspace
./hotbox my-app
```

First run prompts for a Hotbox password (12+ characters), an Android alias, an
optional existing keystore, and an optional Nostr private key. Blank keystore
or Nostr key means Hotbox creates them. An imported JKS must already use the
Hotbox password for store and keys.

Hotbox prints a socket path once. Give agents only that path:

```sh
export HOTBOX_SOCKET=/tmp/hb-UID-random/s.sock
curl --silent --show-error --fail-with-body \
  --unix-socket "$HOTBOX_SOCKET" \
  http://localhost/v1/status
```

## How it works

One encrypted vault holds one shared Android JKS, its public alias list, and
one Nostr identity. Create one alias per Android app. Start and unlock Hotbox
yourself; it then accepts local Unix-socket requests from programs running as
your OS user until it stops.

An agent receives only the random Unix socket path for one unlocked session.
Through it, the agent can sign an already-built APK, link its Android identity,
sign one Nostr event, or issue a bounded NIP-46 session. It never needs a
Hotbox executable, vault path, password, JKS, or Nostr private key.

APK identity linking publishes a Nostr proof to configured relays. Other
operations make outbound connections only through explicitly created NIP-46
sessions.

## Vault and aliases

The vault must sit outside the APK workspace. With no path argument, Hotbox
asks for a `.hotbox` filename and stores it in `~/.hotbox`. A bare name such as
`test` first uses an existing `~/.hotbox/test.hotbox`; otherwise it is treated
as a relative path.

The Hotbox password encrypts the vault and protects the JKS. New Android
certificates use the vault filename as their subject, for example
`developer.hotbox` creates `CN=developer`. Leave the keystore path blank to
create a 4096-bit RSA JKS with `keytool`.

An imported keystore remains at its original path. Move that file to offline
backup or remove it after checking that the new vault opens correctly.

Stop Hotbox, then add a signing identity for another Android app without
creating another vault:

```sh
./hotbox add-alias "$HOME/.hotbox/developer.hotbox" my-other-app
```

## Export a keystore

Supply the vault and a new destination file. Hotbox prompts for the vault
password again and refuses to replace an existing destination.

```sh
./hotbox export "$HOME/.hotbox/my-app.hotbox" "$HOME/release.jks"
```

The exported JKS and its `.json` metadata sidecar are mode 0600. The sidecar
contains aliases and the Nostr `npub`, never a password or `nsec`.

## Local API

Each unlock creates a random mode-0600 socket inside a new mode-0700 directory
under `/tmp`. That path is full signing authority for the daemon session.

Discover public status:

```sh
curl --silent --show-error --fail-with-body \
  --unix-socket "$HOTBOX_SOCKET" \
  http://localhost/v1/status
```

```json
{
  "ok": true,
  "bunker": true,
  "identity_linking": true,
  "aliases": ["my-app"],
  "certificates": [
    {
      "name": "my-app",
      "certificate_sha256": "AB:CD:...",
      "certificate_dn": "CN=my-app"
    }
  ],
  "npub": "npub1...",
  "workspace": "/absolute/project/workspace"
}
```

`npub` is omitted when Nostr signing is unavailable. The response never
contains private material.

Sign an APK with a workspace-relative path:

```sh
curl --unix-socket "$HOTBOX_SOCKET" \
  --fail-with-body \
  -X POST http://localhost/v1/apk/sign \
  -H 'Content-Type: application/json' \
  --data '{"apk":"app/build/outputs/apk/release/app-release-unsigned.apk","output":"app/build/outputs/apk/release/app-release.apk","alias":"my-app"}'
```

Hotbox copies the input to private scratch storage, signs the copy, verifies
the certificate, and publishes the output without replacing an existing file.

```json
{
  "ok": true,
  "output": "app/build/outputs/apk/release/app-release.apk",
  "certificate_sha256": "AB:CD:..."
}
```

The signed path is `output`, not `apk`. Both `apk` and the optional `output`
must be workspace-relative, and `output` must be beside `apk`. If `output` is
omitted, Hotbox uses `app-release-unsigned-signed.apk`. Add
`"overwrite":true` to replace an existing output; otherwise the request fails
with an actionable `error` and `hint`.

Link the Android certificate to the Nostr identity:

```sh
curl --unix-socket "$HOTBOX_SOCKET" --fail-with-body \
  -X POST http://localhost/v1/apk/identity \
  -H 'Content-Type: application/json' \
  --data '{"alias":"my-app"}'
```

Hotbox keeps the JKS and password inside the daemon while generating and
publishing the kind `30509` proof.

## Nostr signing

`POST /v1/nostr/sign` signs one unsigned event JSON object and returns the
complete event. It accepts every event kind. Useful when nak or another tool
will only publish the result.

`POST /v1/nostr/sessions` creates a bounded NIP-46 session for ngit, nak, zsp,
or another compatible client:

```json
{"ttl":"15m","uses":64}
```

`ttl` defaults to `"15m"` and may be no more than one hour. `uses` defaults to
64 and must be from 1 through 1024.

```json
{
  "id": "session-id",
  "url": "bunker://...?",
  "expires_at": "2026-08-06T13:35:00Z",
  "uses_remaining": 64
}
```

The `url` capability is returned only once. It binds to the first client,
allows signing any event kind, tracks successful signatures, and expires after
at most one hour. Do not print or persist `url`; retain only `id` to revoke the
session. `GET /v1/nostr/sessions` lists redacted sessions. Revoke one with
`DELETE /v1/nostr/sessions/{id}` when the client exits.

Sessions expose only `get_public_key`, `ping`, and `sign_event`; encryption,
decryption, and private-key export are denied. Current ngit and zsp clients use
a short-lived loopback WebSocket relay created only for that session.

## Offline smoke test

With a running Hotbox daemon and Android build tools available:

```sh
HOTBOX_SOCKET=/tmp/hb-UID-random/s.sock \
  HOTBOX_ALIAS=my-app ./scripts/smoke-sign-apk
```
