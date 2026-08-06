---
name: hotbox
description: Uses an unlocked Hotbox socket to sign Android APKs and Nostr events without accessing private keys.
disable-model-invocation: true
---

# Hotbox

The operator starts and unlocks Hotbox from the project workspace, then gives
the agent one random Unix socket path. Use only that socket. Never locate or
invoke a Hotbox executable, inspect the vault, export a keystore, request a
password, or use an `nsec`.

The socket path is full signing authority for the unlocked session. Do not
print, persist, commit, or share it. All API requests use JSON over HTTP through
the Unix socket. Paths sent to Hotbox are relative to its workspace.

## Status

`GET /v1/status` returns this public metadata shape. `npub` is omitted when
Nostr signing is unavailable:

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

Avoid a status preflight when the requested operation can provide the same
validation.

## Sign an APK

Build the unsigned APK normally, then make one request:

```http
POST /v1/apk/sign
Content-Type: application/json

{
  "apk":"app/build/outputs/apk/release/app-release-unsigned.apk",
  "output":"app/build/outputs/apk/release/app-release.apk",
  "alias":"my-app"
}
```

`apk` and optional `output` must be workspace-relative. An explicit `output`
must be beside the input APK. If omitted, Hotbox uses
`app-release-unsigned-signed.apk`; provide `output` to use a clean name. Omit
`alias` only when Hotbox has exactly one. Set `"overwrite":true` only when
replacing an existing signed output is intended.

```json
{
  "ok": true,
  "output": "app/build/outputs/apk/release/app-release.apk",
  "certificate_sha256": "AB:CD:..."
}
```

The signed pathname is the response's `output` field, not `apk`. A non-2xx
response is a failure; report its JSON `error` and `hint` without bypassing
Hotbox. In particular, an existing output returns a hint to choose a new name
or set `overwrite` to `true`.

## Link an Android identity

Before the first zsp publication for an alias:

```http
POST /v1/apk/identity
Content-Type: application/json

{"alias":"my-app"}
```

Hotbox keeps the JKS and password inside the daemon, generates the kind `30509`
proof, and publishes it. Never pass `--skip-certificate-linking` to zsp.

## One-shot Nostr signing

For nak or another one-shot publisher, send an unsigned event template:

```http
POST /v1/nostr/sign
Content-Type: application/json

{"event":{"kind":1,"created_at":1770000000,"tags":[],"content":"hello"}}
```

Hotbox accepts any event kind. Do not supply `id`, `sig`, or a different
`pubkey`. The response contains the complete signed event; publication remains
the caller's responsibility.

## NIP-46 sessions

Clients such as ngit, nak, and zsp can request a short-lived session:

```http
POST /v1/nostr/sessions
Content-Type: application/json

{"ttl":"15m","uses":64}
```

`ttl` defaults to `"15m"` and may be no more than one hour. `uses` defaults to
`64` and must be from 1 through 1024. The creation response is:

```json
{
  "id": "session-id",
  "url": "bunker://...?",
  "expires_at": "2026-08-06T13:35:00Z",
  "uses_remaining": 64
}
```

`url` is the `bunker://` capability and is returned exactly once. Scope it
only to the intended child process. Do not print or persist it. Save only the
non-secret `id` needed to revoke it when the child finishes:

```http
DELETE /v1/nostr/sessions/<id>
```

Sessions allow `get_public_key`, `ping`, and signing any event kind. They deny
encryption, decryption, and private-key export. They also expire, enforce a
signature-use limit, and bind to the first NIP-46 client.

For zsp, set the returned URL as `SIGN_WITH` only for `zsp publish -q` and use
an explicit APK/config input. For ngit, use it as the local bunker URL for the
single repository operation, then revoke it. For nak, pass it through nak's
NIP-46 signer option or use the one-shot endpoint above.
