---
name: hotbox
description: >-
  Uses an unlocked Hotbox socket to sign Android APKs and Nostr events without
  accessing private keys. Optionally covers ngit/grasp bunker signing.
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

## Optional: ngit / grasp

Use this only when the operator wants Hotbox for Nostr git (ngit/grasp). Ask
for the unlocked socket path. Never locate the binary, vault, password, or
`nsec`. Never print, persist, or commit bunker URLs or session secrets.

Prerequisites: `ngit` and `git-remote-nostr` on `PATH`, and network access to
the grasp relay (commonly `wss://relay.ngit.dev` / `https://relay.ngit.dev`).

### Session login

```bash
SOCK=<socket-from-operator>

curl -sS --unix-socket "$SOCK" http://localhost/v1/status
# Expect ok, bunker, npub

RESP=$(mktemp)
curl -sS --unix-socket "$SOCK" -X POST http://localhost/v1/nostr/sessions \
  -H 'Content-Type: application/json' \
  -d '{"ttl":"15m","uses":64}' > "$RESP"

SESSION_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$RESP")
BUNKER_URL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["url"])' "$RESP")
rm -f "$RESP"

cd <repo>
ngit account login --local --offline --bunker-url "$BUNKER_URL" -d
unset BUNKER_URL
```

When finished:

```bash
curl -sS --unix-socket "$SOCK" -X DELETE \
  "http://localhost/v1/nostr/sessions/${SESSION_ID}"
```

### One-time publish

Use a short identifier (no spaces), usually the repo name. Announce grasp only
via `-g` — do not put unrelated clone/git-server hosts into the announcement.

```bash
NPUB=<from hotbox status>
ID=<identifier>

cd <repo>
ngit init --name "$ID" --identifier "$ID" -g relay.ngit.dev -d
```

`ngit init` / `ngit repo edit` rewrite `origin` to nostr. That is expected for
a grasp-only remote. Browser pages such as gitworkshop need the grasp HTTPS
mirror, for example:

`https://gitworkshop.dev/<npub>/relay.ngit.dev/<identifier>`

Push with the nostr or grasp HTTPS URL:

```bash
git push "nostr://${NPUB}/relay.ngit.dev/${ID}" main
# or, after a clean state event exists:
# git push "https://relay.ngit.dev/${NPUB}/${ID}.git" …
```

### Grasp authorization (kind 30618)

Grasp checks a signed kind `30618` repo state against the git push.

1. State must list only `refs/heads/*`, `refs/tags/*`, and `HEAD` — never
   `refs/remotes/*`. Stale remotes in state break sync.
2. One `git push` must include every ref declared in state. Separate
   `--all` then `--tags` fails even when both exist locally.
3. If sync is stuck, wipe the local cache and rebuild:
   `rm -rf .git/nostr-cache.lmdb`

Rebuild clean state, sign with Hotbox, publish, then push atomically:

```bash
SOCK=<socket>
NPUB=<npub>
ID=<identifier>
GRASP="https://relay.ngit.dev/${NPUB}/${ID}.git"

rm -rf .git/nostr-cache.lmdb

python3 - <<PY
import json, subprocess, time
tags=[["d","${ID}"],["HEAD","ref: refs/heads/main"]]
out=subprocess.check_output(
    ["git","for-each-ref","--format=%(refname) %(objectname)","refs/heads","refs/tags"],
    text=True,
)
for line in out.splitlines():
    ref, sha = line.split()
    if ref.startswith("refs/remotes/"):
        continue
    tags.append([ref, sha])
json.dump({"event":{"kind":30618,"created_at":int(time.time()),"tags":tags,"content":""}},
          open("/tmp/state-unsigned.json","w"))
PY

curl -sS --unix-socket "$SOCK" -X POST http://localhost/v1/nostr/sign \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/state-unsigned.json > /tmp/state-signed.json

python3 - <<'PY'
import json
d=json.load(open("/tmp/state-signed.json"))
ev=d.get("event", d)
assert "sig" in ev and ev.get("kind")==30618
json.dump(ev, open("/tmp/state-event.json","w"))
PY

# Publish pre-signed event on stdin (a path arg is ignored by nak).
python3 -c 'import json; print(json.dumps(json.load(open("/tmp/state-event.json"))))' \
  | nak event --auth wss://relay.ngit.dev

REFSPECS=()
while read -r ref sha; do
  REFSPECS+=("${ref}:${ref}")
done < <(git for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags)
git push "$GRASP" "${REFSPECS[@]}"

rm -f /tmp/state-unsigned.json /tmp/state-signed.json /tmp/state-event.json
```

Verify with `git ls-remote "$GRASP" refs/heads/main` and
`ngit repo --json --offline` (grasp server present; no unrelated clone hosts).

### Checklist

1. Socket → status → session → `ngit account login --local --offline`
2. `ngit init` or `ngit repo edit` with `-g relay.ngit.dev` only
3. Clean `30618` state (heads + tags + `HEAD` only)
4. Atomic grasp push of all declared refs
5. `git ls-remote` / gitworkshop URL
6. `DELETE` the Hotbox session

### Failure cheatsheet

| Symptom | Cause | Fix |
|---------|--------|-----|
| gitworkshop: browser can't access code | No grasp objects / wrong announcement | Ensure `-g` grasp; push to grasp HTTPS/nostr |
| `src refspec 'refs/remotes/…'` | Dirty state | Wipe `.git/nostr-cache.lmdb`; republish clean `30618`; atomic push |
| Grasp auth: refs missing after `--all` then `--tags` | Non-atomic push | One `git push` with all refspecs |
| Hotbox curl fails | Stale socket | Ask operator for the current path |
