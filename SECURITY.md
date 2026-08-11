# Hotbox security model

> [!WARNING]
> Hotbox is alpha software and has not received an independent security audit.
> It handles Android and Nostr signing keys, so defects can result in key
> compromise or unauthorized signatures. Use only disposable or otherwise
> recoverable keys until you have assessed these risks for your environment.

## Reporting vulnerabilities

Do not report security issues in public. Send details to
[`security@zapstore.dev`](mailto:security@zapstore.dev).

Hotbox keeps one Android keystore and one Nostr private key in an encrypted
vault. The daemon decrypts them after an interactive password prompt. Private
material stays in the Hotbox process except while `apksigner` reads a temporary
keystore.

## Trust boundary

The operating system, the Hotbox binary, the selected JDK, Android SDK signing
tools, and zsp used for Android identity proofs are trusted. Root, kernel
compromise, a debugger with equivalent privileges, and physical memory attacks
are outside this model. A malicious `apksigner` or zsp can read the temporary
keystore it was asked to use. Install tools outside the project, keep them
read-only while Hotbox runs, and verify their source.

The random Unix socket path is a bearer capability for full APK and Nostr
signing authority. Hotbox accepts every Nostr event kind by design. Filesystem
permissions and peer credentials reject other operating-system users, but a
same-user process that learns the path is trusted. The socket does not reveal
either private key or the vault password. Stop Hotbox to revoke the socket.

Each NIP-46 grant gets a separate ephemeral TCP loopback listener because
current ngit and zsp clients require a WebSocket relay URL. Loopback TCP has no
filesystem permissions, but a listener accepts no signing request before a
valid 192-bit single-use secret binds its first client. NIP-46 content is
encrypted; connection timing and public event metadata remain visible locally.

## Controls

- Vaults use Argon2id and XChaCha20-Poly1305. New passwords must contain at
  least 12 characters.
- Vault creation is exclusive. Hotbox refuses to replace an existing vault.
- Keystore exports require the vault password, are created mode 0600, and
  refuse to replace an existing destination.
- Each unlock creates a new random directory under `/tmp` with mode 0700 and a
  mode-0600 socket. Accepted peers must have the daemon's UID.
- APK input is copied into private scratch storage before parsing. Signed
  output is verified and published without overwriting an existing file.
- `apksigner` receives passwords on standard input. Passwords never appear in
  its arguments. `keytool` receives passwords through anonymous file-descriptor
  pipes.
- Current zsp requires JKS passwords in its environment for non-interactive
  identity linking. Hotbox first copies the selected alias into a temporary JKS
  protected by a random one-operation password, then scopes that password to
  the validated zsp child. The vault password never reaches zsp.
- Android signing tools receive a small environment with proxy and credential
  variables removed. Group- or world-writable signing tools are rejected.
- Core dumps are disabled.
- NIP-46 secrets are consumed by the first client, expire within one hour,
  enforce successful-signature limits, and can be revoked by session ID.
  Sessions permit only public-key lookup, ping, and event signing.
- The socket does not expose keystore bytes or passwords. Certificate identity
  linking must run as a bounded operation inside the daemon.
- Logs record operations and public certificate fingerprints. They do not
  record passwords, private keys, vault content, or bunker URLs.

## Remaining exposure

Go strings cannot be reliably erased. Keystore passwords and the Nostr key may
remain in process memory until the OS reclaims those pages. Hotbox clears
mutable byte buffers and disables dumps, but this does not protect against root
or a compromised kernel.

The password-protected Android keystore exists briefly in private temporary
storage after the vault is unlocked. Root and the current user can inspect that
storage, and a forced kill can leave the temporary file until the operating
system removes the directory.

An authorized same-user process can sign arbitrary Nostr events. Session
expiry and usage limits reduce replay but do not provide human approval or
restrict event kinds.

Keep vaults outside source and signing workspaces. The file named `test` in this
project predates this rule and appears to be an encrypted vault. It is ignored
by the supplied `.gitignore`, but the operator should move it to private
storage or delete it after confirming that it is disposable.

## Audit procedure

Before a release:

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Inspect the selected tools:

```sh
command -v keytool apksigner zipalign
shasum -a 256 "$(command -v keytool)" "$(command -v apksigner)"
```

Verify the Unix API and the NIP-46 loopback relay on the target host.

## Audit status

The 2026-08-04 audit passed `go test`, the race detector, `go vet`,
Staticcheck, and gosec. Govulncheck reported no reachable vulnerabilities. It
reported GO-2026-5932 for the unmaintained `x/crypto/openpgp` package at module
level; Hotbox does not import that package.

The code builds for macOS arm64 and Linux amd64 with the pinned Go 1.25.12
toolchain.
