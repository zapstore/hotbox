# Hotbox security model

Hotbox keeps one Android keystore and one Nostr private key in an encrypted
vault. The daemon decrypts them after an interactive password prompt. Private
material stays in the Hotbox process except while `apksigner` reads a temporary
keystore.

## Trust boundary

The operating system, the Hotbox binary, the selected JDK, and Android SDK
signing tools are trusted. Root, kernel compromise, a debugger with equivalent
privileges, and physical memory attacks are outside this model. A malicious
`apksigner` can read the keystore it was asked to use. Install the SDK outside
the project, keep it read-only while Hotbox runs, and verify its source.

Any process running as the same user can request a signature or short-lived
bunker capability through the private Unix socket. This is deliberate because
Hotbox supports unattended agents after the operator unlocks it. The socket
does not reveal either private key. It is still a signing authority, similar to
an unlocked SSH agent.

The NIP-46 relay uses an ephemeral TCP loopback port. Loopback TCP has no Unix
file permissions, so other local users can connect if they discover the port.
Relay filters prevent clients from receiving responses addressed to a
different subscription. NIP-46 content is encrypted, but connection timing and
public event metadata remain visible to a local observer.

## Controls

- Vaults use Argon2id and XChaCha20-Poly1305. New passwords must contain at
  least 12 characters.
- Vault creation is exclusive. Hotbox refuses to replace an existing vault.
- Keystore exports require the vault password, are created mode 0600, and
  refuse to replace an existing destination.
- The Unix socket lives under a mode-0700 per-user runtime directory and is
  mode 0600.
- APK input is copied into private scratch storage before parsing. Signed
  output is verified and published without overwriting an existing file.
- `apksigner` receives passwords on standard input. Passwords never appear in
  its arguments. `keytool` also receives its passwords on standard input.
- Child processes receive a small environment with proxy and credential
  variables removed. Group- or world-writable signing tools are rejected.
- Core dumps are disabled. Linux marks the process non-dumpable, and macOS
  denies debugger attachment.
- Bunker tokens expire, are consumed by the first client that binds them, and
  authorize only the event kinds listed in `internal/nostr/local.go`.
- Logs record operations and public certificate fingerprints. They do not
  record passwords, private keys, vault content, or bunker URLs.

## Network isolation

Hotbox makes no outbound connection. Its TCP listener exists solely for local
NIP-46 clients. The Linux wrapper blocks the `connect` system call for Hotbox
and its children while leaving bind, accept, and replies available. The macOS
Seatbelt profile denies non-loopback IP traffic.

`bwrap --unshare-net` and containers with `--network none` isolate the NIP-46
listener from host clients. They are suitable only when bunker support is not
needed or when a separate local proxy bridges the namespace.

The macOS `sandbox-exec` interface is deprecated and undocumented. The supplied
wrapper fails if Seatbelt cannot be applied. For a maintained hard boundary on
macOS, run Hotbox and the Android toolchain in a VM with no external network
adapter and expose only the required local relay through a narrow host proxy.

## Remaining exposure

Go strings cannot be reliably erased. Keystore passwords and the Nostr key may
remain in process memory until the OS reclaims those pages. Hotbox clears
mutable byte buffers and disables dumps, but this does not protect against root
or a compromised kernel.

The password-protected Android keystore exists briefly in private temporary
storage after the vault is unlocked. Use the supplied wrapper so Linux places
it in a private temporary mount. On macOS, temporary storage remains visible
to root and the current user. A forced kill can leave that temporary file until
the operating system removes the directory.

An authorized same-user process can request signatures. Bunker grants are
short-lived and single-use, which limits replay but does not provide human
approval. Stop Hotbox when signing work is complete.

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

Run the wrapper checks in `README.md` on the target host. External connections
must fail. The Unix API and the NIP-46 loopback relay must continue to work.

## Audit status

The 2026-08-04 audit passed `go test`, the race detector, `go vet`,
Staticcheck, and gosec. Govulncheck reported no reachable vulnerabilities. It
reported GO-2026-5932 for the unmaintained `x/crypto/openpgp` package at module
level; Hotbox does not import that package.

The code builds for macOS arm64 and Linux amd64 with the pinned Go 1.25.12
toolchain. The macOS network profile could not be nested inside the sandbox
used for this audit: macOS returned `sandbox_apply: Operation not permitted`
for an allow-all test profile. Test the wrapper from a normal Terminal session
before loading a production vault. The Linux systemd profile also requires a
Linux host test.
