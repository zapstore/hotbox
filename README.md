# hotbox

hotbox signs Nostr events and Android packages on this machine, and keeps the private keys in a vault the clients never see.

A tool such as zsp needs a signature to publish. apksigner needs a signature to finish an APK. Both ask hotbox. hotbox unlocks the vault, signs, and wipes the key when that call returns. It listens on `127.0.0.1` and on a Unix socket that only this user can open.

While it is unlocked:

- zsp, and any other NIP-46 client, signs with the bunker URL printed at startup.
- `hotbox sign` signs APKs through apksigner. The private key stays in the vault.
- zsp can ask the same process for a NIP-C1 certificate proof when a release needs one.

Stop hotbox and both kinds of signing stop. With the second secret in the macOS keychain or a key file, a copy of the vault is not enough to start it again.

## Install

Download the file for this machine, then `chmod +x` it:

| Machine | File |
| --- | --- |
| macOS arm64 | [hotbox-0.1.0-darwin-arm64](https://github.com/zapstore/hotbox/releases/download/v0.1.0/hotbox-0.1.0-darwin-arm64) |
| Linux arm64 | [hotbox-0.1.0-linux-arm64](https://github.com/zapstore/hotbox/releases/download/v0.1.0/hotbox-0.1.0-linux-arm64) |
| Linux amd64 | [hotbox-0.1.0-linux-amd64](https://github.com/zapstore/hotbox/releases/download/v0.1.0/hotbox-0.1.0-linux-amd64) |

`hotbox --version` prints `v0.1.0` for that release. A build from any other commit prints `dev`.

## Build

```bash
make
./hotbox
```

`make` also links the binary into `~/.local/bin` when you build for this machine. `make darwin-arm64`, `make linux-arm64`, and `make linux-amd64` cross-compile.

## Create a vault

Run `./hotbox` with no arguments. It asks for:

1. **Path.** A name without `.hotbox` gets that suffix. A relative path is taken from the working directory. `~/` is expanded.
2. **Where to keep the second secret.** The macOS keychain (preselected when this machine has one), a key file, or the passphrase alone.
3. **nsec.** `nsec1…` or 64 hex characters. Leave it empty to generate one. Creation prints that key's npub. The nsec stays inside the vault.
4. **Password.** Leave it empty for no passphrase.
5. **Android keystore, optional.** JKS, PKCS#12, or an unencrypted PEM. Leave it empty to seal only the nsec. A file with more than one key asks which entry to seal. The sealed alias is always `hotbox`.

The keystore is read once, at creation. There is no command to add or replace the Android key later. Create the vault again to change it.

| Second secret | Where it lives | What opens the vault |
| --- | --- | --- |
| macOS keychain | Printed at creation as hex | Keychain entry, and the passphrase if you set one |
| Key file | `<name>.key`, 32 bytes, mode 0600 | That file, and the passphrase if you set one |
| Passphrase only | The passphrase | The passphrase. A leaked file can be guessed offline |

A key file defaults to `<name>.key` in `$HOTBOX_KEYS`, or `~/.keys/hotbox` when that is unset. `zapstore.hotbox` uses `zapstore.key`. `--key` sets the file for the next vault, and only for a key file:

```bash
./hotbox --key /path/to/zapstore.key zapstore --key /path/to/releases.key releases
```

An empty passphrase with the keychain or a key file uses that secret alone. An empty passphrase and no second secret means anyone with the vault file can unlock it.

Creation prints the key, then the `.env` block, and listens. A key file prints its path. The keychain prints `Keychain value to back up` and the output of `security find-generic-password -w`. That hex is the backup: `xxd -r -p` turns it into a key file you can pass to `--key`.

If the password or the key is lost, create a new vault from your own copy of the nsec. The container cannot produce it.

## Run

```bash
./hotbox zapstore releases
```

Each argument is one vault. A name without `.hotbox` gets that suffix. A vault named `sign` has to be given as `./sign`, because `sign` is the APK command. A directory vault from an older hotbox still opens.

On a terminal, hotbox asks for each password. An empty password unlocks a vault created with an empty passphrase. When stdin is not a terminal, it reads one password line per vault, in the same order as the paths. An empty line is an empty password.

With no `--key`, a Mac looks in the keychain first, then the default key file.

Unlocking stretches the password with Argon2id at 1 GiB of memory, so each vault needs about that much free RAM and takes 1–3 seconds at start. Under systemd `Type=notify`, hotbox signals ready after every vault is listening.

## Connect a project

Creation prints one block. Opening several vaults prefixes each block with `[name]`. `HOTBOX_PIN` and `HOTBOX_SOCKET` appear only when that vault has an Android key.

```text
SIGN_WITH='bunker://…'
HOTBOX_PIN='…'
HOTBOX_SOCKET='/tmp/hotbox-501/zapstore.sock'
```

```text
[zapstore]
SIGN_WITH='bunker://…'
HOTBOX_PIN='…'
HOTBOX_SOCKET='/tmp/hotbox-501/zapstore.sock'

[releases]
SIGN_WITH='bunker://…'
```

Paste a block into the project `.env`. Anyone who can read that file can sign as you while hotbox is unlocked, so keep it mode 0600 and out of git. `hotbox sign` and `zsp` refuse a `.env` that other users can read.

The bunker URL and the PIN go to stdout. Connections and signature attempts, including a denied signature, go to stderr. The private key is not logged.

## Sign an APK

```bash
hotbox sign app/build/outputs/apk/release/app-release-unsigned.apk
```

`hotbox sign` reads `HOTBOX_SOCKET` and `HOTBOX_PIN` from the environment, then from `.env` in the current directory. It finds `zipalign` and `apksigner` on `PATH` or under `$ANDROID_HOME`.

`app-release-unsigned.apk` is written as `app-release.apk` beside it. Any other name is written as `<name>-signed.apk`. hotbox verifies the output and prints its path and certificate digest.

The PKCS#11 module is compiled into the hotbox binary. When a vault with an Android key opens, hotbox writes it to `/tmp/hotbox-<uid>/libhotbox-pkcs11.dylib` (or `.so`). apksigner loads that file. The module forwards each signature to the socket. The key alias is `hotbox`.

## Certificate proofs

The same socket signs a NIP-C1 certificate proof (kind 30509) for this vault's npub. The caller sends `created_at` and `expiry`. Hotbox builds the message from its own npub, so the proof is for this certificate only.

`zsp publish` uses that when the APK's certificate has no proof yet, or the proof expires within 30 days. It asks hotbox for the certificate signature, signs the 30509 event with `SIGN_WITH`, publishes the proof, then publishes the release.

## The vault

One profile, in a vaultcore single-file container:

```text
profiles/<name>/nsec          Nostr private key, secret
profiles/<name>/bunker        connect secret, token, ports
profiles/<name>/android-key   Android private key, secret, optional
profiles/<name>/android       certificate chain and signing PIN, optional
```

`nsec` and `android-key` have no read command. Each signature calls `Vault.Use`, which decrypts that key for the callback and wipes it when the callback returns. `bunker` and `android` are ordinary ciphertext. The URL and the PIN printed at startup are those values.

New vaults are one file. Directory vaults already in vaultcore format version 1 stay readable. A hotbox v1 file vault is a different format and is refused. Choosing the keychain or a passphrase alone does not change the container format.

Each bunker listens on `127.0.0.1` only, with ws and wss. A vault with an Android key also listens on a Unix socket and accepts only this user. The socket and the PKCS#11 config are `/tmp/hotbox-<uid>/<name>.sock` and `/tmp/hotbox-<uid>/<name>.pkcs11.cfg`. `<name>` is the vault name with `.hotbox` removed, and those paths stay the same across runs. One vault is one npub and at most one Android key.

## License

MIT
