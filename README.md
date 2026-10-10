# hotbox

Loopback NIP-46 bunker. It unlocks a vault and signs for clients such as zsp. It does not dial the network. It does not sign APKs itself: apksigner asks it to sign through a local PKCS#11 module, and the private key stays inside the vault.

The vault is a vaultcore directory container. One profile lives inside it:

```text
profiles/<name>/nsec          Nostr private key, secret
profiles/<name>/bunker        connect secret, token, ports
profiles/<name>/android-key   Android private key, secret, optional
profiles/<name>/android       certificate chain and signing PIN, optional
```

`nsec` and `android-key` have no read command. Each signature calls `Vault.Use`, which decrypts that key for the callback and wipes it when the callback returns. `bunker` and `android` are ordinary ciphertext. The URL and the PIN printed at startup are the same capabilities.

```bash
make
./hotbox
```

With no arguments, hotbox asks for a path, where to keep the key, an nsec, a password, and an optional Android keystore, prints the npub, then listens. Leave the keystore empty to seal only the nsec. A keystore is JKS, PKCS#12, or an unencrypted PEM. It is read once, at creation. A file with more than one key asks which entry to seal. The sealed name is always `hotbox`. There is no command to add or replace the Android key. A vault sealed under a keystore alias has to be created again. The path is the container directory. A name that does not end in `.hotbox` gets that suffix. A relative path is taken from the working directory.

Creating a vault asks where to keep the second secret: the macOS keychain (preselected when this machine has one), a key file, or the passphrase alone. A key file is 32 bytes, mode 0600. The default path is `<name>.key` in `$HOTBOX_KEYS`, or `~/.keys/hotbox` when that is unset. `zapstore.hotbox` uses `zapstore.key`. Pass another file with `--key`:

```bash
./hotbox --key /path/to/zapstore.key zapstore --key /path/to/releases.key releases
```

Opening a vault needs the password and, unless the vault was created with the passphrase alone, the keychain entry or the key file. With no `--key`, a Mac looks in the keychain first and then the default key file. A leaked container that has a key is not an offline password-guessing target. A passphrase-only vault is. After creation, hotbox prints what to back up.

Nothing recovers the nsec from the container. If the password or the key is lost, create a new vault from your own copy of the nsec. File vaults from hotbox v1 are not accepted. Directory vaults already in vaultcore format version 1 stay readable: the keychain and passphrase-only choices do not change that format.

The password is stretched with Argon2id at 1 GiB of memory, so unlocking takes 1–3 s and needs that much free RAM once per vault at start.

```bash
./hotbox zapstore releases
```

On a terminal, that asks for each password. When stdin is not a terminal, it reads one password line per vault, in the same order as the paths. Under systemd `Type=notify`, it signals ready after every vault is listening.

Each bunker listens on `127.0.0.1` only, with ws and wss. A vault with an Android key also listens on a Unix socket and accepts only this user. The socket and the PKCS#11 config are `/tmp/hotbox-<uid>/<name>.sock` and `/tmp/hotbox-<uid>/<name>.pkcs11.cfg`. `<name>` is the vault name with `.hotbox` removed. Those two paths stay the same across runs. A vault holds one profile, so it has one npub and at most one Android key. Startup prints one `.env` block per vault. `HOTBOX_SOCKET` and `HOTBOX_PIN` appear only when an Android key was sealed:

```text
# zapstore: paste into the project .env, then chmod 600 .env and keep it out of git
HOTBOX_SOCKET='/tmp/hotbox-501/zapstore.sock'
HOTBOX_PIN='…'
SIGN_WITH='bunker://…'
```

Paste the block into the project `.env` as is. Anyone who can read that file can sign as you while hotbox is unlocked, so keep it mode 0600 and out of git. `hotbox sign` and `zsp` refuse a `.env` that other users can read. Stopping hotbox stops all signing.

`make` also builds `dist/libhotbox-pkcs11-<os>-<arch>.dylib` (or `.so`) next to the binary. apksigner loads that module. The module forwards each signature to the socket. It never receives the private key. The key alias is `hotbox`.

`hotbox sign` signs APKs through that module. It reads `HOTBOX_SOCKET` and `HOTBOX_PIN` from the environment, then from `.env` in the current directory, and finds `zipalign` and `apksigner` on `PATH` or under `$ANDROID_HOME`. An input named `app-release-unsigned.apk` is written as `app-release.apk` beside it. Any other name is written as `<name>-signed.apk`. It verifies the output and prints its path and certificate digest.

```bash
hotbox sign app/build/outputs/apk/release/app-release-unsigned.apk
```

The socket also signs a NIP-C1 certificate proof (kind 30509) for the vault's own npub. The caller sends `created_at` and `expiry`. Hotbox builds the message from its npub, so the socket cannot prove the certificate for another key. `zsp publish` uses this when the APK's certificate has no proof yet or the proof expires within 30 days: it asks hotbox for the certificate signature, signs the 30509 event with `SIGN_WITH`, publishes it, then publishes the release. No second step is needed.

Connections and signature attempts are logged to stderr, including a denied signature. The bunker URL and the PIN stay on stdout. The private key is not logged.
