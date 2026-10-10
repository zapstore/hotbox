# hotbox

Loopback NIP-46 bunker. It unlocks a vault and signs for clients such as zsp. It does not dial the network. It does not sign APKs itself: apksigner asks it to sign through a local PKCS#11 module, and the private key stays inside the vault.

The vault is a vaultcore directory container. One profile lives inside it:

```text
profiles/<name>/nsec          Nostr private key, secret
profiles/<name>/bunker        connect secret, token, ports
profiles/<name>/android-key   Android private key, secret
profiles/<name>/android       certificate chain and signing PIN
```

`nsec` and `android-key` have no read command. Each signature calls `Vault.Use`, which decrypts that key for the callback and wipes it when the callback returns. `bunker` and `android` are ordinary ciphertext. The URL and the PIN printed at startup are the same capabilities.

```bash
make
./hotbox
```

With no arguments, hotbox asks for a path, where to keep the key, an nsec, a password, and an Android keystore, prints the npub, then listens. The keystore is JKS, PKCS#12, or an unencrypted PEM. It is read once, at creation. There is no command to add or replace the Android key. A vault created before that requirement has to be created again. The path is the container directory. A name that does not end in `.hotbox` gets that suffix. A relative path is taken from the working directory.

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

Each bunker listens on `127.0.0.1` only, with ws and wss. The Android signer listens on a Unix socket under `/tmp/hotbox-<uid>` and accepts only this user. Startup prints one block per vault:

```text
[zapstore] SIGN_WITH='bunker://…'
[zapstore] ANDROID_ALIAS='release'
[zapstore] HOTBOX_TOKEN='/tmp/hotbox-501/….sock'
[zapstore] HOTBOX_PIN='…'
[zapstore] HOTBOX_PKCS11='/tmp/hotbox-501/….pkcs11.cfg'
```

`make` also builds `dist/libhotbox-pkcs11-<os>-<arch>.dylib` (or `.so`) next to the binary. apksigner loads that module. The module forwards each signature to the socket. It never receives the private key. Pass `HOTBOX_TOKEN` in the environment and `HOTBOX_PIN` as `--ks-pass env:HOTBOX_PIN`. Java 21 also needs `JAVA_TOOL_OPTIONS=--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED`. The command is in the hotbox skill.

Connections and signature attempts are logged to stderr, including a denied signature. The bunker URL and the PIN stay on stdout. The private key is not logged.
