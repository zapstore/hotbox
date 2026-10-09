# hotbox

Loopback NIP-46 bunker. It unlocks a vault and signs for clients such as zsp. It does not dial the network, and it does not sign APKs.

The vault is a vaultcore directory container. One profile lives inside it:

```text
profiles/<name>/nsec     private key, secret flag
profiles/<name>/bunker   connect secret, token, ports
```

`nsec` has no read command. Each signature calls `Vault.Use`, which decrypts the key for the callback and wipes it when the callback returns. `bunker` is ordinary ciphertext; the URL printed at startup is the same capability.

```bash
make
./hotbox
```

With no arguments, hotbox asks for a path, an nsec, and a password, prints the npub, then listens. The path is the container directory. A name that does not end in `.hotbox` gets that suffix. A relative path is taken from the working directory.

Creating a vault also writes a 32-byte key file, mode 0600. The default path is `<name>.key` in `$HOTBOX_KEYS`, or `~/.keys/hotbox` when that is unset. `zapstore.hotbox` uses `zapstore.key`. Pass another file with `--key`:

```bash
./hotbox --key /path/to/zapstore.key zapstore --key /path/to/releases.key releases
```

Opening a vault needs both the password and that file. A leaked container on its own is not an offline password-guessing target.

Nothing recovers the nsec from the container. If the password or the key file is lost, create a new vault from your own copy of the nsec. File vaults from hotbox v1 are not accepted.

The password is stretched with Argon2id at 1 GiB of memory, so unlocking takes 1–3 s and needs that much free RAM once per vault at start.

```bash
./hotbox zapstore releases
```

On a terminal, that asks for each password. When stdin is not a terminal, it reads one password line per vault, in the same order as the paths. Under systemd `Type=notify`, it signals ready after every vault is listening. It prints one line per vault:

```text
[zapstore] SIGN_WITH='bunker://…'
[releases] SIGN_WITH='bunker://…'
```

Each bunker listens on `127.0.0.1` only, with ws and wss.

Connections and signature attempts are logged to stderr, including a denied signature. The bunker URL stays on stdout. The private key is not logged.
