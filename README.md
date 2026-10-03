# Hotbox

Loopback NIP-46 bunker. It unlocks one or more vaults and signs for clients such as zsp. It does not dial the network, and it does not sign APKs.

```bash
go build -trimpath -o hotbox ./cmd/hotbox
./hotbox
```

With no arguments, Hotbox asks for a path, an nsec, and a password, prints the npub, then listens. The vault file is the path you give it. A relative path is taken from the working directory.

Creating a vault also writes a 32-byte key file, mode 0600, in the key directory: `$HOTBOX_KEYS` if set, otherwise `~/.local/share/hotbox`. Opening a vault needs both the password and the key file, so a leaked vault file on its own is not an offline password-guessing target. Keep the key directory out of whatever holds the vault (backups, sync, repos); set `HOTBOX_KEYS` to put it on removable media or in a service's private directory.

Hotbox never shows the nsec or the key file, and nothing recovers them from the vault. If the password or the key file is lost, the vault is unusable; create a new vault from your own copy of the nsec. Vaults created by earlier versions are not accepted.

The password is stretched with Argon2id at 1 GiB of memory, so unlocking takes 1–3 s on most machines and needs that much free RAM once per vault at start.

```bash
./hotbox /path/to/zapstore.hotbox /path/to/releases.hotbox
```

On a terminal, that asks for each password. When stdin is not a terminal, it reads one password line per vault, in the same order as the paths. Under systemd `Type=notify`, it signals ready after every vault is listening. It prints one line per vault:

```text
[zapstore] SIGN_WITH='bunker://…'
[releases] SIGN_WITH='bunker://…'
```

Each bunker listens on `127.0.0.1` only, with ws and wss.
