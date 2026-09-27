# Hotbox

Loopback NIP-46 bunker. It unlocks one vault and signs for clients such as zsp. It does not dial the network, and it does not sign APKs.

```bash
go build -trimpath -o hotbox ./cmd/hotbox
./hotbox
```

With no arguments, Hotbox asks for a vault name, an nsec, and a password, prints the npub, then listens. The vault file is `~/.hotbox/<name>.hotbox`.

```bash
./hotbox zapstore
```

On a terminal, that asks for the password. Otherwise it reads one password line from stdin. Under systemd `Type=notify`, it signals ready after the vault unlocks. It prints `SIGN_WITH='bunker://…'` for NIP-46 clients.

The bunker listens on `127.0.0.1` only, with ws and wss.
