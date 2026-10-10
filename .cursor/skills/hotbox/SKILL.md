---
name: hotbox
description: >-
  Signs Android APKs with apksigner through an unlocked hotbox PKCS#11 token,
  and passes the printed bunker URL to Nostr clients. Use when signing an APK,
  running apksigner or zipalign, or when HOTBOX_TOKEN, HOTBOX_PIN,
  HOTBOX_PKCS11, ANDROID_ALIAS, or SIGN_WITH is available.
---

# Hotbox

The operator unlocks hotbox and gives you the startup lines for one vault. Use only those values. Do not open the vault, read a keystore, ask for a password, or use an `nsec`.

`HOTBOX_TOKEN` is the socket. `HOTBOX_PIN` is the PKCS#11 login. Together they can sign any APK for this vault. Do not print them again, persist them, or commit them.

If any of `ANDROID_ALIAS`, `HOTBOX_TOKEN`, `HOTBOX_PIN`, or `HOTBOX_PKCS11` is missing, ask the operator for the current lines. Do not search the disk for the socket or the module. A missing `HOTBOX_PKCS11` line means the module was not built; the operator runs `make` in the hotbox repo.

## Sign an APK

Align, then sign. `HOTBOX_TOKEN` must be in the environment of `apksigner`, because the PKCS#11 module reads it. `HOTBOX_PIN` is the keystore password.

```bash
zipalign -f -p 4 app-release-unsigned.apk app-release-aligned.apk

JAVA_TOOL_OPTIONS='--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED' \
HOTBOX_TOKEN="$HOTBOX_TOKEN" HOTBOX_PIN="$HOTBOX_PIN" \
  apksigner sign \
  --provider-class sun.security.pkcs11.SunPKCS11 \
  --provider-arg "$HOTBOX_PKCS11" \
  --ks NONE \
  --ks-type PKCS11 \
  --ks-key-alias "$ANDROID_ALIAS" \
  --ks-pass env:HOTBOX_PIN \
  --in app-release-aligned.apk \
  --out app-release.apk

apksigner verify --verbose --print-certs app-release.apk
```

Use the alias string exactly as printed. Do not pass `--ks` a file, `--key`, or `--cert`. Do not set `KEYSTORE_PASSWORD`. If verify fails, report the apksigner output and stop. Do not fall back to a local keystore.

`--out` is the signed APK. Do not overwrite the unsigned input.

## Nostr

Clients such as zsp read `SIGN_WITH`. Set it to the printed `bunker://` URL for that one command, then unset it. Do not print the URL. The bunker accepts `get_public_key`, `ping`, and `sign_event`. It does not export the private key.
