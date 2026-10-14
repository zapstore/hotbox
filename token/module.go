package token

import _ "embed"

// pkcs11Module is the shared library make compiled from pkcs11/hotbox.c
// for this binary's OS and architecture. SunPKCS11 can only dlopen a file,
// so LibraryPath writes these bytes into the signer directory.
//
//go:embed pkcs11.module
var pkcs11Module []byte
