//go:build !vaultcore_weakkdf

package profile_test

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	fmt.Fprintln(os.Stderr, "hotbox: running with the production KDF; each unlock costs 1 GiB. Use -tags vaultcore_weakkdf for the fast suite.")
	os.Exit(m.Run())
}
