package main

import (
	"errors"
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

// maxPasswordLine matches the vaultcore passphrase limit.
const maxPasswordLine = 4 << 10

func unlockPassword(label string) ([]byte, error) {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return readPassword(os.Stdin)
	}
	text, err := ask("Password for "+label, "Leave empty if this vault has no passphrase.", true, allowEmpty)
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

// readPassword reads one password line. It does not buffer past that line,
// so successive calls return the following lines and the scratch buffer is wiped.
// An empty line is an empty passphrase.
func readPassword(r io.Reader) ([]byte, error) {
	var buf [maxPasswordLine + 1]byte
	defer clear(buf[:])
	n := 0
	var one [1]byte
	for {
		_, err := io.ReadFull(r, one[:])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if one[0] == '\n' {
			break
		}
		if n == maxPasswordLine {
			return nil, errors.New("vault password is too large")
		}
		buf[n] = one[0]
		n++
	}
	if n > 0 && buf[n-1] == '\r' {
		buf[n-1] = 0
		n--
	}
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}
