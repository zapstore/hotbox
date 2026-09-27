package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
)

// maxPasswordLine matches the vault package limit.
const maxPasswordLine = 4 << 10

func unlockPassword() (string, error) {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return readPassword(os.Stdin)
	}
	return ask("Vault password", "Unlocks the bunker", true, required)
}

func readPassword(r io.Reader) (string, error) {
	br := bufio.NewReaderSize(r, maxPasswordLine+1)
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New("vault password is too large")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if err != nil && len(line) == 0 {
		return "", errors.New("vault password is required")
	}
	password := strings.TrimRight(string(line), "\r\n")
	if password == "" {
		return "", errors.New("vault password is required")
	}
	if len(password) > maxPasswordLine {
		return "", errors.New("vault password is too large")
	}
	return password, nil
}
