package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func TestComplete(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, "app.jks")
	writeFile(t, "release.jks")
	writeFile(t, "release-old.jks")
	writeFile(t, "release.p12")
	writeFile(t, "key.pem")
	writeFile(t, "store.pfx")
	writeFile(t, "old.keystore")
	writeFile(t, "notes.txt")
	writeFile(t, ".hidden.jks")
	if err := os.Mkdir("keys", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join("keys", "release.jks"))
	if err := os.Symlink("keys", "link"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("app.jks", "linkfile"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, "dot.jks"))

	tests := []struct {
		in      string
		home    string
		want    string
		matches []string
	}{
		{in: "", want: "", matches: []string{"app.jks", "key.pem", "keys/", "link/", "old.keystore", "release-old.jks", "release.jks", "release.p12", "store.pfx"}},
		{in: "app", want: "app.jks"},
		{in: "keys", want: "keys/"},
		{in: "keys/", want: "keys/release.jks"},
		{in: "keys/rel", want: "keys/release.jks"},
		{in: "linkf", want: "linkf"},
		{in: "lin", want: "link/"},
		{in: "notes", want: "notes"},
		{in: "rel", want: "release", matches: []string{"release-old.jks", "release.jks", "release.p12"}},
		{in: ".", want: ".hidden.jks"},
		{in: "./app", want: "./app.jks"},
		{in: "missing", want: "missing"},
		{in: "~/docs", home: home, want: "~/docs/"},
		{in: "~", home: home, want: "~/do", matches: []string{"~/docs/", "~/dot.jks"}},
		{in: "~/nope", home: home, want: "~/nope"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.in), func(t *testing.T) {
			got, matches := complete(tt.in, tt.home)
			if got != tt.want || !slices.Equal(matches, tt.matches) {
				t.Fatalf("complete(%q) = %q, %q; want %q, %q", tt.in, got, matches, tt.want, tt.matches)
			}
		})
	}
}

func TestMatchBase(t *testing.T) {
	tests := []struct {
		in, match, want string
	}{
		{in: "keys/release", match: "keys/release.jks", want: "release.jks"},
		{in: "keys/", match: "keys/release.jks", want: "release.jks"},
		{in: "release", match: "release.jks", want: "release.jks"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := matchBase(tt.in, tt.match)
			if got != tt.want {
				t.Fatalf("matchBase(%q, %q) = %q, want %q", tt.in, tt.match, got, tt.want)
			}
		})
	}
}

func TestViewListsMatches(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, "app.jks")
	writeFile(t, "release.jks")
	writeFile(t, "release-old.jks")
	writeFile(t, "notes.txt")
	m := newPathPrompt("Android keystore", "Optional keystore")
	m.Init()
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	assertListed(t, updated.View(), 80, "app.jks", "release.jks", "release-old.jks")
	if strings.Contains(ansi.Strip(updated.View()), "notes.txt") {
		t.Fatal("listing contains notes.txt")
	}

	for _, r := range []rune{'r', 'e', 'l'} {
		updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	updated, _ = updated.Update(tea.KeyMsg{Type: tea.KeyTab})
	prompt := updated.(*pathPrompt)
	if prompt.input.Value() != "release" {
		t.Fatalf("tab completed %q, want %q", prompt.input.Value(), "release")
	}
	assertListed(t, prompt.View(), 80, "release.jks", "release-old.jks")
	plain := ansi.Strip(prompt.View())
	if strings.Contains(plain, "app.jks") {
		t.Fatalf("listing still contains app.jks:\n%s", plain)
	}
	if !strings.Contains(ansi.Strip(prompt.input.View()), "-old.jks") {
		t.Fatalf("inline suggestion missing from %q", ansi.Strip(prompt.input.View()))
	}
}

func assertListed(t *testing.T, view string, width int, names ...string) {
	t.Helper()
	plain := ansi.Strip(view)
	for _, name := range names {
		if !strings.Contains(plain, name) {
			t.Fatalf("view missing %q:\n%s", name, plain)
		}
	}
	for i, line := range strings.Split(view, "\n") {
		if w := lipgloss.Width(line); w >= width {
			t.Fatalf("line %d is %d columns wide, terminal is %d:\n%s", i, w, width, ansi.Strip(line))
		}
	}
}

func writeFile(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}
