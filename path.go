package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

const maxPathMatches = 100

// askPath reads a filesystem path. Tab completes directories and keystores.
func askPath(title, description string) (string, error) {
	prompt := newPathPrompt(title, description)
	final, err := tea.NewProgram(prompt).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return "", huh.ErrUserAborted
	}
	if err != nil {
		return "", fmt.Errorf("path prompt: %w", err)
	}
	done, ok := final.(*pathPrompt)
	if !ok {
		return "", fmt.Errorf("path prompt: %T", final)
	}
	if done.aborted {
		return "", huh.ErrUserAborted
	}
	return strings.TrimSpace(done.input.Value()), nil
}

type pathPrompt struct {
	title       string
	description string
	input       textinput.Model
	theme       *huh.Theme
	matches     []string
	width       int
	aborted     bool
	done        bool
}

func newPathPrompt(title, description string) *pathPrompt {
	theme := huh.ThemeCharm()
	input := textinput.New()
	input.Prompt = "> "
	input.PromptStyle = theme.Focused.TextInput.Prompt
	input.TextStyle = theme.Focused.TextInput.Text
	input.Cursor.Style = theme.Focused.TextInput.Cursor
	input.ShowSuggestions = true
	// Placeholder gray (ANSI 238) disappears on a dark background.
	input.CompletionStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "242", Dark: "246"})
	input.Width = pathInputWidth(80)
	prompt := &pathPrompt{
		title:       title,
		description: description,
		input:       input,
		theme:       theme,
		width:       80,
	}
	prompt.syncMatches()
	return prompt
}

func (m *pathPrompt) Init() tea.Cmd {
	return m.input.Focus()
}

func (m *pathPrompt) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.input.Width = pathInputWidth(msg.Width)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.aborted = true
			m.done = true
			return m, tea.Quit
		case "enter":
			m.done = true
			return m, tea.Quit
		case "tab":
			next, _ := completePath(m.input.Value())
			m.input.SetValue(next)
			m.input.CursorEnd()
			m.syncMatches()
			return m, nil
		}
	}
	previous := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.input.Value() != previous {
		m.syncMatches()
	}
	return m, cmd
}

// syncMatches refreshes the directory listing and the inline suggestion.
// textinput only ghosts a completion once the field is non-empty, so the
// column listing below is what shows every match, including on an empty field.
func (m *pathPrompt) syncMatches() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	m.matches = listPath(m.input.Value(), home)
	m.input.ShowSuggestions = true
	m.input.SetSuggestions(m.matches)
}

func (m *pathPrompt) View() string {
	if m.done {
		return ""
	}
	inner := pathInputWidth(m.width) + 2
	var body strings.Builder
	body.WriteString(m.theme.Focused.Title.Width(inner).Render(m.title))
	body.WriteString("\n")
	body.WriteString(m.theme.Focused.Description.Width(inner).Render(m.description))
	body.WriteString("\n")
	// The ghost completion is drawn past the value, and textinput still pads
	// out to Width. Shrink Width by that suffix or the line wraps onto the list.
	extra := suggestionSuffixWidth(m.input.Value(), m.input.CurrentSuggestion())
	m.input.Width = max(pathInputWidth(m.width)-extra, 1)
	body.WriteString(m.input.View())
	if len(m.matches) > 1 {
		names := visibleNames(m.input.Value(), m.matches)
		current := ""
		if suggestion := m.input.CurrentSuggestion(); suggestion != "" {
			current = matchBase(m.input.Value(), suggestion)
		}
		body.WriteString("\n\n")
		body.WriteString(formatNames(names, inner, m.theme.Focused.Directory, m.theme.Focused.Option, m.theme.Focused.SelectedOption, current))
	}
	return m.theme.Focused.Base.Render(body.String())
}

func suggestionSuffixWidth(value, suggestion string) int {
	if suggestion == "" || !strings.HasPrefix(suggestion, value) {
		return 0
	}
	return lipgloss.Width(suggestion[len(value):])
}

func pathInputWidth(term int) int {
	// border 1 + padding 1 + prompt 2 + cursor 1, and one column left so a
	// full line does not wrap and cover the match list.
	width := term - 6
	if width < 20 {
		return 20
	}
	return width
}

func completePath(input string) (string, []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		// ~ cannot be completed without a home directory.
		home = ""
	}
	return complete(input, home)
}

func complete(input, home string) (string, []string) {
	matches := listPath(input, home)
	if len(matches) == 0 {
		return input, nil
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	prefix := commonPrefix(matches)
	if len(prefix) > len(input) && strings.HasPrefix(prefix, input) {
		return prefix, matches
	}
	return input, matches
}

func listPath(input, home string) []string {
	if input == "~" {
		input = "~/"
	}
	displayPrefix := ""
	base := input
	if i := strings.LastIndex(input, "/"); i >= 0 {
		displayPrefix = input[:i+1]
		base = input[i+1:]
	}
	dir := "."
	if displayPrefix != "" {
		dir = strings.TrimRight(displayPrefix, "/")
		if dir == "" {
			dir = "/"
		}
	}
	switch {
	case dir == "~":
		if home == "" {
			return nil
		}
		dir = home
	case strings.HasPrefix(dir, "~/"):
		if home == "" {
			return nil
		}
		dir = filepath.Join(home, dir[2:])
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// A missing or unreadable directory has nothing to complete.
		return nil
	}
	matches := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		// Dot names stay hidden until the typed base starts with a dot.
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
			continue
		}
		if !strings.HasPrefix(name, base) {
			continue
		}
		if entry.IsDir() || followsDir(filepath.Join(dir, name)) {
			name += "/"
		} else if !keystoreFile(name) {
			continue
		}
		matches = append(matches, displayPrefix+name)
	}
	slices.Sort(matches)
	return matches
}

// keystoreFile is a name this prompt can open: JKS, PKCS#12, or PEM.
func keystoreFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jks", ".keystore", ".p12", ".pfx", ".pem":
		return true
	default:
		return false
	}
}

func followsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func commonPrefix(values []string) string {
	prefix := values[0]
	for _, value := range values[1:] {
		for !strings.HasPrefix(value, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func visibleNames(input string, matches []string) []string {
	names := make([]string, len(matches))
	for i, match := range matches {
		names[i] = matchBase(input, match)
	}
	if len(names) <= maxPathMatches {
		return names
	}
	extra := len(names) - maxPathMatches
	return append(names[:maxPathMatches], fmt.Sprintf("… %d more", extra))
}

func matchBase(input, match string) string {
	dir := ""
	if strings.HasSuffix(input, "/") {
		dir = input
	} else if i := strings.LastIndex(input, "/"); i >= 0 {
		dir = input[:i+1]
	}
	return strings.TrimPrefix(match, dir)
}

func formatNames(names []string, width int, dir, file, selected lipgloss.Style, current string) string {
	if len(names) == 0 {
		return ""
	}
	if width < 10 {
		width = 80
	}
	dir = dir.Inline(true)
	file = file.Inline(true)
	selected = selected.Inline(true)
	maxLen := 1
	for _, name := range names {
		maxLen = max(maxLen, lipgloss.Width(name))
	}
	cols := max(width/(maxLen+2), 1)
	var rows []string
	var row strings.Builder
	for i, name := range names {
		style := file
		if name == current {
			style = selected
		} else if strings.HasSuffix(name, "/") {
			style = dir
		}
		cell := name
		if (i+1)%cols != 0 && i != len(names)-1 {
			if pad := maxLen + 2 - lipgloss.Width(name); pad > 0 {
				cell += strings.Repeat(" ", pad)
			}
		}
		row.WriteString(style.Render(cell))
		if (i+1)%cols == 0 || i == len(names)-1 {
			rows = append(rows, row.String())
			row.Reset()
		}
	}
	return strings.Join(rows, "\n")
}
