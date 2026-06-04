package main

import (
	"os"

	"golang.org/x/term"
)

// useColor returns true when ANSI color is appropriate for normal output.
// It honors https://no-color.org: a NO_COLOR env var with a non-empty value
// disables color. Color is gated on stdout being a terminal, since that is
// where the vast majority of colorized writes go (printCodeBox, the [y/N]
// prompt, "session ended" lines, the join "connecting" banner). Writes that
// go to stderr (warnings, errors) reuse the same gate; this is the standard
// CLI convention and keeps the implementation a single helper.
func useColor() bool {
	if v := os.Getenv("NO_COLOR"); v != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func ansiWrap(code, s string) string {
	if !useColor() {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func red(s string) string    { return ansiWrap("31;1", s) }
func yellow(s string) string { return ansiWrap("33;1", s) }
func green(s string) string  { return ansiWrap("32;1", s) }
func cyan(s string) string   { return ansiWrap("36", s) }
func dim(s string) string    { return ansiWrap("2", s) }

// reset returns an ANSI reset when color is enabled, otherwise an empty
// string. Use it before printing plain text after an external producer
// (e.g. the session recording tailer) may have left an unclosed SGR
// attribute on the terminal.
func reset() string {
	if !useColor() {
		return ""
	}
	return "\x1b[0m"
}
