package main

import (
	"os"

	"golang.org/x/term"
)

// useColor returns true if stderr is a terminal AND NO_COLOR env var is unset.
// Honors https://no-color.org/. Skipped for non-TTYs (CI logs, piped output).
func useColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
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
