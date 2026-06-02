package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func cmdInteractive(_ []string) {
	in := bufio.NewReader(os.Stdin)
	fmt.Print("Tessera, consent-gated remote access\n\nWho are you?\n  [h] Host  (share something on this machine)\n  [g] Guest (connect to someone else's machine)\n  [q] Quit\n> ")
	line, err := in.ReadString('\n')
	if err != nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "h", "host":
		shareInteractive(in)
	case "g", "guest":
		joinInteractive(in)
	case "q", "quit", "exit", "":
		return
	default:
		fmt.Fprintln(os.Stderr, "unknown choice")
		os.Exit(2)
	}
}

func shareInteractive(in *bufio.Reader) {
	coord := prompt(in, "Coordinator host:port", "")
	if coord == "" {
		fmt.Fprintln(os.Stderr, "coordinator is required")
		os.Exit(2)
	}
	base := prompt(in, "Coordinator base URL (http(s)://...)", "")
	if base == "" {
		fmt.Fprintln(os.Stderr, "coord-base-url is required")
		os.Exit(2)
	}
	port := prompt(in, "Local port to share", "")
	reason := prompt(in, "Reason shown to you", "")
	expected := prompt(in, "Expected guest name", os.Getenv("USER"))

	args := []string{
		"-coordinator", coord,
		"-coord-base-url", base,
		"-reason", reason,
		"-expected-name", expected,
	}
	if port != "" {
		args = append(args, "-port", port)
	}
	cmdShare(args)
}

func joinInteractive(in *bufio.Reader) {
	base := prompt(in, "Coordinator base URL (http(s)://...)", "")
	if base == "" {
		fmt.Fprintln(os.Stderr, "coord-base-url is required")
		os.Exit(2)
	}
	code := prompt(in, "Share code", "")
	if code == "" {
		fmt.Fprintln(os.Stderr, "share code is required")
		os.Exit(2)
	}
	args := []string{"-coord-base-url", base, code}
	cmdJoin(args)
}

func prompt(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s (%s): ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := in.ReadString('\n')
	if err != nil {
		return def
	}
	v := strings.TrimSpace(line)
	if v == "" {
		return def
	}
	return v
}
