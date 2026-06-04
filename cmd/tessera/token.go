package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dir := fs.String("config-dir", defaultConfigDir(), "directory to write the operator token into")
	attachUsage(fs, cmdHelp{
		summary:  "tessera token: save the coordinator operator token used by session revoke.",
		synopsis: "tessera token [TOKEN]   (omit TOKEN to paste it on stdin)",
		examples: []string{
			"tessera token",
			"tessera token sometokenvalue",
		},
	})
	_ = fs.Parse(args)

	var tok string
	if fs.NArg() > 0 {
		tok = fs.Arg(0)
	} else {
		fmt.Print("Paste the coordinator operator token: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		tok = line
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		fmt.Fprintln(os.Stderr, "token: refusing to save an empty token")
		os.Exit(1)
	}

	check(os.MkdirAll(*dir, 0o700))
	path := filepath.Join(*dir, "operator-token")
	check(os.WriteFile(path, []byte(tok), 0o600))
	fmt.Printf("saved operator token to %s\n", path)
}
