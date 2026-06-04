package main

import (
	"flag"
	"fmt"
	"os"
)

type cmdHelp struct {
	summary  string
	synopsis string
	examples []string
}

func attachUsage(fs *flag.FlagSet, h cmdHelp) {
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, h.summary)
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Usage:")
		fmt.Fprintln(out, "  "+h.synopsis)
		hasFlags := false
		fs.VisitAll(func(*flag.Flag) { hasFlags = true })
		if hasFlags {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Flags:")
			fs.PrintDefaults()
		}
		if len(h.examples) > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Examples:")
			for _, e := range h.examples {
				fmt.Fprintln(out, "  "+e)
			}
		}
	}
}

const topUsage = `Tessera, consent-gated remote access.

Usage:
  tessera <command> [flags]
  tessera                  (no args: interactive guided mode)

Common commands:
  share        Offer a port, service, or shell on this machine.
  join         Redeem a share code from a host and connect.
  link         Save the coordinator address. Run once after install.

Setup commands:
  quickstart   Mint a personal CA and host certs in the default config dir.
  ca           Mint a CA and host certs into a directory.
  token        Save an operator token used for session revoke.

Advanced:
  connect      Connect to a known share-id directly (no code redeem).
  version      Print version.
  help         Show this help.

Run "tessera <command> -h" for command-specific flags and examples.
`

func usage() {
	fmt.Fprint(os.Stderr, topUsage)
	os.Exit(2)
}
