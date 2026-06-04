package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type coordinatorConfig struct {
	MtlsAddr string
	BaseURL  string
}

func coordinatorFile(dir string) string {
	return filepath.Join(dir, "coordinator")
}

func loadCoordinator(dir string) (*coordinatorConfig, error) {
	b, err := os.ReadFile(coordinatorFile(dir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	line := strings.TrimSpace(string(b))
	if line == "" {
		return nil, nil
	}
	parts := strings.SplitN(line, "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed coordinator config at %s", coordinatorFile(dir))
	}
	mtls := strings.TrimSpace(parts[0])
	base := strings.TrimSpace(parts[1])
	if mtls == "" || base == "" {
		return nil, fmt.Errorf("malformed coordinator config at %s", coordinatorFile(dir))
	}
	return &coordinatorConfig{MtlsAddr: mtls, BaseURL: base}, nil
}

func saveCoordinator(dir string, c coordinatorConfig) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	line := c.MtlsAddr + "|" + c.BaseURL + "\n"
	return os.WriteFile(coordinatorFile(dir), []byte(line), 0o600)
}

func validateMtls(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("mTLS address must be host:port (%w)", err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("mTLS address must be host:port")
	}
	return nil
}

func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base URL scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("base URL must include a host")
	}
	return nil
}

func cmdLink(args []string) {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	mtls := fs.String("mtls", "", "coordinator mTLS address host:port")
	base := fs.String("base-url", "", "coordinator HTTP(S) base URL")
	dirFlag := fs.String("config-dir", "", "config directory (defaults to $XDG_CONFIG_HOME/tessera)")
	attachUsage(fs, cmdHelp{
		summary:  "tessera link: save the coordinator address so share/join can omit it.",
		synopsis: "tessera link [-mtls HOST:PORT] [-base-url URL]",
		examples: []string{
			"tessera link",
			"tessera link -mtls coord.example.com:8443 -base-url https://coord.example.com",
		},
	})
	_ = fs.Parse(args)

	dir := *dirFlag
	if dir == "" {
		dir = defaultConfigDir()
	}

	current, err := loadCoordinator(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	mtlsVal := strings.TrimSpace(*mtls)
	baseVal := strings.TrimSpace(*base)

	if mtlsVal == "" || baseVal == "" {
		in := bufio.NewReader(os.Stdin)
		if mtlsVal == "" {
			def := ""
			if current != nil {
				def = current.MtlsAddr
			}
			mtlsVal = prompt(in, "Coordinator mTLS address", def)
		}
		if baseVal == "" {
			def := ""
			if current != nil {
				def = current.BaseURL
			}
			baseVal = prompt(in, "Coordinator base URL", def)
		}
	}

	if err := validateMtls(mtlsVal); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := validateBaseURL(baseVal); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := saveCoordinator(dir, coordinatorConfig{MtlsAddr: mtlsVal, BaseURL: baseVal}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("linked to %s\n", mtlsVal)
}
