package main

import (
	"net"
	"os"
)

// Service kinds. The wire is just a string; this is the closed set the host
// and guest agree on. Unknown kinds reaching the guest are treated as
// generic-tcp (no hint).
const (
	KindPostgres   = "postgres"
	KindMySQL      = "mysql"
	KindRedis      = "redis"
	KindMongoDB    = "mongodb"
	KindSSH        = "ssh"
	KindHTTP       = "http"
	KindShell      = "shell"
	KindGenericTCP = "generic-tcp"
)

// validKinds is the set accepted on the -kind flag and the @kind suffix.
// KindShell is deliberately excluded: it's set internally by the -shell flag
// path and by inferKindFromTarget("shell"), never by user-supplied input.
var validKinds = map[string]struct{}{
	KindPostgres:   {},
	KindMySQL:      {},
	KindRedis:      {},
	KindMongoDB:    {},
	KindSSH:        {},
	KindHTTP:       {},
	KindGenericTCP: {},
}

func isValidKind(k string) bool {
	_, ok := validKinds[k]
	return ok
}

const kindList = "postgres|mysql|redis|mongodb|ssh|http|generic-tcp"

// inferKindFromTarget returns a kind based on the port in host:port. Falls
// back to generic-tcp when the port is non-standard or the target won't
// parse. The literal target "shell" maps to KindShell.
func inferKindFromTarget(target string) string {
	if target == "shell" {
		return KindShell
	}
	_, p, err := net.SplitHostPort(target)
	if err != nil {
		return KindGenericTCP
	}
	switch p {
	case "22":
		return KindSSH
	case "5432":
		return KindPostgres
	case "3306":
		return KindMySQL
	case "6379":
		return KindRedis
	case "27017":
		return KindMongoDB
	case "80", "443", "3000", "8000", "8080":
		return KindHTTP
	}
	return KindGenericTCP
}

// renderConnectHint produces a guest-side hint for a kind. The literal
// "{port}" is left in place for the caller to substitute. Returns "" when
// there is no useful hint (generic-tcp, shell, or unknown). The hint is
// generated locally on the guest, NOT taken from a host-supplied string.
func renderConnectHint(kind string) string {
	switch kind {
	case KindPostgres:
		return "psql -h 127.0.0.1 -p {port}"
	case KindMySQL:
		return "mysql -h 127.0.0.1 -P {port} -u root"
	case KindRedis:
		return "redis-cli -p {port}"
	case KindMongoDB:
		return "mongosh mongodb://127.0.0.1:{port}"
	case KindSSH:
		user := os.Getenv("USER")
		if user == "" {
			user = "root"
		}
		return "ssh " + user + "@127.0.0.1 -p {port}"
	case KindHTTP:
		return "http://127.0.0.1:{port}"
	}
	return ""
}

// hintLabel is the short prefix shown before a rendered hint. "open" reads
// naturally for a URL; "connect with" reads naturally for a CLI invocation.
func hintLabel(kind string) string {
	if kind == KindHTTP {
		return "open"
	}
	return "connect with"
}
