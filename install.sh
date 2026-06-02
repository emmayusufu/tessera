#!/usr/bin/env bash
set -euo pipefail

REPO="emmayusufu/tessera"
BIN_NAME="tessera"
BINDIR="${TESSERA_BINDIR:-/usr/local/bin}"

err() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

case "${BINDIR}" in
	"${HOME}"/*)
		if [ "$(id -u)" -eq 0 ]; then
			err "refusing to run as root when installing into your home (${BINDIR})."
		fi
		;;
esac

command -v go >/dev/null 2>&1 || err "go is required. Install Go from https://go.dev/dl/ and re-run."
command -v install >/dev/null 2>&1 || err "missing required tool: install"

GOBIN_DIR="$(go env GOPATH)/bin"
say "Running: GOBIN=${GOBIN_DIR} go install github.com/${REPO}/cmd/${BIN_NAME}@latest"
GOBIN="${GOBIN_DIR}" go install "github.com/${REPO}/cmd/${BIN_NAME}@latest"
[ -x "${GOBIN_DIR}/${BIN_NAME}" ] || err "go install did not produce ${GOBIN_DIR}/${BIN_NAME}"

if [ -w "${BINDIR}" ] || { [ ! -e "${BINDIR}" ] && mkdir -p "${BINDIR}" 2>/dev/null; }; then
	install -m 0755 "${GOBIN_DIR}/${BIN_NAME}" "${BINDIR}/${BIN_NAME}"
elif command -v sudo >/dev/null 2>&1; then
	sudo install -d -m 0755 "${BINDIR}"
	sudo install -m 0755 "${GOBIN_DIR}/${BIN_NAME}" "${BINDIR}/${BIN_NAME}"
else
	err "cannot write to ${BINDIR} and sudo is not available. Set TESSERA_BINDIR to a writable path."
fi

say "Installed: ${BINDIR}/${BIN_NAME}"

if [ -t 0 ] && [ -z "${TESSERA_SKIP_LINK:-}" ]; then
	say ""
	say "Link this install to your coordinator now? [Y/n]"
	ans=""
	read -r ans || true
	case "${ans:-Y}" in
		[Nn]|[Nn][Oo]) ;;
		*) "${BINDIR}/${BIN_NAME}" link ;;
	esac
else
	say "Run 'tessera link' to bind to a coordinator."
fi
