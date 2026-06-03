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

command -v install >/dev/null 2>&1 || err "missing required tool: install"
command -v uname >/dev/null 2>&1 || err "missing required tool: uname"

OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "${OS_RAW}" in
	Darwin) OS="darwin" ;;
	Linux)  OS="linux" ;;
	*)      OS="" ;;
esac

case "${ARCH_RAW}" in
	x86_64|amd64) ARCH="amd64" ;;
	arm64|aarch64) ARCH="arm64" ;;
	*) ARCH="" ;;
esac

TMPDIR_INST=""
cleanup() {
	[ -n "${TMPDIR_INST}" ] && [ -d "${TMPDIR_INST}" ] && rm -rf "${TMPDIR_INST}"
}
trap cleanup EXIT INT TERM

install_binary() {
	src="$1"
	if [ -w "${BINDIR}" ] || { [ ! -e "${BINDIR}" ] && mkdir -p "${BINDIR}" 2>/dev/null; }; then
		install -m 0755 "${src}" "${BINDIR}/${BIN_NAME}"
	elif command -v sudo >/dev/null 2>&1; then
		sudo install -d -m 0755 "${BINDIR}"
		sudo install -m 0755 "${src}" "${BINDIR}/${BIN_NAME}"
	else
		err "cannot write to ${BINDIR} and sudo is not available. Set TESSERA_BINDIR to a writable path."
	fi
}

installed_via_release=0

if [ -n "${OS}" ] && [ -n "${ARCH}" ] && command -v curl >/dev/null 2>&1; then
	ASSET_URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}-${OS}-${ARCH}"
	TMPDIR_INST="$(mktemp -d 2>/dev/null || mktemp -d -t tessera)"
	TMP_BIN="${TMPDIR_INST}/${BIN_NAME}"
	say "Fetching ${ASSET_URL}"
	if curl -fsSL -o "${TMP_BIN}" "${ASSET_URL}" && [ -s "${TMP_BIN}" ]; then
		chmod 0755 "${TMP_BIN}"
		install_binary "${TMP_BIN}"
		ver=""
		if "${BINDIR}/${BIN_NAME}" version >/dev/null 2>&1; then
			ver="$("${BINDIR}/${BIN_NAME}" version 2>/dev/null | head -n1 || true)"
		fi
		if [ -n "${ver}" ]; then
			say "installed: ${BINDIR}/${BIN_NAME} (${ver})"
		else
			say "installed: ${BINDIR}/${BIN_NAME}"
		fi
		installed_via_release=1
	else
		say "No release asset for ${OS}/${ARCH}; trying go install."
	fi
fi

if [ "${installed_via_release}" -eq 0 ]; then
	if command -v go >/dev/null 2>&1; then
		GOBIN_DIR="$(go env GOPATH)/bin"
		say "Running: GOBIN=${GOBIN_DIR} go install github.com/${REPO}/cmd/${BIN_NAME}@latest"
		GOBIN="${GOBIN_DIR}" go install "github.com/${REPO}/cmd/${BIN_NAME}@latest"
		[ -x "${GOBIN_DIR}/${BIN_NAME}" ] || err "go install did not produce ${GOBIN_DIR}/${BIN_NAME}"
		install_binary "${GOBIN_DIR}/${BIN_NAME}"
		say "installed: ${BINDIR}/${BIN_NAME}"
	else
		err "No release binary for ${OS:-unknown}/${ARCH:-unknown} and Go is not installed. Either install Go (https://go.dev/dl/) or grab a binary from https://github.com/${REPO}/releases."
	fi
fi

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
