#!/usr/bin/env bash
set -euo pipefail

REPO="emmayusufu/tessera"
BINDIR="${TESSERA_BINDIR:-/usr/local/bin}"
BIN_NAME="tessera"

err() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

case "${BINDIR}" in
	"${HOME}"/*)
		if [ "$(id -u)" -eq 0 ]; then
			err "refusing to run as root when installing into your home (${BINDIR})."
		fi
		;;
esac

need() {
	command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"
}
need curl
need tar
need uname
need install

say "Detecting OS and architecture..."
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "${OS_RAW}" in
	Darwin) OS="darwin" ;;
	Linux)  OS="linux"  ;;
	*) err "unsupported OS: ${OS_RAW} (need Darwin or Linux)" ;;
esac

case "${ARCH_RAW}" in
	x86_64|amd64) ARCH="amd64" ;;
	arm64|aarch64) ARCH="arm64" ;;
	*) err "unsupported arch: ${ARCH_RAW} (need amd64 or arm64)" ;;
esac

say "Platform: ${OS}/${ARCH}"

TMPDIR="$(mktemp -d 2>/dev/null || mktemp -d -t tessera)"
cleanup() { rm -rf "${TMPDIR}"; }
trap cleanup EXIT INT TERM

# sudo only when the target dir isn't writable by us.
place_binary() {
	src="$1"
	chmod 0755 "${src}"
	mkdir -p "${TMPDIR}/place"
	if [ -w "${BINDIR}" ] || { [ ! -e "${BINDIR}" ] && mkdir -p "${BINDIR}" 2>/dev/null; }; then
		install -m 0755 "${src}" "${BINDIR}/${BIN_NAME}"
	else
		if command -v sudo >/dev/null 2>&1; then
			sudo install -d -m 0755 "${BINDIR}"
			sudo install -m 0755 "${src}" "${BINDIR}/${BIN_NAME}"
		else
			err "cannot write to ${BINDIR} and sudo is not available. Set TESSERA_BINDIR to a writable path."
		fi
	fi
	say "Installed: ${BINDIR}/${BIN_NAME}"
}

maybe_link() {
	if [ -t 0 ] && [ -z "${TESSERA_SKIP_LINK:-}" ]; then
		say ""
		say "Link this install to your coordinator now? [Y/n]"
		ans=""
		read -r ans || true
		case "${ans:-Y}" in
			[Nn]|[Nn][Oo]) ;;
			*)
				"${BINDIR}/${BIN_NAME}" link
				;;
		esac
	else
		say "Run 'tessera link' to bind to a coordinator."
	fi
}

ASSET="tessera_${OS}_${ARCH}.tar.gz"
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

say "Checking for latest GitHub release asset (${ASSET})..."
http_code="$(curl -sIL -o /dev/null -w '%{http_code}' "${RELEASE_URL}" || true)"

if [ "${http_code}" = "200" ]; then
	say "Downloading ${ASSET}..."
	curl -fsSL "${RELEASE_URL}" -o "${TMPDIR}/${ASSET}"
	say "Extracting..."
	tar -xzf "${TMPDIR}/${ASSET}" -C "${TMPDIR}"
	if [ ! -f "${TMPDIR}/${BIN_NAME}" ]; then
		# archive may nest the binary; try to find it.
		found="$(find "${TMPDIR}" -type f -name "${BIN_NAME}" -perm -u+x 2>/dev/null | head -n 1 || true)"
		[ -n "${found}" ] || err "release archive did not contain a ${BIN_NAME} binary"
		mv "${found}" "${TMPDIR}/${BIN_NAME}"
	fi
	place_binary "${TMPDIR}/${BIN_NAME}"
	maybe_link
	say "Run 'tessera' to start (interactive picker)."
	exit 0
fi

say "No matching release asset (HTTP ${http_code}). Trying 'go install' fallback..."

if command -v go >/dev/null 2>&1; then
	GOBIN_DIR="$(go env GOPATH)/bin"
	say "Running: GOBIN=${GOBIN_DIR} go install github.com/${REPO}/cmd/tessera@latest"
	GOBIN="${GOBIN_DIR}" go install "github.com/${REPO}/cmd/${BIN_NAME}@latest"
	[ -x "${GOBIN_DIR}/${BIN_NAME}" ] || err "go install did not produce ${GOBIN_DIR}/${BIN_NAME}"
	place_binary "${GOBIN_DIR}/${BIN_NAME}"
	maybe_link
	say "Run 'tessera' to start (interactive picker)."
	exit 0
fi

err "No release published yet. Install Go (https://go.dev/dl/) and re-run this script, or grab binaries from https://github.com/${REPO}/releases when available."
