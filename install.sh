#!/bin/sh
# Vigils one-line installer.
#
#   curl -fsSL https://vigils.ai/install.sh | sh
#
# Downloads the latest Vigils CLI (vigil-hub + vigil-native-host) for your platform
# from GitHub Releases and installs it to ~/.local/bin. Pin a version or change the
# target dir with env vars:
#
#   curl -fsSL https://vigils.ai/install.sh | VIGILS_VERSION=v0.1.26 VIGILS_INSTALL_DIR="$HOME/bin" sh
#
# Conservative by design (this is a security tool): it ONLY downloads the binary and
# puts it on disk. It does NOT edit your shell config, does NOT run `setup`, and does
# NOT touch any agent config — it prints what to do next so you stay in control.
#
# Integrity (fail-closed): the download is over HTTPS from github.com (TLS-authenticated
# transport), AND the archive is verified against the SHA-256 checksum published with the
# release asset (`<asset>.sha256`) before anything is unpacked — a missing checksum, a
# missing sha256 tool, or a mismatch all abort the install. That checksum lives in the same
# release, so it detects corruption/tampering in transit and lets you cross-check the
# artifact; it is not an independent offline signature. The archive is also validated to be
# exactly the two expected regular-file members before extraction (no paths, links, or
# extras). Read this script before piping it to a shell:
#   https://github.com/duncatzat/vigils/blob/main/install.sh
set -eu

REPO="duncatzat/vigils"
INSTALL_DIR="${VIGILS_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
err() { printf 'vigils-install: error: %s\n' "$*" >&2; exit 1; }
# Strip control chars from values we echo / put in a URL so a hostile value can't poison
# the terminal or the request. Keeps printable ASCII path/version chars only.
clean() { printf '%s' "$1" | tr -cd '[:alnum:]._/+-'; }

VERSION="$(clean "${VIGILS_VERSION:-latest}")"
[ -n "$VERSION" ] || VERSION="latest"

# ── detect platform → release asset name ───────────────────────────────────
os="$(clean "$(uname -s)")"
arch="$(clean "$(uname -m)")"
case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) asset="vigils-cli-linux-x64.tar.gz" ;;
      *) err "no prebuilt Linux CLI for '$arch' (x86_64 only). Build from source: https://github.com/$REPO" ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      arm64 | aarch64) asset="vigils-cli-macos-arm64.tar.gz" ;;
      x86_64) err "Intel macOS has no prebuilt CLI yet (Apple Silicon only). Build from source: https://github.com/$REPO" ;;
      *) err "unsupported macOS arch '$arch'" ;;
    esac
    ;;
  *)
    err "unsupported OS '$os'. Windows: grab vigils-cli-windows-x64.zip from https://github.com/$REPO/releases/latest"
    ;;
esac

# ── resolve download URL (latest → GitHub's auto-redirect; else pinned tag) ──
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi
url="$base/$asset"

# ── tools ──────────────────────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
  download() { curl -fsSL -o "$1" "$2"; }                 # fails (nonzero) on 404
elif command -v wget >/dev/null 2>&1; then
  download() { wget -qO "$1" "$2"; }
else
  err "need 'curl' or 'wget' to download"
fi
command -v tar >/dev/null 2>&1 || err "need 'tar' to unpack"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  sha256_of() { echo ""; }   # no tool → integrity check fails closed below
fi

# ── temp workspace + robust cleanup (separate from signal exit codes) ────────
tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

say "Vigils installer"
say "  platform : $os/$arch  ->  $asset"
say "  version  : $VERSION"
say "  target   : $INSTALL_DIR"
say ""
say "Downloading $url"
download "$tmp/cli.tgz" "$url" || err "download failed: $url"

# ── integrity (fail-closed): SHA-256 must match the checksum in the release ──
download "$tmp/cli.sha256" "$url.sha256" 2>/dev/null \
  || err "no published checksum (.sha256) for $VERSION — refusing to install unverified. Use a release >= v0.1.26, or download + verify manually: https://github.com/$REPO/releases"
want="$(head -n1 "$tmp/cli.sha256" | cut -d' ' -f1 | tr -d '[:space:]' | tr 'A-F' 'a-f')"
printf '%s' "$want" | grep -qE '^[0-9a-f]{64}$' || err "published checksum is malformed — refusing to install"
got="$(sha256_of "$tmp/cli.tgz" | tr 'A-F' 'a-f')"
[ -n "$got" ] || err "no sha256 tool (sha256sum/shasum) to verify the download — refusing to install"
[ "$got" = "$want" ] || err "CHECKSUM MISMATCH — refusing to install. expected $want, got $got"
say "Checksum OK (sha256 $got)"

# ── archive safety: validate members BEFORE extracting ──────────────────────
# Must be EXACTLY the two expected bare filenames, both regular-file members, no
# duplicates, no links (sym/hard), no extras. tar -tv prefixes each entry with a mode
# string ('-' regular, 'l' symlink, 'h' hardlink, 'd' dir, ...) and annotates links with
# "link to" / "->" on both GNU and BSD tar; we reject on all of those.
names="$(tar -tzf "$tmp/cli.tgz")" || err "could not read archive"
bad="$(printf '%s\n' "$names" | grep -vxE 'vigil-hub|vigil-native-host' || true)"
[ -z "$bad" ] || err "archive has unexpected entries (refusing to extract): $(printf '%s' "$bad" | tr '\n' ' ')"
n="$(printf '%s\n' "$names" | grep -c .)"
[ "$n" -eq 2 ] || err "archive must contain exactly 2 entries, found $n (refusing to extract)"
[ -z "$(printf '%s\n' "$names" | sort | uniq -d)" ] || err "archive has duplicate entries (refusing to extract)"

verbose="$(tar -tvzf "$tmp/cli.tgz")" || err "could not read archive metadata"
printf '%s\n' "$verbose" | while IFS= read -r line; do
  case "$line" in
    -*) : ;;        # regular-file mode → ok
    *) exit 7 ;;    # symlink/hardlink/dir/device/etc. → reject
  esac
done || err "archive contains a non-regular member (refusing to extract)"
case "$verbose" in
  *"link to "* | *" -> "*) err "archive contains a link member (refusing to extract)" ;;
esac

mkdir -p "$tmp/x"
tar -xzf "$tmp/cli.tgz" -C "$tmp/x" || err "could not extract archive"
[ "$(find "$tmp/x" -mindepth 1 | grep -c .)" -eq 2 ] || err "unexpected files after extraction (refusing to install)"
for bin in vigil-hub vigil-native-host; do
  { [ -f "$tmp/x/$bin" ] && [ ! -L "$tmp/x/$bin" ]; } || err "archive missing or non-regular: $bin"
done

# ── install (announce overwrites; never edit shell rc) ───────────────────────
mkdir -p "$INSTALL_DIR" || err "cannot create $INSTALL_DIR"
for bin in vigil-hub vigil-native-host; do
  [ -e "$INSTALL_DIR/$bin" ] && say "Replacing existing $INSTALL_DIR/$bin"
  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$tmp/x/$bin" "$INSTALL_DIR/$bin" || err "could not install $bin to $INSTALL_DIR"
  else
    cp "$tmp/x/$bin" "$INSTALL_DIR/$bin" && chmod 0755 "$INSTALL_DIR/$bin" || err "could not install $bin"
  fi
done

say ""
say "Installed:"
say "  $INSTALL_DIR/vigil-hub"
say "  $INSTALL_DIR/vigil-native-host"
say ""

# ── PATH hint — delimiter-safe scan, no glob/case pitfalls; never edits rc ────
onpath=0
oldifs="$IFS"; IFS=:
for d in $PATH; do [ "$d" = "$INSTALL_DIR" ] && onpath=1; done
IFS="$oldifs"
if [ "$onpath" -eq 1 ]; then
  run="vigil-hub"
else
  say "NOTE: $INSTALL_DIR is not on your PATH. Add it (then open a new shell):"
  say "      export PATH=\"$INSTALL_DIR:\$PATH\""
  say ""
  run="$INSTALL_DIR/vigil-hub"
fi

say "See Vigils protect a real secret in ~10s (zero setup, no LLM, no account):"
say "      $run demo"
say ""
say "Then protect your agent:"
say "      $run setup --all      # Claude Code: one-command turnkey protection"
say "      $run serve --stdio    # any MCP agent (Codex / Cursor / Zed): point it here"
say ""
say "Docs: https://duncatzat.github.io/vigils"
say "Uninstall: rm \"$INSTALL_DIR/vigil-hub\" \"$INSTALL_DIR/vigil-native-host\""
