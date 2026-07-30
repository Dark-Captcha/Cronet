#!/usr/bin/env bash
# Build libcronet.so from a Chromium checkout and install it into the package.
#
# The C++ sources in native/ are built inside a Chromium tree, because linking
# //net means using Chromium's own toolchain, sysroot and GN graph. They are
# *copied* in rather than symlinked: the sources in this repository stay the
# only ones anybody edits, nothing here or in the published package is a link,
# and the build works on a filesystem that has no symlinks at all.
#
# No file belonging to Chromium is modified. The copy lands in a directory
# Chromium does not otherwise use, and GN is pointed straight at it.
#
# Usage:
#   scripts/build_native.sh [gn-out-dir]
#
# The argument is the GN build directory, relative to the Chromium checkout
# rather than to this repository; it defaults to out/Standalone.
#
# Environment:
#   CHROMIUM_SRC   Path to a Chromium checkout's src/ (required if not at the
#                  default below).
#   DEPOT_TOOLS    Path to depot_tools (default ~/depot_tools).
#
# Two files in this repository are written on success, and both are committed:
# src/cronet/libcronet.so, and src/cronet/_abi.py regenerated from the header.

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chromium_src="${CHROMIUM_SRC:?set CHROMIUM_SRC to the src/ directory of a Chromium checkout}"
depot_tools="${DEPOT_TOOLS:-$HOME/depot_tools}"
out_dir="${1:-out/Standalone}"

# Nothing in Chromium refers to this directory, so GN is aimed at it with
# --root-target. That needs no edit anywhere in the Chromium tree, and it keeps
# the build graph down to what the library actually links.
target_label="//components/cronet/standalone:cronet"
staging_dir="$chromium_src/components/cronet/standalone"

if [[ ! -d "$chromium_src" ]]; then
  echo "No Chromium checkout at $chromium_src." >&2
  echo "Set CHROMIUM_SRC to the src/ directory of one." >&2
  exit 1
fi

if [[ ! -e "$depot_tools/gn" ]]; then
  echo "No depot_tools at $depot_tools. Set DEPOT_TOOLS." >&2
  exit 1
fi

export PATH="$depot_tools:$PATH"

# Guard the removal below: only ever a path this script composed itself, so a
# mistyped CHROMIUM_SRC cannot turn into a delete somewhere unexpected.
case "$staging_dir" in
  */components/cronet/standalone) ;;
  *) echo "Refusing to touch $staging_dir" >&2; exit 1 ;;
esac

# The patches in patches/ add the opt-in TLS profile support that TlsProfile
# drives. Without them the library still builds and works, but a profile would
# be silently ignored — so they are applied, not optional.
#
# Applying is idempotent: a patch already in the tree reverse-applies cleanly,
# which is how that is detected without keeping state anywhere.
apply_patch() {
  local patch="$1" tree="$2" name
  name="$(basename "$patch")"
  if git -C "$tree" apply --reverse --check "$patch" 2>/dev/null; then
    echo "  already applied: $name"
  elif git -C "$tree" apply --check "$patch" 2>/dev/null; then
    git -C "$tree" apply "$patch"
    echo "  applied: $name"
  else
    echo "Cannot apply $name to $tree." >&2
    echo "This expects Chromium $pinned_version; check out that version, or" >&2
    echo "rebase the patch." >&2
    exit 1
  fi
}

pinned_version="150.0.7871.100"
checkout_version="$(sed -n 's/^\(MAJOR\|MINOR\|BUILD\|PATCH\)=//p' \
  "$chromium_src/chrome/VERSION" | paste -sd.)"
if [[ "$checkout_version" != "$pinned_version" ]]; then
  echo "Warning: checkout is Chromium $checkout_version, patches target" \
    "$pinned_version." >&2
fi

echo "Patches:"
apply_patch "$project_root/patches/0001-tls-profile-net.patch" "$chromium_src"
apply_patch "$project_root/patches/0002-tls-profile-boringssl.patch" \
  "$chromium_src/third_party/boringssl/src"
apply_patch "$project_root/patches/0003-socks5-auth.patch" "$chromium_src"
apply_patch "$project_root/patches/0004-socks5-udp-quic.patch" "$chromium_src"

# Replaces whatever was there before, including a symlink left by an older
# version of this script, so the staged copy always matches native/ exactly.
rm -rf "$staging_dir"
mkdir -p "$staging_dir"
cp "$project_root"/native/* "$staging_dir/"
echo "Staged $(ls "$project_root/native" | wc -l) sources into $staging_dir"

# GN and ninja both locate the build from the working directory, so everything
# below runs inside the checkout.
cd "$chromium_src"

# is_official_build is off on purpose: it turns on ThinLTO, which costs far more
# build time than it buys for a network library. The use_* switches drop desktop
# integrations //net does not need.
gn gen "$out_dir" --root-target="$target_label" --args='is_debug=false
is_official_build=false
is_component_build=false
symbol_level=0
dcheck_always_on=false
use_kerberos=false
use_libpci=false
disable_fieldtrial_testing_config=true' >/dev/null

ninja -C "$out_dir" "${target_label#//}"

# Stripped on the way in: the symbol table is ~29% of the file and nothing
# needs it, because ctypes resolves through .dynsym, which strip keeps. Every
# rebuild otherwise commits another 6 MB of debug names to git history.
install -m 0755 --strip \
  --strip-program="$chromium_src/third_party/llvm-build/Release+Asserts/bin/llvm-strip" \
  "$out_dir/libcronet.so" "$project_root/src/cronet/libcronet.so"

# The ctypes binding is generated from native/cronet.h, so a build that changed
# the ABI regenerates it here. Leaving that to whoever remembers is how the two
# descriptions of one ABI drift apart, and a struct read at the wrong offset
# corrupts quietly rather than failing.
if command -v uv >/dev/null 2>&1; then
  uv run --project "$project_root" python "$project_root/scripts/generate_binding.py"
else
  python3 "$project_root/scripts/generate_binding.py"
fi

echo
echo "Installed $(du -h "$project_root/src/cronet/libcronet.so" | cut -f1) into src/cronet/libcronet.so"
echo "System libraries it needs:"
ldd "$project_root/src/cronet/libcronet.so" | awk '{print "  " $1}' | sort -u
