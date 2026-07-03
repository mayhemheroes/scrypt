#!/usr/bin/env bash
#
# scrypt/mayhem/build.sh — build RustCrypto/password-hashes' cargo-fuzz `scrypt` target as a
# sanitized libFuzzer binary, replicating OSS-Fuzz's Rust path (infra/base-images/base-builder/
# compile + projects/scrypt/build.sh which runs `cargo fuzz build`).
#
# password-hashes is a cargo WORKSPACE. The upstream OSS-Fuzz harness (../fuzz, i.e. $SRC/fuzz) was
# written against an OLD scrypt release (the `simple` cargo feature, removed at HEAD) and no longer
# compiles. To keep the mayhem layer strictly ADDITIVE (two-branch contract — never modify
# upstream-tracked files), we build our OWN self-contained cargo-fuzz crate at mayhem/fuzz/ which
# pulls in the `scrypt` crate with its current `phc` feature. cargo-fuzz drives the build:
#   - it provides its own libFuzzer runtime (the produced binary IS a libFuzzer target — Mayhem
#     runs it directly via `libfuzzer: true`);
#   - ASan is enabled the Rust way, through RUSTFLAGS `-Zsanitizer=address` (NOT clang's
#     $SANITIZER_FLAGS / CFLAGS — those don't apply to rustc), which is exactly what OSS-Fuzz's
#     `compile` sets for FUZZING_LANGUAGE=rust. nightly is required for `-Zsanitizer`.
#
# Target (mayhem/fuzz/fuzz_targets/scrypt_fuzzer.rs):
#   scrypt_fuzzer — the OSS-Fuzz `scrypt` target re-expressed for the current API. Decodes an
#            `arbitrary` (password, salt, ScryptRandParams) tuple and drives the low-level scrypt()
#            KDF + the high-level PHC hasher (build a `$scrypt$...` string) + PHC parse/verify
#            round-trip. (Same fuzzing surface as the stale upstream harness; adapted to
#            password-hash 0.6 / phc.)
#
# We copy the produced binary to /mayhem/scrypt_fuzzer.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer (kept for parity even
# though the Rust build doesn't invoke clang directly; cargo's cc-built deps might).
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
export MAYHEM_JOBS
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

# Source root: the base sets $SRC to the build dir; fall back to /mayhem (the COPY dest).
SRC="${SRC:-/mayhem}"
# Build from $SRC and point cargo-fuzz at OUR additive crate via --fuzz-dir. We must NOT cd into a
# `fuzz/`-named dir: cargo-fuzz auto-walks up to the nearest `fuzz/` and would pick the STALE
# upstream $SRC/fuzz crate (which still requests the removed `simple` feature and fails to resolve).
FUZZ_DIR="$SRC/mayhem/fuzz"
cd "$SRC"

# cargo-fuzz target name == output binary name (mayhem/fuzz/Cargo.toml `[[bin]] name`). It is
# `scrypt_fuzzer`, NOT `scrypt`: the $SRC root holds a `scrypt/` crate DIRECTORY, so an output named
# `/mayhem/scrypt` would `cp` the binary INTO that directory. The Mayhemfile cmd points at this name.
FUZZ_TARGET="scrypt_fuzzer"
OUT_BIN="scrypt_fuzzer"
TRIPLE="x86_64-unknown-linux-gnu"

# Replicate OSS-Fuzz `compile` RUSTFLAGS for a libFuzzer+ASan Rust build. cargo-fuzz sets the ASan
# flag itself by default, but we set it explicitly so the behavior is pinned and visible. `--cfg
# fuzzing` matches what libfuzzer-sys expects; force-frame-pointers aids ASan stack traces.
# RUST_DEBUG_FLAGS threads DWARF < 4 symbols (SPEC item 10): -C debuginfo=2 for full line
# tables, -Z dwarf-version=3 to pin rustc CUs to DWARF v3, and -Clinker=<cc-wrapper> which injects
# the clang -gdwarf-3 anchor.o as the FIRST link object so the offset-0 .debug_info CU verify-repo
# reads is DWARF v3 (the precompiled nightly ASan runtime CUs remain v5 deeper in the binary).
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -Z dwarf-version=3 -Clinker=/opt/mayhem-dwarf3-anchor/cc-wrapper.sh}"
export RUST_DEBUG_FLAGS

export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing $RUST_DEBUG_FLAGS -Zsanitizer=address -Cforce-frame-pointers"

echo "=== cargo fuzz build (image-default nightly toolchain, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"

# `-O` (release w/ opt) + `--debug-assertions` mirrors OSS-Fuzz's build.sh (catches overflow/debug
# asserts during fuzzing). Use the image's DEFAULT toolchain (Dockerfile pins it to the required
# nightly); a `+toolchain` override would make rustup try to install a different channel into the
# read-only shared /opt/rust.
cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$FUZZ_TARGET"

# Resolve the cargo-fuzz output dir from the additive crate's `cargo metadata` (target_directory)
# rather than assuming fuzz/target — robust for a standalone crate whose target dir may be
# redirected. Fall back to mayhem/fuzz/target if metadata is unavailable.
TARGET_DIR="$(cargo metadata --manifest-path "$FUZZ_DIR/Cargo.toml" --no-deps --format-version 1 2>/dev/null \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$TARGET_DIR" ] || TARGET_DIR="$FUZZ_DIR/target"

bin="$TARGET_DIR/$TRIPLE/release/$FUZZ_TARGET"
if [ ! -x "$bin" ]; then
  echo "ERROR: expected fuzz binary not found at $bin" >&2
  echo "searching under $TARGET_DIR ..." >&2
  find "$TARGET_DIR" -maxdepth 4 -name "$FUZZ_TARGET" -type f -perm -u=x 2>/dev/null >&2 || true
  exit 1
fi
cp "$bin" "/mayhem/$OUT_BIN"
echo "built /mayhem/$OUT_BIN"

echo "build.sh complete:"
ls -la "/mayhem/$OUT_BIN" 2>&1 || true
