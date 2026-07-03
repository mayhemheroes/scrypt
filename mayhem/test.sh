#!/usr/bin/env bash
#
# scrypt/mayhem/test.sh — RUN RustCrypto/password-hashes' own test suite for the `scrypt` crate
# (`cargo test -p scrypt --all-features`) and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: the scrypt crate ships the RFC 7914 / Colin Percival reference KDF vectors
# (tests/mod.rs — byte-exact derived keys for known (password, salt, log_n, r, p)) plus PHC and
# MCF parse+verify unit tests (src/phc.rs, src/mcf.rs) that assert a known `$scrypt$...` / `$7$...`
# string verifies and that a wrong password is rejected, and a `lib.rs` doctest round-trip. These
# assert byte-exact KDF outputs and exact PHC parse/verify behavior, so a no-op / "exit(0)" /
# output-altering patch CANNOT pass. This script only RUNS the suite via `cargo test`; it never
# builds the fuzz target.
#
# Note: we run `cargo test` with the crate's NORMAL flags (the default/stable resolution of the
# installed toolchain) — no sanitizer RUSTFLAGS — to keep the oracle honest and fast.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
SRC="${SRC:-/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test" 0 1 0; exit 2
fi

echo "=== running cargo test (scrypt RFC 7914 KDF vectors + PHC/MCF parse+verify) ==="
# Use the image's DEFAULT toolchain (the Dockerfile pins it to the same nightly the fuzz build
# uses), so no `+toolchain` override. --no-fail-fast so we count every test; RUSTFLAGS cleared so
# it inherits nothing from the sanitizer build. Scope to the `scrypt` crate (the OSS-Fuzz project
# fuzzes scrypt's PHC parsing) with --all-features so phc/mcf/kdf paths are exercised.
out="$(RUSTFLAGS="" cargo test -p scrypt --all-features --no-fail-fast --jobs "$MAYHEM_JOBS" 2>&1)"; rc=$?
echo "$out"

# libtest prints one line per test binary:
#   test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
# Sum across all binaries (unit + integration + doctests).
PASSED=0; FAILED=0; IGNORED=0
while read -r p f i; do
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f )); IGNORED=$(( IGNORED + i ))
done < <(printf '%s\n' "$out" \
  | sed -n 's/^test result:.* \([0-9][0-9]*\) passed; \([0-9][0-9]*\) failed; \([0-9][0-9]*\) ignored.*/\1 \2 \3/p')

# If we parsed no result lines, fall back to the cargo exit code (e.g. compile error).
if [ "$(( PASSED + FAILED + IGNORED ))" -eq 0 ]; then
  echo "could not parse any 'test result:' lines; using cargo exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "cargo-test" 1 0 0; exit 0; }
  emit_ctrf "cargo-test" 0 1 0; exit 1
fi

emit_ctrf "cargo-test" "$PASSED" "$FAILED" "$IGNORED"
