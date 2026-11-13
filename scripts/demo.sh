#!/usr/bin/env bash
# MintMap demo: scan the example project, then show `mintmap diff` failing on a bad pull request.
#
#   bash scripts/demo.sh
#
# Runs the MintMap in this checkout (nothing is installed; only Python 3.11+ and git are needed), on the demo
# project in examples/demo. The bad change (examples/demo/bad-pr.patch) is applied to a temporary copy, so the
# checkout is not modified. Exits 0 only if both diffs return the expected exit codes (0, then 12); the CI job
# "demo" runs this script, so the demo in the README cannot go stale.
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 1

py="${PYTHON:-}"
if [ -z "$py" ]; then
  if command -v python3 >/dev/null 2>&1; then py=python3; else py=python; fi
fi

mintmap() { "$py" -I "$root/scripts/run_mintmap.py" "$@"; }
say() { printf '\n# %s\n' "$1"; }
show() { printf '$ %s\n' "$1"; }

work="$(mktemp -d)" || exit 1
trap 'rm -rf "$work"' EXIT

say "1. Every way to get signed in to the demo project (the full report: mintmap scan examples/demo)"
show "mintmap scan examples/demo | grep -E '^ +\[[0-9a-f]{16}\] (high|medium|low)'"
mintmap scan examples/demo | grep -E '^ +\[[0-9a-f]{16}\] (high|medium|low)'

say "2. The reviewed baseline (examples/demo/mintmap.lock) matches the code"
show "mintmap diff examples/demo"
mintmap diff examples/demo
clean=$?

say "3. A pull request makes the TOTP step ignore the result of its check"
cp -R examples/demo "$work/pr"
show "git apply examples/demo/bad-pr.patch   # on a temporary copy"
grep -E '^[-+][^-+]' examples/demo/bad-pr.patch
(cd "$work/pr" && git apply bad-pr.patch) || { echo "demo FAILED: the patch does not apply" >&2; exit 1; }

say "4. CI runs mintmap diff on the pull request"
show "mintmap diff ."
(cd "$work/pr" && mintmap diff .)
bad=$?
show 'echo $?'
echo "$bad"

echo
if [ "$clean" -eq 0 ] && [ "$bad" -eq 12 ]; then
  echo "demo ok: the reviewed code exits 0, the bad pull request exits 12 (fingerprint_changed + evidence_downgraded), and CI fails."
  exit 0
fi
echo "demo FAILED: expected exit codes 0 and 12, got $clean and $bad" >&2
exit 1
