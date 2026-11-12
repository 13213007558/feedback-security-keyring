#!/bin/zsh
# Verify:
#   1. minimal config / env pin selects exactly the expected backend
#   2. misconfiguration fails LOUDLY (non-zero, clear error), never silently
#      falls back to another backend
set -euo pipefail

HERE=${0:A:h}
REPO=${HERE:h}
PY=${REPO}/.venv/bin/python
[[ -x $PY ]] || PY=$(command -v python3)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/keyring-pin.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
SITE=$WORK/site
SITE_SOFT=$WORK/site-soft
HOMEW=$WORK/home
mkdir -p "$SITE" "$SITE_SOFT" "$HOMEW/.config/python_keyring"
"$PY" "$HERE/make_fake_plugins.py" "$SITE" vault legacy >/dev/null
# Soft-fallback scenario needs only a benign backend: a raising plugin would
# itself crash auto-detection (get_all_keyring only suppresses TypeError).
"$PY" "$HERE/make_fake_plugins.py" "$SITE_SOFT" legacy >/dev/null
CFG=$HOMEW/.config/python_keyring/keyringrc.cfg

pass=0; fail=0
report() { # desc 0|1 (1=pass)
  if [[ $2 == 1 ]]; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi
}

probe() { # remaining args become the child environment
  env -i HOME="$HOMEW" USER=diag PATH=/usr/bin:/bin \
      PYTHONPATH="$REPO:$SITE" "$@" \
      "$PY" -c 'import keyring
kr = keyring.get_keyring()
print("SELECTED:", type(kr).__module__ + "." + type(kr).__name__)'
}

echo "== 1. minimal ENV pin selects the strong backend =="
out=$(probe PYTHON_KEYRING_BACKEND=fake_vault.VaultKeyring \
            KEYRING_PROPERTY_VAULT_PIN=x 2>&1) && rc=0 || rc=$?
echo "$out" | sed 's/^/   /'
report "env pin exits 0" $(( rc == 0 ))
grep -q 'SELECTED: fake_vault.VaultKeyring' <<<"$out" && report "env pin selects VaultKeyring" 1 || report "env pin selects VaultKeyring" 0

echo
echo "== 2. minimal CONFIG pin (two lines) selects the legacy backend =="
print -r -- '[backend]
default-keyring=fake_legacy.LegacyFileKeyring' > "$CFG"
out=$(probe 2>&1) && rc=0 || rc=$?
echo "$out" | sed 's/^/   /'
report "config pin exits 0" $(( rc == 0 ))
grep -q 'SELECTED: fake_legacy.LegacyFileKeyring' <<<"$out" && report "config pin selects LegacyFileKeyring" 1 || report "config pin selects LegacyFileKeyring" 0

echo
echo "== 3. bad env backend: import error must HARD FAIL, no fallback =="
set +e
out=$(probe PYTHON_KEYRING_BACKEND=fake_vault.DoesNotExist 2>&1); rc=$?
set -e
echo "$out" | tail -3 | sed 's/^/   /'
report "bad env backend exits non-zero" $(( rc != 0 ))
if grep -q 'SELECTED:' <<<"$out"; then report "no silent SELECTED line" 0; else report "no silent SELECTED line" 1; fi

echo
echo "== 4. unviable env backend: RuntimeError must HARD FAIL =="
set +e
out=$(probe PYTHON_KEYRING_BACKEND=fake_vault.VaultKeyring 2>&1); rc=$?
set -e
echo "$out" | tail -3 | sed 's/^/   /'
report "unviable backend (missing property gate) exits non-zero" $(( rc != 0 ))
if grep -q 'VaultKeyring requires KEYRING_PROPERTY_VAULT_PIN' <<<"$out"; then report "error states the missing gate" 1; else report "error states the missing gate" 0; fi

echo
echo "== 5. bad config backend: HARD FAIL instead of auto-detect fallback =="
print -r -- '[backend]
default-keyring=fake_legacy.NotARealBackend' > "$CFG"
set +e
out=$(probe 2>&1); rc=$?
set -e
echo "$out" | tail -3 | sed 's/^/   /'
report "bad config backend exits non-zero" $(( rc != 0 ))
if grep -q 'SELECTED:' <<<"$out"; then report "config error does not silently select another backend" 0; else report "config error does not silently select another backend" 1; fi

echo
echo "== 6. documented soft-fallback case: malformed option warns then auto-detects =="
print -r -- '[backend]
some-other-option=ignored' > "$CFG"
out=$(env -i HOME="$HOMEW" USER=diag PATH=/usr/bin:/bin \
        PYTHONPATH="$REPO:$SITE_SOFT" \
        "$PY" -c 'import keyring
kr = keyring.get_keyring()
print("SELECTED:", type(kr).__module__ + "." + type(kr).__name__)' 2>&1) && rc=0 || rc=$?
echo "$out" | sed 's/^/   /'
report "missing default-keyring warns and still resolves (documented fallback)" $(( rc == 0 ))
grep -q 'Keyring config file contains incorrect values' <<<"$out" && report "library emitted the incorrect-values warning" 1 || report "library emitted the incorrect-values warning" 0
echo "   NOTE: this is keyring's only soft path; use an exact default-keyring"
echo "         value or PYTHON_KEYRING_BACKEND to guarantee a hard pin."
echo "   NOTE: a plugin whose constructor raises a non-TypeError exception"
echo "         crashes auto-detection entirely instead of being skipped."

echo
echo "== 7. fail.Keyring sentinel raises NoKeyringError at first use =="
set +e
out=$(env -i HOME="$HOMEW" PATH=/usr/bin:/bin PYTHONPATH="$REPO" \
      "$PY" -c 'from keyring.backends.fail import Keyring
Keyring().get_password("svc", "user")' 2>&1); rc=$?
set -e
echo "$out" | tail -2 | sed 's/^/   /'
report "fail sentinel raises NoKeyringError non-zero" $(( rc != 0 ))

echo
echo "summary: $pass passed, $fail failed"
(( fail == 0 ))
