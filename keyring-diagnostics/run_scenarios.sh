#!/bin/zsh
# Reproduce the interactive vs process-manager keyring divergence.
#
# Both scenarios run the SAME code with a minimal, explicitly constructed
# environment. Only keyring-relevant variable NAMES are echoed; no full
# environment is ever printed. All artifacts live under a temp HOME that is
# removed on exit.
set -euo pipefail

HERE=${0:A:h}
REPO=${HERE:h}
PY=${REPO}/.venv/bin/python
[[ -x $PY ]] || PY=$(command -v python3)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/keyring-diag.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

SITE_A=$WORK/siteA
SITE_B=$WORK/siteB
HOME_A=$WORK/home-interactive
HOME_B=$WORK/home-daemon
mkdir -p "$SITE_A" "$SITE_B" "$HOME_A" "$HOME_B"

# Each scenario installs only its own fake plugin distribution.
"$PY" "$HERE/make_fake_plugins.py" "$SITE_A" vault >/dev/null
"$PY" "$HERE/make_fake_plugins.py" "$SITE_B" legacy >/dev/null

# Scenario B (process manager): config file under the platform config root.
# On non-Windows, keyring uses XDG_CONFIG_HOME or ~/.config.
CFG_DIR_B=$HOME_B/.config/python_keyring
mkdir -p "$CFG_DIR_B"
cat > "$CFG_DIR_B/keyringrc.cfg" <<CFG
[backend]
default-keyring=fake_legacy.LegacyFileKeyring
keyring-path=$SITE_B
CFG

run_diag() {
  local label=$1 home=$2 site=$3; shift 3
  echo
  echo "# $label"
  echo "# HOME=$home  plugin-dir=$site"
  env -i \
    HOME="$home" \
    USER="${USER:-diag}" \
    PATH=/usr/bin:/bin \
    PYTHONPATH="$REPO${site:+:$site}" \
    "$@" \
    "$PY" "$HERE/keyring_diagnose.py"
}

echo "############################################################"
echo "# Scenario A: interactive shell (env override + property)"
echo "############################################################"
run_diag "interactive" "$HOME_A" "$SITE_A" \
  PYTHON_KEYRING_BACKEND=fake_vault.VaultKeyring \
  KEYRING_PROPERTY_VAULT_PIN=redacted-secret \
  KEYRING_PROPERTY_TIMEOUT=5

echo
echo "############################################################"
echo "# Scenario B: process manager (clean env, config + keyring-path)"
echo "############################################################"
run_diag "process-manager" "$HOME_B" "$SITE_B"

# Structured comparison, redacted to backend names and capability flags.
echo
echo "############################################################"
echo "# Comparison summary (no env values, only names/capabilities)"
echo "############################################################"
json_a=$(env -i HOME="$HOME_A" PATH=/usr/bin:/bin PYTHONPATH="$REPO:$SITE_A" \
  PYTHON_KEYRING_BACKEND=fake_vault.VaultKeyring \
  KEYRING_PROPERTY_VAULT_PIN=x KEYRING_PROPERTY_TIMEOUT=5 \
  "$PY" "$HERE/keyring_diagnose.py" --json)
json_b=$(env -i HOME="$HOME_B" PATH=/usr/bin:/bin PYTHONPATH="$REPO:$SITE_B" \
  "$PY" "$HERE/keyring_diagnose.py" --json)

"$PY" - "$json_a" "$json_b" <<'PY'
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])

def show(value):
    return "-" if value is None else str(value)

rows = [
    ("scenario", "interactive", "process-manager"),
    ("selection source",
        next(k for k, v in a["stages"].items() if v.get("selected") == a["selected"]),
        next(k for k, v in b["stages"].items() if v.get("selected") == b["selected"])),
    ("selected backend", a["selected"], b["selected"]),
    ("env override name", "PYTHON_KEYRING_BACKEND", "-"),
    ("KEYRING_PROPERTY_* names",
        ",".join(k for k in a["env"] if k.startswith("KEYRING_PROPERTY_")) or "-",
        ",".join(k for k in b["env"] if k.startswith("KEYRING_PROPERTY_")) or "-"),
    ("config file",
        next((x["path"] for x in a["config_locations"] if x["state"] == "present"), "-"),
        next((x["path"] for x in b["config_locations"] if x["state"] == "present"), "-")),
    ("encrypted at rest", show(a["security"]["encrypted_at_rest"]), show(b["security"]["encrypted_at_rest"])),
    ("plaintext storage", show(a["security"]["plaintext"]), show(b["security"]["plaintext"])),
    ("survives reboot", show(a["security"]["survives_reboot"]), show(b["security"]["survives_reboot"])),
]
width = max(len(r[0]) for r in rows)
for label, va, vb in rows:
    print(f"  {label:<{width}} | {va:<38} | {vb}")
print()
print("writable inputs observed:")
for tag, report in (("interactive", a), ("process-manager", b)):
    for item in report["writable_inputs"]:
        print(f"  [{tag}] [{item['writable']}] {item['input']}")
PY
