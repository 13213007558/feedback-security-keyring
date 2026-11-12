#!/usr/bin/env python3
"""
Reproducible keyring backend-selection diagnostic.

Traces the three inputs that decide which keyring backend a service gets:

  1. environment override      PYTHON_KEYRING_BACKEND
  2. config file override      <config_root>/keyringrc.cfg  (+ keyring-path)
  3. entry-point auto-detect   importlib.metadata group 'keyring.backends'

The precedence mirrors keyring.core._detect_backend exactly:
load_env() or load_config() or max(viable entry-point backends, fail.Keyring).

Only keyring-relevant environment variable *names* are printed; values are
redacted by design. Every input location is labelled writable / read-only and
the selected backend's security capabilities are summarized.
"""

from __future__ import annotations

import argparse
import configparser
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

import keyring
from keyring import backend, core
from keyring.util import platform_

# --- env vars that influence selection; values are never printed ------------
ENV_BACKEND = "PYTHON_KEYRING_BACKEND"
ENV_PROPERTY_PREFIX = "KEYRING_PROPERTY_"
ENV_KEYCHAIN_PATH = "KEYCHAIN_PATH"
TRACKED_ENV = (ENV_BACKEND, ENV_KEYCHAIN_PATH)

# Security profiles for backends shipped with keyring itself.
BUILTIN_SECURITY = {
    "keyring.backends.macOS.Keyring": {
        "storage": "OS keychain (encrypted at rest, OS access control)",
        "encrypted_at_rest": True,
        "plaintext": False,
        "survives_reboot": True,
        "notes": "Backed by macOS Security framework; prompts/ACL enforced by OS.",
    },
    "keyring.backends.SecretService.Keyring": {
        "storage": "D-Bus Secret Service (e.g. GNOME Keyring/KWallet)",
        "encrypted_at_rest": True,
        "plaintext": False,
        "survives_reboot": True,
        "notes": "Encrypted collection managed by a user-session daemon.",
    },
    "keyring.backends.libsecret.Keyring": {
        "storage": "libsecret/Secret Service",
        "encrypted_at_rest": True,
        "plaintext": False,
        "survives_reboot": True,
        "notes": "libsecret binding to the Secret Service daemon.",
    },
    "keyring.backends.kwallet.DBusKeyring": {
        "storage": "KDE Wallet (D-Bus)",
        "encrypted_at_rest": True,
        "plaintext": False,
        "survives_reboot": True,
        "notes": "KDE wallet daemon; encrypted wallet file.",
    },
    "keyring.backends.Windows.WinVaultKeyring": {
        "storage": "Windows Credential Manager",
        "encrypted_at_rest": True,
        "plaintext": False,
        "survives_reboot": True,
        "notes": "OS credential vault with user-context isolation.",
    },
    "keyring.backends.null.Keyring": {
        "storage": "none (all operations return None)",
        "encrypted_at_rest": False,
        "plaintext": False,
        "survives_reboot": False,
        "notes": "Secrets are silently discarded; availability, not storage.",
    },
    "keyring.backends.fail.Keyring": {
        "storage": "none (every operation raises NoKeyringError)",
        "encrypted_at_rest": False,
        "plaintext": False,
        "survives_reboot": False,
        "notes": "Explicit failure sentinel: no recommended backend was usable.",
    },
    "keyring.backends.chainer.ChainerBackend": {
        "storage": "composite: delegates to every viable backend in turn",
        "encrypted_at_rest": None,
        "plaintext": None,
        "survives_reboot": None,
        "notes": "Weakest-link semantics; inspect member backends below.",
    },
}


def writable_label(path: Path) -> str:
    """Classify a location's writability without modifying anything."""
    probe = path
    if path.exists() and path.is_file():
        probe = path.parent
    probe.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(dir=probe, prefix=".krprobe-"):
            pass
        return "WRITABLE"
    except OSError:
        return "READ-ONLY"


def fqname(backend_obj: object | type) -> str:
    cls = backend_obj if isinstance(backend_obj, type) else type(backend_obj)
    return f"{cls.__module__}.{cls.__name__}"


def redacted_env() -> dict[str, str]:
    """Return keyring-relevant env names with values redacted."""
    result: dict[str, str] = {}
    for name in sorted(os.environ):
        if name in TRACKED_ENV or name.startswith(ENV_PROPERTY_PREFIX):
            result[name] = "<set, redacted>"
    return result


def config_locations() -> list[Path]:
    root = Path(platform_.config_root())
    return [root, root / "keyringrc.cfg"]


def parse_config(path: Path) -> tuple[dict[str, str], list[str]]:
    parser = configparser.RawConfigParser()
    parser.read(path, encoding="utf-8")
    data: dict[str, str] = {}
    if parser.has_section("backend"):
        for key, value in parser.items("backend"):
            data[key] = value.strip()
    return data, parser.sections()


def entry_point_inventory() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for ep in sorted(backend.metadata.entry_points(group="keyring.backends"), key=lambda e: e.name):
        dist_path = str(getattr(ep.dist, "_path", "?"))
        try:
            writable = writable_label(Path(dist_path).parent)
        except OSError:
            writable = "UNKNOWN"
        rows.append(
            {
                "name": ep.name,
                "target": ep.value,
                "dist": ep.dist.metadata["Name"] if ep.dist else "?",
                "dist_path": dist_path,
                "dist_writable": writable,
            }
        )
    return rows


def viability_table() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for cls in sorted(backend.KeyringBackend._classes, key=fqname):
        try:
            priority = float(cls.priority)
            viable = bool(priority >= 1)
            reason = ""
        except Exception as exc:  # noqa: BLE001 - diagnostic wants the reason
            priority = None
            viable = False
            reason = f"{type(exc).__name__}: {exc}"
        rows.append(
            {
                "class": fqname(cls),
                "priority": priority,
                "recommended": viable,
                "excluded_reason": reason,
            }
        )
    return rows


def security_profile(name: str, instance: object) -> dict[str, object]:
    profile = dict(BUILTIN_SECURITY.get(name, {}))
    plugin_meta = getattr(instance, "keyring_security", None)
    if isinstance(plugin_meta, dict):
        profile.update(plugin_meta)
        profile["source"] = "plugin-declared (untrusted metadata)"
    elif profile:
        profile["source"] = "keyring built-in profile"
    else:
        profile = {
            "storage": "unknown third-party backend",
            "encrypted_at_rest": None,
            "plaintext": None,
            "survives_reboot": None,
            "notes": "No embedded security profile; audit the plugin code.",
            "source": "unclassified",
        }
    from keyring.backends.chainer import ChainerBackend

    if isinstance(instance, ChainerBackend):
        profile["members"] = [fqname(m) for m in instance.backends]
    return profile


def stage_resolution() -> dict[str, object]:
    """Re-run each stage of keyring.core._detect_backend independently."""
    stages: dict[str, object] = {}

    env_value = os.environ.get(ENV_BACKEND)
    if env_value is not None:
        try:
            stages["1_env"] = {"selected": fqname(core.load_env()), "error": None}
        except Exception as exc:  # noqa: BLE001
            stages["1_env"] = {
                "selected": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
    else:
        stages["1_env"] = {"selected": None, "error": None, "skipped": "env var unset"}

    try:
        loaded = core.load_config()
        stages["2_config"] = {"selected": fqname(loaded) if loaded else None, "error": None}
    except Exception as exc:  # noqa: BLE001
        stages["2_config"] = {"selected": None, "error": f"{type(exc).__name__}: {exc}"}

    auto = max(
        filter(None, backend.get_all_keyring()),
        default=core.fail.Keyring(),
        key=backend.by_priority,
    )
    stages["3_entrypoint_autodetect"] = {"selected": fqname(auto)}

    return stages


def cross_check() -> dict[str, object]:
    """What the real library actually returns through its public entry point."""
    core._keyring_backend = None
    try:
        chosen = core.get_keyring()
        return {"selected": fqname(chosen), "error": None}
    except Exception as exc:  # noqa: BLE001
        return {
            "selected": None,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback_tail": traceback.format_exc().strip().splitlines()[-3:],
        }


def render_text(report: dict[str, object]) -> str:
    out: list[str] = []
    add = out.append
    add("=" * 72)
    add("KEYRING BACKEND SELECTION DIAGNOSTIC")
    add("=" * 72)
    add(f"pid={os.getpid()}  python={sys.version.split()[0]}  platform={sys.platform}")
    add(f"keyring package: {Path(keyring.__file__).resolve()}")
    add("")

    add("-- 1. environment inputs (values redacted) --")
    env = report["env"]
    if env:
        for name in sorted(env):
            add(f"  {name} = {env[name]}")
    else:
        add("  <no keyring-related environment variables set>")
    add("  input class: process environment, WRITABLE by anything that can")
    add("               spawn the process (shell profile, service unit, launcher)")
    add("")

    add("-- 2. config file inputs --")
    for loc in report["config_locations"]:
        add(f"  {loc['path']}  [{loc['state']}]  writable={loc['writable']}")
    if report["config_values"]:
        for key, value in sorted(report["config_values"].items()):
            add(f"    [{key}] = {value}")
        if "keyring-path" in report["config_values"]:
            kp = Path(
                os.path.expanduser(report["config_values"]["keyring-path"])
            ).resolve()
            add(
                f"    keyring-path inserts into sys.path[0]; target {kp} "
                f"writable={writable_label(kp)}  <-- code-execution surface"
            )
    else:
        add("  <no [backend] section / no config file>")
    add("")

    add("-- 3. entry-point plugins (group 'keyring.backends') --")
    for row in report["entry_points"]:
        add(
            f"  {row['name']:<14} -> {row['target']}  "
            f"[{row['dist']}] dist writable={row['dist_writable']}"
        )
        add(f"      metadata: {row['dist_path']}")
    add("")

    add("-- 4. backend viability --")
    for row in report["viability"]:
        if row["priority"] is None:
            add(f"  {row['class']:<45} NOT VIABLE  ({row['excluded_reason']})")
        else:
            tag = "recommended" if row["recommended"] else "priority<1"
            add(f"  {row['class']:<45} priority={row['priority']:g}  {tag}")
    add("")

    add("-- 5. staged resolution (env > config > entry points > fail) --")
    for stage, data in report["stages"].items():
        if data.get("skipped"):
            add(f"  {stage:<28} skipped ({data['skipped']})")
        elif data.get("error"):
            add(f"  {stage:<28} HARD FAILURE -> {data['error']}")
        else:
            add(f"  {stage:<28} -> {data['selected']}")
    add("")

    add("-- 6. actual library result (keyring.get_keyring) --")
    cc = report["cross_check"]
    if cc["error"]:
        add(f"  HARD FAILURE: {cc['error']}")
        for line in cc["traceback_tail"]:
            add(f"    {line}")
    else:
        add(f"  selected: {cc['selected']}")
    add("")

    add("-- 7. security capabilities of the selected backend --")
    sec = report["security"]
    add(f"  storage           : {sec.get('storage')}")
    add(f"  encrypted at rest : {sec.get('encrypted_at_rest')}")
    add(f"  plaintext storage : {sec.get('plaintext')}")
    add(f"  survives reboot   : {sec.get('survives_reboot')}")
    add(f"  profile source    : {sec.get('source')}")
    if "members" in sec:
        add("  chainer members   :")
        for member in sec["members"]:
            add(f"    - {member}")
    add(f"  notes             : {sec.get('notes')}")
    add("")

    add("-- 8. writable input summary --")
    for item in report["writable_inputs"]:
        add(f"  [{item['writable']}] {item['input']}")
    return "\n".join(out)


def build_report() -> dict[str, object]:
    cfg_root, cfg_file = config_locations()
    cfg_exists = cfg_file.exists()
    config_values: dict[str, str] = {}
    sections: list[str] = []
    if cfg_exists:
        config_values, sections = parse_config(cfg_file)

    locations = [
        {
            "path": str(cfg_root),
            "state": "dir" if cfg_root.exists() else "missing",
            "writable": writable_label(cfg_root),
        },
        {
            "path": str(cfg_file),
            "state": "present" if cfg_exists else "missing",
            "writable": writable_label(cfg_file)
            if cfg_exists
            else writable_label(cfg_root),
        },
    ]

    stages = stage_resolution()
    cross = cross_check()
    selected_name = cross["selected"] or "UNRESOLVED"
    if cross["selected"]:
        selected = core.get_keyring()
        security = security_profile(selected_name, selected)
    else:
        security = {"storage": "no backend resolved", "source": "n/a"}

    writable_inputs = [
        {
            "input": f"env {ENV_BACKEND} / {ENV_PROPERTY_PREFIX}* (process environment)",
            "writable": "WRITABLE",
        }
    ]
    for loc in locations:
        writable_inputs.append(
            {"input": f"config location {loc['path']}", "writable": loc["writable"]}
        )
    for row in entry_point_inventory():
        writable_inputs.append(
            {
                "input": f"entry point metadata {row['dist_path']} ({row['name']})",
                "writable": row["dist_writable"],
            }
        )
    if "keyring-path" in config_values:
        kp = Path(os.path.expanduser(config_values["keyring-path"])).resolve()
        writable_inputs.append(
            {"input": f"keyring-path sys.path injection {kp}", "writable": writable_label(kp)}
        )

    return {
        "env": redacted_env(),
        "config_locations": locations,
        "config_sections": sections,
        "config_values": config_values,
        "entry_points": entry_point_inventory(),
        "viability": viability_table(),
        "stages": stages,
        "cross_check": cross,
        "security": security,
        "writable_inputs": writable_inputs,
        "selected": selected_name,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON instead of text"
    )
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0 if report["cross_check"]["selected"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
