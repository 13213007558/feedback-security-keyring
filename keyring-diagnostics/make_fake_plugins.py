#!/usr/bin/env python3
"""
Build fake, in-process keyring plugin distributions for diagnostics.

Each backend is its own importable package + .dist-info so importlib.metadata
discovers it when its directory is on sys.path. The two distributions are
independent, which mirrors real third-party plugins and lets each startup
scenario install exactly the backends it needs:

  fake-vault-dist / fake_vault.VaultKeyring
      "strong" simulated OS vault; construction fails loudly unless
      KEYRING_PROPERTY_VAULT_PIN is present (instance-level property gate)

  fake-legacy-dist / fake_legacy.LegacyFileKeyring
      "weak" simulated plaintext-on-disk backend; always viable

The keyring_security dict is read by keyring_diagnose.py and describes the
*simulated* capabilities of the fake backend.
"""

from __future__ import annotations

import argparse
import pathlib
import textwrap

VAULT_INIT = '''\
from keyring.backend import KeyringBackend
from keyring.compat import properties


class VaultKeyring(KeyringBackend):
    """Simulated OS-backed encrypted vault plugin."""

    keyring_security = {
        "storage": "simulated OS vault (encrypted, non-exportable, session-bound)",
        "encrypted_at_rest": True,
        "plaintext": False,
        "survives_reboot": True,
        "notes": "Fake plugin for diagnostics; gate enforces KEYRING_PROPERTY_VAULT_PIN.",
    }

    def __init__(self):
        super().__init__()
        # KEYRING_PROPERTY_* values are injected on the instance, so the
        # viability gate is enforced at construction time.
        if not getattr(self, "vault_pin", None):
            raise RuntimeError(
                "VaultKeyring requires KEYRING_PROPERTY_VAULT_PIN"
            )

    @properties.classproperty
    def priority(cls):
        return 6

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        raise NotImplementedError("simulated read-only vault")
'''

LEGACY_INIT = '''\
from keyring.backend import KeyringBackend
from keyring.compat import properties


class LegacyFileKeyring(KeyringBackend):
    """Simulated legacy backend writing plaintext files under HOME."""

    keyring_security = {
        "storage": "simulated plaintext file under HOME, no OS access control",
        "encrypted_at_rest": False,
        "plaintext": True,
        "survives_reboot": True,
        "notes": "Fake plugin for diagnostics; no encryption, no access control.",
    }

    @properties.classproperty
    def priority(cls):
        return 6

    def get_password(self, service, username):
        return None

    def set_password(self, service, username, password):
        raise NotImplementedError("simulated legacy backend")
'''

VARIANTS = {
    "vault": {
        "package": "fake_vault",
        "class": "VaultKeyring",
        "dist_dir": "fake_vault_dist-0.0.1.dist-info",
        "dist_name": "fake-vault-dist",
        "source": VAULT_INIT,
    },
    "legacy": {
        "package": "fake_legacy",
        "class": "LegacyFileKeyring",
        "dist_dir": "fake_legacy_dist-0.0.1.dist-info",
        "dist_name": "fake-legacy-dist",
        "source": LEGACY_INIT,
    },
}


def build(root: pathlib.Path, variant: str) -> pathlib.Path:
    spec = VARIANTS[variant]
    root.mkdir(parents=True, exist_ok=True)
    pkg_dir = root / spec["package"]
    pkg_dir.mkdir(exist_ok=True)
    (pkg_dir / "__init__.py").write_text(textwrap.dedent(spec["source"]), encoding="utf-8")

    dist = root / spec["dist_dir"]
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {spec['dist_name']}\nVersion: 0.0.1\n",
        encoding="utf-8",
    )
    (dist / "entry_points.txt").write_text(
        "[keyring.backends]\n"
        f"{spec['package']} = {spec['package']}\n",
        encoding="utf-8",
    )
    (dist / "RECORD").write_text("", encoding="utf-8")
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=pathlib.Path, help="directory to populate")
    parser.add_argument(
        "variants",
        nargs="+",
        choices=sorted(VARIANTS),
        help="which fake backend distribution(s) to install",
    )
    args = parser.parse_args()
    for variant in args.variants:
        build(args.root, variant)
    print(f"fake plugin distribution(s) {args.variants} written to {args.root}")


if __name__ == "__main__":
    main()
