#!/usr/bin/env python3
"""
Installation verifier for the AI-Powered Cloud Monitoring & Auto-Healing System.

Runs a series of self-contained checks and prints a PASS/FAIL report so you can
confirm a clean installation *before* launching the program. It does NOT modify
anything on disk and is safe to run as many times as you like.

Usage (from the project root, inside the virtual environment):

    python install/verify_installation.py

Exit codes:
    0  -> all required checks passed (installation is ready)
    1  -> one or more required checks failed
"""

from __future__ import annotations

import importlib
import importlib.metadata as importlib_metadata
import os
import sys
import platform
from pathlib import Path

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

MIN_PYTHON = (3, 9)

# Third-party runtime dependencies (import name -> friendly/pip name).
REQUIRED_PACKAGES = {
    "numpy": "numpy",
    "psutil": "psutil",
    "yaml": "pyyaml",
    "pandas": "pandas",
    "sklearn": "scikit-learn",
    "joblib": "joblib",
    "proxmoxer": "proxmoxer",
    "requests": "requests",
    "urllib3": "urllib3",
    "rich": "rich",
}

# Machine-learning artifacts that must ship with / be trained into src/.
REQUIRED_MODEL_ARTIFACTS = [
    "model_cpu.pkl",
    "model_mem.pkl",
    "model_stg.pkl",
    "model_net.pkl",
    "model_features.pkl",
    "scaler_cpu.pkl",
    "scaler_mem.pkl",
    "scaler_stg.pkl",
    "scaler_net.pkl",
]

# Core application modules that must import cleanly with PYTHONPATH=src.
CORE_MODULES = [
    "data.collector",
    "logic.detector",
    "logic.healer",
    "healing.auto_healer",
    "ui.dashboard_tui",
    "main",
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

# --------------------------------------------------------------------------- #
# Pretty output helpers (no external dependency required)
# --------------------------------------------------------------------------- #

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return _c(text, "1;32")


def red(text: str) -> str:
    return _c(text, "1;31")


def yellow(text: str) -> str:
    return _c(text, "1;33")


def cyan(text: str) -> str:
    return _c(text, "1;36")


def header(title: str) -> None:
    print()
    print(cyan("=" * 70))
    print(cyan(f" {title}"))
    print(cyan("=" * 70))


PASS = green("PASS")
FAIL = red("FAIL")
WARN = yellow("WARN")


# --------------------------------------------------------------------------- #
# Individual checks. Each returns (ok: bool, required: bool).
# --------------------------------------------------------------------------- #

def check_python_version() -> bool:
    header("1. Python interpreter")
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    print(f"   Interpreter : {sys.executable}")
    print(f"   Version     : {version_str} on {platform.system()} {platform.machine()}")
    ok = version[:2] >= MIN_PYTHON
    needed = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}+"
    if ok:
        print(f"   [{PASS}] Python {version_str} meets minimum {needed}")
    else:
        print(f"   [{FAIL}] Python {version_str} is older than the required {needed}")
    return ok


def check_virtualenv() -> bool:
    header("2. Virtual environment")
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if in_venv:
        print(f"   [{PASS}] Running inside an isolated virtual environment")
        print(f"   Location    : {sys.prefix}")
    else:
        print(f"   [{WARN}] Not running inside a virtual environment")
        print("           This is recommended but not strictly required.")
    # Non-fatal: only a warning.
    return True


def check_packages() -> bool:
    header("3. Required Python packages")
    all_ok = True
    for import_name, pip_name in REQUIRED_PACKAGES.items():
        try:
            module = importlib.import_module(import_name)
            version = getattr(module, "__version__", None)
            if not version:
                try:
                    version = importlib_metadata.version(pip_name)
                except Exception:
                    version = "?"
            print(f"   [{PASS}] {pip_name:<14} (import '{import_name}', v{version})")
        except Exception as exc:  # noqa: BLE001 - report any import error
            all_ok = False
            print(f"   [{FAIL}] {pip_name:<14} could not be imported: {exc}")
    if not all_ok:
        print()
        print(yellow("   Fix: re-run the installer, or 'pip install -r requirements.txt'."))
    return all_ok


def check_model_artifacts() -> bool:
    header("4. Machine-learning model artifacts")
    all_ok = True
    for artifact in REQUIRED_MODEL_ARTIFACTS:
        path = SRC_DIR / artifact
        if path.exists() and path.stat().st_size > 0:
            size_kb = path.stat().st_size / 1024.0
            print(f"   [{PASS}] {artifact:<22} ({size_kb:.1f} KB)")
        else:
            all_ok = False
            print(f"   [{FAIL}] {artifact:<22} missing or empty at {path}")
    if not all_ok:
        print()
        print(yellow("   Fix: run 'python src/ai/train_model.py' to regenerate the models."))
    return all_ok


def check_core_modules() -> bool:
    header("5. Application modules import cleanly")
    # Mirror how the program is launched: PYTHONPATH=src.
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))

    all_ok = True
    for module_name in CORE_MODULES:
        try:
            importlib.import_module(module_name)
            print(f"   [{PASS}] {module_name}")
        except Exception as exc:  # noqa: BLE001 - surface import-time failures
            all_ok = False
            print(f"   [{FAIL}] {module_name} -> {type(exc).__name__}: {exc}")
    return all_ok


def check_prometheus() -> bool:
    """Optional connectivity probe — never fails the installation."""
    header("6. Prometheus data source (optional)")
    url = os.environ.get("PROMETHEUS_URL", "http://127.0.0.1:9090")
    try:
        import requests  # already validated above

        resp = requests.get(f"{url}/-/ready", timeout=3)
        if resp.ok:
            print(f"   [{PASS}] Prometheus reachable at {url}")
        else:
            print(f"   [{WARN}] Prometheus at {url} returned HTTP {resp.status_code}")
    except Exception:
        print(f"   [{WARN}] Prometheus not reachable at {url}")
        print("           The program still runs; live metrics will read 0% until a")
        print("           Prometheus server (and node exporter on the target) is online.")
    return True


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> int:
    print(cyan("AI-Powered Cloud Monitoring & Auto-Healing System"))
    print(cyan("Installation verification"))
    print(f"Project root: {PROJECT_ROOT}")

    # (check function, is_required)
    checks = [
        (check_python_version, True),
        (check_virtualenv, False),
        (check_packages, True),
        (check_model_artifacts, True),
        (check_core_modules, True),
        (check_prometheus, False),
    ]

    required_failures = 0
    optional_warnings = 0

    for func, required in checks:
        try:
            ok = func()
        except Exception as exc:  # noqa: BLE001 - a check should never crash the report
            ok = False
            print(f"   [{FAIL}] Unexpected error during check: {exc}")
        if not ok:
            if required:
                required_failures += 1
            else:
                optional_warnings += 1

    header("Summary")
    if required_failures == 0:
        print(green("   ALL REQUIRED CHECKS PASSED — installation verified."))
        print()
        print("   Launch the program with:")
        print(cyan("     ./install/run.sh            ") + "(Linux/macOS, console mode)")
        print(cyan("     ./install/run.sh --tui      ") + "(Linux/macOS, dashboard)")
        print(cyan("     install\\run.bat             ") + "(Windows, console mode)")
        print(cyan("     install\\run.bat --tui       ") + "(Windows, dashboard)")
        return 0

    print(red(f"   {required_failures} required check(s) FAILED."))
    print(yellow("   Resolve the issues above and run this verifier again."))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
