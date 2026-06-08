#!/usr/bin/env bash
#
# Launcher for the AI-Powered Cloud Monitoring & Auto-Healing System (Linux/macOS).
#
# It activates the virtual environment created by install/install.sh, sets the
# PYTHONPATH so the 'src' package layout resolves, and starts the program.
#
# Usage:
#   ./install/run.sh           # console mode (default)
#   ./install/run.sh --tui     # rich terminal dashboard
#
# Any extra arguments are forwarded straight to src/main.py.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_PY="$PROJECT_ROOT/.venv/bin/python"

if [[ ! -x "$VENV_PY" ]]; then
    echo "[FAIL] Virtual environment not found. Run ./install/install.sh first." >&2
    exit 1
fi

cd "$PROJECT_ROOT"
export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"

echo "[INFO] Starting AI-Powered Auto-Healing System (Ctrl+C to stop) ..."
exec "$VENV_PY" src/main.py "$@"
