#!/usr/bin/env bash
#
# Clean installer for the AI-Powered Cloud Monitoring & Auto-Healing System
# (Linux / macOS).
#
# What it does, end to end:
#   1. Verifies a suitable Python 3 interpreter is available.
#   2. Creates a FRESH, isolated virtual environment in ./.venv
#      (any existing ./.venv is removed first for a guaranteed clean install).
#   3. Upgrades pip and installs every dependency from requirements.txt.
#   4. Runs install/verify_installation.py to confirm the install is healthy.
#
# Usage:
#   ./install/install.sh            # clean install + verify
#   ./install/install.sh --keep     # reuse ./.venv if it already exists
#
# Re-running this script is always safe.

set -euo pipefail

# ----------------------------------------------------------------------------
# Resolve paths so the script works no matter where it is called from.
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/.venv"
REQUIREMENTS="$PROJECT_ROOT/requirements.txt"

KEEP_VENV=0
if [[ "${1:-}" == "--keep" ]]; then
    KEEP_VENV=1
fi

# ----------------------------------------------------------------------------
# Colour helpers
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    BLUE='\033[1;34m'; GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    BLUE=''; GREEN=''; RED=''; YELLOW=''; NC=''
fi
info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()   { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE} AI-Powered Cloud Monitoring & Auto-Healing System${NC}"
echo -e "${BLUE} Clean installation (Linux/macOS)${NC}"
echo -e "${BLUE}============================================================${NC}"
info "Project root: $PROJECT_ROOT"

# ----------------------------------------------------------------------------
# 1. Locate a Python 3 interpreter (>= 3.9)
# ----------------------------------------------------------------------------
PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 9) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    fi
done
[[ -n "$PY" ]] || die "Python 3.9+ not found. Install Python 3 (e.g. 'sudo apt install python3 python3-venv')."
ok "Using Python: $("$PY" --version 2>&1) ($(command -v "$PY"))"

[[ -f "$REQUIREMENTS" ]] || die "requirements.txt not found at $REQUIREMENTS"

# ----------------------------------------------------------------------------
# 2. Create a fresh virtual environment
#
# Preferred path is the stdlib 'venv'. On minimal systems where 'venv' cannot
# bootstrap pip (missing ensurepip), fall back to the 'virtualenv' package.
# ----------------------------------------------------------------------------
create_venv() {
    # Attempt 1: stdlib venv (the common, fully-supported case).
    if "$PY" -m venv "$VENV_DIR" >/dev/null 2>&1 && [[ -x "$VENV_DIR/bin/python" ]]; then
        return 0
    fi

    warn "Standard 'venv' creation failed (ensurepip/python3-venv may be missing)."
    warn "Falling back to 'virtualenv' ..."
    rm -rf "$VENV_DIR"

    # Make sure virtualenv is available to the system Python.
    if ! "$PY" -m virtualenv --version >/dev/null 2>&1; then
        info "Installing 'virtualenv' ..."
        "$PY" -m pip install --user virtualenv >/dev/null 2>&1 \
            || "$PY" -m pip install virtualenv >/dev/null 2>&1 \
            || return 1
    fi

    "$PY" -m virtualenv "$VENV_DIR" >/dev/null 2>&1 && [[ -x "$VENV_DIR/bin/python" ]]
}

if [[ -d "$VENV_DIR" && "$KEEP_VENV" -eq 0 ]]; then
    info "Removing existing virtual environment for a clean install: $VENV_DIR"
    rm -rf "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment: $VENV_DIR"
    if create_venv; then
        ok "Virtual environment created"
    else
        die "Could not create a virtual environment. On Debian/Ubuntu run: sudo apt install python3-venv"
    fi
else
    warn "Reusing existing virtual environment (--keep): $VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
[[ -x "$VENV_PY" ]] || die "Virtual environment python not found at $VENV_PY"

# ----------------------------------------------------------------------------
# 3. Install dependencies
# ----------------------------------------------------------------------------
info "Upgrading pip / setuptools / wheel ..."
"$VENV_PY" -m pip install --upgrade pip setuptools wheel >/dev/null
ok "pip toolchain upgraded"

info "Installing dependencies from requirements.txt ..."
"$VENV_PY" -m pip install -r "$REQUIREMENTS"
ok "All dependencies installed"

# ----------------------------------------------------------------------------
# 4. Verify the installation
# ----------------------------------------------------------------------------
info "Verifying installation ..."
if "$VENV_PY" "$SCRIPT_DIR/verify_installation.py"; then
    echo
    ok "Installation complete and verified."
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo -e "   Run (console)   : ${BLUE}./install/run.sh${NC}"
    echo -e "   Run (dashboard) : ${BLUE}./install/run.sh --tui${NC}"
else
    die "Verification reported problems. See the report above."
fi
