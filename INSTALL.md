# Installation Kit & User Manual

**AI-Powered Cloud Monitoring & Auto-Healing System**

This guide takes you from *"I just downloaded the repository folder"* all the way
to *"the program is running"* — with no manual code changes required. The
installation kit creates an isolated environment, installs every dependency, and
**verifies the installation** for you.

---

## 1. What you get

The kit lives in the [`install/`](install/) folder:

| File | Platform | Purpose |
|------|----------|---------|
| `install/install.sh` | Linux / macOS | One-command clean install + verification |
| `install/install.bat` | Windows | One-command clean install + verification |
| `install/run.sh` | Linux / macOS | Launch the program |
| `install/run.bat` | Windows | Launch the program |
| `install/verify_installation.py` | All | Standalone installation health-check |

The installer creates a self-contained virtual environment in `./.venv` and never
touches your system Python.

---

## 2. Prerequisites

- **Python 3.9 or newer** (3.10+ recommended). Check with `python3 --version`.
  - **Windows:** install from <https://www.python.org/downloads/> and tick
    *"Add Python to PATH"* during setup.
  - **Debian/Ubuntu:** `sudo apt install python3 python3-venv`
  - **macOS:** `brew install python` (or use the official installer).
- ~500 MB free disk space (NumPy / pandas / scikit-learn wheels).
- Internet access for the first install (to download Python packages).

> **No build tools needed** in normal cases — dependencies install from prebuilt
> wheels.

---

## 3. Quick start

### Linux / macOS

```bash
# From the repository root (the folder containing this file):
chmod +x install/install.sh install/run.sh   # first time only
./install/install.sh
./install/run.sh            # console mode
# or
./install/run.sh --tui      # live terminal dashboard
```

### Windows (Command Prompt or PowerShell)

```bat
REM From the repository root:
install\install.bat
install\run.bat
REM or
install\run.bat --tui
```

That's it. The installer prints a green **"Installation complete and verified"**
message when everything is ready.

---

## 4. What the installer does (step by step)

1. **Finds a suitable Python 3** interpreter (3.9+).
2. **Creates a fresh virtual environment** in `./.venv`. Any previous `./.venv`
   is removed first, so every install is clean and reproducible.
   *(Pass `--keep` to reuse an existing environment instead:
   `./install/install.sh --keep`.)*
3. **Upgrades pip / setuptools / wheel** inside that environment.
4. **Installs all dependencies** from [`requirements.txt`](requirements.txt).
5. **Verifies the installation** by running `install/verify_installation.py`.

---

## 5. Verifying the installation

Verification runs automatically at the end of the installer, but you can run it
again at any time:

```bash
# Linux / macOS
.venv/bin/python install/verify_installation.py

# Windows
.venv\Scripts\python.exe install\verify_installation.py
```

It checks, and reports `PASS` / `FAIL` / `WARN` for:

1. **Python interpreter** — version meets the minimum.
2. **Virtual environment** — running in an isolated env (warning only).
3. **Required packages** — every dependency imports, with its version.
4. **ML model artifacts** — the trained `model_*.pkl` / `scaler_*.pkl` files
   exist in `src/`.
5. **Application modules** — core modules (`main`, `logic.detector`,
   `logic.healer`, `healing.auto_healer`, `data.collector`, `ui.dashboard_tui`)
   import cleanly.
6. **Prometheus data source** *(optional)* — probes `http://127.0.0.1:9090`.
   A warning here is fine: the program still runs without Prometheus.

The script exits with code `0` when all **required** checks pass, or `1`
otherwise — handy for CI or scripted setups.

---

## 6. Running the program

The launcher activates `./.venv`, sets `PYTHONPATH=src`, and starts the
SENSE → DECIDE → ACT monitoring loop.

| Mode | Linux / macOS | Windows |
|------|---------------|---------|
| Console (default) | `./install/run.sh` | `install\run.bat` |
| Terminal dashboard (TUI) | `./install/run.sh --tui` | `install\run.bat --tui` |

- In the **TUI**, press **`R`** to reset the escalation state machine and
  **`Ctrl+C`** to exit.
- In **console mode**, press **`Ctrl+C`** to exit.

> **Note on live data:** the system reads live metrics from Prometheus at
> `http://127.0.0.1:9090` (scraping the target container `CT 100` at
> `10.0.2.100`). If Prometheus is not running, the program still launches and
> all metrics simply read `0%` until a data source is available — so you can
> install and smoke-test the application on any machine.

---

## 7. Manual installation (fallback)

If you prefer to do it by hand instead of using the kit:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python install/verify_installation.py
PYTHONPATH=src python src/main.py          # add --tui for the dashboard
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Python 3.9+ not found` | Install Python 3 and ensure it is on your `PATH`. |
| `The 'venv' module is missing` (Debian/Ubuntu) | `sudo apt install python3-venv` |
| `verify_installation.py` reports missing **packages** | Re-run the installer, or `pip install -r requirements.txt` inside `.venv`. |
| `verify_installation.py` reports missing **model artifacts** | Run `PYTHONPATH=src .venv/bin/python src/ai/train_model.py` to regenerate them. |
| Dashboard looks broken / garbled | Use a modern terminal (Windows Terminal, iTerm2, GNOME Terminal) and make the window reasonably large. |
| `Prometheus not reachable` warning | Expected when no Prometheus server is running locally; the app still runs. |

---

## 9. Uninstall

The installation is fully contained in the `./.venv` folder. To remove it:

```bash
rm -rf .venv            # Windows: rmdir /s /q .venv
```

No system-wide changes are made by the kit.
