# AI-Powered Cloud Monitoring and Auto-Healing System

An intelligent, hybrid cloud server monitoring and remediation system that combines traditional time-series monitoring with unsupervised machine learning. Built to align with Industry 4.0 principles, this system detects abnormal server behavior, reduces downtime, and automatically triggers native hypervisor recovery actions without human intervention.

## 📖 Overview
This project demonstrates the integration of artificial intelligence into traditional server administration. It monitors core infrastructure components (CPU, Memory, Disk, and Network) utilizing a decoupled microservices architecture. 

While threshold-based monitoring handles predictable network bursts, CPU, memory, and disk resources are evaluated using an **Isolation Forest** anomaly detection model. This allows the system to distinguish between legitimate workload spikes and genuine faults (like rogue processes or memory leaks) that static thresholds often miss.

## 🎯 Project Scope & Methodology
Developed using the **Iterative and Incremental Development Model**, the core scope of this system focuses on testing and validating the AI anomaly detection model using mock datasets that represent system performance metrics in a cloud monitoring environment. 

## 🏗️ System Architecture
The system operates on a continuous **SENSE-LEARN-THINK-ACT** loop across a decoupled environment (a Management Node and a Target LXC Node):

* **SENSE (Data Collection):** Continuous, lightweight monitoring is achieved using pull-based Prometheus exporter agents, visualizing the time-series data via Grafana.
* **LEARN & THINK (AI Anomaly Detection):** The AI model is trained on a processed version of the Westermo industrial dataset. Using the `sklearn` Isolation Forest algorithm (with a static 0.05 contamination rate), the system dynamically evaluates multivariate metrics to flag anomalies in real-time.
* **ACT (Auto-Healing):** When an anomaly is detected, a stateful orchestrator executes a non-linear escalation matrix via Proxmox (`pct`) and Docker pass-through commands to stabilize the target container.

## 🛡️ The 5-Tier Auto-Healing Matrix
To ensure safe and effective recovery, the system tracks retries and escalates remediation actions progressively:
* **Level 1 (Service Restart - Dockerized):** Lightweight Docker container restart inside the target LXC (`pct exec 100 -- docker restart nginx`), followed by a mandatory 20-second synchronization delay so the container can cycle and Prometheus (15-second scrape interval) can pull fresh post-recovery telemetry before Level 2 is evaluated.
* **Level 2 (Process Reset):** Aggressive termination of rogue processes (e.g., `pkill -9 stress-ng`).
* **Level 3 (Network Traffic Throttling):** Injection of rate-limiting rules to mitigate potential network flood attacks (e.g., `iptables` connection throttling).
* **Level 4 (Container State Reset / Namespace Isolation):** Full LXC state reset via `pct stop 100`, a brief 5-second buffer, then `pct start 100`, followed by a mandatory 35-second boot delay to let the LXC boot its OS, initialize the Docker daemon, spin up the Nginx container, and allow Prometheus to establish a clean baseline scrape.
* **Level 5 (Circuit Breaker):** Halts the auto-healer and issues a Critical Alert for Human-in-the-Loop (HITL) Root Cause Analysis.

*(Note: Synchronization delays are enforced after Level 1 (20s) and Level 4 (35s) actions to allow Prometheus to scrape the recovered state. Exact wait times are logged to the console for Mean Time To Recovery (MTTR) tracking).*

## 🚀 Quick Install (Installation Kit)
A self-contained installation kit takes you from a freshly downloaded repository to a running program — no manual code changes required. It creates an isolated virtual environment, installs all dependencies, and **verifies the installation**.

```bash
# Linux / macOS
chmod +x install/install.sh install/run.sh   # first time only
./install/install.sh        # clean install + verification
./install/run.sh            # run (console)   |   ./install/run.sh --tui  (dashboard)
```

```bat
REM Windows
install\install.bat         REM clean install + verification
install\run.bat             REM run (console) |   install\run.bat --tui  (dashboard)
```

Re-verify at any time with `python install/verify_installation.py`. See **[INSTALL.md](INSTALL.md)** for the full User Manual (prerequisites, verification details, and troubleshooting).

## ⚙️ Configuration & Execution
System parameters are managed via a centralized YAML configuration file, which defines paths for datasets, model exports, and logging directories.

**Execution Flow:**
1. Preprocess the Westermo dataset.
2. Train and export the Isolation Forest model.
3. Boot the Proxmox target containers.
4. Execute the main orchestrator (`main.py`) to begin the SENSE-LEARN-THINK-ACT cycle.

## 💻 Tech Stack
* **Language:** Python 3.x
* **AI/ML:** Scikit-Learn (Isolation Forest), Pandas
* **Monitoring:** Prometheus, Grafana, Node Exporter
* **Infrastructure:** Proxmox VE (LXC Containers), Docker
* **Automation:** Native Bash & Subprocess Execution

## 🎓 Academic Context
This project was developed for academic evaluation as a Final Year Project submission, establishing a foundation for future enhancements in AIOps, distributed multi-region monitoring, and intelligent recovery optimization.

**Author:** Mohamad Syahmi
**Degree:** Bachelor's Degree in Computer Science with Honours (Network Computing)
