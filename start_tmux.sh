#!/bin/bash

# [INFO] Launching AI-Powered Auto-Healing Environment...
echo -e "\033[1;34m[INFO] Launching AI-Powered Auto-Healing Environment...\033[0m"

# 1. Checks: TMUX installed?
if ! command -v tmux &> /dev/null; then
    echo "Error: TMUX is not installed. Please run 'sudo apt install tmux'."
    exit 1
fi

SESSION_NAME="auto_healing_lab"

# Kill any existing session with the same name
tmux kill-session -t "$SESSION_NAME" 2>/dev/null

# Create a new session and start in detached mode
# Window 1 (Main Dashboard)
tmux new-session -d -s "$SESSION_NAME" -n "Main Dashboard"

# 2. Layout Configuration (3-Pane Strategy)

# Pane 1 (Large Left): Launch the TUI
tmux send-keys -t "$SESSION_NAME:0.0" "export PYTHONPATH=src; python3 src/main.py --tui" C-m

# Split the window vertically for the right side (creating Pane 1)
tmux split-window -h -t "$SESSION_NAME:0.0" -p 40

# Pane 2 (Top Right): Watch real-time forensics data
tmux send-keys -t "$SESSION_NAME:0.1" "tail -f anomalies_forensics.csv" C-m

# Split the right pane horizontally (creating Pane 2)
tmux split-window -v -t "$SESSION_NAME:0.1" -p 50

# Pane 3 (Bottom Right): [FAULT INJECTION CONSOLE]
tmux send-keys -t "$SESSION_NAME:0.2" "clear; echo -e '\033[1;31m[FAULT INJECTION CONSOLE]\033[0m'; cd /home/mohamad-syahmi/AI-Powered-Cloud-Monitoring-and-Auto-Healing-System" C-m

# 3. Visual Formatting & UX
# Set the TMUX status bar color to Blue to match "Cyberpunk" theme
tmux set-option -t "$SESSION_NAME" status-style bg=blue,fg=white

# Ensure focus is on the Main TUI Pane (Pane 0)
tmux select-pane -t "$SESSION_NAME:0.0"

# Attach to the session
tmux attach-session -t "$SESSION_NAME"
