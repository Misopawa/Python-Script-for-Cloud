AI-Based Cloud Server Monitoring & Auto-Healing System 🛡️

🎓 Final Year Project | Bachelor in Network Computing

Author: Mohamad Syahmi bin Soria

Focus: Intelligent Automation, Reliability, and Industry 4.0 Infrastructure.

📖 Project Overview

This project implements a hybrid cloud server monitoring system that bridges the gap between traditional threshold-based monitoring and AI-driven anomaly detection. By integrating the Isolation Forest algorithm, the system identifies abnormal behavior patterns that static thresholds might miss, while providing automated recovery actions (Auto-Healing) to maintain high system availability.

🧠 Hybrid Detection Logic

The system monitors four core components: CPU, Memory, Disk, and Network.

Threshold-Based Monitoring: Fast and interpretable alerts for resource usage exceeding predefined limits.

AI-Based Anomaly Detection: Utilizes an Isolation Forest model (trained on the Westermo industrial dataset) to identify unusual behavior in CPU, Memory, and Disk metrics.

Network Monitoring: Handled via threshold-based detection to account for the cumulative and bursty nature of network traffic.

🛠️ Installation & Execution

1. Prerequisites

    Ensure you have Python 3.8+ installed. Install the necessary dependencies:

        pip install psutil pandas scikit-learn pyyaml


2. Training the AI Model

    First, preprocess the industrial dataset and train the Isolation Forest model:

        python src/utils/westermo_preprocessor.py
        python src/ai/train_model.py


3. Running the System

    Start the real-time monitoring and auto-healing service:

        python src/main.py


📝 Configuration

    System behavior (including CPU/Memory limits and file paths) is managed via config/config.yaml. This allows for easy adjustments to network thresholds and alert sensitivity without modifying the core logic.

© 2026 Mohamad Syahmi | Final Year Project Submission
