@echo off
cd /d d:\FYP\Python-Script-for-Cloud
fyp-env\Scripts\python.exe compute_metrics.py > metrics_output.txt 2>&1
echo Exit code: %ERRORLEVEL% >> metrics_output.txt
