#!/usr/bin/env bash
# ==============================================================================
# run_experiment.sh — Test Orchestration and Experiment Runner
# Project 25: Network Intrusion Detection and Response System
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

function show_help() {
    echo "======================================================================"
    echo " Project 25: Network Intrusion Detection & Response Experiment Runner"
    echo "======================================================================"
    echo " Usage: ./run_experiment.sh [OPTION]"
    echo ""
    echo " Options:"
    echo "   --test        Run automated unit and integration test suite"
    echo "   --demo        Launch interactive 5-phase terminal demonstration"
    echo "   --demo-auto   Launch automated non-interactive terminal showcase"
    echo "   --analyze     Run comparative evaluation report (Baseline vs SDN Defense)"
    echo "   --clean       Terminate background python test processes and clean logs"
    echo "   --all         Run full test suite, automated demo, and generate reports"
    echo "   --help        Display this help message"
    echo "======================================================================"
}

function clean_processes() {
    echo "[*] Cleaning up background processes and temporary files..."
    pkill -f "python3 tcp_server.py" 2>/dev/null || true
    pkill -f "python3 ids_monitor.py" 2>/dev/null || true
    pkill -f "python3 sdn_controller.py" 2>/dev/null || true
    pkill -f "python3 attack_generator.py" 2>/dev/null || true
    rm -f *.pyc
    rm -rf __pycache__
    echo "[✓] Cleanup complete."
}

if [ "$1" == "--test" ]; then
    python3 test_suite.py
elif [ "$1" == "--demo" ]; then
    python3 demo.py
elif [ "$1" == "--demo-auto" ]; then
    python3 demo.py --auto
elif [ "$1" == "--analyze" ]; then
    python3 analyze_results.py
elif [ "$1" == "--clean" ]; then
    clean_processes
elif [ "$1" == "--all" ] || [ -z "$1" ]; then
    echo ">>> Step 1/3: Running Test Suite..."
    python3 test_suite.py
    echo ""
    echo ">>> Step 2/3: Running Automated Showcase..."
    python3 demo.py --auto
    echo ""
    echo ">>> Step 3/3: Generating Comparative Performance Report..."
    python3 analyze_results.py
    echo ""
    echo "[✓] Complete Project 25 verification suite finished successfully!"
else
    show_help
fi
