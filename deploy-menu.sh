#!/usr/bin/env bash
# Wazuh Agent Auto Deploy Menu
# Linux/macOS launcher.
# Windows users should run scripts/windows/Deploy-Wazuh-Windows.ps1 as Administrator.

set -e

echo "============================================================"
echo "Wazuh Agent Auto Deploy"
echo "============================================================"
echo "1) Deploy on Linux"
echo "2) Deploy on macOS"
echo "3) Show Windows command"
echo "4) Exit"
echo ""

read -rp "Select option [1-4]: " choice

case "$choice" in
  1)
    sudo bash ./scripts/linux/deploy-wazuh-linux.sh
    ;;
  2)
    sudo bash ./scripts/macos/deploy-wazuh-macos.sh
    ;;
  3)
    echo ""
    echo "Open PowerShell as Administrator and run:"
    echo "Set-ExecutionPolicy Bypass -Scope Process -Force"
    echo ".\\scripts\\windows\\Deploy-Wazuh-Windows.ps1"
    ;;
  4)
    exit 0
    ;;
  *)
    echo "Invalid choice."
    exit 1
    ;;
esac
