#!/usr/bin/env bash
# Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer menu.
# Windows users should run scripts/windows/Invoke-Wazuh-Combined-Windows.ps1 as Administrator.

set -e

echo "============================================================"
echo "Combined Wazuh Agent Auto Deploy + Security Enforcer"
echo "============================================================"
echo "1) Linux"
echo "2) macOS"
echo "3) Show Windows command"
echo "4) Exit"
echo ""

read -rp "Select target OS [1-4]: " choice

case "$choice" in
  1)
    sudo bash ./scripts/linux/invoke-wazuh-combined-linux.sh
    ;;
  2)
    sudo bash ./scripts/macos/invoke-wazuh-combined-macos.sh
    ;;
  3)
    echo ""
    echo "Open PowerShell as Administrator and run:"
    echo "Set-ExecutionPolicy Bypass -Scope Process -Force"
    echo ".\\scripts\\windows\\Invoke-Wazuh-Combined-Windows.ps1"
    ;;
  4)
    exit 0
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
