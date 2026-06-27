#!/bin/bash
# =============================================================================
# Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer - macOS
#
# This single script:
#   - Takes Wazuh Manager IP/FQDN, Agent Name, Agent Group
#   - Checks lab/production pilot acknowledgement
#   - Checks TCP 1514, 1515, optional 55000
#   - Checks enrollment password handling
#   - Installs Wazuh Agent if missing
#   - Writes SOC-ready ossec.conf
#   - Adds FIM noise-control entries
#   - Loads LaunchDaemon
#   - Optionally enrolls the agent
#   - Generates test event for Wazuh Dashboard validation
#   - Restarts and validates agent
#   - Saves report
#
# Usage:
#   sudo bash invoke-wazuh-combined-macos.sh
# =============================================================================

set -Eeuo pipefail

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

MANAGER=""
AGENT_NAME=""
AGENT_GROUP=""
PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.12.0-1.pkg"
NON_INTERACTIVE="false"
SKIP_API_CHECK="false"
SKIP_ENROLLMENT="false"
REPORT_LINES=()

section() { echo -e "\n${CYAN}============================================================${NC}\n${CYAN}$1${NC}\n${CYAN}============================================================${NC}"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; REPORT_LINES+=("[OK] $1"); }
fixed() { echo -e "${GREEN}[FIXED]${NC} $1"; REPORT_LINES+=("[FIXED] $1"); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; REPORT_LINES+=("[WARN] $1"); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; REPORT_LINES+=("[FAIL] $1"); }

usage() {
  cat <<'EOF'
Usage:
  sudo bash invoke-wazuh-combined-macos.sh [options]

Options:
  --manager <IP_OR_FQDN>       Wazuh Manager IP or FQDN
  --agent-name <NAME>          Agent name
  --agent-group <GROUP>        Agent group/profile
  --pkg-url <URL>              Wazuh macOS package URL
  --non-interactive            Do not prompt where possible
  --skip-api-check             Skip TCP 55000 check
  --skip-enrollment            Do not run agent-auth
  -h, --help                   Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager) MANAGER="$2"; shift 2 ;;
    --agent-name) AGENT_NAME="$2"; shift 2 ;;
    --agent-group) AGENT_GROUP="$2"; shift 2 ;;
    --pkg-url) PKG_URL="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE="true"; shift ;;
    --skip-api-check) SKIP_API_CHECK="true"; shift ;;
    --skip-enrollment) SKIP_ENROLLMENT="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    fail "Run as root or with sudo."
    exit 1
  fi
}

ask_required() {
  local prompt="$1"
  local default="${2:-}"
  local value=""

  while true; do
    if [[ -n "$default" ]]; then
      read -rp "$prompt [$default]: " value
      value="${value:-$default}"
    else
      read -rp "$prompt: " value
    fi

    if [[ -n "${value// }" ]]; then
      echo "$value"
      return
    fi
    warn "Value cannot be empty."
  done
}

confirm_yes() {
  local prompt="$1"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then return 0; fi
  local answer=""
  read -rp "$prompt (Y/N): " answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

test_tcp() {
  local host="$1"
  local port="$2"
  nc -vz -G 5 "$host" "$port" >/dev/null 2>&1
}

set_lab_ack() {
  section "1. Lab Test / Production Pilot Acknowledgement"

  local marker_dir="/Library/Application Support/WazuhCombinedDeploy"
  local marker_file="$marker_dir/lab_test_acknowledged.txt"

  if [[ -f "$marker_file" ]]; then
    ok "Lab acknowledgement marker exists: $marker_file"
    return
  fi

  if confirm_yes "Confirm this script/configuration has been tested in a lab or approved for production pilot"; then
    mkdir -p "$marker_dir"
    echo "Acknowledged by $(whoami) on $(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$marker_file"
    chmod 600 "$marker_file"
    fixed "Created lab acknowledgement marker: $marker_file"
  else
    warn "Lab test not acknowledged. Avoid mass deployment until validated."
  fi
}

confirm_ports() {
  section "2. Wazuh Manager Port Validation"

  local ports=(1514 1515)
  if [[ "$SKIP_API_CHECK" != "true" ]]; then ports+=(55000); fi

  for port in "${ports[@]}"; do
    if test_tcp "$MANAGER" "$port"; then
      ok "TCP port $port reachable on $MANAGER"
    else
      warn "TCP port $port not reachable on $MANAGER. Check firewall/network path."
    fi
  done
}

check_password_policy() {
  section "3. Enrollment Password Handling Policy"

  local found="false"

  while IFS= read -r -d '' file; do
    found="true"
    warn "Possible plaintext enrollment password file found: $file"
    if confirm_yes "Remove this file? $file"; then
      rm -f "$file"
      fixed "Removed possible plaintext password file: $file"
    fi
  done < <(find /tmp /Users -maxdepth 4 -type f \( -iname "*wazuh*password*.txt" -o -iname "*enrollment*password*.txt" \) -print0 2>/dev/null)

  [[ "$found" == "false" ]] && ok "No obvious plaintext enrollment password files found."
  ok "Recommended password policy: runtime prompt only; do not store secrets in scripts/files."
}

install_agent() {
  section "4. Wazuh Agent Installation"

  if [[ -x /Library/Ossec/bin/wazuh-control ]]; then
    ok "Wazuh Agent already installed."
    return
  fi

  local tmp_pkg="/tmp/wazuh-agent.pkg"
  curl -L "$PKG_URL" -o "$tmp_pkg"
  WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" installer -pkg "$tmp_pkg" -target /

  fixed "Wazuh Agent installed."
}

write_soc_ossec_conf() {
  section "5. Writing SOC-Ready ossec.conf"

  local conf="/Library/Ossec/etc/ossec.conf"

  if [[ ! -d /Library/Ossec/etc ]]; then
    fail "/Library/Ossec/etc not found. Wazuh Agent install may have failed."
    exit 1
  fi

  if [[ -f "$conf" ]]; then
    cp "$conf" "${conf}.bak_$(date +%Y%m%d_%H%M%S)"
    ok "Created ossec.conf backup."
  fi

  cat > "$conf" <<EOF
<ossec_config>

  <client>
    <server>
      <address>$MANAGER</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <config-profile>$AGENT_GROUP</config-profile>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>300</events_per_second>
  </client_buffer>

  <!-- macOS Logs -->
  <localfile><log_format>syslog</log_format><location>/var/log/system.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/install.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/wifi.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/fsck_hfs.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/audit/current</location></localfile>
  <localfile><log_format>syslog</log_format><location>/Library/Logs/*.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/Library/Logs/DiagnosticReports/*.crash</location></localfile>
  <localfile><log_format>syslog</log_format><location>/Library/Ossec/logs/ossec.log</location></localfile>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>

    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes">/usr/bin</directories>
    <directories check_all="yes">/usr/sbin</directories>
    <directories check_all="yes">/bin</directories>
    <directories check_all="yes">/sbin</directories>
    <directories check_all="yes" realtime="yes">/Library/LaunchDaemons</directories>
    <directories check_all="yes" realtime="yes">/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/System/Library/LaunchDaemons</directories>
    <directories check_all="yes" realtime="yes">/System/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/Users/*/Library/LaunchAgents</directories>
    <directories check_all="yes" realtime="yes">/Library/StartupItems</directories>
    <directories check_all="yes" realtime="yes">/Library/PrivilegedHelperTools</directories>
    <directories check_all="yes" realtime="yes">/Library/Application Support</directories>
    <directories check_all="yes" realtime="yes">/Users/*/Library/Application Support</directories>
    <directories check_all="yes" realtime="yes">/private/etc/ssh</directories>
    <directories check_all="yes" realtime="yes">/Users/*/.ssh</directories>

    <!-- FIM Noise Controls -->
    <ignore>/private/var/log</ignore>
    <ignore>/private/var/folders</ignore>
    <ignore>/private/tmp</ignore>
    <ignore>/tmp</ignore>
    <ignore>/Library/Caches</ignore>
    <ignore>/Users/*/Library/Caches</ignore>
    <ignore type="sregex">.log$|.tmp$|.swp$|.pid$|.DS_Store$</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
  </rootcheck>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <localfile><log_format>full_command</log_format><command>last -20</command><frequency>3600</frequency></localfile>
  <localfile><log_format>full_command</log_format><command>netstat -an</command><frequency>3600</frequency></localfile>

  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
EOF

  fixed "SOC-ready ossec.conf written."
  warn "Review FIM noise in Wazuh Dashboard after 24-48 hours."
}

configure_launchdaemon() {
  section "6. macOS LaunchDaemon Auto-Start"

  if [[ -f /Library/LaunchDaemons/com.wazuh.agent.plist ]]; then
    launchctl load -w /Library/LaunchDaemons/com.wazuh.agent.plist || true
    fixed "Wazuh LaunchDaemon loaded."
  else
    warn "Wazuh LaunchDaemon plist not found."
  fi
}

enroll_agent_if_requested() {
  section "7. Agent Enrollment"

  if [[ "$SKIP_ENROLLMENT" == "true" ]]; then
    warn "Agent enrollment skipped by parameter."
    return
  fi

  if [[ "$NON_INTERACTIVE" != "true" ]]; then
    if ! confirm_yes "Run agent-auth enrollment now"; then
      warn "Agent enrollment skipped by user."
      return
    fi
  fi

  if [[ ! -x /Library/Ossec/bin/agent-auth ]]; then
    warn "agent-auth not found."
    return
  fi

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    /Library/Ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || warn "agent-auth failed."
  else
    read -rsp "Enrollment password if used, otherwise press Enter: " password
    echo ""
    if [[ -n "$password" ]]; then
      /Library/Ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" -P "$password" || warn "agent-auth failed."
    else
      /Library/Ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || warn "agent-auth failed."
    fi
  fi

  fixed "agent-auth executed."
}

generate_test_event() {
  section "8. Event Ingestion Validation Test"

  logger "WAZUH_READINESS_TEST macOS combined deployment test from $(hostname) at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  fixed "Generated syslog test event marker: WAZUH_READINESS_TEST"
  warn "Validate in Wazuh Dashboard by searching WAZUH_READINESS_TEST."
}

restart_validate_agent() {
  section "9. Restart and Validate Wazuh Agent"

  /Library/Ossec/bin/wazuh-control restart || true
  sleep 5
  /Library/Ossec/bin/wazuh-control status || true
  tail -n 30 /Library/Ossec/logs/ossec.log 2>/dev/null || true

  fixed "Wazuh agent restart command executed."
}

save_report() {
  section "Final Combined Deployment Report"

  local report_dir="/Library/Logs/WazuhCombinedDeploy"
  local report_file="$report_dir/wazuh_combined_deployment_report_$(date +%Y%m%d_%H%M%S).txt"

  mkdir -p "$report_dir"
  printf "%s\n" "${REPORT_LINES[@]}" > "$report_file"
  chmod 600 "$report_file"

  printf "%s\n" "${REPORT_LINES[@]}"
  echo ""
  echo -e "${CYAN}Report saved to: $report_file${NC}"
}

main() {
  require_root

  section "Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer - macOS"

  if [[ -z "$MANAGER" ]]; then
    if [[ "$NON_INTERACTIVE" == "true" ]]; then fail "--manager is required in non-interactive mode."; exit 1; fi
    MANAGER="$(ask_required "Enter Wazuh Manager IP/FQDN")"
  fi

  if [[ -z "$AGENT_NAME" ]]; then
    default_name="$(scutil --get ComputerName 2>/dev/null || hostname)"
    AGENT_NAME="$(if [[ "$NON_INTERACTIVE" == "true" ]]; then echo "$default_name"; else ask_required "Enter Agent Name" "$default_name"; fi)"
  fi

  if [[ -z "$AGENT_GROUP" ]]; then
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      AGENT_GROUP="macos,soc"
    else
      read -rp "Enter Agent Group/Profile [macos,soc]: " AGENT_GROUP
      AGENT_GROUP="${AGENT_GROUP:-macos,soc}"
    fi
  fi

  set_lab_ack
  confirm_ports
  check_password_policy
  install_agent
  write_soc_ossec_conf
  configure_launchdaemon
  enroll_agent_if_requested
  generate_test_event
  restart_validate_agent
  save_report
}

main "$@"
