#!/usr/bin/env bash
# =============================================================================
# Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer - Linux
#
# This single script:
#   - Takes Wazuh Manager IP/FQDN, Agent Name, Agent Group
#   - Checks lab/production pilot acknowledgement
#   - Checks TCP 1514, 1515, optional 55000
#   - Checks enrollment password handling
#   - Installs Wazuh Agent if missing
#   - Writes SOC-ready ossec.conf
#   - Adds FIM noise-control entries
#   - Installs/enables auditd
#   - Applies Linux SOC auditd rules
#   - Configures systemd auto-start and auto-recovery
#   - Optionally enrolls the agent
#   - Generates test event for Wazuh Dashboard validation
#   - Restarts and validates wazuh-agent
#   - Saves report
#
# Usage:
#   sudo bash invoke-wazuh-combined-linux.sh
#   sudo bash invoke-wazuh-combined-linux.sh --manager 10.10.10.50 --agent-name linux-web-01 --agent-group linux,soc,web
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
  sudo bash invoke-wazuh-combined-linux.sh [options]

Options:
  --manager <IP_OR_FQDN>       Wazuh Manager IP or FQDN
  --agent-name <NAME>          Agent name
  --agent-group <GROUP>        Agent group/profile
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

detect_family() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID_LIKE:-$ID}" in
      *debian*|*ubuntu*) echo "debian" ;;
      *rhel*|*fedora*|*centos*) echo "rhel" ;;
      *)
        case "$ID" in
          ubuntu|debian) echo "debian" ;;
          rhel|centos|rocky|almalinux|fedora) echo "rhel" ;;
          *) echo "unknown" ;;
        esac
        ;;
    esac
  else
    echo "unknown"
  fi
}

test_tcp() {
  local host="$1"
  local port="$2"

  if command -v nc >/dev/null 2>&1; then
    nc -vz -w 5 "$host" "$port" >/dev/null 2>&1
  else
    timeout 5 bash -c "cat < /dev/null > /dev/tcp/$host/$port" >/dev/null 2>&1
  fi
}

install_package() {
  local pkg="$1"
  local family="$2"

  if [[ "$family" == "debian" ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
  elif [[ "$family" == "rhel" ]]; then
    if command -v dnf >/dev/null 2>&1; then dnf install -y "$pkg"; else yum install -y "$pkg"; fi
  else
    warn "Unknown OS family. Cannot auto-install package: $pkg"
    return 1
  fi
}

set_lab_ack() {
  section "1. Lab Test / Production Pilot Acknowledgement"

  local marker_dir="/var/lib/wazuh-combined-deploy"
  local marker_file="$marker_dir/lab_test_acknowledged.txt"

  if [[ -f "$marker_file" ]]; then
    ok "Lab acknowledgement marker exists: $marker_file"
    return
  fi

  if confirm_yes "Confirm this script/configuration has been tested in a lab or approved for production pilot"; then
    mkdir -p "$marker_dir"
    echo "Acknowledged by $(whoami) on $(date -Is)" > "$marker_file"
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

check_enrollment_password_policy() {
  section "3. Enrollment Password Handling Policy"

  local found="false"

  while IFS= read -r -d '' file; do
    found="true"
    warn "Possible plaintext enrollment password file found: $file"
    if confirm_yes "Remove this file? $file"; then
      shred -u "$file" 2>/dev/null || rm -f "$file"
      fixed "Removed possible plaintext password file: $file"
    fi
  done < <(find /tmp /root /home -maxdepth 3 -type f \( -iname "*wazuh*password*.txt" -o -iname "*enrollment*password*.txt" \) -print0 2>/dev/null)

  [[ "$found" == "false" ]] && ok "No obvious plaintext enrollment password files found."

  if [[ -n "${WAZUH_ENROLLMENT_PASSWORD:-}" ]]; then
    warn "WAZUH_ENROLLMENT_PASSWORD env variable is set. Avoid long-lived environment secrets."
  fi

  ok "Recommended password policy: runtime prompt only; do not store secrets in scripts/files."
}

install_prereqs() {
  section "4. Installing Prerequisites"

  local family="$1"

  if [[ "$family" == "debian" ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg apt-transport-https lsb-release netcat-openbsd auditd audispd-plugins
  elif [[ "$family" == "rhel" ]]; then
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y curl gnupg nc audit audit-libs
    else
      yum install -y curl gnupg nc audit audit-libs
    fi
  else
    warn "Unknown Linux family. Install curl, gnupg, nc, and auditd manually if needed."
  fi

  fixed "Prerequisites checked/installed."
}

install_wazuh_agent() {
  section "5. Wazuh Agent Installation"

  local family="$1"

  if [[ -x /var/ossec/bin/wazuh-control || -x /var/ossec/bin/agent-auth ]]; then
    ok "Wazuh Agent already installed."
    return
  fi

  if [[ "$family" == "debian" ]]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    apt-get update -y
    WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" apt-get install -y wazuh-agent
  elif [[ "$family" == "rhel" ]]; then
    cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    if command -v dnf >/dev/null 2>&1; then
      WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" dnf install -y wazuh-agent
    else
      WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" yum install -y wazuh-agent
    fi
  else
    fail "Unsupported Linux family for auto install."
    exit 1
  fi

  fixed "Wazuh Agent installed."
}

write_soc_ossec_conf() {
  section "6. Writing SOC-Ready ossec.conf"

  local conf="/var/ossec/etc/ossec.conf"

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
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Core Linux Logs -->
  <localfile><log_format>syslog</log_format><location>/var/log/syslog</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/kern.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/daemon.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/messages</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/secure</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/cron</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/maillog</location></localfile>

  <!-- auditd and journald -->
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
  <localfile><log_format>journald</log_format><location>journald</location></localfile>

  <!-- Package Management -->
  <localfile><log_format>syslog</log_format><location>/var/log/dpkg.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/apt/history.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/yum.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/dnf.log</location></localfile>

  <!-- Web Server Logs -->
  <localfile><log_format>apache</log_format><location>/var/log/apache2/access.log</location></localfile>
  <localfile><log_format>apache</log_format><location>/var/log/apache2/error.log</location></localfile>
  <localfile><log_format>apache</log_format><location>/var/log/httpd/access_log</location></localfile>
  <localfile><log_format>apache</log_format><location>/var/log/httpd/error_log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/nginx/access.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/nginx/error.log</location></localfile>

  <!-- Database Logs -->
  <localfile><log_format>syslog</log_format><location>/var/log/mysql/error.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/mariadb/mariadb.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/postgresql/postgresql-*.log</location></localfile>

  <!-- Docker/Container Logs -->
  <localfile><log_format>syslog</log_format><location>/var/log/docker.log</location></localfile>
  <localfile><log_format>json</log_format><location>/var/lib/docker/containers/*/*-json.log</location></localfile>

  <!-- Firewall Logs -->
  <localfile><log_format>syslog</log_format><location>/var/log/ufw.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/firewalld</location></localfile>

  <!-- Wazuh Internal Log -->
  <localfile><log_format>syslog</log_format><location>/var/ossec/logs/ossec.log</location></localfile>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>

    <directories check_all="yes" realtime="yes">/etc/passwd</directories>
    <directories check_all="yes" realtime="yes">/etc/shadow</directories>
    <directories check_all="yes" realtime="yes">/etc/group</directories>
    <directories check_all="yes" realtime="yes">/etc/gshadow</directories>
    <directories check_all="yes" realtime="yes">/etc/sudoers</directories>
    <directories check_all="yes" realtime="yes">/etc/sudoers.d</directories>
    <directories check_all="yes" realtime="yes">/etc/ssh</directories>
    <directories check_all="yes" realtime="yes">/root/.ssh</directories>
    <directories check_all="yes" realtime="yes">/etc/crontab</directories>
    <directories check_all="yes" realtime="yes">/etc/cron.d</directories>
    <directories check_all="yes" realtime="yes">/etc/cron.daily</directories>
    <directories check_all="yes" realtime="yes">/etc/cron.hourly</directories>
    <directories check_all="yes" realtime="yes">/etc/cron.weekly</directories>
    <directories check_all="yes" realtime="yes">/etc/systemd/system</directories>
    <directories check_all="yes" realtime="yes">/lib/systemd/system</directories>
    <directories check_all="yes" realtime="yes">/usr/lib/systemd/system</directories>
    <directories check_all="yes">/bin</directories>
    <directories check_all="yes">/sbin</directories>
    <directories check_all="yes">/usr/bin</directories>
    <directories check_all="yes">/usr/sbin</directories>
    <directories check_all="yes">/boot</directories>
    <directories check_all="yes" realtime="yes">/var/www</directories>

    <!-- FIM Noise Controls -->
    <ignore>/var/log</ignore>
    <ignore>/var/cache</ignore>
    <ignore>/var/tmp</ignore>
    <ignore>/tmp</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$|.pid$</ignore>
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

  <localfile><log_format>full_command</log_format><command>last -n 20</command><frequency>3600</frequency></localfile>
  <localfile><log_format>full_command</log_format><command>ss -tulpn</command><frequency>3600</frequency></localfile>

  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
EOF

  fixed "SOC-ready ossec.conf written."
  warn "Review FIM noise in Wazuh Dashboard after 24-48 hours."
}

configure_auditd() {
  section "7. auditd Installation and SOC Rules"

  local family="$1"

  if ! command -v auditctl >/dev/null 2>&1; then
    warn "auditctl not found. Installing auditd."
    if [[ "$family" == "debian" ]]; then
      install_package "auditd" "$family"
      install_package "audispd-plugins" "$family" || true
    elif [[ "$family" == "rhel" ]]; then
      install_package "audit" "$family"
      install_package "audit-libs" "$family" || true
    fi
  else
    ok "auditctl found."
  fi

  systemctl enable auditd || true
  systemctl start auditd || true

  mkdir -p /etc/audit/rules.d

  cat > /etc/audit/rules.d/soc.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege

-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k root_ssh
-w /home/ -p wa -k user_home

-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron

-w /etc/systemd/system/ -p wa -k systemd
-w /lib/systemd/system/ -p wa -k systemd
-w /usr/lib/systemd/system/ -p wa -k systemd

-w /var/log/ -p wa -k log_tampering
-w /var/log/audit/ -p wa -k audit_log_tampering

-a always,exit -F arch=b64 -S execve -F euid=0 -k root_command
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_command

-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_module
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_module
EOF

  if command -v augenrules >/dev/null 2>&1; then augenrules --load || warn "augenrules failed. Check syntax."; fi

  fixed "auditd installed/enabled and SOC audit rules applied."
}

configure_systemd_recovery() {
  section "8. Wazuh Agent Auto-Start and Auto-Recovery"

  systemctl enable wazuh-agent

  mkdir -p /etc/systemd/system/wazuh-agent.service.d

  cat > /etc/systemd/system/wazuh-agent.service.d/override.conf <<'EOF'
[Service]
Restart=always
RestartSec=10
StartLimitIntervalSec=0
EOF

  systemctl daemon-reload
  fixed "systemd auto-recovery override configured."
}

enroll_agent_if_requested() {
  section "9. Agent Enrollment"

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

  if [[ ! -x /var/ossec/bin/agent-auth ]]; then
    warn "agent-auth not found."
    return
  fi

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || warn "agent-auth failed."
  else
    read -rsp "Enrollment password if used, otherwise press Enter: " password
    echo ""
    if [[ -n "$password" ]]; then
      /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" -P "$password" || warn "agent-auth failed."
    else
      /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || warn "agent-auth failed."
    fi
  fi

  fixed "agent-auth executed."
}

generate_test_event() {
  section "10. Event Ingestion Validation Test"

  if command -v logger >/dev/null 2>&1; then
    logger "WAZUH_READINESS_TEST Linux combined deployment test from $(hostname) at $(date -Is)"
    fixed "Generated syslog test event marker: WAZUH_READINESS_TEST"
    warn "Validate in Wazuh Dashboard by searching WAZUH_READINESS_TEST."
  else
    warn "logger command not found."
  fi
}

restart_validate_agent() {
  section "11. Restart and Validate Wazuh Agent"

  systemctl restart wazuh-agent
  sleep 5

  if systemctl is-active --quiet wazuh-agent; then
    fixed "wazuh-agent is active."
  else
    warn "wazuh-agent is not active. Review /var/ossec/logs/ossec.log"
  fi

  tail -n 30 /var/ossec/logs/ossec.log 2>/dev/null || true
}

save_report() {
  section "Final Combined Deployment Report"

  local report_dir="/var/log/wazuh-combined-deploy"
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

  section "Combined Wazuh Agent Auto Deploy + Security Recommendation Enforcer - Linux"

  local family
  family="$(detect_family)"
  ok "Detected Linux family: $family"

  if [[ -z "$MANAGER" ]]; then
    if [[ "$NON_INTERACTIVE" == "true" ]]; then fail "--manager is required in non-interactive mode."; exit 1; fi
    MANAGER="$(ask_required "Enter Wazuh Manager IP/FQDN")"
  fi

  if [[ -z "$AGENT_NAME" ]]; then
    AGENT_NAME="$(if [[ "$NON_INTERACTIVE" == "true" ]]; then hostname; else ask_required "Enter Agent Name" "$(hostname)"; fi)"
  fi

  if [[ -z "$AGENT_GROUP" ]]; then
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      AGENT_GROUP="linux,soc"
    else
      read -rp "Enter Agent Group/Profile [linux,soc]: " AGENT_GROUP
      AGENT_GROUP="${AGENT_GROUP:-linux,soc}"
    fi
  fi

  set_lab_ack
  confirm_ports
  check_enrollment_password_policy
  install_prereqs "$family"
  install_wazuh_agent "$family"
  write_soc_ossec_conf
  configure_auditd "$family"
  configure_systemd_recovery
  enroll_agent_if_requested
  generate_test_event
  restart_validate_agent
  save_report
}

main "$@"
