#!/usr/bin/env bash
set -Eeuo pipefail

MANAGER=""
AGENT_NAME="$(hostname -s 2>/dev/null || hostname)"
AGENT_GROUP="linux,soc"
SKIP_ENROLLMENT="false"

usage(){
cat <<'EOF'
Usage:
  sudo bash scripts/invoke-soc-offline-linux.sh --manager <IP/FQDN> [options]

Options:
  --manager <IP/FQDN>       Wazuh Manager address
  --agent-name <NAME>       Agent name (default: hostname)
  --agent-group <GROUP>     Wazuh group/profile (default: linux,soc)
  --skip-enrollment         Do not run agent-auth
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager) MANAGER="$2"; shift 2 ;;
    --agent-name) AGENT_NAME="$2"; shift 2 ;;
    --agent-group) AGENT_GROUP="$2"; shift 2 ;;
    --skip-enrollment) SKIP_ENROLLMENT="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$MANAGER" ]] || { echo "--manager is required" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "Run as root/sudo" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_ROOT="$REPO_ROOT/packages/linux"
STATE_DIR="/var/log/soc-offline-deploy"
mkdir -p "$STATE_DIR"
REPORT="$STATE_DIR/deployment_$(date +%Y%m%d_%H%M%S).log"

log(){ printf '[%s] [%s] %s\n' "$(date -Is)" "$1" "$2" | tee -a "$REPORT"; }

family(){
  . /etc/os-release
  case "${ID_LIKE:-$ID}" in
    *debian*|*ubuntu*) echo debian ;;
    *rhel*|*fedora*|*centos*) echo rhel ;;
    *) case "$ID" in ubuntu|debian) echo debian;; rhel|centos|rocky|almalinux|fedora) echo rhel;; *) echo unknown;; esac ;;
  esac
}

sha(){ command -v sha256sum >/dev/null 2>&1 && sha256sum "$1" | tee -a "$REPORT" || true; }

test_tcp(){ timeout 5 bash -c "cat < /dev/null > /dev/tcp/$MANAGER/$1" >/dev/null 2>&1; }

install_wazuh(){
  if [[ -x /var/ossec/bin/wazuh-control ]]; then log OK "Wazuh Agent already installed."; return; fi
  local fam="$1"
  if [[ "$fam" == debian ]]; then
    local pkg
    pkg="$(find "$PKG_ROOT/debian" -maxdepth 1 -type f -name 'wazuh-agent*.deb' | sort -V | tail -1)"
    [[ -n "$pkg" ]] || { log FAIL "No Wazuh .deb found in $PKG_ROOT/debian"; exit 1; }
    sha "$pkg"
    WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" dpkg -i "$pkg" || {
      log FAIL "dpkg reported missing dependencies. Stage the required dependency .deb files under packages/linux/debian/prereqs and install them first."; exit 1;
    }
    log OK "Installed Wazuh Agent offline from $pkg"
  elif [[ "$fam" == rhel ]]; then
    local pkg
    pkg="$(find "$PKG_ROOT/rhel" -maxdepth 1 -type f \( -name 'wazuh-agent*.rpm' -o -name 'wazuh-agent*.x86_64.rpm' \) | sort -V | tail -1)"
    [[ -n "$pkg" ]] || { log FAIL "No Wazuh RPM found in $PKG_ROOT/rhel"; exit 1; }
    sha "$pkg"
    if command -v rpm >/dev/null 2>&1; then
      WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" rpm -Uvh "$pkg"
    else
      log FAIL "rpm command unavailable."; exit 1
    fi
    log OK "Installed Wazuh Agent offline from $pkg"
  else
    log FAIL "Unsupported Linux family."; exit 1
  fi
}

configure_wazuh(){
  local conf=/var/ossec/etc/ossec.conf
  [[ -d /var/ossec/etc ]] || { log FAIL "Wazuh config directory not found."; exit 1; }
  [[ ! -f "$conf" ]] || cp -a "$conf" "${conf}.bak_$(date +%Y%m%d_%H%M%S)"
  cat > "$conf" <<EOF
<ossec_config>
  <client>
    <server><address>$MANAGER</address><port>1514</port><protocol>tcp</protocol></server>
    <notify_time>10</notify_time><time-reconnect>60</time-reconnect><auto_restart>yes</auto_restart>
    <config-profile>$AGENT_GROUP</config-profile>
  </client>
  <client_buffer><disabled>no</disabled><queue_size>5000</queue_size><events_per_second>500</events_per_second></client_buffer>
  <localfile><log_format>syslog</log_format><location>/var/log/syslog</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/messages</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/secure</location></localfile>
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
  <localfile><log_format>journald</log_format><location>journald</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/dpkg.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/yum.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/dnf.log</location></localfile>
  <localfile><log_format>apache</log_format><location>/var/log/apache2/access.log</location></localfile>
  <localfile><log_format>apache</log_format><location>/var/log/httpd/access_log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/nginx/access.log</location></localfile>
  <syscheck>
    <disabled>no</disabled><frequency>43200</frequency><scan_on_start>yes</scan_on_start><alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes">/etc/passwd</directories>
    <directories check_all="yes" realtime="yes">/etc/shadow</directories>
    <directories check_all="yes" realtime="yes">/etc/group</directories>
    <directories check_all="yes" realtime="yes">/etc/sudoers</directories>
    <directories check_all="yes" realtime="yes">/etc/ssh</directories>
    <directories check_all="yes" realtime="yes">/etc/systemd/system</directories>
    <directories check_all="yes" realtime="yes">/etc/cron.d</directories>
    <ignore>/var/log</ignore><ignore>/tmp</ignore><ignore>/var/tmp</ignore>
  </syscheck>
  <rootcheck><disabled>no</disabled><check_files>yes</check_files><check_trojans>yes</check_trojans><check_dev>yes</check_dev><check_sys>yes</check_sys><check_pids>yes</check_pids><check_ports>yes</check_ports><check_if>yes</check_if><frequency>43200</frequency></rootcheck>
  <sca><enabled>yes</enabled><scan_on_start>yes</scan_on_start><interval>12h</interval></sca>
  <wodle name="syscollector"><disabled>no</disabled><interval>1h</interval><scan_on_start>yes</scan_on_start><hardware>yes</hardware><os>yes</os><network>yes</network><packages>yes</packages><ports all="no">yes</ports><processes>yes</processes></wodle>
</ossec_config>
EOF
  log OK "SOC-oriented ossec.conf written."
}

configure_auditd(){
  if ! command -v auditctl >/dev/null 2>&1; then
    log WARN "auditd/auditctl not installed. For an offline environment, stage its OS-specific packages under packages/linux/<family>/prereqs/."
    return
  fi
  mkdir -p /etc/audit/rules.d
  cat > /etc/audit/rules.d/99-soc-monitoring.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/systemd/system/ -p wa -k persistence
-w /etc/cron.d/ -p wa -k persistence
-w /etc/crontab -p wa -k persistence
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_exec
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system_identity
EOF
  augenrules --load >/dev/null 2>&1 || true
  systemctl enable auditd >/dev/null 2>&1 || true
  systemctl restart auditd >/dev/null 2>&1 || true
  log OK "SOC auditd rules applied."
}

configure_recovery(){
  mkdir -p /etc/systemd/system/wazuh-agent.service.d
  cat > /etc/systemd/system/wazuh-agent.service.d/recovery.conf <<'EOF'
[Service]
Restart=on-failure
RestartSec=60s
StartLimitIntervalSec=0
EOF
  systemctl daemon-reload
  systemctl enable wazuh-agent >/dev/null 2>&1 || true
  log OK "Wazuh systemd recovery configured."
}

enroll(){
  [[ "$SKIP_ENROLLMENT" == true ]] && { log WARN "Enrollment skipped."; return; }
  if [[ -x /var/ossec/bin/agent-auth ]]; then
    /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || log WARN "agent-auth returned non-zero status."
  else
    log WARN "agent-auth not found."
  fi
}

validate(){
  for p in 1514 1515; do
    if test_tcp "$p"; then log OK "Manager TCP $p reachable."; else log WARN "Manager TCP $p not reachable."; fi
  done
  systemctl restart wazuh-agent
  sleep 2
  systemctl is-active --quiet wazuh-agent && log OK "wazuh-agent service is active." || log FAIL "wazuh-agent service is not active."
  logger -t SOCOfflineDeploy 'WAZUH_READINESS_TEST offline deployment validation'
  log OK "Readiness marker written to system log."
}

FAM="$(family)"
log INFO "Offline deployment start. Family=$FAM Manager=$MANAGER Agent=$AGENT_NAME Group=$AGENT_GROUP"
install_wazuh "$FAM"
configure_wazuh
configure_auditd
configure_recovery
enroll
validate
log OK "Deployment complete. Report: $REPORT"
