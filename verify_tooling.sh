#!/usr/bin/env bash
# verify_tooling.sh — Step 2 "Definition of Done" checker
# ---------------------------------------------------------------------------
# Run INSIDE the Kali sandbox container. No internet access required.
# Mirrors the Decepticon philosophy: a `doctor`-style check that proves,
# phase by phase (recon -> scan -> exploit -> post-exploit), that the attack
# toolchain is installed AND functional.
#
# Usage:
#   chmod +x verify_tooling.sh
#   ./verify_tooling.sh
#   # or, from the host:
#   docker compose cp verify_tooling.sh sandbox:/tmp/verify_tooling.sh
#   docker compose exec sandbox bash /tmp/verify_tooling.sh
#
# Exit code 0  = every REQUIRED tool passed  -> Step 2 is DONE.
# Exit code !0 = at least one required tool failed.
# ---------------------------------------------------------------------------
set -uo pipefail

# LinPEAS / WinPEAS are NOT apt packages. Because sandbox-net is isolated,
# they must be STAGED into the image at build time. Point this at where you
# placed them.
PEASS_DIR="${PEASS_DIR:-/opt/peass}"

PASS=0; FAIL=0; WARN=0
GREEN="\033[32m"; RED="\033[31m"; YEL="\033[33m"; RST="\033[0m"
line() { printf '%s\n' "------------------------------------------------------------"; }

# check <label> <required|optional> <command to run as a functional probe...>
check() {
  local label="$1"; local req="$2"; shift 2
  if "$@" >/dev/null 2>&1; then
    printf "  [ ${GREEN}PASS${RST} ] %-12s\n" "$label"; PASS=$((PASS+1))
  elif [ "$req" = "required" ]; then
    printf "  [ ${RED}FAIL${RST} ] %-12s (required, not runnable)\n" "$label"; FAIL=$((FAIL+1))
  else
    printf "  [ ${YEL}WARN${RST} ] %-12s (optional, missing)\n" "$label"; WARN=$((WARN+1))
  fi
}

# check_file <label> <required|optional> <path>  (for staged, non-apt tools)
check_file() {
  local label="$1"; local req="$2"; local path="$3"
  if [ -s "$path" ]; then
    printf "  [ ${GREEN}PASS${RST} ] %-12s %s\n" "$label" "$path"; PASS=$((PASS+1))
  elif [ "$req" = "required" ]; then
    printf "  [ ${RED}FAIL${RST} ] %-12s missing: %s\n" "$label" "$path"; FAIL=$((FAIL+1))
  else
    printf "  [ ${YEL}WARN${RST} ] %-12s missing (optional): %s\n" "$label" "$path"; WARN=$((WARN+1))
  fi
}

echo
echo "Decepticon-style Toolchain Verifier — Step 2 Definition of Done"
echo "Container: $(hostname)   Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
line

echo "Phase 1 — Reconnaissance"
check "nmap"        required nmap --version
check "dig"         optional dig -v
check "masscan"     optional masscan --version
line

echo "Phase 2 — Vulnerability Scanning"
check "gobuster"    required command -v gobuster
check "nikto"       required nikto -Version
check "whatweb"     optional whatweb --version
check "feroxbuster" optional feroxbuster --version
line

echo "Phase 3 — Exploitation"
check "msfconsole"  required command -v msfconsole
check "msfvenom"    required command -v msfvenom
check "sqlmap"      required sqlmap --version
check "hydra"       optional command -v hydra
line

echo "Phase 4 — Post-Exploitation (staged scripts, not apt)"
check_file "linpeas"  required "$PEASS_DIR/linpeas.sh"
check_file "winpeas"  required "$PEASS_DIR/winPEASx64.exe"
check "python3"     optional python3 --version
line

echo "Summary:  PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
line
if [ "$FAIL" -eq 0 ]; then
  printf "${GREEN}Step 2 Definition of Done: SATISFIED${RST} — all required tools present & runnable.\n"
  exit 0
else
  printf "${RED}Step 2 NOT complete:${RST} %s required tool(s) failed — see FAIL rows.\n" "$FAIL"
  exit 1
fi