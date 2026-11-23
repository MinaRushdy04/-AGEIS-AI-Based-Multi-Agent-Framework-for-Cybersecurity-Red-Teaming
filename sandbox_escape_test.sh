#!/usr/bin/env bash
# sandbox_escape_test.sh — Step 8: Sandbox Escape Testing
# ---------------------------------------------------------------------------
# Run INSIDE the Kali sandbox. Actively tries each escape / break-out vector
# and documents the result. "PASS" = the sandbox is isolated as intended;
# "FAIL" = a break-out path is open and must be fixed.
#
#   docker compose exec sandbox bash /tmp/sandbox_escape_test.sh
#
# A positive control (DVWA reachable) proves the FAIL-expected tests really
# mean "isolated", not just "networking is broken".
# ---------------------------------------------------------------------------
set -uo pipefail
GREEN="\033[32m"; RED="\033[31m"; RST="\033[0m"
PASS=0; FAIL=0

pass() { printf "  [ ${GREEN}PASS${RST} ] %s\n" "$1"; PASS=$((PASS+1)); }
fail() { printf "  [ ${RED}FAIL${RST} ] %s\n" "$1"; FAIL=$((FAIL+1)); }
line() { printf '%s\n' "------------------------------------------------------------"; }

echo
echo "Sandbox Escape Testing — Step 8"
echo "Container: $(hostname)   Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
line

# 1) Internet egress by name — must FAIL (isolated)
if curl -s --max-time 5 https://google.com -o /dev/null 2>/dev/null; then
  fail "T1 internet egress (google.com) — reachable, ISOLATION BROKEN"
else
  pass "T1 internet egress (google.com) blocked"
fi

# 2) Internet egress by raw IP — must FAIL (rules out DNS-only blocking)
if curl -s --max-time 5 http://1.1.1.1 -o /dev/null 2>/dev/null; then
  fail "T2 internet egress (raw IP 1.1.1.1) — reachable, ISOLATION BROKEN"
else
  pass "T2 internet egress (raw IP 1.1.1.1) blocked"
fi

# 3) Reach the management plane — must FAIL (infra is on management-net only)
code=$(curl -s --max-time 5 http://infra/ -o /dev/null -w '%{http_code}' 2>/dev/null)
if [ "$code" = "000" ] || [ -z "$code" ]; then
  pass "T3 management-plane host 'infra' unreachable"
else
  fail "T3 management-plane host 'infra' reachable (HTTP $code) — ISOLATION BROKEN"
fi

# 4) Docker socket — must be ABSENT (its presence = trivial host takeover)
if [ -S /var/run/docker.sock ]; then
  fail "T4 /var/run/docker.sock is MOUNTED — host escape possible"
else
  pass "T4 docker socket not present"
fi

# 5) Not privileged — mounting a new filesystem needs CAP_SYS_ADMIN; must FAIL
if mount -t tmpfs tmpfs /tmp/_escape_caps_test 2>/dev/null; then
  umount /tmp/_escape_caps_test 2>/dev/null; rmdir /tmp/_escape_caps_test 2>/dev/null
  fail "T5 able to mount tmpfs (CAP_SYS_ADMIN) — container is over-privileged"
else
  pass "T5 cannot mount (no CAP_SYS_ADMIN / not privileged)"
fi

# 6) Own PID namespace — PID 1 should be our process, not the host init
p1=$(cat /proc/1/comm 2>/dev/null)
if [ "$p1" = "systemd" ] || [ "$p1" = "init" ]; then
  fail "T6 PID 1 is '$p1' — sharing the HOST pid namespace"
else
  pass "T6 isolated pid namespace (PID 1 = '$p1')"
fi

# 7) POSITIVE CONTROL — DVWA must be REACHABLE (proves tests above are meaningful)
code=$(curl -s --max-time 5 http://dvwa/ -o /dev/null -w '%{http_code}' 2>/dev/null)
if [ "$code" = "200" ] || [ "$code" = "302" ]; then
  pass "T7 positive control: DVWA reachable (HTTP $code)"
else
  fail "T7 positive control: DVWA NOT reachable (HTTP $code) — results above are inconclusive"
fi

line
echo "Summary:  PASS=$PASS  FAIL=$FAIL"
line
if [ "$FAIL" -eq 0 ]; then
  printf "${GREEN}SANDBOX ISOLATION HOLDS${RST} — no escape path found; positive control OK.\n"
  exit 0
else
  printf "${RED}ISOLATION ISSUE${RST} — %s test(s) failed. Review the FAIL rows.\n" "$FAIL"
  exit 1
fi
