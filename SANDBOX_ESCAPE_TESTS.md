# Sandbox Escape Testing (Step 8)

**Project:** AEGIS — AI-Based Multi-Agent Framework for Cybersecurity Red Teaming
**Goal:** Actively prove the Kali sandbox cannot break out of its container or reach the host
/ the management network. This is the final validation of the isolation built in Step 1.
**How:** `sandbox_escape_test.sh` runs inside the sandbox, attempts each break-out vector, and
documents the result. A **positive control** (DVWA reachable) proves the "blocked" results
really mean *isolated*, not just *networking broken*.

Run:
```
docker compose cp sandbox_escape_test.sh sandbox:/tmp/sandbox_escape_test.sh
docker compose exec sandbox bash /tmp/sandbox_escape_test.sh
```

---

## Tests

| # | Test | What it proves | Expected |
|---|------|----------------|----------|
| T1 | Internet egress by name (`google.com`) | sandbox has no outbound internet | **blocked** |
| T2 | Internet egress by raw IP (`1.1.1.1`) | egress is blocked at the network, not just DNS | **blocked** |
| T3 | Reach `infra` (management-net host) | the attack plane can't touch the management plane | **unreachable** |
| T4 | `/var/run/docker.sock` present? | no Docker socket → no trivial host takeover | **absent** |
| T5 | Mount a tmpfs (needs `CAP_SYS_ADMIN`) | container is not privileged | **denied** |
| T6 | PID 1 identity | own PID namespace, not the host's | **not host init** |
| T7 | **Positive control:** DVWA reachable | the lab network actually works | **reachable (200/302)** |

A run is a success when **T1–T6 all PASS** (isolation holds) **and T7 PASSES** (control OK).

## Why the positive control matters

If every network test "failed to connect", that could mean either *good isolation* or *the
container simply has no working network at all*. T7 reaching DVWA on `sandbox-net` proves the
network is up — so T1–T3 being blocked is real isolation, not a broken lab.

---

## Results

Paste the output of the run here and record the date:

```
(paste sandbox_escape_test.sh output)
```

- **Date run:**
- **Outcome:** ☐ all PASS (isolation holds)   ☐ issue found (describe below)
- **Notes / any FAIL and the fix applied:**

> Re-run this after any change to the Docker networks, the sandbox image, or the compose file
> (it is the lab's isolation regression test).
