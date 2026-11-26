#!/usr/bin/env python3
"""
Exec API — sandbox command-execution daemon (Step 4).
-----------------------------------------------------------------------------
Implements the Decepticon sandbox-daemon contract 1:1, so the AI agents
(which follow Decepticon's contract) plug straight in:

    GET  /healthz   ->  { "status": "ok" }
    POST /execute   {  "command": "<shell command>", "timeout": 120 }
                 ->  {  "output": "<stdout+stderr>", "exit_code": 0, "truncated": false }

Runs INSIDE the Kali sandbox. Agents (on sandbox-net) call
http://sandbox:9999/execute. No internet needed at runtime.

Step-4 safety features: command whitelist, per-command timeout, output cap,
and a log line for every command (also useful later for MITRE mapping / audit).
Commands run WITHOUT a shell (shell=False on the parsed argv), so shell
metacharacters (; | && $() `) cannot chain extra commands — the whitelisted
binary is the only program that runs. Shell interpreters are not whitelisted.
RoE enforcement: every command is also checked against plan/roe.json's
machine_enforcement block (scope hosts, forbidden command patterns, forbidden
destinations) before it runs — the execution-chokepoint guard rail.
Auth: optional "Authorization: Bearer <SANDBOX_TOKEN>" (matches Decepticon).
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import re
import shlex
import subprocess
import time
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

# ── Config (all via env, with sensible defaults) ────────────────────────────
DEFAULT_TIMEOUT = int(os.environ.get("SANDBOX_DEFAULT_TIMEOUT", "120"))
MAX_OUTPUT_BYTES = int(os.environ.get("SANDBOX_MAX_OUTPUT", str(1_000_000)))  # ~1 MB
WORKSPACE = os.environ.get("SANDBOX_ROOT_DIR", "/workspace")
_TOKEN = os.environ.get("SANDBOX_TOKEN") or None  # unset = open (dev)

# Allowed binaries. The command is parsed and run WITHOUT a shell (shell=False),
# so the whitelisted binary is the ONLY program that runs. Shell interpreters
# (bash/sh/python3) are deliberately NOT whitelisted: allowing them would let
# `bash -c '<anything>'` bypass the whitelist and run arbitrary commands.
WHITELIST = set(
    t.strip()
    for t in os.environ.get(
        "SANDBOX_WHITELIST",
        "nmap,gobuster,nikto,sqlmap,hydra,curl,wget,whatweb,"
        "msfconsole,msfvenom,linpeas,cat,ls,grep,head,tail,"
        "echo,whoami,id",
    ).split(",")
    if t.strip()
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("exec_api")

# ── Rules of Engagement (machine enforcement, read from plan/roe.json) ───────
# Decepticon-style guard rail at the execution chokepoint: every command is
# checked against the machine RoE before it runs. Loaded once at startup; if the
# file is missing/invalid the daemon still runs with whitelist-only enforcement.
ROE_FILE = os.environ.get("SANDBOX_ROE_FILE", "/opt/plan/roe.json")


def _load_roe(path: str) -> dict:
    empty = {"in_scope": set(), "out_of_scope": set(),
             "forbidden_destinations": set(), "forbidden_patterns": []}
    try:
        with open(path, encoding="utf-8") as fh:
            machine = json.load(fh).get("machine_enforcement", {})
    except FileNotFoundError:
        log.warning("RoE file not found at %s — enforcing whitelist only", path)
        return empty
    except Exception as exc:  # malformed JSON, etc.
        log.warning("RoE file %s unreadable (%s) — enforcing whitelist only", path, exc)
        return empty

    def _hosts(key: str) -> set[str]:
        return {(e.get("target") or "").lower() for e in machine.get(key, []) if e.get("target")}

    patterns = []
    for pat in machine.get("forbidden_command_patterns", []):
        try:
            patterns.append(re.compile(pat, re.I))
        except re.error as exc:
            log.warning("skipping bad forbidden_command_pattern %r (%s)", pat, exc)
    roe = {
        "in_scope": _hosts("in_scope"),
        "out_of_scope": _hosts("out_of_scope"),
        "forbidden_destinations": {d.lower() for d in machine.get("forbidden_destinations", [])},
        "forbidden_patterns": patterns,
    }
    log.info("RoE loaded: in_scope=%s out_of_scope=%s forbidden_patterns=%d destinations=%d",
             sorted(roe["in_scope"]), sorted(roe["out_of_scope"]),
             len(roe["forbidden_patterns"]), len(roe["forbidden_destinations"]))
    return roe


ROE = _load_roe(ROE_FILE)
_URL_HOST_RE = re.compile(r"https?://([^/:\s\"'`]+)", re.I)


def _hosts_in_command(command: str) -> tuple[set[str], set[str]]:
    """Best-effort (all referenced hosts, URL hosts) from a shell command."""
    url_hosts = {m.group(1).lower() for m in _URL_HOST_RE.finditer(command)}
    hosts = set(url_hosts)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for tok in tokens:
        t = tok.strip().lower().rstrip("/")
        # a bare host or host:port argument (not a flag, path, or key=value)
        if t and not t.startswith("-") and "/" not in t and "=" not in t:
            host = t.split(":")[0]
            if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", host):
                hosts.add(host)
    return hosts, url_hosts


def _roe_reject_reason(command: str) -> str | None:
    """Return a rejection reason if the command violates the machine RoE, else None."""
    for pat in ROE["forbidden_patterns"]:
        if pat.search(command):
            return f"destructive command pattern {pat.pattern!r} is forbidden by RoE"
    hosts, url_hosts = _hosts_in_command(command)
    bad = hosts & (ROE["out_of_scope"] | ROE["forbidden_destinations"])
    if bad:
        return f"target(s) {sorted(bad)} are out of scope / forbidden by RoE"
    if ROE["in_scope"]:
        off = url_hosts - ROE["in_scope"]
        if off:
            return f"URL target(s) {sorted(off)} are not in the RoE scope"
    return None

app = FastAPI(title="Lab sandbox exec API", summary="Decepticon-compatible /execute")


# ── Wire models (mirror Decepticon's ExecuteRequest / ExecuteResponseModel) ──
class ExecuteRequest(BaseModel):
    command: str
    timeout: int | None = None


class ExecuteResponse(BaseModel):
    output: str
    exit_code: int | None = None
    truncated: bool = False


# ── Optional bearer-token auth ──────────────────────────────────────────────
def auth(authorization: Annotated[str | None, Header()] = None) -> None:
    if _TOKEN is None:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    if not hmac.compare_digest(authorization[len("Bearer "):], _TOKEN):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")


# ── Routes ──────────────────────────────────────────────────────────────────
@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/execute", response_model=ExecuteResponse)
def execute(req: ExecuteRequest, _: Annotated[None, Depends(auth)]) -> ExecuteResponse:
    # Parse into an argv list and run WITHOUT a shell. This is what makes the
    # whitelist sound: shell metacharacters (; | && $() `) become literal
    # arguments instead of chaining extra commands, so only argv[0] ever runs.
    try:
        argv = shlex.split(req.command)
    except ValueError as exc:
        log.warning("REJECTED (unparseable): %s | %s", exc, req.command)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"could not parse command: {exc}")
    if not argv:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty command")

    binary = os.path.basename(argv[0])
    if binary not in WHITELIST:
        log.warning("REJECTED (not whitelisted): %s", req.command)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"command '{binary}' is not allowed by the whitelist",
        )

    # RoE guard rail: scope + destructive-pattern + forbidden-destination checks
    # from plan/roe.json. Runs at the execution chokepoint, after the whitelist.
    roe_reason = _roe_reject_reason(req.command)
    if roe_reason:
        log.warning("REJECTED (RoE): %s | %s", roe_reason, req.command)
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"blocked by RoE: {roe_reason}")

    timeout = req.timeout or DEFAULT_TIMEOUT
    log.info("EXEC: %s  (timeout=%ss)", req.command, timeout)
    start = time.time()
    try:
        proc = subprocess.run(
            argv,                       # run the parsed argv directly — NO shell
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=WORKSPACE if os.path.isdir(WORKSPACE) else None,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or "") + (e.stderr or "") + f"\n[TIMEOUT after {timeout}s]"
        exit_code = None

    truncated = False
    raw = output.encode("utf-8", "ignore")
    if len(raw) > MAX_OUTPUT_BYTES:
        output = raw[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore")
        truncated = True

    log.info("DONE: exit=%s duration=%.2fs truncated=%s", exit_code, time.time() - start, truncated)
    return ExecuteResponse(output=output, exit_code=exit_code, truncated=truncated)