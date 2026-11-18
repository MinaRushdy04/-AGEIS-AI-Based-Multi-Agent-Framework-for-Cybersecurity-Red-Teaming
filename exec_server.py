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
Auth: optional "Authorization: Bearer <SANDBOX_TOKEN>" (matches Decepticon).
"""
from __future__ import annotations

import hmac
import logging
import os
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

# Allowed first-token binaries. Extend/trim for your engagement.
WHITELIST = set(
    t.strip()
    for t in os.environ.get(
        "SANDBOX_WHITELIST",
        "nmap,gobuster,nikto,sqlmap,hydra,curl,wget,whatweb,"
        "msfconsole,msfvenom,linpeas,python3,bash,sh,cat,ls,grep,head,tail,"
        "echo,whoami,id",
    ).split(",")
    if t.strip()
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("exec_api")

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


def _first_binary(command: str) -> str:
    """The binary the command starts with (basename), for the whitelist check."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return ""
    return os.path.basename(tokens[0]) if tokens else ""


# ── Routes ──────────────────────────────────────────────────────────────────
@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/execute", response_model=ExecuteResponse)
def execute(req: ExecuteRequest, _: Annotated[None, Depends(auth)]) -> ExecuteResponse:
    binary = _first_binary(req.command)
    if binary not in WHITELIST:
        log.warning("REJECTED (not whitelisted): %s", req.command)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"command '{binary}' is not allowed by the whitelist",
        )

    timeout = req.timeout or DEFAULT_TIMEOUT
    log.info("EXEC: %s  (timeout=%ss)", req.command, timeout)
    start = time.time()
    try:
        proc = subprocess.run(
            ["bash", "-lc", req.command],
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