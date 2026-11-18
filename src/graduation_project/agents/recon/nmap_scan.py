"""nmap wrapper: port/service scan, parsed into structured facts.

Shells out to the system `nmap` binary (expected to be present in the
sandbox image, see docker/sandbox) rather than depending on a Python
binding, so the agent needs no extra dependency beyond the CLI tool itself.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


class ToolUnavailable(Exception):
    """Raised when the required CLI tool is not installed."""


@dataclass
class PortFinding:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extrainfo: str

    def as_text(self) -> str:
        bits = [self.service or "unknown"]
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(bits)


def run_nmap_scan(host: str, timeout: int = 180) -> list[PortFinding]:
    """Run `nmap -sV` against `host` and return parsed open-port facts.

    `host` must be a bare hostname/IP (no scheme) — the caller is
    responsible for scope enforcement before this is invoked.
    """
    if shutil.which("nmap") is None:
        raise ToolUnavailable("nmap is not installed on this host")

    cmd = ["nmap", "-sV", "-Pn", "-oX", "-", host]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"nmap timed out after {timeout}s") from exc

    if not proc.stdout.strip():
        detail = proc.stderr.strip() or f"nmap exited {proc.returncode} with no output"
        raise RuntimeError(detail)

    return _parse_nmap_xml(proc.stdout)


def _parse_nmap_xml(xml_text: str) -> list[PortFinding]:
    findings: list[PortFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"could not parse nmap XML output: {exc}") from exc

    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            service_el = port_el.find("service")
            findings.append(
                PortFinding(
                    port=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", ""),
                    state=state,
                    service=service_el.get("name", "") if service_el is not None else "",
                    product=service_el.get("product", "") if service_el is not None else "",
                    version=service_el.get("version", "") if service_el is not None else "",
                    extrainfo=service_el.get("extrainfo", "") if service_el is not None else "",
                )
            )
    return findings
