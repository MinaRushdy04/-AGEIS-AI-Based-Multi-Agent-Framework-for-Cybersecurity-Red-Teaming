# Tool Output Interpretation (Step 6)

**Project:** AEGIS — AI-Based Multi-Agent Framework for Cybersecurity Red Teaming
**Scope:** How raw recon-tool output is turned into structured data the agent can reason over.
**Status:** nmap / nikto / headers implemented by the agent team; gobuster added in this step. All four parsers verified against sample outputs (see §7).

---

## 1. Why this step exists

Security tools print **text for humans**. An LLM agent reasons far more reliably over
**structured fields** than over free text. Step 6 defines the raw → structured mapping for
every recon tool, so the agent receives clean facts (ports, paths, headers) instead of a wall
of console output.

## 2. The single structured format: `Finding`

Every tool's output is normalised into one shared type (`core/contracts.py`):

```python
Finding(objective_id, agent_type, target, title, detail, severity="info", data={...})
```

- `title` / `detail` — short human-readable text (for the report).
- `data` — the **machine-readable** fields the agent uses. Always includes a `source` tag
  naming the tool that produced it.

**Design principle:** wherever a tool can emit a structured format (XML/JSON), we parse that
instead of screen-scraping console text — structured output is stable across versions; text
layout is not.

---

## 3. nmap — port & service discovery

- **Command:** `nmap -sV -Pn -oX - <host>`
  - `-sV` = detect service + version on each open port.
  - `-Pn` = skip host-discovery ping (lab hosts may not answer ping).
  - `-oX -` = emit **XML** to stdout (this is what we parse).
- **Raw output (abridged XML):**
  ```xml
  <port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.7"/>
  </port>
  ```
- **Port states to understand:** `open` (service listening — the only state we keep),
  `closed` (reachable host, nothing listening), `filtered` (a firewall dropped the probe).
- **Maps to `Finding.data`:**
  ```json
  {"port":80,"protocol":"tcp","service":"http","product":"Apache httpd","version":"2.4.7","source":"nmap"}
  ```

## 4. nikto — web server scan

- **Command:** `nikto -h <url> -Format json -o <file> -ask no`
- **Raw output:** JSON with a `vulnerabilities` array; each item has `id`, `url`, `msg`.
  (A plain-text fallback parser handles older nikto builds that ignore `-Format json`.)
- **Maps to `Finding.data`:**
  ```json
  {"nikto_id":"999103","url":"/","source":"nikto"}
  ```
  with the message carried in `title`/`detail`.

## 5. header_check — HTTP security headers (curl)

- **Command:** `curl -s -D - -o /dev/null <url>` (dump response headers, discard body).
- **What it looks for:**
  - **Missing** security headers: `Content-Security-Policy`, `X-Content-Type-Options`,
    `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`.
  - **Version-leaking banners:** `Server`, `X-Powered-By`.
- **Maps to `Finding.data`:**
  ```json
  {"missing_headers":["Content-Security-Policy","X-Frame-Options"],"source":"header_check"}
  {"header":"Server","value":"Apache/2.4.7","source":"header_check"}
  ```

## 6. gobuster — content / directory discovery (added this step)

- **Command:** `gobuster dir -u <url> -w <wordlist> -q -t 20 --no-error`
  - `-q` = quiet (found paths only, no banner/progress).
  - Needs a **wordlist** (default `/usr/share/wordlists/dirb/common.txt`).
- **Raw output (text):**
  ```
  /admin   (Status: 301) [Size: 312] [--> /admin/]
  /login   (Status: 200) [Size: 1500]
  ```
  gobuster `dir` mode has no stable JSON format, so these lines are parsed with an explicit
  regex into `path`, `status`, `size`, and an optional `redirect`.
- **Maps to `Finding.data`:**
  ```json
  {"path":"/admin","status":301,"size":312,"redirect":"/admin/","source":"gobuster"}
  ```
- **Dependency note:** the sandbox image must contain a wordlist. If none is present, the
  tool raises `ToolUnavailable` and the agent simply skips the step (same pattern as the
  other tools). To enable it, stage a wordlist in the sandbox image (e.g. install the `dirb`
  or `seclists` package).

---

## 7. Verification

Each parser was exercised with a representative raw sample and checked to produce the correct
structured fields:

| Tool | Raw input sample | Result |
|------|------------------|--------|
| nmap | XML with one open (80) + one closed (22) port | only the open port kept; service/product/version correct ✅ |
| nikto | JSON `vulnerabilities` array | id + message parsed ✅ |
| headers | curl header block with a `Server` banner, no CSP | banner captured; missing headers detected ✅ |
| gobuster | 3 result lines + 1 junk line | 3 paths parsed, junk ignored; status/size/redirect correct ✅ |

End-to-end verification (running each tool live against DVWA in the lab) is done on the lab
host, since the tools and target run inside the sandbox network.
