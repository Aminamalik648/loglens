"""
LogLens – Lambda handler  (v4 — Windows Security event support)
Single function, zero external dependencies.

New in v4:
 - Auto-detects Linux auth.log vs Windows Security event export
 - Windows detections: 4625 brute force, 4624 success-after-failure,
   4720 account creation, 1102 audit log cleared
 - New MITRE entries: T1110, T1021.001, T1136.001, T1070.001
 - source_type field returned in API response
 - "Load Linux sample" / "Load Windows sample" buttons in UI
 - Detected log type shown as badge after analysis
"""
import json
import re
from collections import defaultdict

MAX_LOG_BYTES = 500 * 1024

# ── Linux regex patterns ───────────────────────────────────────────────────────
RE_TIMESTAMP   = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
RE_FAILED      = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
RE_INVALID_USER= re.compile(r"Invalid user (\S+) from ([\d.]+)")
RE_SUCCESS     = re.compile(r"Accepted password for (\S+) from ([\d.]+)")
RE_SUDO_FAIL   = re.compile(
    r"sudo[:\s].*?(?:authentication failure|incorrect password attempts|FAILED su)|"
    r"pam_unix\(sudo:auth\):.*authentication failure",
    re.IGNORECASE,
)
RE_SUDO_USER   = re.compile(r"\bsudo:\s+(\S+)\s+:")

# ── Windows: key:value block parser ───────────────────────────────────────────
# Matches "KeyName  : value" or "KeyName: value" (Format-List style)
RE_KV = re.compile(r"^([A-Za-z][A-Za-z0-9 _]*?)\s*:\s*(.*)$")

# Canonical field names — all comparisons lower-cased
# Maps raw key variants → canonical name
WIN_KEY_ALIASES = {
    "id":                     "event_id",
    "eventid":                "event_id",
    "event id":               "event_id",
    "timecreated":            "time",
    "time created":           "time",
    "time":                   "time",
    "targetusername":         "username",
    "account name":           "username",
    "subjectusername":        "subject_username",
    "ipaddress":              "ip",
    "source network address": "ip",
    "workstationname":        "workstation",
    "logontype":              "logon_type",
    "logon type":             "logon_type",
    "message":                "message",
}

# ── MITRE ATT&CK definitions ───────────────────────────────────────────────────
MITRE = {
    "T1110": {
        "id":   "T1110",
        "name": "Brute Force",
        "url":  "https://attack.mitre.org/techniques/T1110/",
        "why":  "Repeated authentication failures from a single source indicate "
                "automated credential-guessing against Windows accounts.",
    },
    "T1110.001": {
        "id":   "T1110.001",
        "name": "Brute Force: Password Guessing",
        "url":  "https://attack.mitre.org/techniques/T1110/001/",
        "why":  "Repeated password guessing is a common initial-access technique "
                "used to compromise accounts without prior credential knowledge.",
    },
    "T1078": {
        "id":   "T1078",
        "name": "Valid Accounts",
        "url":  "https://attack.mitre.org/techniques/T1078/",
        "why":  "A successful login after brute-forcing suggests the attacker "
                "obtained working credentials and may now have persistent access.",
    },
    "T1078.003": {
        "id":   "T1078.003",
        "name": "Valid Accounts: Local Accounts",
        "url":  "https://attack.mitre.org/techniques/T1078/003/",
        "why":  "Targeting the root account directly indicates the adversary seeks "
                "full system control via a known local privileged account.",
    },
    "T1021.001": {
        "id":   "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "url":  "https://attack.mitre.org/techniques/T1021/001/",
        "why":  "Logon Type 10 (RemoteInteractive) indicates an RDP session, "
                "a common lateral-movement path used after credential compromise.",
    },
    "T1021.004": {
        "id":   "T1021.004",
        "name": "Remote Services: SSH",
        "url":  "https://attack.mitre.org/techniques/T1021/004/",
        "why":  "SSH is a standard lateral-movement vector; successful SSH logins "
                "from suspicious IPs indicate possible unauthorised remote access.",
    },
    "T1136.001": {
        "id":   "T1136.001",
        "name": "Create Account: Local Account",
        "url":  "https://attack.mitre.org/techniques/T1136/001/",
        "why":  "Unexpected local account creation is a persistence technique "
                "used to maintain access after initial compromise.",
    },
    "T1070.001": {
        "id":   "T1070.001",
        "name": "Indicator Removal: Clear Windows Event Logs",
        "url":  "https://attack.mitre.org/techniques/T1070/001/",
        "why":  "Clearing the Security audit log destroys forensic evidence and "
                "is a strong indicator of deliberate anti-forensic activity.",
    },
    "T1548.003": {
        "id":   "T1548.003",
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "url":  "https://attack.mitre.org/techniques/T1548/003/",
        "why":  "Failed sudo attempts may indicate an attacker testing for "
                "privilege-escalation paths on a compromised account.",
    },
}

# ── Sample logs ────────────────────────────────────────────────────────────────
LINUX_SAMPLE = """\
Jun 15 03:21:14 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 54321 ssh2
Jun 15 03:21:19 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 54322 ssh2
Jun 15 03:21:25 webserver sshd[1234]: Failed password for admin from 192.168.1.105 port 54323 ssh2
Jun 15 03:21:31 webserver sshd[1234]: Invalid user ubuntu from 192.168.1.105 port 54324
Jun 15 03:21:31 webserver sshd[1234]: Failed password for invalid user ubuntu from 192.168.1.105 port 54324 ssh2
Jun 15 03:21:37 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 54325 ssh2
Jun 15 03:21:43 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 54326 ssh2
Jun 15 03:21:49 webserver sshd[1234]: Accepted password for root from 192.168.1.105 port 54327 ssh2
Jun 15 03:22:01 webserver sshd[2345]: Failed password for deploy from 10.0.0.88 port 41000 ssh2
Jun 15 03:22:07 webserver sshd[2345]: Failed password for deploy from 10.0.0.88 port 41001 ssh2
Jun 15 03:22:13 webserver sshd[2345]: Failed password for deploy from 10.0.0.88 port 41002 ssh2
Jun 15 03:22:19 webserver sshd[2345]: Failed password for deploy from 10.0.0.88 port 41003 ssh2
Jun 15 03:22:25 webserver sshd[2345]: Failed password for deploy from 10.0.0.88 port 41004 ssh2
Jun 15 03:25:01 webserver sshd[5678]: Failed password for root from 10.10.10.50 port 33001 ssh2
Jun 15 03:25:07 webserver sshd[5678]: Failed password for root from 10.10.10.50 port 33002 ssh2
Jun 15 03:25:13 webserver sshd[5678]: Failed password for root from 10.10.10.50 port 33003 ssh2
Jun 15 03:25:19 webserver sshd[5678]: Failed password for root from 10.10.10.50 port 33004 ssh2
Jun 15 03:25:25 webserver sshd[5678]: Failed password for root from 10.10.10.50 port 33005 ssh2
Jun 15 03:24:00 webserver sshd[4567]: Invalid user oracle from 203.0.113.7 port 9000
Jun 15 03:24:00 webserver sshd[4567]: Failed password for invalid user oracle from 203.0.113.7 port 9000 ssh2
Jun 15 03:24:06 webserver sshd[4567]: Invalid user oracle from 203.0.113.7 port 9001
Jun 15 03:24:06 webserver sshd[4567]: Failed password for invalid user oracle from 203.0.113.7 port 9001 ssh2
Jun 15 03:24:12 webserver sshd[4567]: Invalid user oracle from 203.0.113.7 port 9002
Jun 15 03:24:12 webserver sshd[4567]: Failed password for invalid user oracle from 203.0.113.7 port 9002 ssh2
Jun 15 03:24:18 webserver sshd[4567]: Invalid user oracle from 203.0.113.7 port 9003
Jun 15 03:24:18 webserver sshd[4567]: Failed password for invalid user oracle from 203.0.113.7 port 9003 ssh2
Jun 15 03:24:24 webserver sshd[4567]: Invalid user oracle from 203.0.113.7 port 9004
Jun 15 03:24:24 webserver sshd[4567]: Failed password for invalid user oracle from 203.0.113.7 port 9004 ssh2
Jun 15 03:26:00 webserver sudo: www-data : authentication failure ; logname= uid=33 euid=0 tty=/dev/pts/0 ruser=www-data rhost=  user=root
Jun 15 03:26:15 webserver sudo: www-data : authentication failure ; logname= uid=33 euid=0 tty=/dev/pts/0 ruser=www-data rhost=  user=root
Jun 15 03:26:30 webserver sudo: www-data : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash
Jun 15 03:26:45 webserver sudo: jenkins : authentication failure ; logname= uid=113 euid=0 tty=/dev/pts/1 ruser=jenkins rhost=  user=root
Jun 15 03:27:00 webserver sudo: jenkins : authentication failure ; logname= uid=113 euid=0 tty=/dev/pts/1 ruser=jenkins rhost=  user=root
Jun 15 03:27:15 webserver sudo: jenkins : authentication failure ; logname= uid=113 euid=0 tty=/dev/pts/1 ruser=jenkins rhost=  user=root
Jun 15 03:27:30 webserver sudo: jenkins : authentication failure ; logname= uid=113 euid=0 tty=/dev/pts/1 ruser=jenkins rhost=  user=root
Jun 15 03:27:45 webserver sudo: jenkins : authentication failure ; logname= uid=113 euid=0 tty=/dev/pts/1 ruser=jenkins rhost=  user=root
"""

# Windows sample — reserved IPs (203.0.113.x, 198.51.100.x), made-up usernames
# Covers: 4625 brute force, 4624 after failures, 4720 account creation, 1102 log clear
WINDOWS_SAMPLE = """\
TimeCreated  : 2024-06-15 03:21:01
Id           : 4625
TargetUserName : jdavis
IpAddress    : 203.0.113.55
LogonType    : 3

TimeCreated  : 2024-06-15 03:21:07
Id           : 4625
TargetUserName : jdavis
IpAddress    : 203.0.113.55
LogonType    : 3

TimeCreated  : 2024-06-15 03:21:13
Id           : 4625
TargetUserName : administrator
IpAddress    : 203.0.113.55
LogonType    : 3

TimeCreated  : 2024-06-15 03:21:19
Id           : 4625
TargetUserName : jdavis
IpAddress    : 203.0.113.55
LogonType    : 3

TimeCreated  : 2024-06-15 03:21:25
Id           : 4625
TargetUserName : jdavis
IpAddress    : 203.0.113.55
LogonType    : 3

TimeCreated  : 2024-06-15 03:21:31
Id           : 4624
TargetUserName : jdavis
IpAddress    : 203.0.113.55
LogonType    : 10

TimeCreated  : 2024-06-15 03:22:00
Id           : 4625
TargetUserName : svc_backup
IpAddress    : 198.51.100.12
LogonType    : 3

TimeCreated  : 2024-06-15 03:22:06
Id           : 4625
TargetUserName : svc_backup
IpAddress    : 198.51.100.12
LogonType    : 3

TimeCreated  : 2024-06-15 03:22:12
Id           : 4625
TargetUserName : svc_backup
IpAddress    : 198.51.100.12
LogonType    : 3

TimeCreated  : 2024-06-15 03:22:18
Id           : 4625
TargetUserName : svc_backup
IpAddress    : 198.51.100.12
LogonType    : 3

TimeCreated  : 2024-06-15 03:22:24
Id           : 4625
TargetUserName : svc_backup
IpAddress    : 198.51.100.12
LogonType    : 3

TimeCreated  : 2024-06-15 03:23:00
Id           : 4720
TargetUserName : helpdesk_tmp
SubjectUserName : jdavis

TimeCreated  : 2024-06-15 03:24:00
Id           : 1102
SubjectUserName : jdavis
"""


# ── Detection: auto-detect log type ───────────────────────────────────────────

def detect_type(text: str) -> str:
    """Return 'windows' if text looks like Windows Security event output, else 'linux'."""
    # Windows exports always have EventID/Id and TimeCreated fields
    t = text[:4096]  # only scan the top of the file
    has_event_id   = bool(re.search(r"^\s*(?:Id|EventID|Event ID)\s*:", t, re.MULTILINE | re.IGNORECASE))
    has_timecreated= bool(re.search(r"^\s*(?:TimeCreated|Time Created)\s*:", t, re.MULTILINE | re.IGNORECASE))
    return "windows" if (has_event_id and has_timecreated) else "linux"


# ── Windows parser ─────────────────────────────────────────────────────────────

def _parse_win_blocks(text: str) -> list[dict]:
    """
    Split text into per-event blocks separated by blank lines or '---' dividers.
    Each block is parsed as key:value pairs.
    Returns a list of dicts with canonical field names.
    All values are stripped strings — never executed or fetched.
    """
    # Normalise dividers so we can split on double-newline uniformly
    normalised = re.sub(r"\n-{3,}\n", "\n\n", text)
    raw_blocks = re.split(r"\n{2,}", normalised.strip())

    events = []
    for block in raw_blocks:
        ev: dict = {}
        for line in block.splitlines():
            m = RE_KV.match(line.strip())
            if not m:
                continue
            raw_key = m.group(1).strip()
            value   = m.group(2).strip()
            canon   = WIN_KEY_ALIASES.get(raw_key.lower())
            if canon and value:
                # Only keep the first occurrence of each canonical key per block
                ev.setdefault(canon, value)
        if "event_id" in ev:
            events.append(ev)
    return events


def analyse_windows(text: str) -> list[dict]:
    """Analyse Windows Security event blocks and return finding rows."""
    events = _parse_win_blocks(text)

    # Per-IP 4625 tracking
    fail_count:  dict[str, int] = defaultdict(int)
    fail_users:  dict[str, set] = defaultdict(set)
    fail_first:  dict[str, str] = {}
    fail_last:   dict[str, str] = {}
    fail_order:  list[str] = []

    # Per-IP 4624 (success) after failure tracking
    success_events: list[dict] = []   # raw event dicts for post-processing

    # 4720 account creation events (any occurrence is a finding)
    acct_create_events: list[dict] = []

    # 1102 audit log cleared (any occurrence = HIGH)
    log_clear_events: list[dict] = []

    def _reg_fail(ip: str, ts: str):
        if ip not in fail_count:
            fail_order.append(ip)
        if ts:
            fail_first.setdefault(ip, ts)
            fail_last[ip] = ts

    for ev in events:
        eid  = ev.get("event_id", "").strip()
        ts   = ev.get("time", "")
        ip   = ev.get("ip", "").strip()
        user = ev.get("username", "").strip()

        if eid == "4625":
            src = ip if ip and ip not in ("-", "") else "unknown"
            _reg_fail(src, ts)
            fail_count[src] += 1
            if user:
                fail_users[src].add(user)

        elif eid == "4624":
            success_events.append(ev)

        elif eid == "4720":
            acct_create_events.append(ev)

        elif eid == "1102":
            log_clear_events.append(ev)

    rows: list[dict] = []

    # ── 4625 brute force rows ──────────────────────────────────────────────
    for ip in fail_order:
        count = fail_count[ip]
        if count < 5:
            continue
        rows.append({
            "ip":         ip,
            "usernames":  sorted(fail_users[ip]),
            "failures":   count,
            "first_seen": fail_first.get(ip, ""),
            "last_seen":  fail_last.get(ip, ""),
            "severity":   "MEDIUM",
            "reason":     f"Repeated Windows logon failures (Event 4625)",
            "techniques": [MITRE["T1110"]],
        })

    # ── 4624 success-after-failure rows ───────────────────────────────────
    seen_success_ips: set[str] = set()
    for ev in success_events:
        ip   = ev.get("ip", "").strip()
        src  = ip if ip and ip not in ("-", "") else "unknown"
        user = ev.get("username", "").strip()
        ts   = ev.get("time", "")
        ltype= ev.get("logon_type", "").strip()

        # Only flag if this IP also had failures
        if src not in fail_count or src in seen_success_ips:
            continue
        seen_success_ips.add(src)

        techniques = [MITRE["T1078"]]
        reason = "Successful Windows logon after failures (Event 4624)"
        if ltype == "10":
            techniques.append(MITRE["T1021.001"])
            reason += " via RDP (Logon Type 10)"

        rows.append({
            "ip":         src,
            "usernames":  [user] if user else [],
            "failures":   fail_count[src],
            "first_seen": fail_first.get(src, ""),
            "last_seen":  ts,
            "severity":   "HIGH",
            "reason":     reason,
            "techniques": techniques,
        })

    # ── 4720 account creation rows ─────────────────────────────────────────
    for ev in acct_create_events:
        new_user  = ev.get("username", "unknown").strip()
        actor     = ev.get("subject_username", "unknown").strip()
        ts        = ev.get("time", "")
        rows.append({
            "ip":         "localhost",
            "usernames":  [new_user],
            "failures":   1,
            "first_seen": ts,
            "last_seen":  ts,
            "severity":   "MEDIUM",
            "reason":     f"Local account created: '{new_user}' by '{actor}' (Event 4720)",
            "techniques": [MITRE["T1136.001"]],
        })

    # ── 1102 audit log cleared rows ────────────────────────────────────────
    for ev in log_clear_events:
        actor = ev.get("subject_username", ev.get("username", "unknown")).strip()
        ts    = ev.get("time", "")
        rows.append({
            "ip":         "localhost",
            "usernames":  [actor],
            "failures":   1,
            "first_seen": ts,
            "last_seen":  ts,
            "severity":   "HIGH",
            "reason":     f"Security audit log cleared by '{actor}' (Event 1102)",
            "techniques": [MITRE["T1070.001"]],
        })

    rows.sort(key=lambda r: (0 if r["severity"] == "HIGH" else 1, -r["failures"]))
    return rows


# ── Linux analysis (unchanged from v3) ────────────────────────────────────────

def _ts(line: str) -> str:
    m = RE_TIMESTAMP.match(line.strip())
    return m.group(1) if m else ""


def analyse_linux(log_text: str) -> list[dict]:
    ssh_users:       dict[str, set] = defaultdict(set)
    ssh_fail_count:  dict[str, int] = defaultdict(int)
    ssh_invalid_count: dict[str, int] = defaultdict(int)
    ssh_root_count:  dict[str, int] = defaultdict(int)
    ssh_success:     dict[str, set] = defaultdict(set)
    ssh_first:       dict[str, str] = {}
    ssh_last:        dict[str, str] = {}
    ssh_order:       list[str] = []

    sudo_fail_count: dict[str, int] = defaultdict(int)
    sudo_first:      dict[str, str] = {}
    sudo_last:       dict[str, str] = {}
    sudo_order:      list[str] = []

    def _update_ts(sf: dict, sl: dict, key: str, ts: str):
        if ts:
            sf.setdefault(key, ts)
            sl[key] = ts

    def _reg_ssh(ip: str, ts: str):
        if ip not in ssh_fail_count:
            ssh_order.append(ip)
        _update_ts(ssh_first, ssh_last, ip, ts)

    for line in log_text.splitlines():
        ts = _ts(line)

        m = RE_INVALID_USER.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            _reg_ssh(ip, ts)
            ssh_users[ip].add(user)
            ssh_fail_count[ip] += 1
            ssh_invalid_count[ip] += 1
            if user.lower() == "root":
                ssh_root_count[ip] += 1
            continue

        m = RE_FAILED.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            _reg_ssh(ip, ts)
            ssh_users[ip].add(user)
            ssh_fail_count[ip] += 1
            if user.lower() == "root":
                ssh_root_count[ip] += 1
            continue

        m = RE_SUCCESS.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            ssh_success[ip].add(user)
            _update_ts(ssh_first, ssh_last, ip, ts)
            continue

        if RE_SUDO_FAIL.search(line):
            mu = RE_SUDO_USER.search(line)
            user = mu.group(1) if mu else "unknown"
            if user not in sudo_fail_count:
                sudo_order.append(user)
            sudo_fail_count[user] += 1
            _update_ts(sudo_first, sudo_last, user, ts)

    rows: list[dict] = []

    for ip in ssh_order:
        count = ssh_fail_count[ip]
        if count < 5:
            continue
        has_root    = ssh_root_count[ip] > 0
        has_invalid = ssh_invalid_count[ip] > 0
        had_success = bool(ssh_success.get(ip))

        technique_ids: list[str] = ["T1110.001"]
        if has_root and ssh_root_count[ip] >= 3:
            technique_ids.append("T1078.003")
        if had_success:
            if "T1078.003" not in technique_ids:
                technique_ids.append("T1078")
            technique_ids.append("T1021.004")
            severity = "HIGH"
            reason   = "Possible brute force then successful login"
        elif has_root and ssh_root_count[ip] >= 3:
            severity = "HIGH"
            reason   = "Targeted root login attempts"
        else:
            severity = "MEDIUM"
            reason   = "Possible brute force"
        if has_invalid:
            reason += " (includes username enumeration)"

        rows.append({
            "ip":         ip,
            "usernames":  sorted(ssh_users[ip]),
            "failures":   count,
            "first_seen": ssh_first.get(ip, ""),
            "last_seen":  ssh_last.get(ip, ""),
            "severity":   severity,
            "reason":     reason,
            "techniques": [MITRE[t] for t in technique_ids],
        })

    for user in sudo_order:
        count = sudo_fail_count[user]
        if count < 3:
            continue
        rows.append({
            "ip":         "localhost",
            "usernames":  [user],
            "failures":   count,
            "first_seen": sudo_first.get(user, ""),
            "last_seen":  sudo_last.get(user, ""),
            "severity":   "MEDIUM",
            "reason":     f"Repeated failed sudo by local user '{user}'",
            "techniques": [MITRE["T1548.003"]],
        })

    rows.sort(key=lambda r: (0 if r["severity"] == "HIGH" else 1, -r["failures"]))
    return rows


# ── Unified entry point ────────────────────────────────────────────────────────

def analyse(log_text: str) -> tuple[list[dict], str]:
    """Return (rows, source_type) where source_type is 'linux' or 'windows'."""
    src = detect_type(log_text)
    if src == "windows":
        return analyse_windows(log_text), "windows"
    return analyse_linux(log_text), "linux"


# ── HTML page ──────────────────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogLens</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2e3147;
    --text: #e2e8f0; --muted: #8892a4;
    --high: #ff4d4f; --medium: #faad14;
    --accent: #4f8ef7; --mitre: #a78bfa;
    --win: #34d399; --linux: #60a5fa;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif;
         min-height: 100vh; padding: 2rem 1rem; }
  header { text-align: center; margin-bottom: 2rem; }
  header h1 { font-size: 2rem; letter-spacing: .05em; }
  header p  { color: var(--muted); margin-top: .4rem; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: .75rem; padding: 1.5rem; max-width: 1100px; margin: 0 auto 1.5rem; }
  textarea { width: 100%; height: 220px; background: var(--bg); color: var(--text);
             border: 1px solid var(--border); border-radius: .5rem; padding: .75rem;
             font-family: monospace; font-size: .85rem; resize: vertical; outline: none; }
  textarea:focus { border-color: var(--accent); }
  .btn-row { display: flex; gap: .75rem; margin-top: .75rem; flex-wrap: wrap; align-items: center; }
  button { padding: .55rem 1.2rem; border: none; border-radius: .5rem; cursor: pointer;
           font-size: .9rem; font-weight: 600; transition: opacity .15s; }
  button:hover { opacity: .85; }
  #btnAnalyse   { background: var(--accent); color: #fff; }
  #btnLinux     { background: var(--surface); color: var(--text); border: 1px solid var(--border); }
  #btnWindows   { background: var(--surface); color: var(--text); border: 1px solid var(--border); }
  #btnCopy      { background: var(--surface); color: var(--text); border: 1px solid var(--border); display:none; }
  .type-badge   { display:none; padding: .25rem .65rem; border-radius: .4rem;
                  font-size: .78rem; font-weight: 700; letter-spacing: .04em; }
  .type-linux   { background: rgba(96,165,250,.15); color: var(--linux); }
  .type-windows { background: rgba(52,211,153,.15); color: var(--win); }
  #status { color: var(--muted); font-size: .85rem; margin-top: .6rem; min-height: 1.2em; }
  #results { max-width: 1100px; margin: 0 auto; }
  table { width: 100%; border-collapse: collapse; font-size: .86rem; }
  th { text-align: left; padding: .55rem .8rem; color: var(--muted);
       border-bottom: 1px solid var(--border); font-weight: 600; white-space: nowrap; }
  td { padding: .6rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: .2rem .55rem; border-radius: .35rem;
           font-size: .75rem; font-weight: 700; letter-spacing: .04em; }
  .HIGH   { background: rgba(255,77,79,.18); color: var(--high); }
  .MEDIUM { background: rgba(250,173,20,.18); color: var(--medium); }
  .usernames { font-family: monospace; font-size: .82rem; color: var(--muted); }
  .ts { font-family: monospace; font-size: .78rem; color: var(--muted); white-space: nowrap; }
  .empty { text-align: center; padding: 2rem; color: var(--muted); }
  .mitre-list { display: flex; flex-direction: column; gap: .4rem; }
  .mitre-tag  { display: inline-flex; align-items: baseline; gap: .35rem; flex-wrap: wrap; }
  .mitre-tag a { color: var(--mitre); font-family: monospace; font-size: .8rem; font-weight: 700;
                 text-decoration: none; border-bottom: 1px dotted var(--mitre); }
  .mitre-tag a:hover { border-bottom-style: solid; }
  .mitre-name { font-size: .78rem; color: var(--muted); }
  .why { font-size: .77rem; color: var(--muted); font-style: italic;
         margin-top: .2rem; padding-left: .1rem; }
</style>
</head>
<body>
<header>
  <h1>🔍 LogLens</h1>
  <p>Paste a Linux <code>auth.log</code> or Windows Security event export to detect threats</p>
</header>

<div class="card">
  <textarea id="logInput" placeholder="Paste your auth.log or Windows Security events here…" spellcheck="false"></textarea>
  <div class="btn-row">
    <button id="btnAnalyse">Analyse</button>
    <button id="btnLinux">Load Linux sample</button>
    <button id="btnWindows">Load Windows sample</button>
    <button id="btnCopy">Copy as Markdown report</button>
    <span id="typeBadge" class="type-badge"></span>
  </div>
  <div id="status"></div>
</div>

<div id="results"></div>

<script>
"use strict";

const LINUX_SAMPLE   = LINUX_SAMPLE_PLACEHOLDER;
const WINDOWS_SAMPLE = WINDOWS_SAMPLE_PLACEHOLDER;

// Hardcoded MITRE URLs — never constructed from log content
const MITRE_URLS = {
  "T1110":     "https://attack.mitre.org/techniques/T1110/",
  "T1110.001": "https://attack.mitre.org/techniques/T1110/001/",
  "T1078":     "https://attack.mitre.org/techniques/T1078/",
  "T1078.003": "https://attack.mitre.org/techniques/T1078/003/",
  "T1021.001": "https://attack.mitre.org/techniques/T1021/001/",
  "T1021.004": "https://attack.mitre.org/techniques/T1021/004/",
  "T1136.001": "https://attack.mitre.org/techniques/T1136/001/",
  "T1070.001": "https://attack.mitre.org/techniques/T1070/001/",
  "T1548.003": "https://attack.mitre.org/techniques/T1548/003/",
};

function esc(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

function renderTechniques(techniques) {
  if (!techniques || techniques.length === 0) return "—";
  return '<div class="mitre-list">' +
    techniques.map(t => {
      const safeUrl = MITRE_URLS[t.id] || "#";
      return `<div>
        <span class="mitre-tag">
          <a href="${esc(safeUrl)}" target="_blank" rel="noopener noreferrer">${esc(t.id)}</a>
          <span class="mitre-name">${esc(t.name)}</span>
        </span>
        <div class="why">${esc(t.why)}</div>
      </div>`;
    }).join("") + "</div>";
}

function showTypeBadge(sourceType) {
  const b = document.getElementById("typeBadge");
  b.className = "type-badge type-" + (sourceType === "windows" ? "windows" : "linux");
  b.textContent = sourceType === "windows" ? "Windows Security Events" : "Linux auth.log";
  b.style.display = "inline-block";
}

document.getElementById("btnLinux").addEventListener("click", () => {
  document.getElementById("logInput").value = LINUX_SAMPLE;
  document.getElementById("status").textContent = "Linux sample loaded. Click Analyse to inspect it.";
  document.getElementById("typeBadge").style.display = "none";
});

document.getElementById("btnWindows").addEventListener("click", () => {
  document.getElementById("logInput").value = WINDOWS_SAMPLE;
  document.getElementById("status").textContent = "Windows sample loaded. Click Analyse to inspect it.";
  document.getElementById("typeBadge").style.display = "none";
});

document.getElementById("btnAnalyse").addEventListener("click", async () => {
  const text = document.getElementById("logInput").value.trim();
  const status = document.getElementById("status");
  const results = document.getElementById("results");

  if (!text) { status.textContent = "Paste some log content first."; return; }
  if (text.length > 500 * 1024) { status.textContent = "Input too large (max 500 KB)."; return; }

  status.textContent = "Analysing…";
  results.innerHTML = "";
  document.getElementById("btnCopy").style.display = "none";
  document.getElementById("typeBadge").style.display = "none";

  try {
    const resp = await fetch("./analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log: text }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    if (data.source_type) showTypeBadge(data.source_type);

    if (!data.results || data.results.length === 0) {
      results.innerHTML = '<div class="card"><p class="empty">No flagged activity found.</p></div>';
      status.textContent = "Analysis complete — nothing to flag.";
      return;
    }

    let html = '<div class="card"><table><thead><tr>' +
      '<th>Source</th><th>Usernames</th><th>Attempts</th>' +
      '<th>First Seen</th><th>Last Seen</th>' +
      '<th>Severity</th><th>Finding</th><th>MITRE ATT&amp;CK</th>' +
      '</tr></thead><tbody>';

    for (const row of data.results) {
      html += `<tr>
        <td><code>${esc(row.ip)}</code></td>
        <td class="usernames">${row.usernames.map(esc).join(", ")}</td>
        <td>${esc(row.failures)}</td>
        <td class="ts">${esc(row.first_seen || "—")}</td>
        <td class="ts">${esc(row.last_seen  || "—")}</td>
        <td><span class="badge ${esc(row.severity)}">${esc(row.severity)}</span></td>
        <td>${esc(row.reason)}</td>
        <td>${renderTechniques(row.techniques)}</td>
      </tr>`;
    }
    html += "</tbody></table></div>";
    results.innerHTML = html;

    const srcLabel = data.source_type === "windows" ? "Windows Security Events" : "Linux auth.log";
    status.textContent = `Detected: ${srcLabel} — found ${data.results.length} flagged source(s).`;
    document.getElementById("btnCopy").style.display = "inline-block";
    window._lastResults = data.results;
    window._lastSourceType = data.source_type || "linux";
  } catch(e) {
    status.textContent = "Error: " + e.message;
  }
});

document.getElementById("btnCopy").addEventListener("click", () => {
  if (!window._lastResults) return;
  const rows = window._lastResults;
  const srcLabel = window._lastSourceType === "windows" ? "Windows Security Events" : "Linux auth.log";
  let md = `# LogLens Security Report\n\n**Source type:** ${srcLabel}\n\n`;
  md += "| Source | Usernames | Attempts | First Seen | Last Seen | Severity | Finding | MITRE ATT&CK |\n";
  md += "|---|---|---|---|---|---|---|---|\n";
  for (const r of rows) {
    const techniques = (r.techniques || [])
      .map(t => `[${t.id}](${MITRE_URLS[t.id] || "#"}) ${t.name}`)
      .join(", ");
    md += `| ${r.ip} | ${r.usernames.join(", ")} | ${r.failures} | ${r.first_seen || "—"} | ${r.last_seen || "—"} | **${r.severity}** | ${r.reason} | ${techniques} |\n`;
  }
  md += "\n## Why It Matters\n\n";
  const seen = new Set();
  for (const r of rows) {
    for (const t of (r.techniques || [])) {
      if (!seen.has(t.id)) {
        seen.add(t.id);
        md += `**${t.id} – ${t.name}:** ${t.why}\n\n`;
      }
    }
  }
  navigator.clipboard.writeText(md).then(
    () => { document.getElementById("status").textContent = "Markdown report copied to clipboard!"; },
    () => { document.getElementById("status").textContent = "Copy failed – clipboard access denied."; }
  );
});
</script>
</body>
</html>
"""


def _js_escape(s: str) -> str:
    """Escape a string for safe embedding in a JS template literal."""
    return (s
            .replace("\\", "\\\\")
            .replace("`",  "\\`")
            .replace("${", "\\${"))


def make_html() -> str:
    page = HTML_PAGE
    page = page.replace("LINUX_SAMPLE_PLACEHOLDER",   f"`{_js_escape(LINUX_SAMPLE)}`")
    page = page.replace("WINDOWS_SAMPLE_PLACEHOLDER", f"`{_js_escape(WINDOWS_SAMPLE)}`")
    return page


# ── Lambda entry point ─────────────────────────────────────────────────────────
def handler(event: dict, context) -> dict:
    method = (event.get("requestContext", {})
              .get("http", {})
              .get("method", "GET"))
    path = event.get("rawPath", "/")

    if method == "GET" and path in ("/", ""):
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/html; charset=utf-8",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": (
                    "default-src 'none'; "
                    "script-src 'unsafe-inline'; "
                    "style-src 'unsafe-inline'; "
                    "connect-src 'self';"
                ),
            },
            "body": make_html(),
        }

    if method == "POST" and path == "/analyze":
        body_str = event.get("body", "") or ""
        if event.get("isBase64Encoded"):
            import base64
            body_str = base64.b64decode(body_str).decode("utf-8", errors="replace")

        if len(body_str.encode("utf-8")) > MAX_LOG_BYTES + 4096:
            return _json_response(413, {"error": "Payload too large (max 500 KB of log text)"})

        try:
            payload = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            return _json_response(400, {"error": "Invalid JSON body"})

        if not isinstance(payload, dict) or "log" not in payload:
            return _json_response(400, {"error": "Missing 'log' field"})

        log_text = payload["log"]
        if not isinstance(log_text, str):
            return _json_response(400, {"error": "'log' must be a string"})

        if len(log_text.encode("utf-8")) > MAX_LOG_BYTES:
            return _json_response(413, {"error": "Log text too large (max 500 KB)"})

        results, source_type = analyse(log_text)
        return _json_response(200, {"source_type": source_type, "results": results})

    if method == "GET" and path == "/sample":
        return _json_response(200, {"log": LINUX_SAMPLE})

    return _json_response(404, {"error": "Not found"})


def _json_response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
        },
        "body": json.dumps(body),
    }
