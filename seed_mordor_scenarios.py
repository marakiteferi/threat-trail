#!/usr/bin/env python3
"""
seed_mordor_scenarios.py
Smart Signal-Preserving Ingestion for all 5 Mordor / OTRF Active Directory ZIP archives!
Instead of blindly slicing `lines[:120]` (which can miss the actual attack events if they
occur later in the recording), this script scans the ENTIRE archive, extracts all high-signal
security/attack events, and samples surrounding background logs up to `target_count` (350 logs)
sorted chronologically.
"""

import json
import zipfile
from pathlib import Path
from datetime import datetime
from database import SessionLocal
from models import Scenario, Alert, Log, Question, SeverityLevel
from main import extract_field_from_message

ROOT = Path(__file__).resolve().parent

# High-value Windows Security, System, PowerShell, and Sysmon Event IDs
PRIORITY_EVENT_IDS = {
    4624, 4625, 4648, 4662, 4672, 4688, 4697, 4698, 4768, 4769, 5140, 5145, 7045,
    4103, 4104, 1, 3, 7, 8, 10, 11, 13, 17, 18, 22
}

MORDOR_SCENARIOS = [
    {
        "zip_name": "covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "name": "Active Directory DCSync Attack (Covenant C2)",
        "mitre_technique": "T1003.006",
        "target_count": 350,
        "key_event_ids": {4662, 4624},
        "description": (
            "An attacker with Domain Admin-equivalent privileges used Covenant C2 to perform a "
            "DCSync attack via the MS-DRSR Directory Replication Service (DsGetNCChanges) protocol "
            "to replicate password hashes from the Domain Controller. Investigate Event ID 4662 and "
            "network logon events to identify the compromised account and replication abuse."
        ),
        "alert_title": "Critical: Directory Replication Service (DCSync) Abuse Detected (Event 4662)",
        "severity": SeverityLevel.CRITICAL,
        "sigma_rule": """title: Mimikatz / Covenant DCSync Replication (Event 4662)
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006""",
        "ad_context": {
            "domain": "shire.com",
            "attack_type": "DCSync (MS-DRSR DsGetNCChanges)",
            "critical_guids": {
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
            },
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for DCSync?",
                "correct_answer": "T1003.006",
                "acceptable_answers": ["T1003"],
                "explanation": "DCSync is categorized under OS Credential Dumping: DCSync (T1003.006).",
                "points": 15,
            },
            {
                "question_text": "Which Windows Security Event ID logs directory service object access used to detect DCSync?",
                "correct_answer": "4662",
                "acceptable_answers": ["4662"],
                "explanation": "Event ID 4662 ('An operation was performed on an object') logs AD replication rights checks.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "empire_mimikatz_logonpasswords.zip",
        "name": "Empire Mimikatz LSASS Credential Dumping",
        "mitre_technique": "T1003.001",
        "target_count": 350,
        "key_event_ids": {10, 4688, 4104, 7},
        "description": (
            "A threat actor operating PowerShell Empire executed Mimikatz (sekurlsa::logonpasswords) "
            "on an Active Directory workstation to dump credentials from LSASS process memory. "
            "Analyze the Windows and Sysmon events to trace the credential dump."
        ),
        "alert_title": "Critical: Suspicious Process Access to LSASS Memory (Mimikatz)",
        "severity": SeverityLevel.CRITICAL,
        "sigma_rule": """title: LSASS Memory Dump via Mimikatz (Sysmon Event 10)
status: stable
logsource:
  product: windows
  category: process_access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001""",
        "ad_context": {
            "target_process": "C:\\Windows\\System32\\lsass.exe",
            "tool": "PowerShell Empire / Invoke-Mimikatz",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for dumping LSASS memory?",
                "correct_answer": "T1003.001",
                "acceptable_answers": ["T1003"],
                "explanation": "T1003.001 corresponds to OS Credential Dumping: LSASS Memory.",
                "points": 15,
            },
            {
                "question_text": "Which Windows system process is targeted by sekurlsa::logonpasswords?",
                "correct_answer": "lsass.exe",
                "acceptable_answers": ["lsass", "c:\\windows\\system32\\lsass.exe"],
                "explanation": "Local Security Authority Subsystem Service (lsass.exe) stores active logon credentials in memory.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "cmd_psexec_lsa_secrets_dump.zip",
        "name": "PsExec Lateral Movement & LSA Secrets Dump",
        "mitre_technique": "T1003.004",
        "target_count": 300,  # Ingests all 286 events!
        "key_event_ids": {7045, 4697, 1, 13},
        "description": (
            "An adversary used Sysinternals PsExec to execute commands as SYSTEM and dump "
            "LSA Secrets from the registry. All 286 events from the incident capture are loaded—"
            "investigate service creation, process execution, and named pipe activity."
        ),
        "alert_title": "High Severity: PsExec Service Installation & LSA Secrets Access",
        "severity": SeverityLevel.HIGH,
        "sigma_rule": """title: PsExec Service Execution (PSEXESVC)
status: stable
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1569.002""",
        "ad_context": {
            "service_binary": "PSEXESVC.exe",
            "technique": "PsExec SYSTEM escalation + LSA Secrets Dump",
        },
        "questions": [
            {
                "question_text": "What is the default service name installed by Sysinternals PsExec on the target host?",
                "correct_answer": "PSEXESVC",
                "acceptable_answers": ["psexesvc.exe"],
                "explanation": "PsExec drops and registers the PSEXESVC service binary on the remote Windows host.",
                "points": 20,
            },
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for LSA Secrets credential dumping?",
                "correct_answer": "T1003.004",
                "acceptable_answers": ["T1003", "T1569.002"],
                "explanation": "T1003.004 is OS Credential Dumping: LSA Secrets.",
                "points": 15,
            },
        ],
    },
    {
        "zip_name": "empire_dcom_shellwindows_stager.zip",
        "name": "Empire Lateral Movement via DCOM ShellWindows",
        "mitre_technique": "T1021.003",
        "target_count": 350,
        "key_event_ids": {4624, 4688, 4104, 1, 3},
        "description": (
            "An attacker abused Distributed Component Object Model (DCOM) ShellWindows CLSID "
            "(9BA05972-F6A8-11CF-A442-00A0C90A8F39) via explorer.exe to execute a PowerShell Empire "
            "stager laterally across the domain. Investigate the curated logs from the 32,706-event capture."
        ),
        "alert_title": "High Severity: Remote DCOM ShellWindows Spawning PowerShell Stager",
        "severity": SeverityLevel.HIGH,
        "sigma_rule": """title: DCOM ShellWindows Lateral Movement (Explorer Spawning PowerShell)
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\explorer.exe'
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.003""",
        "ad_context": {
            "dcom_clsid": "9BA05972-F6A8-11CF-A442-00A0C90A8F39 (ShellWindows)",
            "parent_process": "explorer.exe",
            "child_process": "powershell.exe",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for Component Object Model (DCOM) lateral movement?",
                "correct_answer": "T1021.003",
                "acceptable_answers": ["T1021"],
                "explanation": "T1021.003 is Remote Services: Distributed Component Object Model.",
                "points": 20,
            },
            {
                "question_text": "Which Windows shell process acts as the parent process when ShellWindows DCOM is abused?",
                "correct_answer": "explorer.exe",
                "acceptable_answers": ["explorer", "c:\\windows\\explorer.exe"],
                "explanation": "Abusing the ShellWindows COM object causes the remote host's explorer.exe process to spawn the attacker's payload.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "psh_python_webserver.zip",
        "name": "PowerShell Web Download & Staging (Invoke-WebRequest)",
        "mitre_technique": "T1059.001",
        "target_count": 350,
        "key_event_ids": {4104, 4103, 1, 3, 22},
        "description": (
            "A user workstation executed PowerShell to download a payload hosted on an adversary's "
            "Python SimpleHTTPServer. Investigate PowerShell ScriptBlock logging (Event 4104) and "
            "Sysmon network connection events (Event 3) to uncover the staging activity."
        ),
        "alert_title": "Medium Severity: Suspicious PowerShell Web Download From Non-Standard Port",
        "severity": SeverityLevel.MEDIUM,
        "sigma_rule": """title: PowerShell DownloadString / Invoke-WebRequest Execution
status: stable
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-WebRequest'
      - 'DownloadString'
      - 'Net.WebClient'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001""",
        "ad_context": {
            "staging_protocol": "HTTP (Python SimpleHTTPServer)",
            "key_telemetry": "PowerShell Event ID 4104 (ScriptBlock Logging) & Sysmon Event ID 3",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for PowerShell execution?",
                "correct_answer": "T1059.001",
                "acceptable_answers": ["T1059", "T1105"],
                "explanation": "T1059.001 is Command and Scripting Interpreter: PowerShell.",
                "points": 15,
            },
            {
                "question_text": "Which Windows PowerShell Event ID records full ScriptBlock text content?",
                "correct_answer": "4104",
                "acceptable_answers": ["4104"],
                "explanation": "Event ID 4104 (Execute a Remote Command) records the de-obfuscated PowerShell ScriptBlock text.",
                "points": 20,
            },
        ],
    },
]


def parse_single_record(data: dict, scenario_id: int, key_event_ids: set) -> Log:
    ts_str = (
        data.get("@timestamp")
        or data.get("TimeCreated")
        or data.get("EventTime")
        or data.get("UtcTime")
    )
    try:
        clean_ts = str(ts_str).replace("Z", "+00:00")
        ts = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
    except Exception:
        ts = datetime.now()

    ev_raw = data.get("EventID") or data.get("event_id") or 0
    if isinstance(ev_raw, dict):
        ev_raw = ev_raw.get("$numberInt") or 0
    try:
        event_id = int(ev_raw)
    except Exception:
        event_id = 0

    msg = data.get("Message") or ""
    source_ip = (
        data.get("IpAddress")
        or data.get("SourceAddress")
        or data.get("SourceIp")
        or data.get("DestinationIp")
        or extract_field_from_message(msg, r"Source Network Address:\s*([^\r\n\t]+)")
    )
    username = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName")
        or data.get("User")
        or extract_field_from_message(msg, r"Account Name:\s*([^\r\n\t]+)")
    )
    target_host = (
        data.get("Hostname")
        or data.get("Computer")
        or data.get("host")
    )

    return Log(
        scenario_id=scenario_id,
        event_id=event_id,
        timestamp=ts,
        source_ip=source_ip,
        username=username,
        target_host=target_host,
        is_key_evidence=(event_id in key_event_ids),
        raw_event_data=data,
    )


def smart_sample_mordor_zip(zip_path: Path, scenario_id: int, target_count: int, key_event_ids: set):
    """
    Scans the entire ZIP archive so high-signal events later in the file are never lost!
    Preserves priority/key events and evenly samples background events up to target_count.
    """
    all_raw = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith(".json") or info.filename.endswith(".jsonl"):
                with zf.open(info) as f:
                    for raw_line in f:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            if isinstance(item, dict):
                                all_raw.append(item)
                        except Exception:
                            continue
                if all_raw:
                    break

    total_in_zip = len(all_raw)
    if total_in_zip <= target_count:
        selected_raw = all_raw
    else:
        priority_records = []
        background_records = []
        for idx, d in enumerate(all_raw):
            ev = d.get("EventID") or d.get("event_id") or 0
            if isinstance(ev, dict):
                ev = ev.get("$numberInt") or 0
            try:
                ev = int(ev)
            except Exception:
                ev = 0

            if ev in key_event_ids or ev in PRIORITY_EVENT_IDS:
                priority_records.append((idx, d))
            else:
                background_records.append((idx, d))

        # Take up to 70% from priority events (evenly spaced if huge) + fill rest with background
        max_priority = int(target_count * 0.75)
        if len(priority_records) > max_priority:
            step = max(1, len(priority_records) // max_priority)
            chosen_priority = priority_records[::step][:max_priority]
        else:
            chosen_priority = priority_records

        remaining_slots = max(0, target_count - len(chosen_priority))
        if remaining_slots > 0 and background_records:
            step_bg = max(1, len(background_records) // remaining_slots)
            chosen_bg = background_records[::step_bg][:remaining_slots]
        else:
            chosen_bg = []

        combined = sorted(chosen_priority + chosen_bg, key=lambda x: x[0])
        selected_raw = [x[1] for x in combined]

    entries = [parse_single_record(d, scenario_id, key_event_ids) for d in selected_raw]
    entries.sort(key=lambda x: x.timestamp)
    return entries, total_in_zip


def main():
    db = SessionLocal()
    try:
        for item in MORDOR_SCENARIOS:
            zpath = ROOT / item["zip_name"]
            if not zpath.exists():
                print(f"[SKIP] {item['zip_name']} not found in root.")
                continue

            existing = db.query(Scenario).filter(Scenario.name == item["name"]).first()
            if existing:
                # Refresh logs for existing Mordor scenario with smart sampling
                sc = existing
                db.query(Log).filter(Log.scenario_id == sc.id).delete()
                logs, total_raw = smart_sample_mordor_zip(
                    zpath, sc.id, item["target_count"], item["key_event_ids"]
                )
                db.add_all(logs)
                db.commit()
                print(f"[REFRESHED] '{item['name']}': Smart-sampled {len(logs)} / {total_raw} total ZIP events.")
                continue

            sc = Scenario(
                name=item["name"],
                description=item["description"],
                mitre_technique=item["mitre_technique"],
                status="Published",
                ad_context=item["ad_context"],
            )
            db.add(sc)
            db.flush()

            db.add(
                Alert(
                    scenario_id=sc.id,
                    title=item["alert_title"],
                    severity=item["severity"],
                    sigma_rule=item["sigma_rule"],
                )
            )

            for q in item["questions"]:
                db.add(
                    Question(
                        scenario_id=sc.id,
                        question_text=q["question_text"],
                        correct_answer=q["correct_answer"],
                        acceptable_answers=q["acceptable_answers"],
                        explanation=q["explanation"],
                        points=q["points"],
                    )
                )

            logs, total_raw = smart_sample_mordor_zip(
                zpath, sc.id, item["target_count"], item["key_event_ids"]
            )
            db.add_all(logs)
            db.commit()
            print(f"[+] Imported '{item['name']}': Smart-sampled {len(logs)} / {total_raw} total ZIP events!")
    finally:
        db.close()


if __name__ == "__main__":
    main()
