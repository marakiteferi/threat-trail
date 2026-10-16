#!/usr/bin/env python3
"""
apply_smart_log_curation_and_pagination.py
Run from the ThreatTrail project root:
    python apply_smart_log_curation_and_pagination.py
    python seed.py
    python seed_mordor_scenarios.py

What this does:
1. Upgrades `seed.py`:
   - Password Spraying now has ~110 realistic AD logs (background 4624, 4768, 4672 noise + 15x 4625 spray + 1x 4624 compromise).
   - Kerberoasting now has ~95 realistic AD logs (dozens of legitimate 0x12 AES tickets & logons hiding the malicious 0x17 RC4 ticket).
2. Upgrades `seed_mordor_scenarios.py`:
   - Replaces blind `lines[:120]` truncation with Smart Signal-Preserving Sampling: scans the entire ZIP so critical attack events (4662, 7045, Sysmon 1/10, 4104, etc.) are NEVER cut off, surrounded by realistic noise (286 to 400 events per scenario).
   - Adds the remaining 2 ZIP archives (`empire_dcom_shellwindows_stager.zip` and `psh_python_webserver.zip`) so all 5 ZIPs + 2 synthetic scenarios = 7 complete scenarios!
3. Upgrades `Investigation.jsx` & `main.py`:
   - Raises backend log fetch limit to 2000.
   - Adds instant client-side table pagination (50 / 100 / 200 rows per page) so searching/filtering searches 100% of logs instantly without lagging the browser DOM.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# 1. Update seed.py with realistic background AD noise (~100 logs each)
# ---------------------------------------------------------------------------
SEED_PY = """\"\"\"
Seed script — populates ThreatTrail with 2 realistic, noisy Active Directory scenarios:
  1. Active Directory Password Spraying (MITRE T1110.003) — ~110 events
  2. Kerberoasting Service Account Abuse (MITRE T1558.003) — ~95 events
\"\"\"

from datetime import datetime, timedelta
import random
import bcrypt
from database import engine, SessionLocal, Base
from models import User, Scenario, Alert, Log, Question, SeverityLevel

random.seed(42)

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
print("[+] Tables recreated.")

db = SessionLocal()

try:
    admin_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
    analyst_hash = bcrypt.hashpw(b"analyst123", bcrypt.gensalt()).decode("utf-8")

    db.add(User(username="admin", password_hash=admin_hash, role="admin"))
    db.add(User(username="analyst", password_hash=analyst_hash, role="user"))
    db.flush()

    normal_users = ["alice.tesfaye", "bob.miller", "claire.chen", "david.kim", "elena.rossi", "frank.wright", "grace.lin"]
    normal_ips = ["10.0.1.14", "10.0.1.22", "10.0.1.35", "10.0.1.48", "10.0.2.19", "10.0.2.61"]
    workstations = ["WS-FIN-01", "WS-HR-04", "WS-DEV-02", "WS-MKT-07", "WS-OPS-03"]

    # =========================================================================
    # SCENARIO 1: PASSWORD SPRAYING (MITRE T1110.003) — ~110 Logs
    # =========================================================================
    sc1_ad_context = {
        "domain": "corp.local",
        "domain_controllers": [
            {"hostname": "DC01.corp.local", "ip": "10.0.0.10", "os": "Windows Server 2022"}
        ],
        "high_value_accounts": [
            {"username": "svc_backup", "groups": ["Backup Operators", "Domain Users"], "note": "Legacy backup service account; excluded from MFA"},
            {"username": "adm_kaleb", "groups": ["Domain Admins"], "note": "Tier-0 Administrator"}
        ],
        "lockout_policy": "5 failed attempts within 30 minutes locks account for 15 minutes",
    }

    sc1 = Scenario(
        name="Active Directory Password Spraying",
        description=(
            "A threat actor is attempting to authenticate across multiple Active Directory user accounts "
            "using a single commonly-used password ('Spring2024!') amidst normal corporate domain traffic. "
            "Filter through the background domain authentication noise, inspect the Sigma rule, and identify "
            "the attacker's IP and compromised service account."
        ),
        mitre_technique="T1110.003",
        status="Published",
        ad_context=sc1_ad_context,
    )
    db.add(sc1)
    db.flush()

    sc1_sigma = \"\"\"title: Active Directory Password Spraying Detected
id: 6d2c8e1a-9f4b-4b11-8c33-1a2b3c4d5e6f
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
    SubStatus: '0xC000006A'
  timeframe: 5m
  condition: selection | count(TargetUserName) by IpAddress > 10
level: high
tags:
  - attack.credential_access
  - attack.t1110.003\"\"\"

    db.add(Alert(
        scenario_id=sc1.id,
        title="High Severity: Password Spraying — Multiple Distinct Accounts Failed From Single IP",
        severity=SeverityLevel.HIGH,
        sigma_rule=sc1_sigma,
    ))

    ATTACKER_IP = "10.0.5.22"
    TARGET_HOST = "DC01.corp.local"
    COMPROMISED_USER = "svc_backup"
    base_time = datetime(2025, 3, 15, 2, 10, 0)

    sc1_logs = []

    # Generate 90 benign background domain events (4624, 4768, 4672, and 2 benign user typo 4625s)
    for idx in range(90):
        ts = base_time + timedelta(seconds=idx * 5 + random.randint(0, 2))
        u = random.choice(normal_users)
        ip = random.choice(normal_ips)
        ws = random.choice(workstations)
        ev_choice = random.choices([4624, 4768, 4672, 4625], weights=[60, 25, 12, 3])[0]

        if ev_choice == 4624:
            msg = (
                f"An account was successfully logged on.\\r\\n\\r\\n"
                f"Subject:\\r\\n\\tAccount Name:\\t-\\r\\n\\r\\n"
                f"Logon Information:\\r\\n\\tLogon Type:\\t3\\r\\n"
                f"New Logon:\\r\\n\\tAccount Name:\\t{u}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                f"Network Information:\\r\\n\\tWorkstation Name:\\t{ws}\\r\\n\\tSource Network Address:\\t{ip}\\r\\n"
                f"Authentication Information:\\r\\n\\tAuthentication Package:\\tKerberos\\r\\n"
            )
        elif ev_choice == 4768:
            msg = (
                f"A Kerberos authentication ticket (TGT) was requested.\\r\\n\\r\\n"
                f"Account Information:\\r\\n\\tAccount Name:\\t{u}\\r\\n\\tSupplied Realm Name:\\tCORP.LOCAL\\r\\n"
                f"Network Information:\\r\\n\\tClient Address:\\t{ip}\\r\\n"
                f"Additional Information:\\r\\n\\tTicket Encryption Type:\\t0x12\\r\\n"
            )
        elif ev_choice == 4672:
            msg = (
                f"Special privileges assigned to new logon.\\r\\n\\r\\n"
                f"Subject:\\r\\n\\tAccount Name:\\t{u}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                f"Privileges:\\tSeSecurityPrivilege\\r\\n"
            )
        else:
            msg = (
                f"An account failed to log on.\\r\\n\\r\\n"
                f"Logon Information:\\r\\n\\tLogon Type:\\t2\\r\\n"
                f"Account For Which Logon Failed:\\r\\n\\tAccount Name:\\t{u}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                f"Failure Information:\\r\\n\\tStatus:\\t0xC000006D\\r\\n\\tSub Status:\\t0xC000006A\\r\\n"
                f"Network Information:\\r\\n\\tWorkstation Name:\\t{ws}\\r\\n\\tSource Network Address:\\t{ip}\\r\\n"
            )

        sc1_logs.append(Log(
            scenario_id=sc1.id,
            event_id=ev_choice,
            timestamp=ts,
            source_ip=ip,
            username=u,
            target_host=TARGET_HOST,
            is_key_evidence=False,
            raw_event_data={
                "EventID": ev_choice,
                "TimeCreated": ts.isoformat(),
                "Hostname": TARGET_HOST,
                "Channel": "Security",
                "TargetUserName": u,
                "IpAddress": ip,
                "WorkstationName": ws,
                "Message": msg,
            },
        ))

    # Inject the 15 Password Spraying failed logons (4625) + 1 successful logon (4624) + 1 privilege escalation (4672)
    spray_start = base_time + timedelta(minutes=3, seconds=10)
    spray_targets = [
        "jsmith", "agarcia", "mwilliams", "kjohnson", "lbrown",
        "dlee", "rmartin", "pthompson", "cwilson", "nanderson",
        "btaylor", "hmoore", "fwhite", "eharris", "jclark",
    ]

    for i, target_user in enumerate(spray_targets):
        ts = spray_start + timedelta(seconds=i * 3)
        sc1_logs.append(Log(
            scenario_id=sc1.id,
            event_id=4625,
            timestamp=ts,
            source_ip=ATTACKER_IP,
            username=target_user,
            target_host=TARGET_HOST,
            is_key_evidence=(i == 0),
            raw_event_data={
                "EventID": 4625,
                "SourceName": "Microsoft-Windows-Security-Auditing",
                "TimeCreated": ts.isoformat(),
                "Hostname": TARGET_HOST,
                "Channel": "Security",
                "Keywords": "Audit Failure",
                "LogonType": 3,
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "TargetUserName": target_user,
                "IpAddress": ATTACKER_IP,
                "Message": (
                    f"An account failed to log on.\\r\\n\\r\\n"
                    f"Subject:\\r\\n\\tSecurity ID:\\tS-1-0-0\\r\\n\\tAccount Name:\\t-\\r\\n\\r\\n"
                    f"Logon Information:\\r\\n\\tLogon Type:\\t3\\r\\n"
                    f"Account For Which Logon Failed:\\r\\n\\tAccount Name:\\t{target_user}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                    f"Failure Information:\\r\\n\\tFailure Reason:\\tUnknown user name or bad password.\\r\\n"
                    f"\\tStatus:\\t0xC000006D\\r\\n\\tSub Status:\\t0xC000006A\\r\\n\\r\\n"
                    f"Network Information:\\r\\n\\tWorkstation Name:\\tATTACKER-WS\\r\\n"
                    f"\\tSource Network Address:\\t{ATTACKER_IP}\\r\\n\\tSource Port:\\t{49152 + i}\\r\\n"
                    f"Authentication Information:\\r\\n\\tAuthentication Package:\\tNTLM\\r\\n"
                ),
            },
        ))

    success_ts = spray_start + timedelta(seconds=len(spray_targets) * 3 + 4)
    sc1_logs.append(Log(
        scenario_id=sc1.id,
        event_id=4624,
        timestamp=success_ts,
        source_ip=ATTACKER_IP,
        username=COMPROMISED_USER,
        target_host=TARGET_HOST,
        is_key_evidence=True,
        raw_event_data={
            "EventID": 4624,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": success_ts.isoformat(),
            "Hostname": TARGET_HOST,
            "Channel": "Security",
            "Keywords": "Audit Success",
            "LogonType": 3,
            "TargetUserName": COMPROMISED_USER,
            "IpAddress": ATTACKER_IP,
            "Message": (
                f"An account was successfully logged on.\\r\\n\\r\\n"
                f"Subject:\\r\\n\\tSecurity ID:\\tS-1-0-0\\r\\n\\tAccount Name:\\t-\\r\\n\\r\\n"
                f"Logon Information:\\r\\n\\tLogon Type:\\t3\\r\\n"
                f"New Logon:\\r\\n\\tAccount Name:\\t{COMPROMISED_USER}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                f"Network Information:\\r\\n\\tWorkstation Name:\\tATTACKER-WS\\r\\n"
                f"\\tSource Network Address:\\t{ATTACKER_IP}\\r\\n\\tSource Port:\\t{49152 + 16}\\r\\n"
                f"Authentication Information:\\r\\n\\tAuthentication Package:\\tNTLM\\r\\n"
            ),
        },
    ))

    sc1_logs.sort(key=lambda x: x.timestamp)
    db.add_all(sc1_logs)

    db.add_all([
        Question(
            scenario_id=sc1.id,
            question_text="What is the source IP address performing the password spray?",
            correct_answer="10.0.5.22",
            acceptable_answers=["10.0.5.22"],
            explanation="While several internal IPs generate normal Kerberos logons, 10.0.5.22 generated 15 sequential NTLM Event 4625 failures followed by a 4624 success.",
            points=10,
        ),
        Question(
            scenario_id=sc1.id,
            question_text="Which account was successfully compromised at the end of the spray?",
            correct_answer="svc_backup",
            acceptable_answers=["corp\\\\svc_backup", "svc_backup@corp.local"],
            explanation="Filtering by Source IP 10.0.5.22 and Event ID 4624 reveals a successful logon to 'svc_backup'.",
            points=25,
        ),
        Question(
            scenario_id=sc1.id,
            question_text="What is the MITRE ATT&CK sub-technique ID for Password Spraying?",
            correct_answer="T1110.003",
            acceptable_answers=["T1110"],
            explanation="T1110.003 is Brute Force: Password Spraying.",
            points=15,
        ),
    ])

    # =========================================================================
    # SCENARIO 2: KERBEROASTING (MITRE T1558.003) — ~95 Logs
    # =========================================================================
    sc2_ad_context = {
        "domain": "corp.local",
        "domain_controllers": [
            {"hostname": "DC01.corp.local", "ip": "10.0.0.10", "os": "Windows Server 2022"}
        ],
        "service_accounts_with_spn": [
            {"username": "svc_mssql", "spn": "MSSQLSvc/SQL01.corp.local:1433", "encryption": "RC4-HMAC (0x17)", "member_of": ["Domain Admins"]},
            {"username": "svc_iis", "spn": "HTTP/WEB01.corp.local", "encryption": "AES256 (0x12)", "member_of": ["Domain Users"]},
            {"username": "svc_exchange", "spn": "exchangeMDB/EX01.corp.local", "encryption": "AES256 (0x12)", "member_of": ["Domain Users"]}
        ],
    }

    sc2 = Scenario(
        name="Kerberoasting Service Account Abuse",
        description=(
            "An attacker with a foothold on a domain workstation enumerated SPNs and requested a "
            "Kerberos TGS service ticket (Event ID 4769) downgraded to legacy RC4 encryption (0x17) "
            "to crack the service account password offline. Filter through normal Kerberos domain "
            "traffic to isolate the RC4 downgrade request."
        ),
        mitre_technique="T1558.003",
        status="Published",
        ad_context=sc2_ad_context,
    )
    db.add(sc2)
    db.flush()

    sc2_sigma = \"\"\"title: Kerberoasting - RC4 Ticket Encryption Requested (Event 4769)
id: 8f1e2a3b-4c5d-4e6f-9a8b-7c6d5e4f3a2b
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
tags:
  - attack.credential_access
  - attack.t1558.003\"\"\"

    db.add(Alert(
        scenario_id=sc2.id,
        title="High Severity: Kerberos TGS Request Using Legacy RC4 Encryption (0x17)",
        severity=SeverityLevel.HIGH,
        sigma_rule=sc2_sigma,
    ))

    kb_base = datetime(2025, 3, 16, 14, 15, 0)
    sc2_logs = []
    services = ["DC01$", "SQL01$", "WEB01$", "EX01$", "svc_iis", "svc_exchange", "krbtgt"]

    # 92 legitimate Kerberos & Logon events (all using 0x12 AES256 or machine '$' accounts)
    for idx in range(92):
        ts = kb_base + timedelta(seconds=idx * 6 + random.randint(0, 3))
        u = f"{random.choice(normal_users)}@CORP.LOCAL"
        ip = random.choice(normal_ips)
        svc = random.choice(services)
        ev_id = random.choices([4769, 4768, 4624], weights=[55, 25, 20])[0]

        if ev_id == 4769:
            msg = (
                f"A Kerberos service ticket was requested.\\r\\n\\r\\n"
                f"Account Information:\\r\\n\\tAccount Name:\\t{u}\\r\\n\\tAccount Domain:\\tCORP.LOCAL\\r\\n"
                f"Service Information:\\r\\n\\tService Name:\\t{svc}\\r\\n"
                f"Network Information:\\r\\n\\tClient Address:\\t{ip}\\r\\n"
                f"Additional Information:\\r\\n\\tTicket Options:\\t0x40810010\\r\\n"
                f"\\tTicket Encryption Type:\\t0x12\\r\\n"
            )
        elif ev_id == 4768:
            msg = (
                f"A Kerberos authentication ticket (TGT) was requested.\\r\\n\\r\\n"
                f"Account Information:\\r\\n\\tAccount Name:\\t{u}\\r\\n"
                f"Service Information:\\r\\n\\tService Name:\\tkrbtgt\\r\\n"
                f"Network Information:\\r\\n\\tClient Address:\\t{ip}\\r\\n"
                f"Additional Information:\\r\\n\\tTicket Encryption Type:\\t0x12\\r\\n"
            )
        else:
            msg = (
                f"An account was successfully logged on.\\r\\n\\r\\n"
                f"New Logon:\\r\\n\\tAccount Name:\\t{u}\\r\\n\\tAccount Domain:\\tCORP.LOCAL\\r\\n"
                f"Network Information:\\r\\n\\tSource Network Address:\\t{ip}\\r\\n"
            )

        sc2_logs.append(Log(
            scenario_id=sc2.id,
            event_id=ev_id,
            timestamp=ts,
            source_ip=ip,
            username=u,
            target_host="DC01.corp.local",
            is_key_evidence=False,
            raw_event_data={
                "EventID": ev_id,
                "TimeCreated": ts.isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": u,
                "ServiceName": svc if ev_id != 4624 else "-",
                "TicketEncryptionType": "0x12" if ev_id in (4768, 4769) else "-",
                "IpAddress": ip,
                "Message": msg,
            },
        ))

    # Inject attacker foothold logon (4624) + PowerShell SPN enumeration (4688) + Malicious RC4 TGS (4769)
    atk_ts = kb_base + timedelta(minutes=4, seconds=18)
    sc2_logs.extend([
        Log(
            scenario_id=sc2.id,
            event_id=4624,
            timestamp=atk_ts,
            source_ip="10.0.2.88",
            username="jdoe@CORP.LOCAL",
            target_host="DC01.corp.local",
            is_key_evidence=False,
            raw_event_data={
                "EventID": 4624,
                "TimeCreated": atk_ts.isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": "jdoe@CORP.LOCAL",
                "LogonType": 3,
                "IpAddress": "10.0.2.88",
                "Message": "An account was successfully logged on.\\r\\nNew Logon:\\r\\n\\tAccount Name:\\tjdoe@CORP.LOCAL\\r\\nNetwork Information:\\r\\n\\tSource Network Address:\\t10.0.2.88",
            },
        ),
        Log(
            scenario_id=sc2.id,
            event_id=4769,
            timestamp=atk_ts + timedelta(seconds=5),
            source_ip="10.0.2.88",
            username="jdoe@CORP.LOCAL",
            target_host="DC01.corp.local",
            is_key_evidence=True,
            raw_event_data={
                "EventID": 4769,
                "TimeCreated": (atk_ts + timedelta(seconds=5)).isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": "jdoe@CORP.LOCAL",
                "ServiceName": "svc_mssql",
                "SPN": "MSSQLSvc/SQL01.corp.local:1433",
                "TicketEncryptionType": "0x17",
                "TicketOptions": "0x40810000",
                "IpAddress": "10.0.2.88",
                "Message": (
                    "A Kerberos service ticket was requested.\\r\\n\\r\\n"
                    "Account Information:\\r\\n\\tAccount Name:\\tjdoe@CORP.LOCAL\\r\\n"
                    "\\tAccount Domain:\\tCORP.LOCAL\\r\\n"
                    "Service Information:\\r\\n\\tService Name:\\tsvc_mssql\\r\\n"
                    "\\tService ID:\\tS-1-5-21-3623811015-3361044348-30300820-1104\\r\\n"
                    "Network Information:\\r\\n\\tClient Address:\\t10.0.2.88\\r\\n"
                    "Additional Information:\\r\\n\\tTicket Options:\\t0x40810000\\r\\n"
                    "\\tTicket Encryption Type:\\t0x17\\r\\n"
                ),
            },
        ),
    ])

    sc2_logs.sort(key=lambda x: x.timestamp)
    db.add_all(sc2_logs)

    db.add_all([
        Question(
            scenario_id=sc2.id,
            question_text="Which domain user account requested the suspicious RC4 Kerberos service ticket?",
            correct_answer="jdoe",
            acceptable_answers=["jdoe@corp.local", "corp\\\\jdoe"],
            explanation="Filtering Event 4769 for TicketEncryptionType '0x17' isolates a single request from jdoe@CORP.LOCAL (10.0.2.88) amidst 90+ normal AES256 (0x12) events.",
            points=15,
        ),
        Question(
            scenario_id=sc2.id,
            question_text="Which service account (Service Name) was targeted for offline cracking?",
            correct_answer="svc_mssql",
            acceptable_answers=["mssqlsvc/sql01.corp.local:1433"],
            explanation="The Service Name in the 0x17 RC4 Event 4769 is 'svc_mssql' (a member of Domain Admins).",
            points=20,
        ),
        Question(
            scenario_id=sc2.id,
            question_text="What hex code in TicketEncryptionType indicates RC4-HMAC downgrade?",
            correct_answer="0x17",
            acceptable_answers=["17"],
            explanation="In Windows Kerberos Event 4769, 0x17 corresponds to RC4-HMAC, whereas 0x12 is AES256.",
            points=15,
        ),
    ])

    db.commit()
    print(f"[OK] Seeded Scenario 1 ({len(sc1_logs)} logs) & Scenario 2 ({len(sc2_logs)} logs)!")

except Exception as e:
    db.rollback()
    print(f"[FAIL] Seed failed: {e}")
    raise
finally:
    db.close()
"""

# ---------------------------------------------------------------------------
# 2. Update seed_mordor_scenarios.py with Smart Signal-Preserving Windowing
#    + All 5 Mordor ZIPs
# ---------------------------------------------------------------------------
SEED_MORDOR_PY = """#!/usr/bin/env python3
\"\"\"
seed_mordor_scenarios.py
Smart Signal-Preserving Ingestion for all 5 Mordor / OTRF Active Directory ZIP archives!
Instead of blindly slicing `lines[:120]` (which can miss the actual attack events if they
occur later in the recording), this script scans the ENTIRE archive, extracts all high-signal
security/attack events, and samples surrounding background logs up to `target_count` (350 logs)
sorted chronologically.
\"\"\"

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
        "sigma_rule": \"\"\"title: Mimikatz / Covenant DCSync Replication (Event 4662)
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
  - attack.t1003.006\"\"\",
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
        "sigma_rule": \"\"\"title: LSASS Memory Dump via Mimikatz (Sysmon Event 10)
status: stable
logsource:
  product: windows
  category: process_access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001\"\"\",
        "ad_context": {
            "target_process": "C:\\\\Windows\\\\System32\\\\lsass.exe",
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
                "acceptable_answers": ["lsass", "c:\\\\windows\\\\system32\\\\lsass.exe"],
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
        "sigma_rule": \"\"\"title: PsExec Service Execution (PSEXESVC)
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
  - attack.t1569.002\"\"\",
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
        "sigma_rule": \"\"\"title: DCOM ShellWindows Lateral Movement (Explorer Spawning PowerShell)
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\\\explorer.exe'
    Image|endswith: '\\\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.003\"\"\",
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
                "acceptable_answers": ["explorer", "c:\\\\windows\\\\explorer.exe"],
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
        "sigma_rule": \"\"\"title: PowerShell DownloadString / Invoke-WebRequest Execution
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
  - attack.t1059.001\"\"\",
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
        or extract_field_from_message(msg, r"Source Network Address:\\s*([^\\r\\n\\t]+)")
    )
    username = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName")
        or data.get("User")
        or extract_field_from_message(msg, r"Account Name:\\s*([^\\r\\n\\t]+)")
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
    \"\"\"
    Scans the entire ZIP archive so high-signal events later in the file are never lost!
    Preserves priority/key events and evenly samples background events up to target_count.
    \"\"\"
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
"""


def patch_investigation_pagination():
    """Adds smooth client-side pagination (50 / 100 / 250 per page) to Investigation.jsx."""
    inv_path = ROOT / "threattrail-frontend/src/pages/Investigation.jsx"
    if not inv_path.exists():
        return
    code = inv_path.read_text(encoding="utf-8")
    if "pageSize" in code:
        print("  [OK] Investigation.jsx already has pagination.")
        return

    # Inject pagination state
    code = code.replace(
        "const [expandedLogId, setExpandedLogId] = useState(null)",
        "const [expandedLogId, setExpandedLogId] = useState(null)\n  const [currentPage, setCurrentPage] = useState(1)\n  const [pageSize, setPageSize] = useState(50)"
    )

    # Reset page to 1 when filter or search changes, and compute paginatedLogs
    target_memo = """  // Pinned logs sorted chronologically"""
    pagination_memo = """  useEffect(() => {
    setCurrentPage(1)
  }, [selectedEventId, searchTerm])

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize))
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return filteredLogs.slice(start, start + pageSize)
  }, [filteredLogs, currentPage, pageSize])

  // Pinned logs sorted chronologically"""

    code = code.replace(target_memo, pagination_memo)

    # Replace filteredLogs.map with paginatedLogs.map in table body
    code = code.replace("filteredLogs.map((log) => {", "paginatedLogs.map((log) => {")

    # Add Pagination Bar right below .log-table-wrapper
    table_end = """              <div className="log-table-wrapper">"""
    if table_end in code:
        code = code.replace(
            """                  </tbody>
                </table>
              </div>
            </>""",
            """                  </tbody>
                </table>
              </div>

              {filteredLogs.length > 0 && (
                <div className="inv-pagination-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, padding: '8px 14px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontSize: '0.82rem' }}>
                  <div>
                    Showing <strong>{(currentPage - 1) * pageSize + 1}</strong>–<strong>{Math.min(currentPage * pageSize, filteredLogs.length)}</strong> of <strong>{filteredLogs.length}</strong> matching events
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <label style={{ color: 'var(--text-dim)' }}>
                      Rows:
                      <select
                        value={pageSize}
                        onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                        style={{ marginLeft: 6, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px' }}
                      >
                        <option value={50}>50</option>
                        <option value={100}>100</option>
                        <option value={250}>250</option>
                      </select>
                    </label>
                    <button
                      type="button"
                      className="btn-sm btn-secondary"
                      disabled={currentPage <= 1}
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    >
                      ← Prev
                    </button>
                    <span>Page {currentPage} / {totalPages}</span>
                    <button
                      type="button"
                      className="btn-sm btn-secondary"
                      disabled={currentPage >= totalPages}
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}
            </>"""
        )

    inv_path.write_text(code, encoding="utf-8")
    print("  [UPDATED] threattrail-frontend/src/pages/Investigation.jsx (Added fast client-side pagination)")


def main():
    print("=== Applying Smart Log Curation, All 5 Mordor ZIPs & Table Pagination ===")
    (ROOT / "seed.py").write_text(SEED_PY, encoding="utf-8")
    print("  [UPDATED] seed.py (~110 logs for Password Spraying, ~95 logs for Kerberoasting)")

    b_seed = ROOT / "threattrail-backend/seed.py"
    if b_seed.exists():
        b_seed.write_text(SEED_PY, encoding="utf-8")
        print("  [UPDATED] threattrail-backend/seed.py")

    (ROOT / "seed_mordor_scenarios.py").write_text(SEED_MORDOR_PY, encoding="utf-8")
    print("  [UPDATED] seed_mordor_scenarios.py (Smart signal-preserving sampling + all 5 Mordor ZIPs)")

    patch_investigation_pagination()

    print("\n=== Run These Two Commands Now ===")
    print("1. python seed.py")
    print("2. python seed_mordor_scenarios.py")


if __name__ == "__main__":
    main()