"""
Seed script — populates the ThreatTrail database with one complete scenario:
  Password Spraying (MITRE T1110.003)

Run:  python seed.py
"""

from datetime import datetime, timedelta
from database import engine, SessionLocal, Base
from models import User, Scenario, Alert, Log, Question, SeverityLevel

# ── 1. Create tables ─────────────────────────────────────────────────────────

Base.metadata.drop_all(bind=engine)   # fresh start
Base.metadata.create_all(bind=engine)
print("[+] Tables created.")

db = SessionLocal()

try:
    # ── 2. Seed default users ──────────────────────────────────────────────
    import bcrypt
    admin_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
    analyst_hash = bcrypt.hashpw(b"analyst123", bcrypt.gensalt()).decode("utf-8")

    admin_user = User(
        username="admin",
        password_hash=admin_hash,
        role="admin",
    )
    db.add(admin_user)

    analyst_user = User(
        username="analyst",
        password_hash=analyst_hash,
        role="user",
    )
    db.add(analyst_user)
    db.flush()
    print("[+] Default users 'admin' (admin) and 'analyst' (user) created.")

    # ── 3. Scenario ───────────────────────────────────────────────────────────

    scenario = Scenario(
        name="Password Spraying",
        description=(
            "A threat actor is attempting to authenticate to multiple user accounts "
            "using a small set of commonly-used passwords. This technique avoids "
            "account lockout thresholds by spreading attempts across many accounts. "
            "Investigate the Windows Security logs to identify the source, compromised "
            "account, and the ATT&CK technique."
        ),
        mitre_technique="T1110.003",
        status="Published",
    )
    db.add(scenario)
    db.flush()  # get scenario.id
    print(f"[+] Scenario '{scenario.name}' created (id={scenario.id}).")

    # ── 4. Alert ──────────────────────────────────────────────────────────────

    alert = Alert(
        scenario_id=scenario.id,
        title="Possible Password Spraying Detected — Multiple Failed Logons From Single Source",
        severity=SeverityLevel.HIGH,
    )
    db.add(alert)
    print("[+] Alert created.")

    # ── 5. Logs (15 × Event 4625 + 1 × Event 4624) ───────────────────────────

    ATTACKER_IP = "10.0.5.22"
    TARGET_HOST = "DC01.corp.local"
    COMPROMISED_USER = "svc_backup"
    base_time = datetime(2024, 3, 15, 2, 14, 30)

    # The 15 target usernames the attacker tried (and failed)
    spray_targets = [
        "jsmith", "agarcia", "mwilliams", "kjohnson", "lbrown",
        "dlee", "rmartin", "pthompson", "cwilson", "nanderson",
        "btaylor", "hmoore", "fwhite", "eharris", "jclark",
    ]

    log_entries = []

    # 15 failed logons (Event 4625)
    for i, target_user in enumerate(spray_targets):
        ts = base_time + timedelta(seconds=i * 3)  # 3 seconds apart
        raw = {
            "EventID": 4625,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": ts.isoformat(),
            "Hostname": TARGET_HOST,
            "Channel": "Security",
            "Task": "12544",
            "Keywords": "Audit Failure",
            "Message": (
                f"An account failed to log on.\r\n\r\n"
                f"Subject:\r\n"
                f"\tSecurity ID:\tS-1-0-0\r\n"
                f"\tAccount Name:\t-\r\n"
                f"\tAccount Domain:\t-\r\n"
                f"\tLogon ID:\t0x0\r\n\r\n"
                f"Logon Information:\r\n"
                f"\tLogon Type:\t3\r\n"
                f"\tRestricted Admin Mode:\t-\r\n"
                f"\tAccount For Which Logon Failed:\r\n"
                f"\t\tSecurity ID:\tS-1-0-0\r\n"
                f"\t\tAccount Name:\t{target_user}\r\n"
                f"\t\tAccount Domain:\tCORP\r\n"
                f"\tFailure Information:\r\n"
                f"\t\tFailure Reason:\tUnknown user name or bad password.\r\n"
                f"\t\tStatus:\t0xC000006D\r\n"
                f"\t\tSub Status:\t0xC000006A\r\n\r\n"
                f"Network Information:\r\n"
                f"\tWorkstation Name:\tATTACKER-WS\r\n"
                f"\tSource Network Address:\t{ATTACKER_IP}\r\n"
                f"\tSource Port:\t{49152 + i}\r\n\r\n"
                f"Authentication Information:\r\n"
                f"\tLogon Process:\tNtLmSsp\r\n"
                f"\tAuthentication Package:\tNTLM\r\n"
            ),
        }
        log_entries.append(Log(
            scenario_id=scenario.id,
            event_id=4625,
            timestamp=ts,
            source_ip=ATTACKER_IP,
            username=target_user,
            target_host=TARGET_HOST,
            raw_event_data=raw,
        ))

    # 1 successful logon (Event 4624) — the compromised account
    success_ts = base_time + timedelta(seconds=len(spray_targets) * 3 + 5)
    success_raw = {
        "EventID": 4624,
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "TimeCreated": success_ts.isoformat(),
        "Hostname": TARGET_HOST,
        "Channel": "Security",
        "Task": "12544",
        "Keywords": "Audit Success",
        "Message": (
            f"An account was successfully logged on.\r\n\r\n"
            f"Subject:\r\n"
            f"\tSecurity ID:\tS-1-0-0\r\n"
            f"\tAccount Name:\t-\r\n"
            f"\tAccount Domain:\t-\r\n"
            f"\tLogon ID:\t0x0\r\n\r\n"
            f"Logon Information:\r\n"
            f"\tLogon Type:\t3\r\n"
            f"\tNew Logon:\r\n"
            f"\t\tSecurity ID:\tS-1-5-21-3623811015-3361044348-30300820-1013\r\n"
            f"\t\tAccount Name:\t{COMPROMISED_USER}\r\n"
            f"\t\tAccount Domain:\tCORP\r\n"
            f"\t\tLogon ID:\t0x1A2B3C\r\n"
            f"\t\tLogon GUID:\t{{00000000-0000-0000-0000-000000000000}}\r\n\r\n"
            f"Network Information:\r\n"
            f"\tWorkstation Name:\tATTACKER-WS\r\n"
            f"\tSource Network Address:\t{ATTACKER_IP}\r\n"
            f"\tSource Port:\t{49152 + len(spray_targets)}\r\n\r\n"
            f"Authentication Information:\r\n"
            f"\tLogon Process:\tNtLmSsp\r\n"
            f"\tAuthentication Package:\tNTLM\r\n"
        ),
    }
    log_entries.append(Log(
        scenario_id=scenario.id,
        event_id=4624,
        timestamp=success_ts,
        source_ip=ATTACKER_IP,
        username=COMPROMISED_USER,
        target_host=TARGET_HOST,
        raw_event_data=success_raw,
    ))

    db.add_all(log_entries)
    print(f"[+] {len(log_entries)} log entries created (15 failed + 1 success).")

    # ── 6. Questions ──────────────────────────────────────────────────────────

    questions = [
        Question(
            scenario_id=scenario.id,
            question_text="What is the source IP address of the attacker?",
            correct_answer="10.0.5.22",
            points=10,
        ),
        Question(
            scenario_id=scenario.id,
            question_text="Which account was successfully compromised?",
            correct_answer="svc_backup",
            points=25,
        ),
        Question(
            scenario_id=scenario.id,
            question_text="What is the MITRE ATT&CK technique ID for this attack?",
            correct_answer="T1110.003",
            points=15,
        ),
    ]
    db.add_all(questions)
    print(f"[+] {len(questions)} investigation questions created.")

    # ── Commit everything ─────────────────────────────────────────────────────

    db.commit()
    print("\n[OK] Database seeded successfully!")

except Exception as e:
    db.rollback()
    print(f"\n[FAIL] Seed failed: {e}")
    raise
finally:
    db.close()
