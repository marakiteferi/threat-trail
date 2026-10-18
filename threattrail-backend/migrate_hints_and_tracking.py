import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent / "threattrail.db"
print(f"Migrating database at: {db_path}")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

# 1. Update questions table
cur.execute("PRAGMA table_info(questions);")
q_cols = [r[1] for r in cur.fetchall()]
if "hint" not in q_cols:
    print("[+] Adding 'hint' column to questions table...")
    cur.execute("ALTER TABLE questions ADD COLUMN hint TEXT;")

# 2. Update investigation_results table
cur.execute("PRAGMA table_info(investigation_results);")
ir_cols = [r[1] for r in cur.fetchall()]
if "hints_used" not in ir_cols:
    print("[+] Adding 'hints_used' column to investigation_results table...")
    cur.execute("ALTER TABLE investigation_results ADD COLUMN hints_used JSON;")
if "trials_count" not in ir_cols:
    print("[+] Adding 'trials_count' column to investigation_results table...")
    cur.execute("ALTER TABLE investigation_results ADD COLUMN trials_count INTEGER DEFAULT 1;")
if "user_guesses" not in ir_cols:
    print("[+] Adding 'user_guesses' column to investigation_results table...")
    cur.execute("ALTER TABLE investigation_results ADD COLUMN user_guesses JSON;")
if "submitted_at" not in ir_cols:
    print("[+] Adding 'submitted_at' column to investigation_results table...")
    cur.execute("ALTER TABLE investigation_results ADD COLUMN submitted_at DATETIME;")

conn.commit()

# 3. Populate realistic, helpful hints for existing questions
cur.execute("SELECT id, scenario_id, question_text, correct_answer FROM questions;")
rows = cur.fetchall()

hints_dict = {
    # Scenario 1: Password Spraying
    "What is the source IP of the attacker": "Filter the log viewer by Event ID 4625 (Failed Logon). Look at the source IP address that appears in rapid succession across multiple user accounts.",
    "Which user account was successfully compromised": "Check for an Event ID 4624 (Successful Logon) originating from the attacker's IP right after the failed attempts. Alternatively, inspect the last event in the spray sequence.",
    "What is the MITRE ATT&CK sub-technique ID": "Password Spraying is classified under Credential Access (T1110). Specifically look up the sub-technique ID for Password Spraying (format: T1110.00X).",
    
    # Scenario 2: Kerberoasting
    "What is the service principal name (SPN)": "Filter by Event ID 4769 (Kerberos Service Ticket Request). Inspect the ServiceName field for non-machine SPNs requested with RC4 encryption (0x17).",
    "Which encryption type was requested": "Look at the TicketEncryptionType field in Event ID 4769. Attackers downgrade to weak legacy encryption (0x17 = RC4-HMAC) to crack tickets offline.",
    "What account requested the ticket": "Look at the TargetUserName or Account Name in the suspicious Event 4769 request.",
}

updated_count = 0
for q_id, sc_id, q_text, ans in rows:
    hint_text = None
    for pattern, h in hints_dict.items():
        if pattern.lower() in q_text.lower():
            hint_text = h
            break
    
    if not hint_text:
        if "ip" in q_text.lower():
            hint_text = "Search the logs for external or anomalous IP addresses generating security events."
        elif "technique" in q_text.lower() or "mitre" in q_text.lower():
            hint_text = "Check the scenario description or MITRE ATT&CK matrix for this specific tactic and sub-technique (format: T1xxx.xxx)."
        elif "user" in q_text.lower() or "account" in q_text.lower():
            hint_text = "Check the Username column in the high-signal security events."
        elif "process" in q_text.lower() or "command" in q_text.lower():
            hint_text = "Filter by Event ID 4688 or Sysmon Event 1 and inspect NewProcessName / CommandLine."
        else:
            hint_text = "Cross-reference the relevant Event IDs in the log viewer with the scenario alert and Active Directory topology."

    cur.execute("UPDATE questions SET hint = ? WHERE id = ?;", (hint_text, q_id))
    updated_count += 1

conn.commit()
print(f"[OK] Successfully populated hints for {updated_count} questions.")
conn.close()
