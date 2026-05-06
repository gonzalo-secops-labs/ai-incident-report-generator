import json
import re
from typing import Dict, List, Optional

import prompts

try:
    import openai  # type: ignore
except Exception:  # pragma: no cover
    openai = None


def classify_incident_type(notes: str) -> str:
    text = notes.lower()

    phishing_terms = [
        "phishing",
        "email",
        "sender",
        "subject",
        "url",
        "link",
        "attachment",
        "mailbox",
        "spf",
        "dkim",
        "dmarc",
        "user clicked",
    ]
    login_terms = [
        "impossible travel",
        "login",
        "sign-in",
        "signin",
        "mfa",
        "oauth",
        "conditional access",
        "session",
        "source ip",
        "geo",
        "account",
        "identity",
    ]
    malware_terms = [
        "malware",
        "endpoint",
        "process",
        "hash",
        "file",
        "edr",
        "persistence",
        "isolation",
        "quarantine",
        "command line",
        "process tree",
        "payload",
        "ransomware",
        "beacon",
    ]

    def score(terms: List[str]) -> int:
        return sum(1 for term in terms if term in text)

    scores = {
        "phishing": score(phishing_terms),
        "suspicious_login": score(login_terms),
        "malware": score(malware_terms),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "generic"


def _contains_any(text: str, terms: List[str]) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


def _extract_field(notes: str, label: str) -> Optional[str]:
    pattern = rf"^\s*{re.escape(label)}\s*:\s*(.+)\s*$"
    match = re.search(pattern, notes, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return None
    value = match.group(1).strip()
    return value if value else None


def _extract_urls(notes: str) -> List[str]:
    candidates = re.findall(r"https?://[^\s\)\]\>\"']+", notes, flags=re.IGNORECASE)
    # also pick up bare domains that look like indicators
    candidates += re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", notes, flags=re.IGNORECASE)

    cleaned: List[str] = []
    for item in candidates:
        item = item.strip().rstrip(".,;)")
        if item and item not in cleaned:
            cleaned.append(item)
    return cleaned[:5]


def extract_phishing_hints(notes: str) -> Dict[str, object]:
    text = notes.lower()
    return {
        "subject": _extract_field(notes, "Subject"),
        "sender": _extract_field(notes, "From"),
        "recipient": _extract_field(notes, "To"),
        "urls": _extract_urls(notes),
        "has_spf": "spf" in text,
        "has_dkim": "dkim" in text,
        "has_dmarc": "dmarc" in text,
        "mentions_click": _contains_any(text, ["clicked", "user clicked", "click", "opened"]),
        "mentions_attachment": "attachment" in text,
        "mentions_quarantine": _contains_any(text, ["quarantine", "removed", "purge", "contain", "mailbox search"]),
    }


def extract_login_hints(notes: str) -> Dict[str, object]:
    text = notes.lower()
    privileged = _contains_any(text, ["cloud-admin", "admin", "administrator", "privileged", "global admin"])
    geos: List[str] = []
    for m in re.findall(r"from\s+([A-Za-z][A-Za-z .'-]{2,40})", notes):
        geo = m.strip()
        if geo and geo.lower() not in [g.lower() for g in geos]:
            geos.append(geo)
    return {
        "account": _extract_field(notes, "account") or _extract_field(notes, "user"),
        "mentions_impossible_travel": "impossible travel" in text,
        "mentions_mfa": "mfa" in text,
        "mentions_oauth": "oauth" in text,
        "mentions_session": _contains_any(text, ["session", "token", "cookie"]),
        "mentions_account_changes": _contains_any(text, ["reset", "password", "revok", "disable", "paused", "changed"]),
        "privileged": privileged,
        "geos": geos[:3],
    }


def extract_malware_hints(notes: str) -> Dict[str, object]:
    text = notes.lower()
    host = _extract_field(notes, "Host") or _extract_field(notes, "Endpoint")
    if not host:
        # fallback: try to capture patterns like endpoint-49
        m = re.search(r"\b(endpoint[-_ ]?\d+|host[-_ ]?\d+)\b", notes, flags=re.IGNORECASE)
        host = m.group(1) if m else None

    file_paths = re.findall(r"[A-Za-z]:\\[^\s\]\)\>\"']+", notes)
    hashes = re.findall(r"\b[a-f0-9]{32,64}\b", notes, flags=re.IGNORECASE)

    return {
        "host": host,
        "file_paths": file_paths[:3],
        "hashes": hashes[:3],
        "mentions_process_tree": _contains_any(text, ["process tree", "parent", "child", "lineage"]),
        "mentions_command_line": "command line" in text,
        "mentions_download": _contains_any(text, ["download", "payload", "ingress tool transfer"]),
        "mentions_beacon": _contains_any(text, ["beacon", "callback", "c2", "command and control"]),
        "mentions_isolation": _contains_any(text, ["isolated", "isolation", "quarantine"]),
        "mentions_persistence": "persistence" in text,
        "mentions_lateral": _contains_any(text, ["lateral", "remote", "smb", "psexec"]),
        "mentions_ransomware": _contains_any(
            text,
            [
                "ransomware",
                "ransom note",
                "files encrypted",
                "encrypted files",
                "file encryption",
                "data encrypted",
                "data encryption impact",
                "encrypted extension",
                "restore files",
                "decrypt",
                "decryption demand",
            ],
        ),
    }


def infer_mitre_attack(notes: str, incident_type: str) -> List[str]:
    text = notes.lower()
    techniques: List[str] = []

    if incident_type == "phishing":
        techniques.append("T1566 - Phishing")
        if _contains_any(text, ["url", "link", "http", "https"]):
            techniques.append("T1566.002 - Spearphishing Link")
        if _contains_any(text, ["attachment", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".zip"]):
            techniques.append("T1566.001 - Spearphishing Attachment")
        if _contains_any(text, ["clicked", "user clicked", "opened", "enabled macros", "executed"]):
            techniques.append("T1204 - User Execution")
        if _contains_any(text, ["c2", "command and control", "beaconing", "beacon", "callback"]):
            if _contains_any(text, ["http", "https", "web"]):
                techniques.append("T1071.001 - Application Layer Protocol: Web Protocols")

    if incident_type == "suspicious_login":
        techniques.append("T1078 - Valid Accounts")
        if _contains_any(text, ["failed login", "failed sign-in", "password spraying", "brute force", "password guess", "guessing"]):
            techniques.append("T1110 - Brute Force")
        if _contains_any(text, ["session cookie", "steal cookie", "cookie theft", "stolen cookie", "session hijack"]):
            techniques.append("T1539 - Steal Web Session Cookie")
        if _contains_any(text, ["oauth", "mailbox rule", "forward", "inbox rule", "mfa change", "privilege", "role change", "account change", "app consent"]):
            techniques.append("T1098 - Account Manipulation")

    if incident_type == "malware":
        if _contains_any(text, ["powershell", "cmd", "bash", "python", "script"]):
            techniques.append("T1059 - Command and Scripting Interpreter")
        if _contains_any(text, ["download", "payload", "ingress", "curl", "wget"]):
            techniques.append("T1105 - Ingress Tool Transfer")
        if _contains_any(text, ["opened", "clicked", "attachment", "user executed"]):
            techniques.append("T1204 - User Execution")
        if _contains_any(text, ["process injection", "inject"]):
            techniques.append("T1055 - Process Injection")
        if _contains_any(text, ["startup", "run key", "autorun", "scheduled task", "persistence"]):
            techniques.append("T1547 - Boot or Logon Autostart Execution")
        if _contains_any(
            text,
            [
                "ransomware",
                "ransom note",
                "files encrypted",
                "encrypted files",
                "file encryption",
                "data encrypted",
                "data encryption impact",
                "encrypted extension",
                "restore files",
                "decrypt",
                "decryption demand",
            ],
        ):
            techniques.append("T1486 - Data Encrypted for Impact")

    unique = []
    for t in techniques:
        if t not in unique:
            unique.append(t)
    return unique


def _format_mitre(techniques: List[str]) -> str:
    if not techniques:
        return "No relevant ATT&CK mapping can be asserted from the provided notes."
    return "Potential mapping based on provided notes:\n- " + "\n- ".join(techniques)


def _normalize_sections_from_json_payload(payload: str, required_sections: List[str]) -> Dict[str, str]:
    trimmed = payload.strip()
    data: Dict[str, str] = {}
    try:
        data = json.loads(trimmed)
    except json.JSONDecodeError:
        # look for JSON substring inside completion
        start = trimmed.find("{")
        end = trimmed.rfind("}")
        if start != -1 and end != -1 and start < end:
            try:
                data = json.loads(trimmed[start : end + 1])
            except json.JSONDecodeError:
                data = {}

    if not data:
        fallback = {}
        for idx, section in enumerate(required_sections):
            fallback[section] = (
                trimmed if idx == 0 else "Awaiting structured response; see the first section for details."
            )
        return fallback

    return {section: str(data.get(section, "Information unavailable.")).strip() for section in required_sections}


def _mock_human_review() -> str:
    return "Human review required before use. Validate timeline, scope, evidence, customer-facing language, and any recommended actions before sharing."


def _mock_tech_next_steps(incident_type: str) -> str:
    if incident_type == "phishing":
        return "- Validate sender domain and header authentication results (SPF/DKIM/DMARC) if available.\n- Validate URL reputation and redirect chain for the reported link.\n- Confirm whether any users received and/or clicked the link.\n- Search mailboxes for similar messages and remove/quarantine if confirmed malicious.\n- Add confirmed IOCs (domain/URL) to block lists where appropriate."
    if incident_type == "suspicious_login":
        return "- Review sign-in logs (source IP/geo, device, app, MFA result) for the time window referenced.\n- Confirm legitimacy with the account owner (travel/VPN) and validate sign-in context.\n- Review active sessions and revoke/reset credentials if unauthorized activity is confirmed.\n- Review recent account changes and OAuth app consents only if evidence in logs supports it."
    if incident_type == "malware":
        return "- Review the EDR alert details, process tree, and command-line arguments (if available).\n- Capture file paths and hashes (if available) and scope across endpoints.\n- Validate quarantine/isolation status and whether the process is still running.\n- Check persistence locations and lateral movement indicators if supported by telemetry."
    return "- Validate scope and impacted assets\n- Gather additional logs\n- Confirm containment actions"


def _mock_summary(inferred_type: str, notes: str) -> str:
    if inferred_type == "phishing":
        return "The notes describe a suspected phishing email containing a reported link, requiring validation of sender authenticity, URL reputation/redirect behavior, and any user interaction."
    if inferred_type == "suspicious_login":
        return "The notes describe impossible-travel style sign-in activity requiring identity validation, MFA outcome review, and session/account scoping."
    if inferred_type == "malware":
        return "The notes describe an endpoint security alert involving suspicious process and network behavior, requiring EDR-centric validation and containment."
    return f"The notes describe a security event requiring triage and validation: {notes[:140]}..."


def _mock_actions_taken(inferred_type: str) -> str:
    if inferred_type == "phishing":
        return "- Preserved available email headers and message artifacts.\n- Submitted reported domain/URL for enrichment or blocking review.\n- Initiated containment steps described in the notes (e.g., isolate message, user notification)."
    if inferred_type == "suspicious_login":
        return "- Reviewed sign-in context (source IP/geo) and MFA outcomes referenced in the notes.\n- Initiated account/session containment actions described in the notes.\n- Exported audit logs for follow-up and escalation review."
    if inferred_type == "malware":
        return "- Isolated/quarantined the endpoint as described in the notes.\n- Preserved relevant telemetry (process tree/network connections) where available.\n- Began IOC scoping across the environment based on available indicators."
    return "- Collected initial evidence\n- Initiated containment steps described in notes"


def generate_mock_report(notes: str, output_type: str, incident_type: Optional[str] = None) -> Dict[str, str]:
    inferred_type = incident_type or classify_incident_type(notes)
    mitre = _format_mitre(infer_mitre_attack(notes, inferred_type))
    safe_notes = notes.strip() or "No notes were entered; analyst will need to supply details."

    phishing_hints = extract_phishing_hints(safe_notes) if inferred_type == "phishing" else {}
    login_hints = extract_login_hints(safe_notes) if inferred_type == "suspicious_login" else {}
    malware_hints = extract_malware_hints(safe_notes) if inferred_type == "malware" else {}

    sections = prompts.sections_for_output_type(output_type)
    base: Dict[str, str] = {key: "" for key in sections}
    base["Human Review Required"] = _mock_human_review()

    if output_type == "Executive Summary":
        if inferred_type == "suspicious_login":
            account = login_hints.get("account")
            privileged = "privileged/cloud admin" if login_hints.get("privileged") else "account"
            base["What Happened"] = (
                "The notes describe impossible-travel style sign-in activity "
                + (f"involving the {privileged} {account}." if account else f"involving a {privileged}.")
            )
            base["Current Assessment"] = (
                "The activity requires identity validation due to the short time window between geographically distant sign-ins. "
                "Final compromise determination requires review of MFA results, session activity, and any account changes referenced in logs."
            )
            base["Business / Operational Impact"] = (
                "Potential impact is elevated if the account has administrative access. "
                "Do not state confirmed data access or exfiltration unless supported by logs referenced in the notes."
            )
            base["Recommended Next Step"] = (
                "Review sign-in logs, MFA results, active sessions, OAuth applications (if present), and recent account changes."
            )
            base["MITRE ATT&CK References"] = mitre
            return base

        base["What Happened"] = _mock_summary(inferred_type, safe_notes)
        base["Current Assessment"] = "The activity warrants validation. Based on the provided notes, final determination of compromise and scope is not yet confirmed."
        base["Business / Operational Impact"] = "No confirmed business impact is stated in the notes. Impact should be treated as unknown until scope validation completes."
        base["Recommended Next Step"] = _mock_tech_next_steps(inferred_type).split("\n", 1)[0].lstrip("- ")
        base["MITRE ATT&CK References"] = mitre
        return base

    if output_type == "Client Update":
        if inferred_type == "phishing":
            subject = phishing_hints.get("subject")
            reviewed = "We reviewed the reported email"
            if subject:
                reviewed += f" with subject '{subject}',"
            reviewed += " including the sender details, the reported link, and available message artifacts."

            observed = (
                "The notes describe a suspicious message containing a link to an external domain. "
                "The investigation should validate sender authenticity, URL reputation, redirect behavior, "
                "and whether additional users received or interacted with the message."
            )
            base["What We Reviewed"] = reviewed
            base["What We Observed"] = observed
        else:
            base["What We Reviewed"] = "We reviewed the activity described in the provided notes and the referenced artifacts (logs, headers, telemetry, and enrichment)."
            base["What We Observed"] = _mock_summary(inferred_type, safe_notes)

        base["Current Assessment"] = "This is an initial assessment based on the notes provided. Scope and root cause remain to be validated."
        base["Actions Taken"] = _mock_actions_taken(inferred_type)
        base["Recommended Next Steps"] = _mock_tech_next_steps(inferred_type)
        base["What Still Needs Confirmation"] = "Confirm scope, affected identities/endpoints, and whether any suspicious activity continued after containment."
        base["MITRE ATT&CK References"] = mitre
        return base

    if output_type == "Technical Findings":
        if inferred_type == "malware":
            host = malware_hints.get("host")
            ctx = "The notes describe an endpoint alert involving suspicious process behavior"
            if malware_hints.get("mentions_download"):
                ctx += " and possible payload download activity"
            ctx += "."
            if host:
                ctx += f" Affected host referenced in notes: {host}."
            base["Alert Context"] = ctx

            ev = ["- EDR alert details."]
            if malware_hints.get("mentions_process_tree"):
                ev.append("- Process tree and parent/child lineage (if available).")
            if malware_hints.get("mentions_command_line"):
                ev.append("- Command-line arguments (if available).")
            if malware_hints.get("file_paths"):
                ev.append("- File path details referenced in notes.")
            if malware_hints.get("hashes"):
                ev.append("- Hash details referenced in notes.")
            ev.append("- Network connection indicators if available.")
            base["Evidence Reviewed"] = "\n".join(ev)

            indicators = ["- Suspicious process behavior."]
            if malware_hints.get("mentions_download"):
                indicators.append("- Possible payload download.")
            if malware_hints.get("mentions_beacon"):
                indicators.append("- Potential beaconing/command-and-control indicators (requires validation).")
            if malware_hints.get("mentions_lateral"):
                indicators.append("- Potential lateral movement indicators (if supported by telemetry).")
            if malware_hints.get("mentions_ransomware"):
                indicators.append("- Ransomware/encryption indicators are referenced in notes.")
            base["Observed Indicators"] = "\n".join(indicators)
        else:
            base["Alert Context"] = _mock_summary(inferred_type, safe_notes)
            base["Evidence Reviewed"] = "- Evidence is limited to what is referenced in the notes.\n- Typical sources include email headers, sign-in logs, EDR telemetry, audit trails, and IOC enrichment."
            base["Observed Indicators"] = f"Key indicators (from notes): {safe_notes[:220]}..."

        base["Relevant MITRE ATT&CK References"] = mitre
        base["Validation Gaps"] = "- Confirm scope beyond the items explicitly referenced.\n- Validate identity/device legitimacy and whether activity persisted after containment.\n- Confirm whether related alerts occurred outside the provided notes."
        base["Recommended Technical Next Steps"] = _mock_tech_next_steps(inferred_type)
        return base

    if output_type == "Internal Ticket Notes":
        summary_line = safe_notes[:160] + ("..." if len(safe_notes) > 160 else "")
        if inferred_type == "phishing" and phishing_hints.get("subject"):
            summary_line = f"Reported email subject: '{phishing_hints.get('subject')}'."
        if inferred_type == "malware" and malware_hints.get("host"):
            summary_line = f"Affected host: {malware_hints.get('host')}."

        base["Triage Summary"] = f"- Type: {inferred_type}\n- Summary: {summary_line}"
        base["Evidence Checked"] = "- Reviewed artifacts referenced in notes (logs/telemetry/headers)\n- Confirmed alert correlation where possible"
        base["Actions Completed"] = _mock_actions_taken(inferred_type)
        base["Pending Validation"] = "- Confirm scope and whether activity persists\n- Confirm user/device legitimacy\n- Validate any referenced IOCs are blocked"
        base["Next Owner / Action"] = "- Next shift: continue validation + hunt for related activity\n- If unauthorized, perform account/session remediation per playbook"
        base["Escalation Criteria"] = "- Evidence of persistence/lateral movement\n- Access to sensitive data confirmed\n- Repeat alerts after containment"
        base["MITRE ATT&CK References"] = mitre
        return base

    if output_type == "Full Incident Report":
        base["Incident Summary"] = _mock_summary(inferred_type, safe_notes)
        base["Scope"] = "Scope is limited to what is explicitly referenced in the notes; broader impact is unknown until validation completes."
        base["Timeline / Known Sequence"] = "Known sequence is based strictly on the notes (timestamps may be incomplete or absent)."
        base["Evidence Reviewed"] = "- Evidence cited in notes (email headers/audit logs/EDR telemetry/IOC enrichment).\n- Additional evidence is not assumed unless explicitly stated in notes."
        base["Confirmed Findings"] = "Confirmed findings are limited to observations explicitly described in the notes."
        base["Unknowns / Validation Needed"] = "Validate: affected users/endpoints, persistence indicators, and whether activity continued after containment."
        base["MITRE ATT&CK References"] = mitre
        base["Impact Assessment"] = "Impact is unknown or limited based on provided notes; do not overstate without corroboration."
        base["Actions Taken"] = _mock_actions_taken(inferred_type)
        base["Recommendations"] = _mock_tech_next_steps(inferred_type)
        return base

    return base


def generate_live_report(
    notes: str,
    output_type: str,
    api_key: str,
    model: str,
    incident_type: Optional[str] = None,
) -> Dict[str, str]:
    if openai is None:
        raise RuntimeError("OpenAI SDK is not installed. Install dependencies or use mock mode.")

    inferred_type = incident_type or classify_incident_type(notes)
    required_sections = prompts.sections_for_output_type(output_type)

    client = openai.OpenAI(api_key=api_key)
    messages = [
        {"role": "system", "content": prompts.OPENAI_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": prompts.build_openai_user_prompt(notes, output_type, inferred_type),
        },
    ]

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.2,
        max_tokens=1400,
    )

    content = response.choices[0].message.content or ""
    return _normalize_sections_from_json_payload(content, required_sections)
