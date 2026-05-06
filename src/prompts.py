INCIDENT_TYPES = [
    "phishing",
    "suspicious_login",
    "malware",
    "generic",
]

OUTPUT_SECTIONS = {
    "Executive Summary": [
        "What Happened",
        "Current Assessment",
        "Business / Operational Impact",
        "Recommended Next Step",
        "MITRE ATT&CK References",
        "Human Review Required",
    ],
    "Client Update": [
        "What We Reviewed",
        "What We Observed",
        "Current Assessment",
        "Actions Taken",
        "Recommended Next Steps",
        "What Still Needs Confirmation",
        "MITRE ATT&CK References",
        "Human Review Required",
    ],
    "Technical Findings": [
        "Alert Context",
        "Evidence Reviewed",
        "Observed Indicators",
        "Relevant MITRE ATT&CK References",
        "Validation Gaps",
        "Recommended Technical Next Steps",
        "Human Review Required",
    ],
    "Internal Ticket Notes": [
        "Triage Summary",
        "Evidence Checked",
        "Actions Completed",
        "Pending Validation",
        "Next Owner / Action",
        "Escalation Criteria",
        "MITRE ATT&CK References",
        "Human Review Required",
    ],
    "Full Incident Report": [
        "Incident Summary",
        "Scope",
        "Timeline / Known Sequence",
        "Evidence Reviewed",
        "Confirmed Findings",
        "Unknowns / Validation Needed",
        "MITRE ATT&CK References",
        "Impact Assessment",
        "Actions Taken",
        "Recommendations",
        "Human Review Required",
    ],
}

DEFAULT_PROMPT = (
    "Organize the analyst notes into a structured incident response deliverable with focused sections "
    "for quick ingestion by SOC, client, and technical stakeholders."
)

PROMPT_TEMPLATES = {
    "Executive Summary": (
        "Condense the incident into two short paragraphs that highlight the situation, impact, and confidence level, "
        "then finish with a clear risk rating for leadership reviewers."
    ),
    "Client Update": (
        "Translate the analyst observations into plain-language messaging suitable for an external client, "
        "highlighting what happened, what we know, and what they should expect next."
    ),
    "Technical Findings": (
        "Expand on telemetry, log artifacts, and forensic insights. Keep the voice technical, precise, and easy to translate into a post-incident review."
    ),
    "Internal Ticket Notes": (
        "Structure the narrative so on-call engineers can quickly pick up remaining work items. Include measurable artifacts, blockers, and next steps."
    ),
    "Full Incident Report": (
        "Deliver a comprehensive write-up that summarizes the attack surface, timeline, controls affected, actions taken, and pending work items."
    ),
}

OPENAI_SYSTEM_PROMPT = (
    "You are a senior MSSP SecOps analyst translating SOC notes into incident response deliverables. "
    "Use ONLY the analyst notes provided by the user. Never invent facts, timelines, systems, users, company names, or conclusions. "
    "Distinguish confirmed findings from assumptions. Avoid stating an incident is resolved unless the notes explicitly confirm it. "
    "Avoid destructive recommendations unless validated by the notes. "
    "Output must be professional, concise, and suitable for incident response documentation. "
    "Return JSON only (no markdown), using exactly the requested keys."
)


def build_openai_user_prompt(notes: str, output_type: str, incident_type: str) -> str:
    prompt = PROMPT_TEMPLATES.get(output_type, DEFAULT_PROMPT)
    safe_notes = notes.strip() or "No analyst notes were provided."

    required_sections = OUTPUT_SECTIONS.get(output_type, OUTPUT_SECTIONS["Full Incident Report"])
    safe_incident_type = incident_type if incident_type in INCIDENT_TYPES else "generic"

    return (
        f"Output type: {output_type}\n"
        f"Incident type (inferred): {safe_incident_type}\n\n"
        f"{prompt}\n\n"
        "Analyst notes:\n"
        f"{safe_notes}\n\n"
        "Response requirements:\n"
        "- Only use the analyst notes above; do not invent new facts or cite real organizations without justification.\n"
        "- Distinguish confirmed findings from assumptions (prefix assumptions with 'Assumption:' or similar).\n"
        "- Avoid stating the incident is resolved unless the notes explicitly confirm containment or remediation.\n"
        "- Do not recommend destructive actions (e.g., wiping systems) unless the analyst notes validate that step.\n"
        "- Do not include secrets, credentials, or tokens.\n"
        "- If something is unknown, explicitly say it is unknown based on the provided notes.\n"
        "- Only include MITRE ATT&CK techniques when the notes explicitly support the mapping; otherwise state that no mapping can be asserted.\n"
        "- For action-oriented sections (Actions Taken, Recommended Next Steps, Evidence Reviewed, Validation Gaps, Recommendations), use bullet lists with one item per line, prefixed with '- '.\n"
        "- Keep Client Update language customer-ready, non-alarming, and free of internal SOC jargon when possible.\n"
        "- Keep Internal Ticket Notes concise, operational, and bullet-based.\n"
        "- Keep Executive Summary business-facing with minimal technical detail.\n"
        "Incident-type guidance:\n"
        "- phishing: focus on sender/domain, subject, URLs/redirects, header authentication (SPF/DKIM/DMARC) if mentioned, user interaction if mentioned, mailbox search/quarantine/removal when relevant.\n"
        "- suspicious_login: focus on sign-in logs, source IP/geo, MFA result, session/account validation, privileged account risk if indicated; mention OAuth/mailbox rules only if present in notes.\n"
        "- malware: focus on endpoint/EDR telemetry, process tree, file path/hash, command line, network connections if present, quarantine/isolation validation, persistence/lateral movement checks only if supported.\n"
        "- Preserve professional, concise, incident-response tone.\n\n"
        "Output format:\n"
        "Return a single JSON object with the following keys (exactly): "
        f"{', '.join(required_sections)}. "
        "Each value must be plain text (no markdown).\n"
        "Human review language is mandatory and must appear in the 'Human Review Required' field: 'Human review required before use. Validate timeline, scope, evidence, customer-facing language, and any recommended actions before sharing.'"
    )


def sections_for_output_type(output_type: str) -> list[str]:
    return OUTPUT_SECTIONS.get(output_type, OUTPUT_SECTIONS["Full Incident Report"])
