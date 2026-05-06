import os
from pathlib import Path

import streamlit as st

from report_generator import classify_incident_type, generate_live_report, generate_mock_report
from prompts import sections_for_output_type

ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLE_CASES = {
    "Phishing Investigation": ROOT_DIR / "sample-data" / "phishing-investigation.txt",
    "Suspicious Login / Impossible Travel": ROOT_DIR / "sample-data" / "suspicious-login.txt",
    "Malware Alert": ROOT_DIR / "sample-data" / "malware-alert.txt",
}
OUTPUT_TYPES = [
    "Executive Summary",
    "Client Update",
    "Technical Findings",
    "Internal Ticket Notes",
    "Full Incident Report",
]

_APP_CSS = """
<style>
    * {
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }

    .stApp, .stApp .main {
        background: #0F172A;
        color: #F8FAFC;
    }

    .hero-card {
        background: #1E293B;
        padding: 1.6rem 1.8rem;
        border-radius: 1rem;
        border: 1px solid rgba(148, 163, 184, 0.25);
        margin-bottom: 1rem;
        box-shadow: 0 15px 35px rgba(15, 23, 42, 0.65);
    }

    .hero-card h1 {
        margin-bottom: 0.2rem;
        color: #F8FAFC;
        letter-spacing: 0.02em;
    }

    .hero-card .subtitle {
        color: #CBD5E1;
        margin-top: 0;
        font-size: 1rem;
        font-weight: 400;
    }

    .card {
        background: #1E293B;
        border-radius: 1rem;
        border: 1px solid rgba(148, 163, 184, 0.15);
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
    }

    .card-body {
        padding-bottom: 0.75rem;
    }

    .control-row {
        display: flex;
        gap: 0.75rem;
        margin: 0.35rem 0 0.75rem;
        flex-wrap: wrap;
    }

    .warning-card {
        padding: 0.95rem 1rem;
        border-radius: 0.75rem;
        margin-bottom: 0.75rem;
        display: flex;
        gap: 0.65rem;
        align-items: center;
        font-weight: 500;
        font-size: 0.95rem;
        background: #1E293B;
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-left-width: 0.35rem;
        box-shadow: 0 6px 18px rgba(2, 6, 23, 0.35);
    }

    .warning-card.safe {
        border-color: #F59E0B;
        color: #F8FAFC;
    }

    .warning-card.review {
        border-color: #60A5FA;
        color: #F8FAFC;
    }

    .info-panel {
        border-radius: 0.75rem;
        padding: 0.75rem 0.9rem;
        background: rgba(96, 165, 250, 0.12);
        border: 1px solid rgba(96, 165, 250, 0.2);
        color: #E0F2FE;
        margin: 0.8rem 0 0.4rem;
        font-size: 0.9rem;
    }

    .generate-button-wrapper .stButton button {
        background-color: #60A5FA !important;
        color: #0F172A !important;
        font-size: 1rem;
        font-weight: 600;
        padding: 0.65rem 1.5rem !important;
        border-radius: 0.75rem;
        border: none;
        box-shadow: 0 10px 30px rgba(96, 165, 250, 0.35);
    }

    .report-card {
        background: linear-gradient(180deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.95));
        border: 1px solid rgba(148, 163, 184, 0.25);
    }

    .report-title {
        color: #60A5FA;
        font-size: 1.2rem;
        margin-bottom: 0.5rem;
    }

    .report-section {
        padding: 0.55rem 0;
        border-bottom: 1px solid rgba(148, 163, 184, 0.2);
    }

    .report-section:last-child {
        border-bottom: none;
    }

    .section-label {
        color: #818CF8;
        font-size: 0.85rem;
        text-transform: uppercase;
        margin-bottom: 0.3rem;
        letter-spacing: 0.08em;
    }

    .section-text {
        color: #F8FAFC;
        margin: 0;
        line-height: 1.6;
        white-space: pre-line;
    }

    .stTextArea textarea {
        background-color: rgba(15, 23, 42, 0.9);
        color: #F8FAFC;
        border-radius: 0.7rem;
        border: 1px solid rgba(148, 163, 184, 0.4);
    }

    .stSelectbox select {
        background: rgba(15, 23, 42, 0.9);
        color: #F8FAFC;
        border-radius: 0.7rem;
        border: 1px solid rgba(148, 163, 184, 0.4);
    }

    .stButton button:hover {
        transform: translateY(-1px);
    }
</style>
"""


def _read_sample(path: Path) -> str:
    if not path.exists():
        return "Unable to load safe demo case."
    return path.read_text()


def _load_into_session(sample_name: str) -> None:
    st.session_state["analyst_notes"] = _read_sample(SAMPLE_CASES[sample_name])


def _setup_session_state() -> None:
    if "analyst_notes" not in st.session_state:
        st.session_state["analyst_notes"] = ""


def _render_warning(message: str, tone: str = "primary") -> None:
    icon = "⚠️" if tone == "safe" else "🔎"
    st.markdown(
        f"""
        <div class="warning-card {tone}">
            <span>{icon}</span>
            <span>{message}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(
        page_title="AI Incident Report / Client Update Generator",
        layout="centered",
    )

    st.markdown(_APP_CSS, unsafe_allow_html=True)

    st.markdown(
        """
        <div class="hero-card">
            <h1>AI Incident Report / Client Update Generator</h1>
            <p class="subtitle">AI-assisted incident reporting for safe SecOps demo workflows.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _render_warning(
        "Use safe demo data only. Do not paste real client, employer, production alert, secret, token, or credential data.",
        tone="safe",
    )
    _render_warning("Human review required before using any generated output.", tone="review")

    _setup_session_state()

    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.markdown("<div class='card-body'>", unsafe_allow_html=True)

    st.text_area(
        "Analyst Notes",
        value=st.session_state["analyst_notes"],
        height=250,
        placeholder="Paste SOC analyst notes here (demo data only).",
        key="analyst_notes",
    )
    notes = st.session_state["analyst_notes"]

    st.markdown("<div class='control-row'>", unsafe_allow_html=True)
    case_columns = st.columns(len(SAMPLE_CASES))
    for column, sample_name in zip(case_columns, SAMPLE_CASES):
        column.button(sample_name, on_click=_load_into_session, args=(sample_name,))
    st.markdown("</div>", unsafe_allow_html=True)

    output_type = st.selectbox("Select output type", OUTPUT_TYPES, index=0)

    openai_key = os.environ.get("OPENAI_API_KEY")
    openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    if openai_key:
        st.markdown(
            """
            <div class='info-panel'>
                OpenAI API key detected. Generating live AI-assisted reports; analyst notes will be sent securely to OpenAI. Use safe demo data only.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class='info-panel'>
                OPENAI_API_KEY not found. Showing mock demo output.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div class='generate-button-wrapper'>", unsafe_allow_html=True)
    generate_clicked = st.button("Generate Report")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    if generate_clicked:
        inferred_type = classify_incident_type(notes)

        if openai_key:
            try:
                report = generate_live_report(
                    notes,
                    output_type,
                    openai_key,
                    openai_model,
                    incident_type=inferred_type,
                )
            except Exception:
                st.error(
                    "Live OpenAI report failed. Showing mock demo output instead. (No analyst notes were logged.)"
                )
                report = generate_mock_report(notes, output_type, incident_type=inferred_type)
        else:
            report = generate_mock_report(notes, output_type, incident_type=inferred_type)

        st.markdown("<div class='card report-card'>", unsafe_allow_html=True)
        st.markdown("<div class='card-body'>", unsafe_allow_html=True)
        st.markdown(
            f"<p class='report-title'>Generated {output_type}</p>",
            unsafe_allow_html=True,
        )

        ordered_sections = sections_for_output_type(output_type)
        for section in ordered_sections:
            narrative = report.get(section, "")
            st.markdown(
                f"""
                <div class='report-section'>
                    <p class='section-label'>{section}</p>
                    <div class='section-text'>{narrative}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
