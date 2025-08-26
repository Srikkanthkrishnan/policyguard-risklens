# policyguard_risklens_agentic.py
# Streamlit app for PolicyGuard RiskLens AI with Agentic Analysis
# Now offers two input paths: 1) Upload PDFs, or 2) Pick from built‑in sample files (dropdown)

from __future__ import annotations
import json, re, csv, datetime as dt
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Iterable, Tuple, Optional


import streamlit as st
st.set_page_config(page_title="PolicyGuard")
st.write("✅ Boot reached")  # If you don’t see this, the app crashed before UI
from PyPDF2 import PdfReader

# try to enable sample PDF generation
try:
    from reportlab.pdfgen import canvas as pdfcanvas
    from reportlab.lib.pagesizes import LETTER
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False

# =========================
# Paths & Bootstrap
# =========================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "sample_data"
DATA_DIR.mkdir(exist_ok=True)
RULEBOOK_PATH = DATA_DIR / "rulebook.json"

DEFAULT_RULEBOOK = {
    "version": "1.0",
    "updated": dt.datetime.utcnow().isoformat() + "Z",
    "rules": [
        {
            "id": "C1",
            "category": "Compliance",
            "description": "Personal data must be processed in compliance with GDPR requirements.",
            "source": "GDPR Article 5",
            "risk": {"type": "Legal", "severity": "High", "likelihood": "Medium"},
            "keywords": ["GDPR", "personal data", "lawful", "consent"],
            "regex": [r"(?i)GDPR"],
            "suggested_fix": "Define lawful basis, consent mechanism, or data map.",
            "rewrite": "Processing of personal data shall comply with GDPR Article 5 principles, including lawful basis, fairness, and transparency.",
        },
        {
            "id": "C2",
            "category": "Compliance",
            "description": "Personal data breach notification must be timely (≤72 hours).",
            "source": "GDPR Article 33",
            "risk": {"type": "Legal", "severity": "High", "likelihood": "High"},
            "keywords": ["breach", "notify", "notification"],
            "regex": [r"(?i)notify.{0,40}(hour|day|business)"],
            "suggested_fix": "Contractually require notification within 72 hours of awareness.",
            "rewrite": "The Vendor shall notify the Organization within 72 hours of becoming aware of a personal data breach, in accordance with GDPR Article 33.",
        },
        {
            "id": "R1",
            "category": "Risk",
            "description": "All sensitive data must be encrypted at rest and in transit using AES-256 or higher; use modern TLS.",
            "source": "ISO 27001 / NIST CSF",
            "risk": {"type": "Cybersecurity", "severity": "High", "likelihood": "High"},
            "keywords": ["AES-256", "encrypted", "encryption", "TLS"],
            "regex": [r"(?i)AES\s*-?128|\bDES\b|3DES|TLS\s*1\.[01]\b"],
            "suggested_fix": "Mandate AES-256 at rest and in transit; require TLS 1.2+ (prefer 1.3).",
            "rewrite": "All sensitive data shall be encrypted at rest and in transit using AES-256 or stronger algorithms and transmitted over TLS 1.2 or higher.",
        },
    ],
}

SEVERITY_SCORE = {"Low": 1, "Medium": 2, "High": 3}
LIKELIHOOD_SCORE = {"Low": 1, "Medium": 2, "High": 3}

@dataclass
class RiskMeta:
    type: str
    severity: str
    likelihood: str
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 0) * LIKELIHOOD_SCORE.get(self.likelihood, 0)

@dataclass
class Rule:
    id: str
    category: str
    description: str
    source: str
    risk: RiskMeta
    keywords: List[str]
    regex: List[str]
    suggested_fix: str
    rewrite: str
    @staticmethod
    def from_dict(d: Dict) -> "Rule":
        r = d.get("risk", {})
        return Rule(
            id=d["id"],
            category=d.get("category", "Other"),
            description=d.get("description", ""),
            source=d.get("source", ""),
            risk=RiskMeta(r.get("type", "Unknown"), r.get("severity", "Low"), r.get("likelihood", "Low")),
            keywords=[k.strip() for k in d.get("keywords", []) if k.strip()],
            regex=[p for p in d.get("regex", []) if p],
            suggested_fix=d.get("suggested_fix", "Review and remediate."),
            rewrite=d.get("rewrite", "No rewrite available."),
        )

@dataclass
class Evidence:
    snippet: str
    page_num: int
    match_type: str

@dataclass
class Finding:
    rule: Rule
    score: int
    evidence: List[Evidence]

# =========================
# Rulebook I/O
# =========================

def seed_rulebook_if_missing() -> None:
    if not RULEBOOK_PATH.exists():
        RULEBOOK_PATH.write_text(json.dumps(DEFAULT_RULEBOOK, indent=2), encoding="utf-8")

@st.cache_data(show_spinner=False)
def load_rulebook() -> List[Rule]:
    seed_rulebook_if_missing()
    data = json.loads(RULEBOOK_PATH.read_text(encoding="utf-8"))
    return [Rule.from_dict(r) for r in data.get("rules", [])]

# =========================
# Sample PDFs
# =========================

def ensure_sample_pdfs() -> List[Path]:
    """Create two small demo PDFs if missing."""
    s1 = DATA_DIR / "sample_vendor_agreement.pdf"
    s2 = DATA_DIR / "sample_security_policy.pdf"
    if REPORTLAB_OK:
        if not s1.exists():
            c = pdfcanvas.Canvas(str(s1), pagesize=LETTER)
            w, h = LETTER
            t = c.beginText(40, h-60)
            for line in [
                "Master Services Agreement - Vendor",
                "",
                "Security: The Vendor shall use encryption with AES-128 for data at rest and in transit.",
                "Incident Response: The Vendor shall notify the Organization within 10 business days of any personal data breach.",
                "Compliance: Vendor acknowledges GDPR applicability.",
            ]:
                t.textLine(line)
            c.drawText(t); c.showPage(); c.save()
        if not s2.exists():
            c = pdfcanvas.Canvas(str(s2), pagesize=LETTER)
            w, h = LETTER
            t = c.beginText(40, h-60)
            for line in [
                "Information Security Policy",
                "",
                "We process personal data in accordance with GDPR.",
                "(Lawful basis and purpose limitation to be defined.)",
                "Protected health information (PHI) is handled per HIPAA.",
            ]:
                t.textLine(line)
            c.drawText(t); c.showPage(); c.save()
    return [s1, s2]

# =========================
# PDF Parsing
# =========================

def pdfs_to_text(files) -> Tuple[str, List[Tuple[int,str]]]:
    texts, all_pages = [], []
    for uf in files:
        reader = PdfReader(uf)
        for i, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            texts.append(text)
            all_pages.append((i, text))
    return "\n\n".join(texts), all_pages

# =========================
# Analyzer
# =========================

def analyze_text(pages: List[Tuple[int,str]], rules: List[Rule]):
    findings: List[Finding] = []
    for rule in rules:
        ev: List[Evidence] = []
        for (pg, pg_text) in pages:
            low = pg_text.lower()
            for kw in rule.keywords:
                if kw.lower() in low:
                    ev.append(Evidence(snippet=kw, page_num=pg, match_type="keyword"))
            for pat in rule.regex:
                try:
                    for m in re.finditer(pat, pg_text):
                        ev.append(Evidence(snippet=m.group(0), page_num=pg, match_type="regex"))
                except re.error:
                    continue
        if ev:
            findings.append(Finding(rule=rule, score=rule.risk.score(), evidence=ev))
    return findings

# =========================
# Rows
# =========================

def to_rows(findings: List[Finding]):
    rows = []
    for f in findings:
        pages = sorted({e.page_num for e in f.evidence})
        rows.append({
            "Rule ID": f.rule.id,
            "Category": f.rule.category,
            "Rule Description": f.rule.description,
            "Regulation Source": f.rule.source,
            "Pages": ", ".join(map(str, pages)) or "-",
            "Evidence": " | ".join(f"p{e.page_num}: {e.snippet}" for e in f.evidence[:2]),
            "Severity": f.rule.risk.severity,
            "Likelihood": f.rule.risk.likelihood,
            "Risk Score": f.score,
            "Risk Level": ("High" if f.score>=9 else ("Medium" if f.score>=4 else "Low")),
            "Suggested Fix": f.rule.suggested_fix,
            "Agentic Rewrite": f.rule.rewrite,
            "Validation Source": "Rulebook",
        })
    return rows

# =========================
# Streamlit UI
# =========================

st.set_page_config(page_title="PolicyGuard RiskLens AI", layout="wide")
st.title("🛡️ PolicyGuard RiskLens AI — Agentic Analysis")

with st.sidebar:
    st.subheader("Mode")
    mode = st.radio("Select", ["Agentic Analysis", "Q&A (coming soon)"])
    st.markdown("---")
    st.subheader("Exports")
    opt_json = st.checkbox("JSON", value=True)
    opt_csv = st.checkbox("CSV", value=False)
    opt_md = st.checkbox("Markdown", value=False)

# ---- Input selector (old PolicyGuard inspiration) ----
st.markdown("### Choose Input Source")
input_mode = st.radio("How would you like to test?", ["Upload files", "Use sample files"], horizontal=True)

selected_samples: List[Path] = []
if input_mode == "Upload files":
    st.markdown("#### Upload policy PDF(s)")
    pdf_files = st.file_uploader("Upload one or more PDF files", type=["pdf"], accept_multiple_files=True)
else:
    st.markdown("#### Pick sample set")
    ensure_sample_pdfs()
    s1, s2 = ensure_sample_pdfs()
    choice = st.selectbox(
        "Select sample:",
        [
            "Vendor Agreement (breach 10 days + AES-128)",
            "Security Policy (GDPR/HIPAA)",
            "Both samples",
        ],
    )
    if choice == "Vendor Agreement (breach 10 days + AES-128)":
        selected_samples = [s1]
    elif choice == "Security Policy (GDPR/HIPAA)":
        selected_samples = [s2]
    else:
        selected_samples = [s1, s2]

run = st.button("🚀 Run Agentic Analysis", type="primary")

if run:
    file_objs = []
    if input_mode == "Upload files":
        if not pdf_files:
            st.error("Please upload at least one PDF file.")
        else:
            file_objs = list(pdf_files)
    else:
        file_objs = [open(p, "rb") for p in selected_samples]

    if file_objs:
        with st.spinner("Extracting text and analyzing…"):
            text, pages = pdfs_to_text(file_objs)
            rules = load_rulebook()
            findings = analyze_text(pages, rules)
            rows = to_rows(findings)
        for fo in file_objs:
            try:
                fo.close()
            except Exception:
                pass

        if rows:
            st.success(f"Found {len(rows)} issues.")
            st.dataframe(rows, use_container_width=True)

            st.markdown("### Agentic Rewrites (Wrong → Right)")
            for f in findings:
                ev = f.evidence[0]
                st.markdown(f"**Rule {f.rule.id} ({f.rule.category})**")
                st.markdown(f"**Original (p{ev.page_num}):** …{ev.snippet}…")
                st.markdown(f"**Correct (rewrite):** {f.rule.rewrite}")
                st.caption(f"Why: {f.rule.suggested_fix} — Source: {f.rule.source}")
                st.markdown("---")

            # Exports
            if opt_json or opt_csv or opt_md:
                c1, c2, c3 = st.columns(3)
                if opt_json:
                    c1.download_button("Download JSON", json.dumps(rows, indent=2), file_name="agentic_report.json")
                if opt_csv:
                    import io
                    sio = io.StringIO()
                    import csv as _csv
                    writer = _csv.DictWriter(sio, fieldnames=rows[0].keys())
                    writer.writeheader(); writer.writerows(rows)
                    c2.download_button("Download CSV", sio.getvalue(), file_name="agentic_report.csv")
                if opt_md:
                    md = ["# Agentic Analysis Report"]
                    for r in rows:
                        md.append(f"- **{r['Rule ID']}** ({r['Category']}) p{r['Pages']}: {r['Evidence']} → {r['Agentic Rewrite']}")
                    c3.download_button("Download Markdown", "\n".join(md), file_name="agentic_report.md")
        else:
            st.info("No findings matched the rulebook.")
