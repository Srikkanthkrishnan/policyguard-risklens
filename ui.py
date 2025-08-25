# ui.py
import streamlit as st
from pathlib import Path
from typing import List
# Import from your single-file RiskLens app
from app import load_rulebook, evaluate_policy, summarize, Finding, Evidence  # noqa

st.set_page_config(page_title="PolicyGuard RiskLens", layout="wide")

# ---------- Caching ----------
@st.cache_data(show_spinner=False)
def cached_rulebook():
    version, rules = load_rulebook()   # cheap + stable -> cache_data
    return version, rules

@st.cache_data(show_spinner=False)
def run_analysis(text: str):
    version, rules = cached_rulebook()
    findings: List[Finding] = evaluate_policy(text, rules)
    summary = summarize(findings)
    # Convert to plain dicts for display/caching
    rows = []
    for f in findings:
        rows.append({
            "Rule": f.rule_id,
            "Category": f.category,
            "Severity": f.severity,
            "Likelihood": f.likelihood,
            "Score": f.score,
            "Evidence": " | ".join(e.snippet for e in f.evidence[:3]),
            "Source": f.source,
            "Description": f.description
        })
    return version, rows, summary

# ---------- UI ----------
st.title("🛡️ PolicyGuard RiskLens")
st.caption("Fast, cached Streamlit UI — analyzes text against your rulebook and scores risks.")

with st.sidebar:
    st.subheader("Rulebook")
    if st.button("Reload rulebook (clear cache)"):
        cached_rulebook.clear()
        st.success("Rulebook cache cleared.")
    version, _ = cached_rulebook()
    st.write(f"Rulebook v{version}")
    st.markdown("---")
    st.subheader("Export")
    exp_json = st.checkbox("JSON", value=True)
    exp_csv = st.checkbox("CSV", value=False)
    exp_md = st.checkbox("Markdown", value=False)

# Input area
default_text = (
    "We encrypt sensitive data in transit using AES-256 and require third-party vendors "
    "to sign DPAs before accessing customer data."
)
policy_text = st.text_area("Paste policy text:", value=default_text, height=220)

col_a, col_b = st.columns([1, 4])
analyze_clicked = col_a.button("Analyze", type="primary")
if analyze_clicked:
    with st.spinner("Analyzing…"):
        version, rows, summary = run_analysis(policy_text)

    st.subheader(f"Overall: {summary['overall']}  ·  Total Score: {summary['total_score']}")
    st.dataframe(rows, use_container_width=True)

    # Category summary
    st.markdown("### Category Breakdown")
    for cat, data in summary["by_category"].items():
        st.write(f"- **{cat}**: {data['count']} finding(s), score {data['score']}")

    # Optional exports
    if any([exp_json, exp_csv, exp_md]):
        from io import StringIO
        import json, csv

        col1, col2, col3 = st.columns(3)
        if exp_json:
            payload = {"summary": summary, "findings": rows}
            col1.download_button("Download JSON", json.dumps(payload, indent=2),
                                 file_name="risk_report.json", mime="application/json")
        if exp_csv:
            sio = StringIO()
            writer = csv.DictWriter(sio, fieldnames=list(rows[0].keys()) if rows else
                                    ["Rule","Category","Severity","Likelihood","Score","Evidence","Source","Description"])
            writer.writeheader()
            for r in rows: writer.writerow(r)
            col2.download_button("Download CSV", sio.getvalue(),
                                 file_name="risk_report.csv", mime="text/csv")
        if exp_md:
            md = [f"# Policy Risk Analysis",
                  f"**Overall:** {summary['overall']}  ",
                  f"**Total Score:** {summary['total_score']}\n",
                  "| Rule | Category | Severity | Likelihood | Score | Evidence |",
                  "|---|---|---|---|---|---|"]
            for r in rows:
                ev = r["Evidence"].replace("|", "‖")
                md.append(f"| {r['Rule']} | {r['Category']} | {r['Severity']} | {r['Likelihood']} | {r['Score']} | {ev} |")
            col3.download_button("Download Markdown", "\n".join(md),
                                 file_name="risk_report.md", mime="text/markdown")
