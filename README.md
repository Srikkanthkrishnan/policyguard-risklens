
# PolicyGuard AI — Demo (Compliance + Risk Intelligence)

This Streamlit app lets you compare **Compliance-only** vs **Compliance + Risk Intelligence** modes for PolicyGuard AI.

## How to run

```bash
pip install -r requirements.txt
streamlit run app.py
```

## What you'll see
- **Compliance Layer:** Extracts notice period & data residency from pasted text, checks against a sample rulebook and simple regulatory settings, and proposes remediation.
- **Risk Intelligence Layer:** Adds vendor risk, audit findings, and external regulatory/news signals to compute a composite risk level and suggest actions.

> Note: This is a **demo** with simplified logic and sample data. Replace `sample_data/*.json` with real connectors or APIs in production.
