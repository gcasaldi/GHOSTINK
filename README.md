# GHOSTINK

I built GHOSTINK as a small, local-first PDF inspection demo for exploring suspicious hidden text and possible prompt-injection instructions.

## What it does

The Streamlit app scans selectable PDF text spans for very small font sizes, near-white text, off-page coordinates, and a few common prompt-injection phrases. It displays findings with page numbers and bounding boxes and exports a JSON report. These are heuristics, not a malware verdict. Scanned PDFs without extractable text may require OCR, which is not implemented.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

On Windows, activate with `.venv\\Scripts\\activate`.

The app does not send PDF contents to external analysis APIs. Avoid deploying it publicly without authentication and resource controls: a hosted Streamlit app processes files on its server, not on the visitor's device.

GJ917 · An independent open-source project
