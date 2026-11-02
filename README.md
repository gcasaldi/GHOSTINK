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

## Public dashboard (GitHub Pages)

Open **https://gcasaldi.github.io/GHOSTINK/** to use the public interface.

- **Analyze PDF**: inspect a local PDF in your browser (up to 20 MB, 100 pages) using PDF.js. The document is not uploaded to a GJ917 server. PDF.js is loaded from a third-party CDN, so an internet connection is required.
- **Run sample simulation**: explore a clearly labeled synthetic example for screenshots and videos; it is **not** a real scan.
- **Export real JSON report**: download findings from the browser inspection with page numbers and approximate positions.

**Important limits:** The browser engine checks selectable text for simple instruction-like patterns, tiny font sizes and off-page positions. It does not inspect font colors, detect white-on-white text, run OCR or detect image-only attacks. Patterns spanning multiple PDF text items can be missed. No findings does not mean a document is safe. For the original PyMuPDF heuristics, use the Streamlit app locally.

The dashboard source is in `docs/index.html` and can be hosted as a static GitHub Pages site.
