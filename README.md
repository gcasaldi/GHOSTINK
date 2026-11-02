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

## Remediation & verification

Every detected text indicator now comes with contextual, **human-reviewed** remediation guidance explaining what to investigate, suggested corrective actions, and how to verify the fix. Both the GitHub Pages browser scanner and the local Streamlit engine include remediation details in their downloadable JSON reports. Advice is not automatic sanitization or a security verdict.

The **synthetic.pdf** label in the original walkthrough was a fictional example stored as JavaScript findings, **not a scanned file**. The dashboard now provides **Download test PDF** to generate a real, harmless one-page PDF test fixture locally. Download it, select it under **Analyze your own PDF**, and run **Analyze PDF** to test the live engine. The fixture includes an instruction-like phrase and tiny text, so these two heuristic types should be detectable. Off-page text may be omitted by some PDF text extractors; outputs can differ by engine. The fictional walkthrough remains clearly labeled as synthetic.

Relevant guidance: [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and the [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html). A string-matching scanner cannot prevent indirect prompt injection; effective protections include trust boundaries, restricted tool privileges, authorization checks, and human review.

The GitHub Pages assets are mirrored in `/` and `/docs` to support either GitHub Pages branch folder configuration.
