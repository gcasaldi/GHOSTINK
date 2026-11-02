import io
import json
import re
import fitz
import streamlit as st

st.set_page_config(page_title="GHOSTINK", page_icon="👻", layout="wide")
st.title("👻 GHOSTINK")
st.caption("Local PDF inspection for hidden text and potential prompt injection · GJ917")
st.info("Heuristic findings are indicators, not proof of malicious intent. Files are processed in the running app environment.")
file = st.file_uploader("Choose a PDF", type=["pdf"])
PATTERNS = [r"ignore (all |previous |prior )?instructions", r"system prompt", r"developer message", r"you are (now |an? )", r"disregard (the |all )?(above|instructions)", r"reveal (your |the )?(secret|prompt)", r"override (your |the )?instructions"]

REMEDIATIONS = {
    "Prompt-injection phrase": {
        "priority": "Investigate AI trust boundary",
        "why": "Instruction-like text might target an AI workflow, but may be an innocent quotation.",
        "steps": [
            "Check the full passage and provenance before determining intent.",
            "If unauthorized, remove suspicious text in the trusted source and regenerate the PDF. Preserve the original as evidence.",
            "In AI/RAG systems, treat PDF content as untrusted and enforce least privilege, approval for sensitive tool actions, and strict trust boundaries.",
        ],
        "verify": "Rescan the regenerated PDF, review extracted text, and test downstream AI controls.",
    },
    "Very small text": {
        "priority": "Inspect visibility",
        "why": "Microtext can be hard to notice, though footnotes or PDF export artifacts may be benign.",
        "steps": [
            "Review the reported text in context.",
            "Remove unintended microtext in the source or adjust to a readable font and regenerate.",
        ],
        "verify": "Rescan and confirm tiny text is removed or documented as legitimate.",
    },
    "Outside page": {
        "priority": "Inspect page geometry",
        "why": "Text outside page bounds can be invisible yet still extractable.",
        "steps": [
            "Compare suspicious text with the trusted source document.",
            "Delete unexpected off-page text or move valid content inside the page before regenerating.",
        ],
        "verify": "Review rendered pages and extracted text, then rescan.",
    },
    "Near-white text": {
        "priority": "Inspect contrast",
        "why": "Pale text may conceal instructions on a pale background, but can be valid on a dark background.",
        "steps": [
            "Check the actual text/background contrast and full content.",
            "Remove unauthorized hidden text or improve intended contrast, then regenerate the PDF.",
        ],
        "verify": "Check visual and extracted content; pale color is not itself proof of malicious intent.",
    },
}


def with_remediation(finding):
    advice = []
    for flag in finding["indicators"]:
        key = next((name for name in REMEDIATIONS if flag.startswith(name)), None)
        if key:
            advice.append({"indicator": flag, **REMEDIATIONS[key]})
    return {**finding, "review_status": "needs-human-review", "remediation": advice}

if file:
    data = file.getvalue()
    if len(data) > 20 * 1024 * 1024:
        st.error("Maximum file size: 20 MB")
        st.stop()
    findings = []
    try:
        doc = fitz.open(stream=data, filetype="pdf")
        if doc.is_encrypted:
            st.error("Encrypted PDFs are not supported.")
            st.stop()
        if doc.page_count > 100:
            st.error("Maximum 100 pages per scan.")
            st.stop()
        for i, page in enumerate(doc):
            rect = page.rect
            for block in page.get_text("dict").get("blocks", []):
                if "lines" not in block:
                    continue
                for line in block["lines"]:
                    for span in line["spans"]:
                        txt = span["text"].strip()
                        if not txt:
                            continue
                        flags = []
                        x0, y0, x1, y1 = span["bbox"]
                        if span["size"] < 4:
                            flags.append("Very small text")
                        if x1 <= 0 or y1 <= 0 or x0 >= rect.width or y0 >= rect.height:
                            flags.append("Outside page")
                        color = span["color"]
                        r, g, b = (color >> 16) & 255, (color >> 8) & 255, color & 255
                        if min(r, g, b) > 245:
                            flags.append("Near-white text (check background)")
                        if any(re.search(p, txt, re.I) for p in PATTERNS):
                            flags.append("Prompt-injection phrase")
                        if flags:
                            findings.append({"page": i + 1, "text": txt[:300], "bbox": [round(v, 2) for v in span["bbox"]], "indicators": flags})
        doc.close()
    except Exception as exc:
        st.error(f"Cannot parse PDF: {type(exc).__name__}")
        st.stop()
    findings = [with_remediation(hit) for hit in findings]
    st.metric("Suspicious text spans", len(findings))
    if findings:
        st.dataframe(
            [{"page": f["page"], "text": f["text"], "indicators": ", ".join(f["indicators"])}
             for f in findings],
            use_container_width=True,
        )
        st.subheader("Remediation & verification")
        st.caption("Advisory guidance. Review findings before changing a document.")
        for index, finding in enumerate(findings[:50], start=1):
            with st.expander(f"Finding {index:02d} — page {finding['page']}"):
                st.code(finding["text"], language=None)
                for advice in finding["remediation"]:
                    st.markdown(f"**{advice['indicator']} — {advice['priority']}**")
                    st.write(advice["why"])
                    for n, step in enumerate(advice["steps"], start=1):
                        st.write(f"{n}. {step}")
                    st.markdown("**How to verify**")
                    st.write(advice["verify"])
        if len(findings) > 50:
            st.caption("Showing first 50 remediation panels; export JSON for all findings.")
    else:
        st.success("No indicators detected by these heuristics. This does not guarantee the PDF is safe.")
    st.download_button("Download JSON report", json.dumps({"filename": file.name, "assessment": "heuristic-not-security-verdict", "findings": findings}, indent=2), file_name="ghostink-report.json", mime="application/json")
