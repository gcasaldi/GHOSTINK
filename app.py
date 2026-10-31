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
    st.metric("Suspicious text spans", len(findings))
    if findings:
        st.dataframe(findings, use_container_width=True)
    else:
        st.success("No indicators detected by these heuristics. This does not guarantee the PDF is safe.")
    st.download_button("Download JSON report", json.dumps({"filename": file.name, "findings": findings}, indent=2), file_name="ghostink-report.json", mime="application/json")
