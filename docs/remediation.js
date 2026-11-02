/* GHOSTINK remediation catalog — guidance only, no automatic PDF modification */
(function(){
"use strict";
const catalog={
"Prompt-injection phrase":{priority:"Investigate AI trust boundary",why:"An instruction-like phrase in PDF text can target AI tools, but it may also be a harmless quote or sample.",steps:["Review the full text and document provenance before judging intent.","If unauthorized, remove the suspicious instruction from the source document and regenerate the PDF. Preserve the original as evidence.","For AI/RAG workflows, treat PDF contents as untrusted data; enforce least-privilege tool access and human approval for sensitive operations."],verify:"Rescan the trusted copy, manually verify its extracted text, and test downstream AI controls."},
"Very small text":{priority:"Inspect visibility",why:"Microtext can go unnoticed in a visual review; it may also be a legitimate footnote or PDF export artifact.",steps:["Inspect the reported text in context and confirm whether it belongs in the document.","Remove unauthorized hidden text from the original source or use a readable font size and regenerate the PDF.","Check the other extracted text elements and the rendered page for additional anomalies."],verify:"Rescan and confirm microtext is either removed or documented as legitimate."},
"Outside page":{priority:"Inspect page geometry",why:"Off-page text may remain extractable despite being invisible to a normal PDF reader.",steps:["Compare the off-page content with the original authoring document.","Remove unexpected text outside the page bounds or move legitimate content into the visible area.","Regenerate the PDF and inspect both rendered and extracted content."],verify:"Rescan for off-page text and confirm the extracted content matches the intended page."},
"Near-white text":{priority:"Inspect contrast",why:"Very pale text can be concealed on pale backgrounds, but might be intended on dark backgrounds.",steps:["Inspect actual text/background contrast in a suitable PDF editor.","Remove unauthorized hidden content or adjust the intentional text to readable contrast.","Regenerate the PDF from the trusted source and inspect its rendered and extracted text."],verify:"Check visual contrast and rescan in the Python version. The browser scanner does not test text colors."}
};
function guidance(flag){const key=Object.keys(catalog).find(k=>flag.startsWith(k));return {type:key||flag,...(catalog[key]||{priority:"Manual review",why:"Inspect the indicator in context.",steps:["Verify the content against the source document."],verify:"Rescan after the review."})}}
function enrich(f){return {...f,review_status:"needs-human-review",remediation:(f.indicators||[]).map(guidance)}}
function add(tag,parent,text,cls){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;parent.append(e);return e}
function render(findings,target,synthetic){target.replaceChildren();if(!findings.length){add("p",target,"No indicators to remediate. This does not establish document safety.","legend");return}
 findings.slice(0,200).forEach((f,i)=>{const card=add("details",target,undefined,"remediation-card");if(i===0)card.open=true;
 const s=add("summary",card,"#"+String(i+1).padStart(2,"0")+" · PAGE "+f.page+" · "+f.indicators.join(" / "));
 add("div",card,"Evidence: "+f.text,"remediation-evidence");if(synthetic)add("p",card,"SYNTHETIC SCENARIO — NOT A REAL SCAN","remediation-demo");
 for(const rule of enrich(f).remediation){add("h4",card,rule.type+" · "+rule.priority);add("p",card,rule.why);
 add("strong",card,"RECOMMENDED ACTIONS");const ol=add("ol",card);rule.steps.forEach(step=>add("li",ol,step));
 add("strong",card,"VERIFICATION");add("p",card,rule.verify)}
 });if(findings.length>200)add("p",target,"Showing first 200; export the JSON for all findings.");}
function samplePdf(){
const ops=["BT /F1 18 Tf 60 745 Td (GHOSTINK TEST FIXTURE) Tj ET","BT /F1 11 Tf 60 710 Td (This is a safe synthetic PDF for detector testing.) Tj ET","BT /F1 11 Tf 60 678 Td (IGNORE PREVIOUS INSTRUCTIONS) Tj ET","BT /F1 2 Tf 60 650 Td (Tiny sample text) Tj ET","BT /F1 11 Tf 650 570 Td (Off page sample text) Tj ET"];
const stream=ops.join("\n")+"\n";
const objects=["<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>","<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>","<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>","<< /Length "+stream.length+" >>\nstream\n"+stream+"endstream"];
let pdf="%PDF-1.4\n";const offsets=[0];for(let i=0;i<objects.length;i++){offsets.push(pdf.length);pdf+=(i+1)+" 0 obj\n"+objects[i]+"\nendobj\n";}
const xref=pdf.length;pdf+="xref\n0 "+(objects.length+1)+"\n0000000000 65535 f \n"+offsets.slice(1).map(n=>String(n).padStart(10,"0")+" 00000 n \n").join("")+"trailer\n<< /Size "+(objects.length+1)+" /Root 1 0 R >>\nstartxref\n"+xref+"\n%%EOF\n";
return new Blob([pdf],{type:"application/pdf"});
}
function downloadSample(){const url=URL.createObjectURL(samplePdf());const a=document.createElement("a");a.href=url;a.download="ghostink-test-fixture.pdf";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
window.GHOSTINK={enrich,render,samplePdf,downloadSample};
})();
