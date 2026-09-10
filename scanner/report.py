import html, json
from pathlib import Path


def write_reports(result:dict,output:Path):
    output.mkdir(parents=True,exist_ok=True)
    (output/"report.json").write_text(json.dumps(result,indent=2))
    rows="".join(f"""<tr><td><span class='{f["severity"].lower()}'>{html.escape(f["severity"])}</span></td>
      <td>{html.escape(f["control_id"])}</td><td>{html.escape(f["resource_id"])}</td>
      <td>{html.escape(f["evidence"])}</td><td>{html.escape(f["remediation"])}</td></tr>""" for f in result["findings"])
    page=f"""<!doctype html><html><head><meta charset='utf-8'><title>Cloud Security Report</title>
    <style>body{{font:15px Arial;margin:40px;background:#f4f7fb;color:#172033}}h1{{color:#123b70}}
    .score{{font-size:42px;font-weight:bold}}table{{width:100%;border-collapse:collapse;background:white}}
    th,td{{padding:12px;border-bottom:1px solid #ddd;text-align:left}}.critical{{color:#b00020;font-weight:bold}}
    .high{{color:#d35400;font-weight:bold}}.medium{{color:#8a6d00}}.low{{color:#236b36}}</style></head>
    <body><h1>Multi-Cloud Security Report</h1><p>Provider: {html.escape(result["provider"])}</p>
    <p class='score'>{result["security_score"]}/100</p><p>Resources scanned: {result["resources_scanned"]}</p>
    <table><tr><th>Severity</th><th>Control</th><th>Resource</th><th>Evidence</th><th>Remediation</th></tr>
    {rows}</table></body></html>"""
    (output/"report.html").write_text(page)
