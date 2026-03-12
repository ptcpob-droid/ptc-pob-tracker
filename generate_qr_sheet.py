import sqlite3
import qrcode
import base64
import os
from io import BytesIO

DB_PATH = os.path.join(os.path.dirname(__file__), 'pob.db')
OUTPUT = os.path.join(os.path.dirname(__file__), 'qr_codes.html')

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
employees = conn.execute(
    'SELECT employee_no, name, designation, discipline FROM employees WHERE active = 1 ORDER BY name'
).fetchall()
conn.close()

cards_html = []
for emp in employees:
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=3)
    qr.add_data(emp['employee_no'])
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode()

    cards_html.append(f'''
    <div class="card">
        <img src="data:image/png;base64,{b64}" alt="{emp['employee_no']}">
        <div class="name">{emp['name']}</div>
        <div class="id">{emp['employee_no']}</div>
        <div class="role">{emp['designation']}</div>
        <div class="disc">{emp['discipline']}</div>
    </div>''')

html = f'''<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>QR Codes - PTC POB Tracker</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
  h1 {{ text-align: center; margin-bottom: 10px; font-size: 1.4rem; }}
  .info {{ text-align: center; color: #666; margin-bottom: 20px; font-size: 0.9rem; }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    max-width: 900px;
    margin: 0 auto;
  }}
  .card {{
    background: white;
    border: 2px solid #333;
    border-radius: 8px;
    padding: 12px 8px;
    text-align: center;
    break-inside: avoid;
  }}
  .card img {{ width: 140px; height: 140px; display: block; margin: 0 auto 6px; }}
  .name {{ font-weight: bold; font-size: 0.75rem; line-height: 1.2; margin-bottom: 2px; }}
  .id {{ font-size: 0.85rem; font-weight: bold; color: #0066cc; margin-bottom: 2px; }}
  .role {{ font-size: 0.65rem; color: #555; }}
  .disc {{ font-size: 0.6rem; color: #888; }}
  @media print {{
    body {{ padding: 0; background: white; }}
    h1, .info {{ display: none; }}
    .grid {{ grid-template-columns: repeat(4, 1fr); gap: 6px; }}
    .card {{ border: 1.5px solid #000; padding: 8px 4px; page-break-inside: avoid; }}
    .card img {{ width: 100px; height: 100px; }}
  }}
</style>
</head><body>
<h1>PTC POB - Worker QR Codes</h1>
<p class="info">{len(employees)} workers | Print this page (Ctrl+P) and cut out the cards | Each QR is unique per worker</p>
<div class="grid">
{"".join(cards_html)}
</div>
</body></html>'''

with open(OUTPUT, 'w', encoding='utf-8') as f:
    f.write(html)

print(f"Generated {len(employees)} QR codes -> qr_codes.html")
print(f"Open this file in your browser: {OUTPUT}")
