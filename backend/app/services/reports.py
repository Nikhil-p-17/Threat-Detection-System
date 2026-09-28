from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib import colors
def build_pdf(scan):
    b=BytesIO(); doc=SimpleDocTemplate(b,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36); st=getSampleStyleSheet()
    story=[Paragraph("SentinelShield Security Report",st["Title"]),Spacer(1,12),Paragraph(f"Scan type: {scan.scan_type}",st["BodyText"]),Paragraph(f"Risk score: {scan.risk_score}/100",st["BodyText"]),Paragraph(f"Threat level: {scan.threat_level}",st["BodyText"]),Paragraph(f"Category: {scan.category}",st["BodyText"]),Spacer(1,12),Paragraph("Analyzed input",st["Heading2"]),Paragraph(scan.target[:5000].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),st["BodyText"]),Spacer(1,12),Paragraph("Detected indicators",st["Heading2"])]
    import json; rows=[["Indicator","Status","Detail"]]+[[x.get("name",""),x.get("status",""),x.get("detail","")] for x in json.loads(scan.indicators)]
    t=Table(rows,colWidths=[130,70,320]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172033")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.5,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),8)])); story += [t,Spacer(1,12),Paragraph("Reasons",st["Heading2"]),Paragraph("<br/>".join(json.loads(scan.reasons)) or "No major reasons detected.",st["BodyText"]),Spacer(1,12),Paragraph("Recommended action",st["Heading2"]),Paragraph(scan.recommendation,st["BodyText"])]; doc.build(story); b.seek(0); return b
