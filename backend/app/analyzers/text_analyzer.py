import re
from ..risk_engine import Finding, calculate_score, level_for
URGENCY=re.compile(r"\b(urgent|immediately|act now|within \d+ (?:hours?|minutes?)|final warning|suspended|expire|last chance)\b",re.I)
CREDENTIALS=re.compile(r"\b(password|passcode|otp|one[- ]time|verification code|login|sign in|credentials)\b",re.I)
PAYMENT=re.compile(r"\b(payment|invoice|refund|bank|card|wallet|transfer|gift card|crypto)\b",re.I)
MALWARE=re.compile(r"\b(attachment|zip file|exe|macro|enable content|download|installer)\b",re.I)
IMPERSONATION=re.compile(r"\b(support|security team|admin|ceo|manager|hr|bank|microsoft|google|paypal|amazon|apple)\b",re.I)
def analyze_text(text):
    findings=[]; indicators=[]
    def add(name,detail,weight,status="warning"):
        findings.append(Finding(name,detail,weight,status)); indicators.append({"name":name,"status":status,"detail":detail,"weight":weight})
    hits=URGENCY.findall(text)
    if hits: add("Urgency/manipulation language",f"Detected urgency cues: {', '.join(dict.fromkeys(hits))}.",18)
    if CREDENTIALS.search(text): add("Credential request","The message references passwords, OTPs, login details, or verification codes.",24,"fail")
    if PAYMENT.search(text): add("Payment/financial request","The message references payment, banking, cards, transfers, or financial actions.",16)
    if MALWARE.search(text): add("Potential malware delivery","The message references attachments or executable/download actions.",22,"fail")
    if IMPERSONATION.search(text): add("Impersonation indicators","The text references brands, roles, or support identities that could be impersonated.",10)
    urls=re.findall(r"https?://[^\s<]+",text,flags=re.I)
    if urls: add("Suspicious link presence",f"Detected {len(urls)} link(s). Links should be verified independently before opening.",12)
    if re.search(r"click here|verify your account|confirm your identity|claim your refund",text,re.I): add("Call-to-action phishing pattern","The message asks the recipient to take a high-impact action through a generic call to action.",16)
    score=calculate_score(findings); level=level_for(score); category=_category(findings); reasons=[f.detail for f in findings]
    return {"risk_score":score,"threat_level":level,"category":category,"reasons":reasons,"indicators":indicators,"recommendation":"Do not click links, open unexpected attachments, or submit credentials. Verify the sender using a trusted channel." if score>=45 else "Treat unexpected requests cautiously and verify the sender before taking action.","ai_explanation":_explain(level,category,reasons),"metadata":{"links_detected":urls,"highlighted_sentences":_highlights(text)}}
def _category(findings):
    names={f.name for f in findings}
    if "Potential malware delivery" in names:return "Malware Delivery"
    if "Credential request" in names:return "Phishing / Credential Harvesting"
    if "Payment/financial request" in names:return "Scam / Financial Fraud"
    if "Impersonation indicators" in names:return "Social Engineering"
    return "Message Safety"
def _highlights(text):
    sentences=re.split(r"(?<=[.!?])\s+",text.strip())
    return [s for s in sentences if URGENCY.search(s) or CREDENTIALS.search(s) or PAYMENT.search(s) or MALWARE.search(s) or re.search(r"https?://",s,re.I)]
def _explain(level,category,reasons):
    if level=="SAFE": return "No strong phishing or scam language patterns were detected. This result is advisory, not a guarantee of safety."
    return f"The content is classified as {category.lower()} because it combines common social-engineering signals. {' '.join(reasons[:3])}"
