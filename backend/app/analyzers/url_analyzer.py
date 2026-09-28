import ipaddress
import re
from urllib.parse import parse_qs, urlparse
from ..risk_engine import Finding, calculate_score, level_for
BRANDS={"paypal":["paypal.com"],"microsoft":["microsoft.com","live.com","office.com"],"google":["google.com","gmail.com"],"apple":["apple.com","icloud.com"],"amazon":["amazon.com","amazon.in"],"facebook":["facebook.com","meta.com"],"instagram":["instagram.com"]}
SUSPICIOUS_TLDS={".zip",".mov",".click",".top",".xyz",".work",".support",".gq",".tk"}
def normalize_url(raw):
    value=raw.strip()
    return value if re.match(r"^https?://",value,re.I) else "https://"+value
def analyze_url(raw):
    url=normalize_url(raw); parsed=urlparse(url); host=(parsed.hostname or "").lower().rstrip("."); findings=[]; indicators=[]
    if parsed.scheme!="https": findings.append(Finding("No HTTPS","The URL does not use HTTPS.",12)); indicators.append({"name":"HTTPS","status":"fail","detail":"HTTPS not detected","weight":12})
    else: indicators.append({"name":"HTTPS","status":"pass","detail":"HTTPS detected","weight":0})
    try: ipaddress.ip_address(host); findings.append(Finding("IP-based host","The URL uses a raw IP address instead of a normal domain.",18)); indicators.append({"name":"Host type","status":"warning","detail":"Raw IP address","weight":18})
    except ValueError: indicators.append({"name":"Host type","status":"pass","detail":"Domain name detected","weight":0})
    if "@" in parsed.netloc: findings.append(Finding("Obfuscated authority","The URL contains an @ symbol that can hide the real destination.",22))
    if len(url)>140: findings.append(Finding("Long URL","Unusually long URL structure can indicate tracking or obfuscation.",8))
    if len(parsed.query)>80 or len(parse_qs(parsed.query))>8: findings.append(Finding("Complex query","The query string contains many parameters.",6))
    words=[w for w in ["login","verify","secure","update","password","billing","payment","wallet","account","signin"] if w in parsed.path.lower()]
    if words: findings.append(Finding("Credential/payment path",f"Path contains sensitive terms: {', '.join(words)}.",14)); indicators.append({"name":"Sensitive path","status":"warning","detail":', '.join(words),"weight":14})
    if host.startswith("xn--") or ".xn--" in host: findings.append(Finding("Punycode domain","Internationalized domain encoding may be used for look-alike domains.",18))
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS): findings.append(Finding("Uncommon high-risk TLD","The domain uses a TLD frequently seen in disposable or abusive infrastructure.",10))
    if host.count(".")>=3: findings.append(Finding("Deep subdomain","The host has multiple subdomain levels.",6))
    if sum(ch.isdigit() for ch in host)/max(1,len(host))>.35: findings.append(Finding("Digit-heavy domain","The domain contains an unusual amount of numeric characters.",10))
    for brand, trusted in BRANDS.items():
        if brand in host and not any(host==d or host.endswith("."+d) for d in trusted): findings.append(Finding("Look-alike brand domain",f"Host contains '{brand}' but is not an official {brand} domain.",24)); indicators.append({"name":"Brand resemblance","status":"fail","detail":f"Resembles {brand}","weight":24}); break
    if re.search(r"(secure|account|verify|support|service)[0-9-]*[.]",host): findings.append(Finding("Deceptive hostname","Hostname uses service-like words that can imitate legitimate portals.",12))
    if not parsed.hostname: findings.append(Finding("Malformed URL","A valid hostname could not be extracted.",30))
    score=calculate_score(findings); level=level_for(score); reasons=[f.detail for f in findings]
    if not findings: indicators.append({"name":"Domain structure","status":"pass","detail":"No strong static phishing indicators","weight":0})
    return {"risk_score":score,"threat_level":level,"category":"Suspicious URL" if score>=45 else "URL Safety","reasons":reasons,"indicators":indicators+[{"name":f.name,"status":f.status,"detail":f.detail,"weight":f.weight} for f in findings],"recommendation":"Safe to continue with normal caution." if score<45 else "Do not enter passwords or payment information until the destination is independently verified.","ai_explanation":_explain(level,reasons),"metadata":{"normalized_url":url,"hostname":host,"scheme":parsed.scheme,"path":parsed.path}}
def _explain(level,reasons):
    return "The URL does not show strong static indicators of phishing. This is not a guarantee that the site is safe." if level=="SAFE" else f"The scanner found indicators that deserve caution. {' '.join(reasons[:3])} Verify the domain through a trusted source before entering sensitive information."
