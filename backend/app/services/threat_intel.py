import asyncio, ipaddress, json, os, socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, quote
import httpx
from sqlalchemy.orm import Session
from ..models import AppSetting

DEFAULTS = {
    "external_lookups": "true", "virustotal_enabled": "true", "virustotal_api_key": "",
    "abuseipdb_enabled": "false", "abuseipdb_api_key": "", "dns_enrichment": "true",
    "ssl_enrichment": "true", "rdap_enrichment": "true", "timeout_seconds": "8"
}

def get_setting(db: Session, key: str):
    row = db.get(AppSetting, key)
    return row.value if row else DEFAULTS.get(key, "")

def bool_setting(db, key): return get_setting(db, key).lower() == "true"
def settings_snapshot(db):
    return {k: get_setting(db, k) for k in DEFAULTS}

def normalize_target(target):
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = parsed.hostname or raw.split('/')[0]
    return raw, parsed, host.lower().strip('.')

def _dns(host):
    result=[]
    try:
        infos=socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips=sorted({x[4][0] for x in infos})
        result=ips[:10]
    except Exception as e: return {"status":"error","detail":str(e)}
    return {"status":"ok","addresses":result}

def _ssl(host, timeout):
    ctx=ssl.create_default_context()
    try:
        with socket.create_connection((host,443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert=ssock.getpeercert()
                return {"status":"ok","tls_version":ssock.version(),"issuer":dict(x[0] for x in cert.get('issuer',())),"subject":dict(x[0] for x in cert.get('subject',())),"not_after":cert.get('notAfter')}
    except Exception as e: return {"status":"error","detail":str(e)}

async def _vt(url, key, timeout):
    if not key: return {"enabled":False,"verdict":"not_configured","provider":"VirusTotal"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r=await client.get(f"https://www.virustotal.com/api/v3/urls/{quote(url,safe='')}",headers={"x-apikey":key})
            if r.status_code==404: return {"enabled":True,"provider":"VirusTotal","verdict":"unknown","detail":"No existing reputation record."}
            r.raise_for_status(); stats=r.json().get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
            m=stats.get('malicious',0); s=stats.get('suspicious',0)
            return {"enabled":True,"provider":"VirusTotal","verdict":"malicious" if m else ("suspicious" if s else "clean"),"malicious":m,"suspicious":s,"stats":stats}
    except Exception as e: return {"enabled":True,"provider":"VirusTotal","verdict":"error","detail":str(e)}

async def _abuse_ip(ip, key, timeout):
    if not key: return {"enabled":False,"verdict":"not_configured","provider":"AbuseIPDB"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r=await client.get("https://api.abuseipdb.com/api/v2/check",params={"ipAddress":ip,"maxAgeInDays":90},headers={"Key":key,"Accept":"application/json"})
            r.raise_for_status(); d=r.json().get('data',{})
            score=d.get('abuseConfidenceScore',0)
            return {"enabled":True,"provider":"AbuseIPDB","verdict":"malicious" if score>=70 else ("suspicious" if score>=20 else "clean"),"confidence_score":score,"country":d.get('countryCode'),"usage_type":d.get('usageType')}
    except Exception as e: return {"enabled":True,"provider":"AbuseIPDB","verdict":"error","detail":str(e)}

async def _rdap(domain, timeout):
    try:
        async with httpx.AsyncClient(timeout=timeout,follow_redirects=True) as client:
            r=await client.get(f"https://rdap.org/domain/{domain}")
            if r.status_code>=400: return {"status":"unknown","detail":f"RDAP returned {r.status_code}"}
            d=r.json(); events={e.get('eventAction'):e.get('eventDate') for e in d.get('events',[])}
            return {"status":"ok","handle":d.get('handle'),"registrar":next((x.get('name') for x in d.get('entities',[]) if x.get('roles') and 'registrar' in x.get('roles')),None),"registration_date":events.get('registration'),"expiration_date":events.get('expiration')}
    except Exception as e: return {"status":"error","detail":str(e)}

async def reputation_lookup(url, db: Session):
    raw, parsed, host=normalize_target(url); cfg=settings_snapshot(db); timeout=int(cfg['timeout_seconds'])
    out={"target":raw,"domain":host,"checked_at":datetime.now(timezone.utc).isoformat(),"configuration":{k:v for k,v in cfg.items() if 'api_key' not in k}}
    if not cfg['external_lookups'].lower() == 'true':
        out["status"]="disabled"; return out
    if cfg['dns_enrichment'].lower()=='true': out['dns']=await asyncio.to_thread(_dns,host)
    if cfg['ssl_enrichment'].lower()=='true': out['ssl']=await asyncio.to_thread(_ssl,host,timeout)
    if cfg['rdap_enrichment'].lower()=='true': out['rdap']=await _rdap(host,timeout)
    if cfg['virustotal_enabled'].lower()=='true': out['virustotal']=await _vt(raw,cfg['virustotal_api_key'],timeout)
    try: ip=ipaddress.ip_address(host); out['ip_reputation']=await _abuse_ip(host,cfg['abuseipdb_api_key'],timeout) if cfg['abuseipdb_enabled'].lower()=='true' else {"enabled":False,"verdict":"not_configured","provider":"AbuseIPDB"}
    except ValueError:
        out['resolved_ip_reputation']={}
        ips=out.get('dns',{}).get('addresses',[])
        if ips and cfg['abuseipdb_enabled'].lower()=='true': out['resolved_ip_reputation']=await _abuse_ip(ips[0],cfg['abuseipdb_api_key'],timeout)
    return out
