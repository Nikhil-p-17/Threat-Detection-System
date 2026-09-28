import json, os
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .models import Scan, AppSetting
from .schemas import DashboardStats, ScanRequest, ScanResult, SettingsResponse, SettingsUpdate, IntelRequest
from .analyzers.url_analyzer import analyze_url
from .analyzers.text_analyzer import analyze_text
from .services.reports import build_pdf
from .services.threat_intel import reputation_lookup, DEFAULTS

Base.metadata.create_all(bind=engine)
app=FastAPI(title='SentinelShield Threat Detection API',version='1.1.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])

def response(scan_type,target,result,scan):
    return ScanResult(id=scan.id,created_at=scan.created_at,scan_type=scan_type,target=target,risk_score=result['risk_score'],threat_level=result['threat_level'],category=result['category'],reasons=result['reasons'],indicators=result['indicators'],recommendation=result['recommendation'],ai_explanation=result['ai_explanation'],metadata=result.get('metadata',{}))
def persist(db,scan_type,target,result):
    scan=Scan(scan_type=scan_type,target=target,risk_score=result['risk_score'],threat_level=result['threat_level'],category=result['category'],reasons=json.dumps(result['reasons']),indicators=json.dumps(result['indicators']),recommendation=result['recommendation']); db.add(scan); db.commit(); db.refresh(scan); return scan

def seed_settings(db):
    for k,v in DEFAULTS.items():
        if not db.get(AppSetting,k): db.add(AppSetting(key=k,value=v))
    db.commit()

@app.on_event('startup')
def startup():
    db=next(get_db())
    try: seed_settings(db)
    finally: db.close()

@app.get('/api/health')
def health(): return {'status':'ok','service':'sentinelshield'}

@app.get('/api/settings',response_model=SettingsResponse)
def get_settings(db:Session=Depends(get_db)):
    seed_settings(db)
    return SettingsResponse(api_base_url='http://localhost:8000',external_lookups=db.get(AppSetting,'external_lookups').value.lower()=='true',virustotal_enabled=db.get(AppSetting,'virustotal_enabled').value.lower()=='true',virustotal_api_key_configured=bool(db.get(AppSetting,'virustotal_api_key').value),abuseipdb_enabled=db.get(AppSetting,'abuseipdb_enabled').value.lower()=='true',abuseipdb_api_key_configured=bool(db.get(AppSetting,'abuseipdb_api_key').value),dns_enrichment=db.get(AppSetting,'dns_enrichment').value.lower()=='true',ssl_enrichment=db.get(AppSetting,'ssl_enrichment').value.lower()=='true',rdap_enrichment=db.get(AppSetting,'rdap_enrichment').value.lower()=='true',timeout_seconds=int(db.get(AppSetting,'timeout_seconds').value))

@app.put('/api/settings',response_model=SettingsResponse)
def update_settings(payload:SettingsUpdate,db:Session=Depends(get_db)):
    seed_settings(db); data=payload.model_dump(exclude_none=True)
    for key,value in data.items():
        row=db.get(AppSetting,key)
        if row is None: row=AppSetting(key=key,value=str(value).lower() if isinstance(value,bool) else str(value)); db.add(row)
        else: row.value=str(value).lower() if isinstance(value,bool) else str(value)
    db.commit(); return get_settings(db)

@app.post('/api/scan/url',response_model=ScanResult)
async def scan_url(payload:ScanRequest,db:Session=Depends(get_db)):
    result=analyze_url(payload.input); intel=await reputation_lookup(result['metadata']['normalized_url'],db); result['metadata']['threat_intelligence']=intel
    vt=intel.get('virustotal',{}).get('verdict')
    if vt=='malicious': result['risk_score']=max(result['risk_score'],92); result['threat_level']='CRITICAL'; result['reasons'].append('Threat-intelligence provider reports malicious indicators.')
    scan=persist(db,'url',payload.input,result); return response('url',payload.input,result,scan)

@app.post('/api/scan/phishing',response_model=ScanResult)
def scan_phishing(payload:ScanRequest,db:Session=Depends(get_db)):
    result=analyze_text(payload.input); scan=persist(db,'phishing',payload.input,result); return response('phishing',payload.input,result,scan)
@app.post('/api/scan/message',response_model=ScanResult)
def scan_message(payload:ScanRequest,db:Session=Depends(get_db)):
    result=analyze_text(payload.input); scan=persist(db,'message',payload.input,result); return response('message',payload.input,result,scan)

@app.post('/api/threat-intelligence/lookup')
async def intel_lookup(payload:IntelRequest,db:Session=Depends(get_db)):
    return await reputation_lookup(payload.target,db)

@app.get('/api/dashboard',response_model=DashboardStats)
def dashboard(db:Session=Depends(get_db)):
    scans=db.query(Scan).order_by(Scan.created_at.desc()).all(); total=len(scans); threats=sum(s.risk_score>=45 for s in scans); phishing=sum(s.scan_type=='phishing' and s.risk_score>=45 for s in scans); urls=sum(s.scan_type=='url' and s.risk_score>=45 for s in scans)
    risk_counts={level:sum(s.threat_level==level for s in scans) for level in ['CRITICAL','HIGH','MEDIUM','LOW','SAFE']}; score=round(sum(100-s.risk_score for s in scans)/total) if total else 100; recent=[]
    for s in scans[:8]:
        reasons=json.loads(s.reasons); indicators=json.loads(s.indicators); recent.append(ScanResult(id=s.id,created_at=s.created_at,scan_type=s.scan_type,target=s.target,risk_score=s.risk_score,threat_level=s.threat_level,category=s.category,reasons=reasons,indicators=indicators,recommendation=s.recommendation,ai_explanation=(f"Detected: {' '.join(reasons[:3])}" if reasons else 'No strong static indicators detected.'),metadata={}))
    return DashboardStats(security_score=max(0,min(100,score)),total_scans=total,threats_detected=threats,phishing_attempts=phishing,suspicious_urls=urls,risk_counts=risk_counts,recent_events=recent)

@app.get('/api/reports/{scan_id}.pdf')
def report(scan_id:int,db:Session=Depends(get_db)):
    scan=db.get(Scan,scan_id)
    if not scan: raise HTTPException(status_code=404,detail='Scan not found')
    return StreamingResponse(build_pdf(scan),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="sentinelshield-report-{scan_id}.pdf"'})
