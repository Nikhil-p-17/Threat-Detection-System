from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    input: str = Field(min_length=1, max_length=10000)
class Indicator(BaseModel):
    name: str
    status: str
    detail: str
    weight: int = 0
class ScanResult(BaseModel):
    id: int | None = None
    scan_type: str
    target: str
    risk_score: int
    threat_level: str
    category: str
    reasons: list[str]
    indicators: list[Indicator]
    recommendation: str
    ai_explanation: str
    created_at: datetime | None = None
    metadata: dict[str, Any] = {}
class DashboardStats(BaseModel):
    security_score: int
    total_scans: int
    threats_detected: int
    phishing_attempts: int
    suspicious_urls: int
    risk_counts: dict[str, int]
    recent_events: list[ScanResult]
class SettingsResponse(BaseModel):
    api_base_url: str
    external_lookups: bool
    virustotal_enabled: bool
    virustotal_api_key_configured: bool
    abuseipdb_enabled: bool
    abuseipdb_api_key_configured: bool
    dns_enrichment: bool
    ssl_enrichment: bool
    rdap_enrichment: bool
    timeout_seconds: int
class SettingsUpdate(BaseModel):
    external_lookups: bool | None = None
    virustotal_enabled: bool | None = None
    virustotal_api_key: str | None = None
    abuseipdb_enabled: bool | None = None
    abuseipdb_api_key: str | None = None
    dns_enrichment: bool | None = None
    ssl_enrichment: bool | None = None
    rdap_enrichment: bool | None = None
    timeout_seconds: int | None = Field(default=None, ge=2, le=30)
class IntelRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
