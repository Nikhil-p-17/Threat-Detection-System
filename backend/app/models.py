from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text
from .database import Base

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    scan_type = Column(String(40), nullable=False)
    target = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    threat_level = Column(String(20), nullable=False)
    category = Column(String(80), nullable=False)
    reasons = Column(Text, nullable=False)
    indicators = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AppSetting(Base):
    __tablename__ = "app_settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
