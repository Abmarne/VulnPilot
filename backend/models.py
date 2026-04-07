from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="In Progress")  # init, recon, sast, fuzzing, analysis, complete, error
    finding_count = Column(Integer, default=0)
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    
    vulnerability_type = Column(String)
    severity = Column(String)
    explanation = Column(Text)
    url = Column(String)
    manual_poc = Column(Text)
    poc_script = Column(Text)
    remediation_code = Column(Text)
    remediation_steps = Column(Text)
    is_verified = Column(Boolean, default=False)
    is_fixed = Column(Boolean, default=False)
    
    scan = relationship("Scan", back_populates="findings")
