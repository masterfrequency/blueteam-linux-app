"""
BlueTeam Enterprise - Database Layer
PostgreSQL schema and ORM models
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, JSON, ForeignKey, Index, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum
import os

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://blueteam:blueteam@localhost/blueteam")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ThreatLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ModuleStatus(str, enum.Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DISABLED = "disabled"


# ============================================================================
# THREAT DETECTION MODELS
# ============================================================================

class Threat(Base):
    """Detected threat"""
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(255), unique=True, index=True)
    threat_type = Column(String(255), index=True)
    severity = Column(Enum(ThreatLevel), index=True)
    status = Column(Enum(ThreatStatus), default=ThreatStatus.NEW, index=True)
    description = Column(Text)
    source_pid = Column(Integer, nullable=True)
    source_process = Column(String(255), nullable=True)
    indicators = Column(JSON)
    action_taken = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    events = relationship("Event", back_populates="threat")
    forensics = relationship("ForensicData", back_populates="threat")
    
    __table_args__ = (
        Index('idx_threat_type_severity', 'threat_type', 'severity'),
        Index('idx_threat_timestamp', 'timestamp'),
    )


class Event(Base):
    """Security event"""
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(255), unique=True, index=True)
    event_type = Column(String(255), index=True)  # network, process, file, auth, etc.
    source = Column(String(255), index=True)
    severity = Column(Enum(ThreatLevel), index=True)
    data = Column(JSON)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    threat = relationship("Threat", back_populates="events")
    
    __table_args__ = (
        Index('idx_event_type_timestamp', 'event_type', 'timestamp'),
    )


# ============================================================================
# MODULE MODELS
# ============================================================================

class Module(Base):
    """Security module"""
    __tablename__ = "modules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    display_name = Column(String(255))
    category = Column(String(255), index=True)  # network, endpoint, vulnerability, etc.
    description = Column(Text)
    status = Column(Enum(ModuleStatus), default=ModuleStatus.STOPPED, index=True)
    enabled = Column(Boolean, default=True)
    config = Column(JSON)
    last_check = Column(DateTime, nullable=True)
    threats_detected = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    metrics = relationship("ModuleMetric", back_populates="module")
    
    __table_args__ = (
        Index('idx_module_category', 'category'),
    )


class ModuleMetric(Base):
    """Module performance metrics"""
    __tablename__ = "module_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    module_id = Column(Integer, ForeignKey("modules.id"), index=True)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    threats_detected = Column(Integer)
    false_positives = Column(Integer)
    detection_latency_ms = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    module = relationship("Module", back_populates="metrics")
    
    __table_args__ = (
        Index('idx_metric_timestamp', 'timestamp'),
    )


# ============================================================================
# NETWORK MONITORING MODELS
# ============================================================================

class NetworkConnection(Base):
    """Network connection log"""
    __tablename__ = "network_connections"
    
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, index=True)
    process_name = Column(String(255), index=True)
    src_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_ip = Column(String(45), index=True)
    dst_port = Column(Integer, index=True)
    protocol = Column(String(10))
    status = Column(String(50))
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.INFO)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_conn_dst_port', 'dst_port'),
        Index('idx_conn_timestamp', 'timestamp'),
    )


class DNSQuery(Base):
    """DNS query log"""
    __tablename__ = "dns_queries"
    
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, nullable=True)
    process_name = Column(String(255), nullable=True)
    query_domain = Column(String(255), index=True)
    query_type = Column(String(10))
    response = Column(String(45), nullable=True)
    blocked = Column(Boolean, default=False)
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.INFO)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_dns_domain', 'query_domain'),
        Index('idx_dns_timestamp', 'timestamp'),
    )


# ============================================================================
# ENDPOINT MONITORING MODELS
# ============================================================================

class ProcessEvent(Base):
    """Process lifecycle event"""
    __tablename__ = "process_events"
    
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, index=True)
    ppid = Column(Integer)
    process_name = Column(String(255), index=True)
    command_line = Column(Text)
    user = Column(String(255), index=True)
    event_type = Column(String(50))  # fork, exec, exit
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.INFO)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_proc_timestamp', 'timestamp'),
    )


class FileAccess(Base):
    """File access event"""
    __tablename__ = "file_access"
    
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, index=True)
    process_name = Column(String(255), index=True)
    file_path = Column(String(512), index=True)
    access_type = Column(String(50))  # read, write, execute
    user = Column(String(255))
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.INFO)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_file_path', 'file_path'),
        Index('idx_file_timestamp', 'timestamp'),
    )


class PrivilegeEscalation(Base):
    """Privilege escalation event"""
    __tablename__ = "privilege_escalations"
    
    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, index=True)
    process_name = Column(String(255), index=True)
    from_user = Column(String(255))
    to_user = Column(String(255))
    command = Column(Text)
    authorized = Column(Boolean)
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.HIGH)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_priv_esc_timestamp', 'timestamp'),
    )


# ============================================================================
# VULNERABILITY MODELS
# ============================================================================

class Vulnerability(Base):
    """Detected vulnerability"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, index=True)
    title = Column(String(512))
    description = Column(Text)
    severity = Column(Enum(ThreatLevel), index=True)
    cvss_score = Column(Float)
    affected_package = Column(String(255), index=True)
    affected_version = Column(String(100))
    patch_available = Column(Boolean)
    patch_version = Column(String(100), nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow, index=True)
    patched_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_vuln_severity', 'severity'),
    )


class ComplianceCheck(Base):
    """Compliance audit check"""
    __tablename__ = "compliance_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    check_id = Column(String(255), unique=True, index=True)
    framework = Column(String(50))  # CIS, NIST, PCI-DSS
    control_id = Column(String(100), index=True)
    title = Column(String(512))
    description = Column(Text)
    status = Column(String(50))  # pass, fail, unknown
    remediation = Column(Text)
    last_checked = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_compliance_framework', 'framework'),
    )


class Secret(Base):
    """Detected secret/credential"""
    __tablename__ = "secrets"
    
    id = Column(Integer, primary_key=True, index=True)
    secret_type = Column(String(100))  # api_key, password, token, etc.
    location = Column(String(512), index=True)
    severity = Column(Enum(ThreatLevel), default=ThreatLevel.CRITICAL)
    status = Column(String(50))  # active, revoked, rotated
    discovered_at = Column(DateTime, default=datetime.utcnow, index=True)
    remediated_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_secret_type', 'secret_type'),
    )


# ============================================================================
# INCIDENT RESPONSE MODELS
# ============================================================================

class Incident(Base):
    """Security incident"""
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(255), unique=True, index=True)
    title = Column(String(512))
    description = Column(Text)
    severity = Column(Enum(ThreatLevel), index=True)
    status = Column(String(50))  # open, investigating, resolved
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)
    assigned_to = Column(String(255), nullable=True)
    
    # Relationships
    playbook_executions = relationship("PlaybookExecution", back_populates="incident")


class Playbook(Base):
    """Incident response playbook"""
    __tablename__ = "playbooks"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    description = Column(Text)
    trigger_type = Column(String(100))  # threat_type, severity, etc.
    trigger_value = Column(String(255))
    actions = Column(JSON)  # List of actions to execute
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    executions = relationship("PlaybookExecution", back_populates="playbook")


class PlaybookExecution(Base):
    """Playbook execution record"""
    __tablename__ = "playbook_executions"
    
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), index=True)
    status = Column(String(50))  # pending, running, success, failed
    result = Column(JSON)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    playbook = relationship("Playbook", back_populates="executions")
    incident = relationship("Incident", back_populates="playbook_executions")


# ============================================================================
# FORENSICS MODELS
# ============================================================================

class ForensicData(Base):
    """Forensic evidence"""
    __tablename__ = "forensic_data"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), index=True)
    data_type = Column(String(100))  # memory_dump, disk_image, logs, etc.
    location = Column(String(512))
    size_bytes = Column(Integer)
    hash_sha256 = Column(String(64), index=True)
    collected_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    threat = relationship("Threat", back_populates="forensics")


# ============================================================================
# INTEGRATION MODELS
# ============================================================================

class Integration(Base):
    """External integration"""
    __tablename__ = "integrations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    integration_type = Column(String(100))  # slack, pagerduty, siem, etc.
    config = Column(JSON)  # Encrypted credentials
    enabled = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    """Sent alert"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), index=True)
    integration_id = Column(Integer, ForeignKey("integrations.id"), index=True)
    destination = Column(String(512))
    status = Column(String(50))  # sent, failed, acknowledged
    sent_at = Column(DateTime, default=datetime.utcnow, index=True)
    response = Column(JSON, nullable=True)


# ============================================================================
# THREAT INTELLIGENCE MODELS
# ============================================================================

class ThreatIntelligence(Base):
    """Threat intelligence feed"""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(100))  # ip, domain, hash, etc.
    indicator_value = Column(String(512), index=True)
    threat_type = Column(String(255))
    severity = Column(Enum(ThreatLevel))
    source = Column(String(255))
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_indicator_value', 'indicator_value'),
    )


# ============================================================================
# AUDIT LOG MODELS
# ============================================================================

class AuditLog(Base):
    """System audit log"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(255), index=True)
    actor = Column(String(255))
    target = Column(String(512))
    result = Column(String(50))  # success, failure
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_audit_timestamp', 'timestamp'),
    )


# Database initialization
def init_db():
    """Initialize database"""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
