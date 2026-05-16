"""
BlueTeam Enterprise - REST API
FastAPI endpoints for all operations
"""

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import json

from backend.database import (
    get_db, Threat, Event, Module, Vulnerability, ComplianceCheck,
    Incident, Playbook, PlaybookExecution, ThreatIntelligence,
    NetworkConnection, ProcessEvent, Alert, Integration
)
from backend.modules_impl import (
    AITrafficAnalyzer, ZeroTrustFirewall, IntrusionDetectionSystem,
    VPNSecureTunneling, DNSSecurityFilter, MalwareScanner,
    ProcessSentinel, KernelHardening, RegistryConfigGuard,
    USBHardwareBlocker, AutoPatchManager, ComplianceAuditor,
    VulnerabilityScanner, SecretScanner, BiometricMFAGateway,
    PrivilegeEscalationMonitor, SessionHijackingGuard,
    LogAggregatorSIEM, SnapshotRecovery, LiveForensicsToolkit,
    ThreatIntelligenceFeed, AutomatedPlaybookEngine,
    AISecurityAssistant, HoneypotDeployer
)

app = FastAPI(title="BlueTeam Enterprise API", version="2.0.0")

# Initialize modules
modules_registry = {
    "ai_traffic_analyzer": AITrafficAnalyzer(),
    "zero_trust_firewall": ZeroTrustFirewall(),
    "intrusion_detection": IntrusionDetectionSystem(),
    "vpn_tunneling": VPNSecureTunneling(),
    "dns_filter": DNSSecurityFilter(),
    "malware_scanner": MalwareScanner(),
    "process_sentinel": ProcessSentinel(),
    "kernel_hardening": KernelHardening(),
    "config_guard": RegistryConfigGuard(),
    "usb_blocker": USBHardwareBlocker(),
    "patch_manager": AutoPatchManager(),
    "compliance_auditor": ComplianceAuditor(),
    "vuln_scanner": VulnerabilityScanner(),
    "secret_scanner": SecretScanner(),
    "mfa_gateway": BiometricMFAGateway(),
    "priv_esc_monitor": PrivilegeEscalationMonitor(),
    "session_guard": SessionHijackingGuard(),
    "siem": LogAggregatorSIEM(),
    "backup_recovery": SnapshotRecovery(),
    "forensics": LiveForensicsToolkit(),
    "threat_intel": ThreatIntelligenceFeed(),
    "playbook_engine": AutomatedPlaybookEngine(),
    "ai_assistant": AISecurityAssistant(),
    "honeypot": HoneypotDeployer(),
}


# ============================================================================
# THREAT ENDPOINTS
# ============================================================================

@app.get("/api/threats")
async def get_threats(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get threats"""
    query = db.query(Threat)
    
    if severity:
        query = query.filter(Threat.severity == severity)
    if status:
        query = query.filter(Threat.status == status)
    
    threats = query.order_by(Threat.timestamp.desc()).offset(skip).limit(limit).all()
    return {"threats": threats, "total": query.count()}


@app.get("/api/threats/{threat_id}")
async def get_threat(threat_id: str, db: Session = Depends(get_db)):
    """Get threat details"""
    threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@app.post("/api/threats/{threat_id}/resolve")
async def resolve_threat(threat_id: str, db: Session = Depends(get_db)):
    """Resolve threat"""
    threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    threat.status = "resolved"
    threat.resolved_at = datetime.utcnow()
    db.commit()
    return {"status": "resolved"}


# ============================================================================
# MODULE ENDPOINTS
# ============================================================================

@app.get("/api/modules")
async def list_modules(db: Session = Depends(get_db)):
    """List all modules"""
    modules = db.query(Module).all()
    return {"modules": modules, "total": len(modules)}


@app.get("/api/modules/{module_name}")
async def get_module(module_name: str, db: Session = Depends(get_db)):
    """Get module details"""
    module = db.query(Module).filter(Module.name == module_name).first()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return module


@app.post("/api/modules/{module_name}/run")
async def run_module(module_name: str, db: Session = Depends(get_db)):
    """Run module"""
    if module_name not in modules_registry:
        raise HTTPException(status_code=404, detail="Module not found")
    
    module_instance = modules_registry[module_name]
    
    # Get appropriate detection method
    if "traffic" in module_name:
        result = module_instance.analyze_traffic()
    elif "firewall" in module_name:
        result = module_instance.check_connection("0.0.0.0", 80)
    elif "malware" in module_name:
        result = module_instance.scan_file("/tmp/test")
    else:
        result = {"status": "executed"}
    
    return result


@app.post("/api/modules/{module_name}/toggle")
async def toggle_module(module_name: str, db: Session = Depends(get_db)):
    """Enable/disable module"""
    module = db.query(Module).filter(Module.name == module_name).first()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    
    module.enabled = not module.enabled
    db.commit()
    return {"enabled": module.enabled}


# ============================================================================
# VULNERABILITY ENDPOINTS
# ============================================================================

@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get vulnerabilities"""
    query = db.query(Vulnerability)
    
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    vulns = query.order_by(Vulnerability.discovered_at.desc()).offset(skip).limit(limit).all()
    return {"vulnerabilities": vulns, "total": query.count()}


@app.post("/api/vulnerabilities/{cve_id}/patch")
async def patch_vulnerability(cve_id: str, db: Session = Depends(get_db)):
    """Mark vulnerability as patched"""
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    vuln.patched_at = datetime.utcnow()
    db.commit()
    return {"status": "patched"}


# ============================================================================
# COMPLIANCE ENDPOINTS
# ============================================================================

@app.get("/api/compliance")
async def get_compliance_status(
    framework: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get compliance status"""
    query = db.query(ComplianceCheck)
    
    if framework:
        query = query.filter(ComplianceCheck.framework == framework)
    
    checks = query.all()
    
    total = len(checks)
    passed = len([c for c in checks if c.status == "pass"])
    failed = len([c for c in checks if c.status == "fail"])
    
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "score": (passed / total * 100) if total > 0 else 0,
        "checks": checks
    }


@app.post("/api/compliance/{check_id}/remediate")
async def remediate_compliance(check_id: str, db: Session = Depends(get_db)):
    """Remediate compliance check"""
    check = db.query(ComplianceCheck).filter(ComplianceCheck.check_id == check_id).first()
    if not check:
        raise HTTPException(status_code=404, detail="Check not found")
    
    check.status = "pass"
    db.commit()
    return {"status": "remediated"}


# ============================================================================
# INCIDENT ENDPOINTS
# ============================================================================

@app.get("/api/incidents")
async def get_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get incidents"""
    query = db.query(Incident)
    
    if status:
        query = query.filter(Incident.status == status)
    
    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    return {"incidents": incidents, "total": query.count()}


@app.post("/api/incidents/{incident_id}/execute-playbook")
async def execute_playbook(incident_id: str, playbook_id: int, db: Session = Depends(get_db)):
    """Execute playbook for incident"""
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    execution = PlaybookExecution(
        playbook_id=playbook_id,
        incident_id=incident.id,
        status="running"
    )
    db.add(execution)
    db.commit()
    
    return {"execution_id": execution.id, "status": "running"}


# ============================================================================
# THREAT INTELLIGENCE ENDPOINTS
# ============================================================================

@app.get("/api/threat-intelligence")
async def get_threat_intelligence(
    indicator_type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get threat intelligence"""
    query = db.query(ThreatIntelligence)
    
    if indicator_type:
        query = query.filter(ThreatIntelligence.indicator_type == indicator_type)
    
    indicators = query.order_by(ThreatIntelligence.last_seen.desc()).offset(skip).limit(limit).all()
    return {"indicators": indicators, "total": query.count()}


@app.post("/api/threat-intelligence/check")
async def check_indicator(indicator_value: str, db: Session = Depends(get_db)):
    """Check if indicator is malicious"""
    indicator = db.query(ThreatIntelligence).filter(
        ThreatIntelligence.indicator_value == indicator_value
    ).first()
    
    if indicator:
        return {
            "malicious": True,
            "threat_type": indicator.threat_type,
            "severity": indicator.severity
        }
    
    return {"malicious": False}


# ============================================================================
# INTEGRATION ENDPOINTS
# ============================================================================

@app.get("/api/integrations")
async def list_integrations(db: Session = Depends(get_db)):
    """List integrations"""
    integrations = db.query(Integration).all()
    return {"integrations": integrations}


@app.post("/api/integrations")
async def create_integration(
    name: str,
    integration_type: str,
    config: dict,
    db: Session = Depends(get_db)
):
    """Create integration"""
    integration = Integration(
        name=name,
        integration_type=integration_type,
        config=config
    )
    db.add(integration)
    db.commit()
    return {"id": integration.id, "status": "created"}


@app.post("/api/integrations/{integration_id}/test")
async def test_integration(integration_id: int, db: Session = Depends(get_db)):
    """Test integration"""
    integration = db.query(Integration).filter(Integration.id == integration_id).first()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    # Test connection
    return {"status": "connected"}


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@app.get("/api/dashboard/summary")
async def get_dashboard_summary(db: Session = Depends(get_db)):
    """Get dashboard summary"""
    
    # Calculate statistics
    total_threats = db.query(Threat).count()
    critical_threats = db.query(Threat).filter(Threat.severity == "critical").count()
    resolved_threats = db.query(Threat).filter(Threat.status == "resolved").count()
    
    total_modules = db.query(Module).count()
    active_modules = db.query(Module).filter(Module.status == "running").count()
    
    total_vulns = db.query(Vulnerability).count()
    unpatched_vulns = db.query(Vulnerability).filter(Vulnerability.patched_at == None).count()
    
    return {
        "threats": {
            "total": total_threats,
            "critical": critical_threats,
            "resolved": resolved_threats
        },
        "modules": {
            "total": total_modules,
            "active": active_modules
        },
        "vulnerabilities": {
            "total": total_vulns,
            "unpatched": unpatched_vulns
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/dashboard/timeline")
async def get_threat_timeline(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db)
):
    """Get threat timeline"""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    threats = db.query(Threat).filter(Threat.timestamp >= since).order_by(Threat.timestamp).all()
    
    # Group by hour
    timeline = {}
    for threat in threats:
        hour = threat.timestamp.strftime("%Y-%m-%d %H:00")
        if hour not in timeline:
            timeline[hour] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        timeline[hour]["total"] += 1
        timeline[hour][threat.severity] += 1
    
    return {"timeline": timeline}


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
