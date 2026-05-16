"""
BlueTeam Enterprise - Event System & Log Correlation
Real-time event processing and threat correlation
"""

import json
import logging
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, asdict
import hashlib
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """Security event"""
    event_id: str
    event_type: str
    source: str
    severity: str
    data: Dict[str, Any]
    timestamp: datetime
    correlated_threats: List[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "severity": self.severity,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "correlated_threats": self.correlated_threats or []
        }


class EventCorrelationEngine:
    """Correlate security events to detect threats"""
    
    def __init__(self):
        self.event_history = []
        self.threat_patterns = self._initialize_patterns()
        self.correlation_rules = self._initialize_rules()
        self.event_window = timedelta(minutes=5)
    
    def _initialize_patterns(self) -> Dict[str, Dict]:
        """Initialize threat patterns"""
        return {
            "brute_force": {
                "events": ["failed_login", "failed_login", "failed_login"],
                "window": timedelta(minutes=5),
                "severity": "high"
            },
            "port_scan": {
                "events": ["connection_attempt", "connection_attempt", "connection_attempt"],
                "window": timedelta(minutes=1),
                "severity": "high"
            },
            "data_exfiltration": {
                "events": ["file_access", "network_connection", "file_access"],
                "window": timedelta(minutes=10),
                "severity": "critical"
            },
            "privilege_escalation": {
                "events": ["sudo_attempt", "sudo_success"],
                "window": timedelta(minutes=1),
                "severity": "high"
            },
            "lateral_movement": {
                "events": ["network_connection", "process_execution", "file_access"],
                "window": timedelta(minutes=5),
                "severity": "high"
            }
        }
    
    def _initialize_rules(self) -> List[Dict]:
        """Initialize correlation rules"""
        return [
            {
                "name": "Multiple Failed Logins",
                "conditions": [
                    {"field": "event_type", "operator": "==", "value": "failed_login"},
                    {"field": "count", "operator": ">", "value": 5}
                ],
                "action": "create_incident",
                "severity": "high"
            },
            {
                "name": "Suspicious Port Access",
                "conditions": [
                    {"field": "event_type", "operator": "==", "value": "connection_attempt"},
                    {"field": "dst_port", "operator": "in", "value": [666, 6666, 31337]}
                ],
                "action": "alert",
                "severity": "high"
            },
            {
                "name": "Unauthorized Privilege Escalation",
                "conditions": [
                    {"field": "event_type", "operator": "==", "value": "sudo_attempt"},
                    {"field": "authorized", "operator": "==", "value": False}
                ],
                "action": "block_and_alert",
                "severity": "critical"
            }
        ]
    
    def add_event(self, event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Add event and check for correlations"""
        self.event_history.append(event)
        
        # Clean old events
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        self.event_history = [e for e in self.event_history if e.timestamp > cutoff_time]
        
        # Check for threat patterns
        detected_threat = self._check_patterns(event)
        
        if detected_threat:
            return detected_threat
        
        # Check correlation rules
        triggered_rule = self._check_rules(event)
        
        if triggered_rule:
            return triggered_rule
        
        return None
    
    def _check_patterns(self, event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Check if event matches threat patterns"""
        
        for threat_name, pattern in self.threat_patterns.items():
            if self._match_pattern(pattern):
                return {
                    "threat_type": threat_name,
                    "severity": pattern["severity"],
                    "events": pattern["events"],
                    "description": f"Detected {threat_name} pattern"
                }
        
        return None
    
    def _match_pattern(self, pattern: Dict) -> bool:
        """Match event pattern"""
        required_events = pattern["events"]
        window = pattern["window"]
        cutoff_time = datetime.utcnow() - window
        
        recent_events = [e for e in self.event_history if e.timestamp > cutoff_time]
        event_types = [e.event_type for e in recent_events]
        
        # Check if pattern matches
        match_count = 0
        for required in required_events:
            if required in event_types:
                match_count += 1
        
        return match_count >= len(required_events) * 0.8
    
    def _check_rules(self, event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Check correlation rules"""
        
        for rule in self.correlation_rules:
            if self._evaluate_rule(rule, event):
                return {
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "action": rule["action"],
                    "description": f"Rule triggered: {rule['name']}"
                }
        
        return None
    
    def _evaluate_rule(self, rule: Dict, event: SecurityEvent) -> bool:
        """Evaluate if rule conditions are met"""
        
        for condition in rule.get("conditions", []):
            if not self._evaluate_condition(condition, event):
                return False
        
        return True
    
    def _evaluate_condition(self, condition: Dict, event: SecurityEvent) -> bool:
        """Evaluate single condition"""
        
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")
        
        if field == "event_type":
            event_value = event.event_type
        elif field == "severity":
            event_value = event.severity
        elif field == "count":
            event_value = len([e for e in self.event_history if e.event_type == event.event_type])
        else:
            event_value = event.data.get(field)
        
        if operator == "==":
            return event_value == value
        elif operator == ">":
            return event_value > value
        elif operator == "<":
            return event_value < value
        elif operator == "in":
            return event_value in value
        elif operator == "contains":
            return value in str(event_value)
        
        return False
    
    def get_correlation_stats(self) -> Dict[str, Any]:
        """Get correlation statistics"""
        
        event_types = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for event in self.event_history:
            event_types[event.event_type] += 1
            severity_counts[event.severity] += 1
        
        return {
            "total_events": len(self.event_history),
            "event_types": dict(event_types),
            "severity_distribution": dict(severity_counts),
            "time_window": self.event_window.total_seconds()
        }


class LogAggregator:
    """Aggregate logs from multiple sources"""
    
    def __init__(self):
        self.logs = []
        self.sources = {}
    
    def register_source(self, source_name: str, log_path: str):
        """Register log source"""
        self.sources[source_name] = log_path
    
    def parse_syslog(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse syslog entry"""
        try:
            # Extract timestamp
            parts = log_line.split()
            if len(parts) < 3:
                return None
            
            # Create event
            event_id = hashlib.md5(log_line.encode()).hexdigest()
            
            return SecurityEvent(
                event_id=event_id,
                event_type="syslog",
                source="syslog",
                severity="info",
                data={"message": log_line},
                timestamp=datetime.utcnow()
            )
        except:
            return None
    
    def parse_auth_log(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse auth log entry"""
        try:
            event_id = hashlib.md5(log_line.encode()).hexdigest()
            
            if "Failed password" in log_line:
                return SecurityEvent(
                    event_id=event_id,
                    event_type="failed_login",
                    source="auth",
                    severity="medium",
                    data={"message": log_line},
                    timestamp=datetime.utcnow()
                )
            elif "Accepted" in log_line:
                return SecurityEvent(
                    event_id=event_id,
                    event_type="successful_login",
                    source="auth",
                    severity="info",
                    data={"message": log_line},
                    timestamp=datetime.utcnow()
                )
            elif "sudo" in log_line:
                return SecurityEvent(
                    event_id=event_id,
                    event_type="sudo_attempt",
                    source="auth",
                    severity="high",
                    data={"message": log_line},
                    timestamp=datetime.utcnow()
                )
        except:
            pass
        
        return None
    
    def parse_firewall_log(self, log_line: str) -> Optional[SecurityEvent]:
        """Parse firewall log entry"""
        try:
            event_id = hashlib.md5(log_line.encode()).hexdigest()
            
            if "DROP" in log_line or "REJECT" in log_line:
                return SecurityEvent(
                    event_id=event_id,
                    event_type="connection_blocked",
                    source="firewall",
                    severity="medium",
                    data={"message": log_line},
                    timestamp=datetime.utcnow()
                )
            elif "ACCEPT" in log_line:
                return SecurityEvent(
                    event_id=event_id,
                    event_type="connection_allowed",
                    source="firewall",
                    severity="info",
                    data={"message": log_line},
                    timestamp=datetime.utcnow()
                )
        except:
            pass
        
        return None
    
    def aggregate_logs(self) -> List[SecurityEvent]:
        """Aggregate logs from all sources"""
        events = []
        
        for source_name, log_path in self.sources.items():
            try:
                with open(log_path, 'r') as f:
                    for line in f:
                        event = None
                        
                        if "auth" in source_name.lower():
                            event = self.parse_auth_log(line)
                        elif "firewall" in source_name.lower():
                            event = self.parse_firewall_log(line)
                        else:
                            event = self.parse_syslog(line)
                        
                        if event:
                            events.append(event)
            except Exception as e:
                logger.error(f"Error reading log from {source_name}: {e}")
        
        return events


class ThreatCorrelator:
    """Correlate multiple indicators to identify threats"""
    
    def __init__(self):
        self.indicators = defaultdict(list)
        self.threat_scores = {}
    
    def add_indicator(self, indicator_type: str, value: str, severity: str):
        """Add threat indicator"""
        self.indicators[indicator_type].append({
            "value": value,
            "severity": severity,
            "timestamp": datetime.utcnow()
        })
    
    def correlate_indicators(self) -> List[Dict[str, Any]]:
        """Correlate indicators to identify threats"""
        threats = []
        
        # Check for IP-based threats
        if "malicious_ip" in self.indicators:
            ips = self.indicators["malicious_ip"]
            if len(ips) > 3:
                threats.append({
                    "threat_type": "Coordinated Attack",
                    "severity": "high",
                    "indicators": [i["value"] for i in ips],
                    "description": "Multiple malicious IPs detected"
                })
        
        # Check for domain-based threats
        if "malicious_domain" in self.indicators:
            domains = self.indicators["malicious_domain"]
            if len(domains) > 2:
                threats.append({
                    "threat_type": "Malware C2 Communication",
                    "severity": "critical",
                    "indicators": [d["value"] for d in domains],
                    "description": "Multiple C2 domains detected"
                })
        
        # Check for hash-based threats
        if "malicious_hash" in self.indicators:
            hashes = self.indicators["malicious_hash"]
            if len(hashes) > 1:
                threats.append({
                    "threat_type": "Malware Distribution",
                    "severity": "critical",
                    "indicators": [h["value"] for h in hashes],
                    "description": "Multiple malware samples detected"
                })
        
        return threats
    
    def calculate_threat_score(self, indicators: List[Dict]) -> float:
        """Calculate overall threat score"""
        if not indicators:
            return 0.0
        
        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.0
        }
        
        total_score = sum(severity_scores.get(i.get("severity", "info"), 0) for i in indicators)
        return min(total_score / len(indicators), 1.0)
