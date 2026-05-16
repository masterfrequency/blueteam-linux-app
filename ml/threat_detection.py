"""
BlueTeam Enterprise - ML-Based Threat Detection
Machine learning models for advanced threat detection
"""

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from typing import Dict, List, Any, Tuple
from datetime import datetime
import json
from dataclasses import dataclass


@dataclass
class MLThreatPrediction:
    """ML threat prediction result"""
    threat_type: str
    confidence: float
    risk_score: float
    indicators: List[str]
    recommendation: str


class NetworkAnomalyDetector:
    """Detect network anomalies using ML"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.pca = PCA(n_components=3)
        self.is_trained = False
        self.baseline_features = None
        
    def extract_features(self, connection: Dict[str, Any]) -> np.ndarray:
        """Extract features from network connection"""
        
        features = [
            self._port_to_risk(connection.get("dst_port", 0)),
            self._ip_to_risk(connection.get("dst_ip", "")),
            1.0 if connection.get("protocol") == "TCP" else 0.5,
            1.0 if connection.get("status") == "ESTABLISHED" else 0.5,
        ]
        
        return np.array(features).reshape(1, -1)
        
    def _port_to_risk(self, port: int) -> float:
        """Convert port to risk score"""
        
        # High-risk ports
        high_risk = [666, 6666, 31337, 27374, 27665, 27666, 27667]
        if port in high_risk:
            return 1.0
            
        # Unusual ports
        if port > 10000:
            return 0.7
            
        # Well-known ports
        if port in [80, 443, 22, 21]:
            return 0.1
            
        return 0.5
        
    def _ip_to_risk(self, ip: str) -> float:
        """Convert IP to risk score"""
        
        # Local networks
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return 0.2
            
        # Private/reserved
        if ip.startswith("127.") or ip.startswith("169.254."):
            return 0.1
            
        # Unknown external
        return 0.8
        
    def train(self, normal_connections: List[Dict[str, Any]]):
        """Train anomaly detector on normal traffic"""
        
        features_list = []
        for conn in normal_connections:
            features = self.extract_features(conn)
            features_list.append(features)
            
        if features_list:
            X = np.vstack(features_list)
            self.baseline_features = X
            X_scaled = self.scaler.fit_transform(X)
            self.isolation_forest.fit(X_scaled)
            self.is_trained = True
            
    def detect_anomaly(self, connection: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if connection is anomalous"""
        
        if not self.is_trained:
            return False, 0.0
            
        features = self.extract_features(connection)
        X_scaled = self.scaler.transform(features)
        
        # Isolation Forest returns -1 for anomalies, 1 for normal
        prediction = self.isolation_forest.predict(X_scaled)[0]
        anomaly_score = -self.isolation_forest.score_samples(X_scaled)[0]
        
        is_anomaly = prediction == -1
        confidence = min(anomaly_score / 2.0, 1.0)  # Normalize to 0-1
        
        return is_anomaly, confidence


class ProcessAnomalyDetector:
    """Detect process anomalies using ML"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        
    def extract_features(self, process: Dict[str, Any]) -> np.ndarray:
        """Extract features from process"""
        
        features = [
            self._process_name_to_risk(process.get("process_name", "")),
            self._user_to_risk(process.get("user", "")),
            1.0 if process.get("event_type") == "exec" else 0.5,
            self._cmdline_to_risk(process.get("command_line", "")),
        ]
        
        return np.array(features).reshape(1, -1)
        
    def _process_name_to_risk(self, name: str) -> float:
        """Convert process name to risk score"""
        
        suspicious = ["nc", "ncat", "netcat", "curl", "wget", "python", "perl"]
        if any(s in name.lower() for s in suspicious):
            return 0.8
            
        if name.startswith("."):
            return 1.0
            
        return 0.2
        
    def _user_to_risk(self, user: str) -> float:
        """Convert user to risk score"""
        
        if user == "root":
            return 0.7
        if user == "nobody":
            return 0.9
            
        return 0.3
        
    def _cmdline_to_risk(self, cmdline: str) -> float:
        """Convert command line to risk score"""
        
        suspicious_patterns = ["-e", "bash", "sh", "/dev/tcp", "nc", "ncat"]
        if any(pattern in cmdline.lower() for pattern in suspicious_patterns):
            return 0.9
            
        return 0.2
        
    def train(self, normal_processes: List[Dict[str, Any]]):
        """Train anomaly detector on normal processes"""
        
        features_list = []
        for proc in normal_processes:
            features = self.extract_features(proc)
            features_list.append(features)
            
        if features_list:
            X = np.vstack(features_list)
            X_scaled = self.scaler.fit_transform(X)
            self.isolation_forest.fit(X_scaled)
            self.is_trained = True
            
    def detect_anomaly(self, process: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if process is anomalous"""
        
        if not self.is_trained:
            return False, 0.0
            
        features = self.extract_features(process)
        X_scaled = self.scaler.transform(features)
        
        prediction = self.isolation_forest.predict(X_scaled)[0]
        anomaly_score = -self.isolation_forest.score_samples(X_scaled)[0]
        
        is_anomaly = prediction == -1
        confidence = min(anomaly_score / 2.0, 1.0)
        
        return is_anomaly, confidence


class ThreatClassifier:
    """Classify threats using ML"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.threat_types = [
            "malware",
            "intrusion",
            "data_exfiltration",
            "privilege_escalation",
            "lateral_movement",
            "resource_abuse"
        ]
        self.is_trained = False
        
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract features from security event"""
        
        features = [
            len(event.get("indicators", [])),
            self._severity_to_score(event.get("severity", "low")),
            self._event_type_to_score(event.get("event_type", "")),
            self._source_to_score(event.get("source", "")),
        ]
        
        return np.array(features).reshape(1, -1)
        
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to score"""
        severity_map = {
            "info": 0.1,
            "low": 0.3,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0
        }
        return severity_map.get(severity.lower(), 0.5)
        
    def _event_type_to_score(self, event_type: str) -> float:
        """Convert event type to score"""
        type_map = {
            "network": 0.6,
            "process": 0.7,
            "file": 0.5,
            "auth": 0.8,
        }
        return type_map.get(event_type.lower(), 0.5)
        
    def _source_to_score(self, source: str) -> float:
        """Convert source to score"""
        if "external" in source.lower():
            return 0.9
        if "internal" in source.lower():
            return 0.4
        return 0.5
        
    def train(self, labeled_events: List[Tuple[Dict[str, Any], str]]):
        """Train classifier on labeled events"""
        
        X_list = []
        y_list = []
        
        for event, threat_type in labeled_events:
            features = self.extract_features(event)
            X_list.append(features)
            y_list.append(threat_type)
            
        if X_list:
            X = np.vstack(X_list)
            X_scaled = self.scaler.fit_transform(X)
            self.classifier.fit(X_scaled, y_list)
            self.is_trained = True
            
    def classify(self, event: Dict[str, Any]) -> MLThreatPrediction:
        """Classify threat type"""
        
        if not self.is_trained:
            return MLThreatPrediction(
                threat_type="unknown",
                confidence=0.0,
                risk_score=0.5,
                indicators=[],
                recommendation="Requires manual analysis"
            )
            
        features = self.extract_features(event)
        X_scaled = self.scaler.transform(features)
        
        prediction = self.classifier.predict(X_scaled)[0]
        probabilities = self.classifier.predict_proba(X_scaled)[0]
        confidence = max(probabilities)
        
        return MLThreatPrediction(
            threat_type=prediction,
            confidence=confidence,
            risk_score=confidence,
            indicators=event.get("indicators", []),
            recommendation=self._get_recommendation(prediction, confidence)
        )
        
    def _get_recommendation(self, threat_type: str, confidence: float) -> str:
        """Get recommendation based on threat type"""
        
        recommendations = {
            "malware": "Isolate system and run full antivirus scan",
            "intrusion": "Block source IP and review logs",
            "data_exfiltration": "Investigate data access and block suspicious connections",
            "privilege_escalation": "Review sudo logs and disable unnecessary privileges",
            "lateral_movement": "Segment network and review access controls",
            "resource_abuse": "Limit resource usage and investigate process",
        }
        
        base_rec = recommendations.get(threat_type, "Monitor and investigate")
        
        if confidence > 0.9:
            return f"URGENT: {base_rec}"
        elif confidence > 0.7:
            return f"HIGH PRIORITY: {base_rec}"
        else:
            return f"Monitor: {base_rec}"


class BehavioralAnalyzer:
    """Analyze behavioral patterns for threats"""
    
    def __init__(self):
        self.baseline_behavior = {}
        self.deviation_threshold = 2.0  # Standard deviations
        
    def learn_baseline(self, events: List[Dict[str, Any]]):
        """Learn baseline behavior"""
        
        # Extract patterns
        for event in events:
            process = event.get("process_name", "unknown")
            if process not in self.baseline_behavior:
                self.baseline_behavior[process] = {
                    "connection_count": 0,
                    "file_access_count": 0,
                    "memory_usage": [],
                    "cpu_usage": [],
                }
                
    def detect_behavioral_anomaly(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect behavioral anomalies"""
        
        process = event.get("process_name", "unknown")
        
        if process not in self.baseline_behavior:
            # Unknown process
            return True, 0.7
            
        baseline = self.baseline_behavior[process]
        
        # Check for deviations
        if event.get("connection_count", 0) > baseline["connection_count"] * 3:
            return True, 0.8
            
        if event.get("file_access_count", 0) > baseline["file_access_count"] * 3:
            return True, 0.75
            
        return False, 0.2
