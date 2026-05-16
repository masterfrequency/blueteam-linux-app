"""
BlueTeam Enterprise - Prometheus Metrics & Monitoring
Real-time metrics collection and export
"""

from prometheus_client import Counter, Gauge, Histogram, Summary, CollectorRegistry
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from typing import Dict, Any
import time
import logging

logger = logging.getLogger(__name__)

# Create registry
registry = CollectorRegistry()

# Threat metrics
threats_total = Counter(
    'blueteam_threats_total',
    'Total threats detected',
    ['severity', 'threat_type'],
    registry=registry
)

threats_active = Gauge(
    'blueteam_threats_active',
    'Currently active threats',
    ['severity'],
    registry=registry
)

threat_response_time = Histogram(
    'blueteam_threat_response_seconds',
    'Time to respond to threat',
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0),
    registry=registry
)

# Module metrics
module_runs_total = Counter(
    'blueteam_module_runs_total',
    'Total module executions',
    ['module_name', 'status'],
    registry=registry
)

module_runtime = Histogram(
    'blueteam_module_runtime_seconds',
    'Module execution time',
    ['module_name'],
    buckets=(0.1, 0.5, 1.0, 5.0, 10.0),
    registry=registry
)

module_detections = Counter(
    'blueteam_module_detections_total',
    'Detections by module',
    ['module_name', 'detection_type'],
    registry=registry
)

# System metrics
system_cpu_usage = Gauge(
    'blueteam_system_cpu_percent',
    'System CPU usage',
    registry=registry
)

system_memory_usage = Gauge(
    'blueteam_system_memory_percent',
    'System memory usage',
    registry=registry
)

system_disk_usage = Gauge(
    'blueteam_system_disk_percent',
    'System disk usage',
    registry=registry
)

# Database metrics
db_query_time = Histogram(
    'blueteam_db_query_seconds',
    'Database query execution time',
    ['query_type'],
    registry=registry
)

db_connections = Gauge(
    'blueteam_db_connections',
    'Active database connections',
    registry=registry
)

# API metrics
api_requests_total = Counter(
    'blueteam_api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status'],
    registry=registry
)

api_request_duration = Histogram(
    'blueteam_api_request_duration_seconds',
    'API request duration',
    ['method', 'endpoint'],
    registry=registry
)

# Integration metrics
integration_alerts_sent = Counter(
    'blueteam_integration_alerts_sent_total',
    'Total alerts sent to integrations',
    ['integration_type', 'status'],
    registry=registry
)

integration_latency = Histogram(
    'blueteam_integration_latency_seconds',
    'Integration alert delivery latency',
    ['integration_type'],
    registry=registry
)

# Event correlation metrics
correlation_events_processed = Counter(
    'blueteam_correlation_events_processed_total',
    'Total events processed by correlation engine',
    registry=registry
)

correlation_threats_detected = Counter(
    'blueteam_correlation_threats_detected_total',
    'Threats detected by correlation',
    ['threat_type'],
    registry=registry
)

# ML metrics
ml_predictions_total = Counter(
    'blueteam_ml_predictions_total',
    'Total ML predictions',
    ['model_name', 'prediction_type'],
    registry=registry
)

ml_prediction_confidence = Gauge(
    'blueteam_ml_prediction_confidence',
    'Average ML prediction confidence',
    ['model_name'],
    registry=registry
)


class MetricsCollector:
    """Collect and export metrics"""
    
    def __init__(self):
        self.start_time = time.time()
    
    def record_threat(self, severity: str, threat_type: str):
        """Record threat detection"""
        threats_total.labels(severity=severity, threat_type=threat_type).inc()
        threats_active.labels(severity=severity).inc()
    
    def resolve_threat(self, severity: str):
        """Record threat resolution"""
        threats_active.labels(severity=severity).dec()
    
    def record_module_run(self, module_name: str, duration: float, status: str = "success"):
        """Record module execution"""
        module_runs_total.labels(module_name=module_name, status=status).inc()
        module_runtime.labels(module_name=module_name).observe(duration)
    
    def record_detection(self, module_name: str, detection_type: str):
        """Record module detection"""
        module_detections.labels(module_name=module_name, detection_type=detection_type).inc()
    
    def update_system_metrics(self, cpu: float, memory: float, disk: float):
        """Update system metrics"""
        system_cpu_usage.set(cpu)
        system_memory_usage.set(memory)
        system_disk_usage.set(disk)
    
    def record_db_query(self, query_type: str, duration: float):
        """Record database query"""
        db_query_time.labels(query_type=query_type).observe(duration)
    
    def set_db_connections(self, count: int):
        """Set active database connections"""
        db_connections.set(count)
    
    def record_api_request(self, method: str, endpoint: str, status: int, duration: float):
        """Record API request"""
        api_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        api_request_duration.labels(method=method, endpoint=endpoint).observe(duration)
    
    def record_integration_alert(self, integration_type: str, status: str, latency: float):
        """Record integration alert"""
        integration_alerts_sent.labels(integration_type=integration_type, status=status).inc()
        integration_latency.labels(integration_type=integration_type).observe(latency)
    
    def record_correlation_event(self, threat_type: str = None):
        """Record correlation event"""
        correlation_events_processed.inc()
        if threat_type:
            correlation_threats_detected.labels(threat_type=threat_type).inc()
    
    def record_ml_prediction(self, model_name: str, prediction_type: str, confidence: float):
        """Record ML prediction"""
        ml_predictions_total.labels(model_name=model_name, prediction_type=prediction_type).inc()
        ml_prediction_confidence.labels(model_name=model_name).set(confidence)
    
    def get_metrics(self) -> bytes:
        """Get metrics in Prometheus format"""
        return generate_latest(registry)
    
    def get_uptime(self) -> float:
        """Get system uptime"""
        return time.time() - self.start_time


# Global metrics collector
metrics_collector = MetricsCollector()
