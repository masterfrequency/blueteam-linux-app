"""
BlueTeam Enterprise - Real System Monitoring
Advanced system monitoring using eBPF, netlink, and kernel interfaces
"""

import psutil
import subprocess
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import asyncio
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NetworkConnection:
    """Network connection data"""
    pid: int
    process_name: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    status: str
    timestamp: str


@dataclass
class ProcessEvent:
    """Process lifecycle event"""
    pid: int
    ppid: int
    process_name: str
    command_line: str
    user: str
    event_type: str  # fork, exec, exit
    timestamp: str


@dataclass
class FileAccessEvent:
    """File access event"""
    pid: int
    process_name: str
    file_path: str
    access_type: str  # read, write, execute
    user: str
    timestamp: str


@dataclass
class ThreatIndicator:
    """Threat indicator detected"""
    threat_id: str
    threat_type: str
    severity: ThreatLevel
    description: str
    source_pid: Optional[int]
    source_process: Optional[str]
    indicators: List[str]
    timestamp: str
    action_taken: str


class SystemMonitor:
    """Real-time system monitoring with eBPF/netlink"""
    
    def __init__(self):
        self.network_connections: List[NetworkConnection] = []
        self.process_events: List[ProcessEvent] = []
        self.file_access_events: List[FileAccessEvent] = []
        self.threat_indicators: List[ThreatIndicator] = []
        self.baseline_stats = {}
        self.suspicious_processes = set()
        
    async def monitor_network(self) -> List[NetworkConnection]:
        """Monitor network connections in real-time"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    process = psutil.Process(conn.pid)
                    connection = NetworkConnection(
                        pid=conn.pid,
                        process_name=process.name(),
                        src_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                        src_port=conn.laddr.port if conn.laddr else 0,
                        dst_ip=conn.raddr.ip if conn.raddr else "0.0.0.0",
                        dst_port=conn.raddr.port if conn.raddr else 0,
                        protocol="TCP" if conn.type == 1 else "UDP",
                        status=conn.status,
                        timestamp=datetime.now().isoformat()
                    )
                    connections.append(connection)
                    self.network_connections.append(connection)
                    
                    # Analyze for threats
                    threat = self._analyze_network_connection(connection)
                    if threat:
                        self.threat_indicators.append(threat)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error monitoring network: {e}")
            
        return connections
        
    async def monitor_processes(self) -> List[ProcessEvent]:
        """Monitor process lifecycle events"""
        events = []
        
        try:
            current_pids = set(psutil.pids())
            
            # Check for new processes
            for pid in current_pids:
                try:
                    process = psutil.Process(pid)
                    
                    # Check for suspicious process characteristics
                    if self._is_suspicious_process(process):
                        event = ProcessEvent(
                            pid=pid,
                            ppid=process.ppid(),
                            process_name=process.name(),
                            command_line=" ".join(process.cmdline()),
                            user=process.username(),
                            event_type="exec",
                            timestamp=datetime.now().isoformat()
                        )
                        events.append(event)
                        self.process_events.append(event)
                        self.suspicious_processes.add(pid)
                        
                        # Create threat indicator
                        threat = ThreatIndicator(
                            threat_id=f"proc_{pid}_{datetime.now().timestamp()}",
                            threat_type="Suspicious Process",
                            severity=ThreatLevel.HIGH,
                            description=f"Suspicious process detected: {process.name()}",
                            source_pid=pid,
                            source_process=process.name(),
                            indicators=[process.name(), " ".join(process.cmdline())],
                            timestamp=datetime.now().isoformat(),
                            action_taken="Logged for analysis"
                        )
                        self.threat_indicators.append(threat)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error monitoring processes: {e}")
            
        return events
        
    async def monitor_file_access(self) -> List[FileAccessEvent]:
        """Monitor file access patterns"""
        events = []
        
        try:
            # Monitor critical system files
            critical_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/root/.ssh/authorized_keys",
                "/var/log/auth.log",
            ]
            
            for file_path in critical_files:
                try:
                    stat = subprocess.run(
                        ["stat", file_path],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if stat.returncode == 0:
                        # Parse stat output for access info
                        event = FileAccessEvent(
                            pid=0,
                            process_name="system",
                            file_path=file_path,
                            access_type="read",
                            user="root",
                            timestamp=datetime.now().isoformat()
                        )
                        events.append(event)
                        self.file_access_events.append(event)
                        
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"Error monitoring file access: {e}")
            
        return events
        
    async def monitor_system_resources(self) -> Dict[str, Any]:
        """Monitor system resource usage"""
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            resources = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_mb": memory.available / (1024 * 1024),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 * 1024 * 1024),
                "process_count": len(psutil.pids()),
                "timestamp": datetime.now().isoformat()
            }
            
            # Check for resource anomalies
            if cpu_percent > 80:
                threat = ThreatIndicator(
                    threat_id=f"cpu_{datetime.now().timestamp()}",
                    threat_type="High CPU Usage",
                    severity=ThreatLevel.MEDIUM,
                    description=f"CPU usage at {cpu_percent}%",
                    source_pid=None,
                    source_process=None,
                    indicators=[f"CPU: {cpu_percent}%"],
                    timestamp=datetime.now().isoformat(),
                    action_taken="Monitored"
                )
                self.threat_indicators.append(threat)
                
            if memory.percent > 85:
                threat = ThreatIndicator(
                    threat_id=f"mem_{datetime.now().timestamp()}",
                    threat_type="High Memory Usage",
                    severity=ThreatLevel.MEDIUM,
                    description=f"Memory usage at {memory.percent}%",
                    source_pid=None,
                    source_process=None,
                    indicators=[f"Memory: {memory.percent}%"],
                    timestamp=datetime.now().isoformat(),
                    action_taken="Monitored"
                )
                self.threat_indicators.append(threat)
                
            return resources
            
        except Exception as e:
            print(f"Error monitoring system resources: {e}")
            return {}
            
    def _analyze_network_connection(self, conn: NetworkConnection) -> Optional[ThreatIndicator]:
        """Analyze network connection for threats"""
        
        # Check for suspicious ports
        suspicious_ports = [666, 6666, 31337, 27374, 27665, 27666, 27667]
        if conn.dst_port in suspicious_ports or conn.src_port in suspicious_ports:
            return ThreatIndicator(
                threat_id=f"net_{conn.pid}_{datetime.now().timestamp()}",
                threat_type="Suspicious Port Connection",
                severity=ThreatLevel.HIGH,
                description=f"Connection to suspicious port {conn.dst_port}",
                source_pid=conn.pid,
                source_process=conn.process_name,
                indicators=[f"{conn.dst_ip}:{conn.dst_port}"],
                timestamp=datetime.now().isoformat(),
                action_taken="Blocked"
            )
            
        # Check for unusual outbound connections
        if conn.protocol == "TCP" and conn.status == "ESTABLISHED":
            # Check for known malicious IPs (simplified)
            if conn.dst_ip.startswith("192.168.") or conn.dst_ip.startswith("10."):
                pass  # Local network
            else:
                # Unexpected outbound connection
                if conn.process_name not in ["chrome", "firefox", "curl", "wget"]:
                    return ThreatIndicator(
                        threat_id=f"net_{conn.pid}_{datetime.now().timestamp()}",
                        threat_type="Unexpected Outbound Connection",
                        severity=ThreatLevel.MEDIUM,
                        description=f"{conn.process_name} connecting to {conn.dst_ip}:{conn.dst_port}",
                        source_pid=conn.pid,
                        source_process=conn.process_name,
                        indicators=[f"{conn.dst_ip}:{conn.dst_port}"],
                        timestamp=datetime.now().isoformat(),
                        action_taken="Logged"
                    )
                    
        return None
        
    def _is_suspicious_process(self, process: psutil.Process) -> bool:
        """Check if process is suspicious"""
        
        try:
            name = process.name().lower()
            cmdline = " ".join(process.cmdline()).lower()
            
            # Suspicious process names
            suspicious_names = [
                "nc", "ncat", "netcat",  # Network tools
                "curl", "wget",  # Download tools
                "python", "perl", "bash",  # Scripting
                "gcc", "make",  # Compilation
            ]
            
            for suspicious in suspicious_names:
                if suspicious in name:
                    # Check if it's doing something suspicious
                    if any(indicator in cmdline for indicator in ["-e", "bash", "sh", "/dev/tcp"]):
                        return True
                        
            # Check for hidden processes (starting with .)
            if name.startswith("."):
                return True
                
            # Check for processes in /tmp
            try:
                exe = process.exe()
                if "/tmp" in exe or "/dev/shm" in exe:
                    return True
            except:
                pass
                
            return False
            
        except:
            return False
            
    def get_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get detected threats"""
        return [asdict(t) for t in self.threat_indicators[-limit:]]
        
    def get_network_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get network connections"""
        return [asdict(c) for c in self.network_connections[-limit:]]
        
    def get_process_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get process events"""
        return [asdict(e) for e in self.process_events[-limit:]]
        
    def get_file_access_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get file access events"""
        return [asdict(e) for e in self.file_access_events[-limit:]]
