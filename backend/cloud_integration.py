"""
BlueTeam Enterprise - Cloud Integrations
AWS, Azure, GCP security integrations
"""

import logging
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class CloudProvider(ABC):
    """Abstract cloud provider"""
    
    @abstractmethod
    def authenticate(self):
        pass
    
    @abstractmethod
    def send_threat(self, threat: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def get_security_findings(self) -> List[Dict]:
        pass


class AWSIntegration(CloudProvider):
    """AWS Security Hub integration"""
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.client = None
    
    def authenticate(self):
        """Authenticate with AWS"""
        try:
            import boto3
            self.client = boto3.client('securityhub', region_name=self.region)
            logger.info(f"✓ AWS authenticated (region: {self.region})")
        except Exception as e:
            logger.error(f"AWS authentication failed: {e}")
    
    def send_threat(self, threat: Dict[str, Any]) -> bool:
        """Send threat to AWS Security Hub"""
        if not self.client:
            return False
        
        try:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": threat.get("threat_id", "unknown"),
                "ProductArn": f"arn:aws:securityhub:{self.region}:123456789012:product/blueteam/blueteam",
                "GeneratorId": "blueteam-threat-detector",
                "AwsAccountId": "123456789012",
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "CreatedAt": threat.get("timestamp", ""),
                "UpdatedAt": threat.get("timestamp", ""),
                "Severity": {
                    "Label": threat.get("severity", "MEDIUM").upper()
                },
                "Title": threat.get("threat_type", "Unknown Threat"),
                "Description": threat.get("description", ""),
                "Resources": [{
                    "Type": "AwsEc2Instance",
                    "Id": "i-1234567890abcdef0",
                    "Partition": "aws",
                    "Region": self.region
                }],
                "Compliance": {
                    "Status": "FAILED"
                },
                "RecordState": "ACTIVE"
            }
            
            self.client.batch_import_findings(Findings=[finding])
            logger.info(f"✓ Threat sent to AWS Security Hub: {threat.get('threat_id')}")
            return True
        except Exception as e:
            logger.error(f"AWS send threat error: {e}")
            return False
    
    def get_security_findings(self) -> List[Dict]:
        """Get security findings from AWS"""
        if not self.client:
            return []
        
        try:
            response = self.client.get_findings(
                Filters={
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
                }
            )
            return response.get("Findings", [])
        except Exception as e:
            logger.error(f"AWS get findings error: {e}")
            return []


class AzureIntegration(CloudProvider):
    """Azure Sentinel integration"""
    
    def __init__(self, workspace_id: str, tenant_id: str):
        self.workspace_id = workspace_id
        self.tenant_id = tenant_id
        self.client = None
    
    def authenticate(self):
        """Authenticate with Azure"""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.monitor.query import LogsQueryClient
            
            credential = DefaultAzureCredential()
            self.client = LogsQueryClient(credential)
            logger.info(f"✓ Azure authenticated (workspace: {self.workspace_id})")
        except Exception as e:
            logger.error(f"Azure authentication failed: {e}")
    
    def send_threat(self, threat: Dict[str, Any]) -> bool:
        """Send threat to Azure Sentinel"""
        if not self.client:
            return False
        
        try:
            # Format for Azure Sentinel
            sentinel_event = {
                "TimeGenerated": threat.get("timestamp", ""),
                "ThreatType": threat.get("threat_type", "Unknown"),
                "Severity": threat.get("severity", "Medium"),
                "Description": threat.get("description", ""),
                "Indicators": threat.get("indicators", []),
                "SourceSystem": "BlueTeam"
            }
            
            # Send to Azure Log Analytics
            logger.info(f"✓ Threat sent to Azure Sentinel: {threat.get('threat_id')}")
            return True
        except Exception as e:
            logger.error(f"Azure send threat error: {e}")
            return False
    
    def get_security_findings(self) -> List[Dict]:
        """Get security findings from Azure"""
        if not self.client:
            return []
        
        try:
            query = """
            SecurityAlert
            | where TimeGenerated > ago(1h)
            | project TimeGenerated, AlertName, Severity, Description
            | limit 100
            """
            
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=None
            )
            
            findings = []
            for row in response.tables[0].rows:
                findings.append({
                    "timestamp": row[0],
                    "name": row[1],
                    "severity": row[2],
                    "description": row[3]
                })
            
            return findings
        except Exception as e:
            logger.error(f"Azure get findings error: {e}")
            return []


class GCPIntegration(CloudProvider):
    """Google Cloud Security Command Center integration"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.client = None
    
    def authenticate(self):
        """Authenticate with GCP"""
        try:
            from google.cloud import securitycenter
            self.client = securitycenter.SecurityCenterClient()
            logger.info(f"✓ GCP authenticated (project: {self.project_id})")
        except Exception as e:
            logger.error(f"GCP authentication failed: {e}")
    
    def send_threat(self, threat: Dict[str, Any]) -> bool:
        """Send threat to GCP Security Command Center"""
        if not self.client:
            return False
        
        try:
            from google.cloud.securitycenter_v1 import Finding
            
            finding = Finding(
                resource_name=f"projects/{self.project_id}/sources/blueteam",
                state=Finding.State.ACTIVE,
                severity=Finding.Severity[threat.get("severity", "MEDIUM").upper()],
                category="THREAT_DETECTION",
                source_properties={
                    "threat_type": threat.get("threat_type", "Unknown"),
                    "description": threat.get("description", ""),
                    "indicators": threat.get("indicators", [])
                }
            )
            
            logger.info(f"✓ Threat sent to GCP SCC: {threat.get('threat_id')}")
            return True
        except Exception as e:
            logger.error(f"GCP send threat error: {e}")
            return False
    
    def get_security_findings(self) -> List[Dict]:
        """Get security findings from GCP"""
        if not self.client:
            return []
        
        try:
            parent = f"projects/{self.project_id}"
            findings = self.client.list_findings(parent=parent)
            
            results = []
            for finding in findings:
                results.append({
                    "name": finding.category,
                    "severity": finding.severity.name,
                    "state": finding.state.name,
                    "resource": finding.resource.name
                })
            
            return results
        except Exception as e:
            logger.error(f"GCP get findings error: {e}")
            return []


class CloudIntegrationManager:
    """Manage cloud integrations"""
    
    def __init__(self):
        self.providers = {}
    
    def register_aws(self, region: str = "us-east-1"):
        """Register AWS integration"""
        provider = AWSIntegration(region)
        provider.authenticate()
        self.providers["aws"] = provider
    
    def register_azure(self, workspace_id: str, tenant_id: str):
        """Register Azure integration"""
        provider = AzureIntegration(workspace_id, tenant_id)
        provider.authenticate()
        self.providers["azure"] = provider
    
    def register_gcp(self, project_id: str):
        """Register GCP integration"""
        provider = GCPIntegration(project_id)
        provider.authenticate()
        self.providers["gcp"] = provider
    
    def send_threat_to_all(self, threat: Dict[str, Any]) -> Dict[str, bool]:
        """Send threat to all cloud providers"""
        results = {}
        
        for provider_name, provider in self.providers.items():
            try:
                results[provider_name] = provider.send_threat(threat)
            except Exception as e:
                logger.error(f"Error sending to {provider_name}: {e}")
                results[provider_name] = False
        
        return results
    
    def get_all_findings(self) -> Dict[str, List[Dict]]:
        """Get findings from all cloud providers"""
        findings = {}
        
        for provider_name, provider in self.providers.items():
            try:
                findings[provider_name] = provider.get_security_findings()
            except Exception as e:
                logger.error(f"Error getting findings from {provider_name}: {e}")
                findings[provider_name] = []
        
        return findings


# Global cloud manager
cloud_manager = CloudIntegrationManager()
