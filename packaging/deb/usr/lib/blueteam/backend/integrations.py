"""
BlueTeam Enterprise - Integration Ecosystem
Slack, Teams, PagerDuty, SIEM, Email integrations
"""

import requests
import json
import smtplib
from typing import Dict, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class SlackIntegration:
    """Slack integration for alerts"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_alert(self, threat: Dict[str, Any]) -> bool:
        """Send threat alert to Slack"""
        try:
            severity_colors = {
                "critical": "#FF0000",
                "high": "#FF6600",
                "medium": "#FFCC00",
                "low": "#00CC00",
                "info": "#0099FF"
            }
            
            payload = {
                "attachments": [{
                    "color": severity_colors.get(threat.get("severity"), "#999999"),
                    "title": f"🚨 {threat.get('threat_type', 'Unknown Threat')}",
                    "text": threat.get("description", "No description"),
                    "fields": [
                        {
                            "title": "Severity",
                            "value": threat.get("severity", "unknown").upper(),
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": datetime.utcnow().isoformat(),
                            "short": True
                        },
                        {
                            "title": "Indicators",
                            "value": ", ".join(threat.get("indicators", [])),
                            "short": False
                        },
                        {
                            "title": "Remediation",
                            "value": threat.get("remediation", "No remediation available"),
                            "short": False
                        }
                    ],
                    "footer": "BlueTeam Enterprise",
                    "ts": int(datetime.utcnow().timestamp())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack integration error: {e}")
            return False


class TeamsIntegration:
    """Microsoft Teams integration for alerts"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_alert(self, threat: Dict[str, Any]) -> bool:
        """Send threat alert to Teams"""
        try:
            severity_colors = {
                "critical": "FF0000",
                "high": "FF6600",
                "medium": "FFCC00",
                "low": "00CC00",
                "info": "0099FF"
            }
            
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": threat.get("threat_type", "Unknown Threat"),
                "themeColor": severity_colors.get(threat.get("severity"), "999999"),
                "sections": [{
                    "activityTitle": f"🚨 {threat.get('threat_type', 'Unknown Threat')}",
                    "activitySubtitle": threat.get("description", "No description"),
                    "facts": [
                        {
                            "name": "Severity",
                            "value": threat.get("severity", "unknown").upper()
                        },
                        {
                            "name": "Timestamp",
                            "value": datetime.utcnow().isoformat()
                        },
                        {
                            "name": "Indicators",
                            "value": ", ".join(threat.get("indicators", []))
                        },
                        {
                            "name": "Remediation",
                            "value": threat.get("remediation", "No remediation available")
                        }
                    ]
                }],
                "potentialAction": [{
                    "@type": "OpenUri",
                    "name": "View in BlueTeam",
                    "targets": [{
                        "os": "default",
                        "uri": f"https://blueteam.example.com/threats/{threat.get('threat_id', '')}"
                    }]
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Teams integration error: {e}")
            return False


class PagerDutyIntegration:
    """PagerDuty integration for incident management"""
    
    def __init__(self, api_key: str, service_id: str):
        self.api_key = api_key
        self.service_id = service_id
        self.base_url = "https://api.pagerduty.com"
    
    def create_incident(self, threat: Dict[str, Any]) -> Optional[str]:
        """Create PagerDuty incident"""
        try:
            headers = {
                "Authorization": f"Token token={self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "incident": {
                    "type": "incident",
                    "title": f"{threat.get('threat_type', 'Unknown Threat')} - {threat.get('severity', 'unknown').upper()}",
                    "service": {
                        "id": self.service_id,
                        "type": "service_reference"
                    },
                    "body": {
                        "type": "incident_body",
                        "details": json.dumps({
                            "description": threat.get("description"),
                            "indicators": threat.get("indicators", []),
                            "remediation": threat.get("remediation")
                        })
                    },
                    "urgency": "high" if threat.get("severity") in ["critical", "high"] else "low"
                }
            }
            
            response = requests.post(
                f"{self.base_url}/incidents",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 201:
                return response.json().get("incident", {}).get("incident_number")
            return None
        except Exception as e:
            logger.error(f"PagerDuty integration error: {e}")
            return None
    
    def acknowledge_incident(self, incident_id: str) -> bool:
        """Acknowledge incident"""
        try:
            headers = {
                "Authorization": f"Token token={self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "incidents": [{
                    "id": incident_id,
                    "type": "incident_reference",
                    "status": "acknowledged"
                }]
            }
            
            response = requests.put(
                f"{self.base_url}/incidents",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"PagerDuty acknowledge error: {e}")
            return False


class SIEMIntegration:
    """SIEM integration (Splunk, ELK, etc.)"""
    
    def __init__(self, siem_type: str, endpoint: str, api_key: str):
        self.siem_type = siem_type
        self.endpoint = endpoint
        self.api_key = api_key
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to SIEM"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Format event for SIEM
            siem_event = {
                "source": "blueteam",
                "sourcetype": event.get("event_type", "security"),
                "event": json.dumps(event),
                "timestamp": int(datetime.utcnow().timestamp())
            }
            
            if self.siem_type.lower() == "splunk":
                response = requests.post(
                    f"{self.endpoint}/services/collector",
                    headers=headers,
                    json={"event": siem_event},
                    timeout=10
                )
            elif self.siem_type.lower() == "elk":
                response = requests.post(
                    f"{self.endpoint}/_doc",
                    headers=headers,
                    json=siem_event,
                    timeout=10
                )
            else:
                response = requests.post(
                    self.endpoint,
                    headers=headers,
                    json=siem_event,
                    timeout=10
                )
            
            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"SIEM integration error: {e}")
            return False


class EmailIntegration:
    """Email integration for alerts"""
    
    def __init__(self, smtp_server: str, smtp_port: int, sender: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender = sender
        self.password = password
    
    def send_alert(self, threat: Dict[str, Any], recipients: list) -> bool:
        """Send threat alert via email"""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[BlueTeam] {threat.get('threat_type', 'Unknown Threat')} - {threat.get('severity', 'unknown').upper()}"
            msg["From"] = self.sender
            msg["To"] = ", ".join(recipients)
            
            # Create HTML email
            html = f"""
            <html>
                <body>
                    <h2>🚨 Security Alert</h2>
                    <p><strong>Threat Type:</strong> {threat.get('threat_type', 'Unknown')}</p>
                    <p><strong>Severity:</strong> <span style="color: red;">{threat.get('severity', 'unknown').upper()}</span></p>
                    <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
                    <p><strong>Indicators:</strong></p>
                    <ul>
                        {''.join([f'<li>{ind}</li>' for ind in threat.get('indicators', [])])}
                    </ul>
                    <p><strong>Remediation:</strong> {threat.get('remediation', 'No remediation available')}</p>
                    <p><strong>Timestamp:</strong> {datetime.utcnow().isoformat()}</p>
                    <hr>
                    <p>BlueTeam Enterprise Security Platform</p>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(html, "html"))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender, self.password)
                server.send_message(msg)
            
            return True
        except Exception as e:
            logger.error(f"Email integration error: {e}")
            return False


class WebhookIntegration:
    """Generic webhook integration"""
    
    def __init__(self, webhook_url: str, headers: Optional[Dict] = None):
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to webhook"""
        try:
            payload = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "blueteam",
                "event": event
            }
            
            response = requests.post(
                self.webhook_url,
                headers=self.headers,
                json=payload,
                timeout=10
            )
            
            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"Webhook integration error: {e}")
            return False


class IntegrationManager:
    """Manage all integrations"""
    
    def __init__(self):
        self.integrations = {}
    
    def register_slack(self, name: str, webhook_url: str):
        """Register Slack integration"""
        self.integrations[name] = SlackIntegration(webhook_url)
    
    def register_teams(self, name: str, webhook_url: str):
        """Register Teams integration"""
        self.integrations[name] = TeamsIntegration(webhook_url)
    
    def register_pagerduty(self, name: str, api_key: str, service_id: str):
        """Register PagerDuty integration"""
        self.integrations[name] = PagerDutyIntegration(api_key, service_id)
    
    def register_siem(self, name: str, siem_type: str, endpoint: str, api_key: str):
        """Register SIEM integration"""
        self.integrations[name] = SIEMIntegration(siem_type, endpoint, api_key)
    
    def register_email(self, name: str, smtp_server: str, smtp_port: int, sender: str, password: str):
        """Register Email integration"""
        self.integrations[name] = EmailIntegration(smtp_server, smtp_port, sender, password)
    
    def register_webhook(self, name: str, webhook_url: str, headers: Optional[Dict] = None):
        """Register generic webhook"""
        self.integrations[name] = WebhookIntegration(webhook_url, headers)
    
    def send_alert_to_all(self, threat: Dict[str, Any]) -> Dict[str, bool]:
        """Send alert to all registered integrations"""
        results = {}
        
        for name, integration in self.integrations.items():
            try:
                if isinstance(integration, (SlackIntegration, TeamsIntegration)):
                    results[name] = integration.send_alert(threat)
                elif isinstance(integration, SIEMIntegration):
                    results[name] = integration.send_event(threat)
                elif isinstance(integration, WebhookIntegration):
                    results[name] = integration.send_event(threat)
                else:
                    results[name] = False
            except Exception as e:
                logger.error(f"Error sending to {name}: {e}")
                results[name] = False
        
        return results
    
    def send_alert_to(self, threat: Dict[str, Any], integration_name: str) -> bool:
        """Send alert to specific integration"""
        if integration_name not in self.integrations:
            logger.error(f"Integration {integration_name} not found")
            return False
        
        integration = self.integrations[integration_name]
        
        try:
            if isinstance(integration, (SlackIntegration, TeamsIntegration)):
                return integration.send_alert(threat)
            elif isinstance(integration, SIEMIntegration):
                return integration.send_event(threat)
            elif isinstance(integration, WebhookIntegration):
                return integration.send_event(threat)
            else:
                return False
        except Exception as e:
            logger.error(f"Error sending to {integration_name}: {e}")
            return False


# Global integration manager
integration_manager = IntegrationManager()
