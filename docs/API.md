# BlueTeam REST API Documentation

## Overview

BlueTeam provides a comprehensive REST API for integrating with external systems and automating security operations.

## Base URL

```
http://localhost:8000/api
```

## Authentication

All API requests require authentication using JWT tokens:

```bash
Authorization: Bearer <token>
```

## Endpoints

### System Status

#### GET /status
Get system status and health information

**Response:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "uptime": 3600,
  "modules_active": 23,
  "threats_detected": 42
}
```

### Threats

#### GET /threats
List all detected threats

**Query Parameters:**
- `limit` (int): Maximum results (default: 100)
- `offset` (int): Pagination offset (default: 0)
- `severity` (string): Filter by severity (critical, high, medium, low)

**Response:**
```json
{
  "total": 42,
  "threats": [
    {
      "id": "threat-001",
      "type": "malware",
      "severity": "critical",
      "detected_at": "2024-05-16T10:30:00Z",
      "source": "file_scanner",
      "description": "Trojan detected"
    }
  ]
}
```

#### GET /threats/{id}
Get threat details

#### POST /threats/{id}/respond
Execute incident response for threat

**Request:**
```json
{
  "action": "quarantine",
  "parameters": {}
}
```

### Modules

#### GET /modules
List all security modules

**Response:**
```json
{
  "modules": [
    {
      "name": "AI Traffic Analyzer",
      "status": "running",
      "enabled": true,
      "last_run": "2024-05-16T10:30:00Z",
      "threats_detected": 5
    }
  ]
}
```

#### GET /modules/{name}
Get module details

#### POST /modules/{name}/enable
Enable a module

#### POST /modules/{name}/disable
Disable a module

#### POST /modules/{name}/run
Manually trigger module execution

### Compliance

#### GET /compliance
Get compliance status

**Response:**
```json
{
  "frameworks": [
    {
      "name": "CIS",
      "score": 85,
      "status": "compliant",
      "findings": 15
    }
  ]
}
```

#### GET /compliance/{framework}
Get framework compliance details

#### POST /compliance/{framework}/audit
Run compliance audit

#### GET /compliance/{framework}/report
Generate compliance report

### Integrations

#### GET /integrations
List configured integrations

#### POST /integrations/{name}/test
Test integration connection

#### POST /integrations/{name}/trigger
Manually trigger integration

### Events

#### GET /events
Get system events

**Query Parameters:**
- `type` (string): Event type filter
- `severity` (string): Severity filter
- `start_time` (ISO8601): Start time
- `end_time` (ISO8601): End time

#### POST /events/search
Search events with advanced filters

### Database

#### GET /database/health
Check database health

#### POST /database/backup
Trigger database backup

#### GET /database/backup/list
List available backups

### Metrics

#### GET /metrics
Get Prometheus metrics

#### GET /metrics/threats
Get threat metrics

#### GET /metrics/modules
Get module metrics

#### GET /metrics/system
Get system metrics

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid request",
  "details": "Missing required parameter: severity"
}
```

### 401 Unauthorized
```json
{
  "error": "Unauthorized",
  "details": "Invalid or missing authentication token"
}
```

### 403 Forbidden
```json
{
  "error": "Forbidden",
  "details": "Insufficient permissions"
}
```

### 404 Not Found
```json
{
  "error": "Not found",
  "details": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "details": "An unexpected error occurred"
}
```

## Rate Limiting

API requests are rate limited to:
- 1000 requests per hour per IP
- 100 requests per minute per IP

Headers returned:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1621234567
```

## Examples

### Get system status
```bash
curl -H "Authorization: Bearer token" \
  http://localhost:8000/api/status
```

### List threats
```bash
curl -H "Authorization: Bearer token" \
  "http://localhost:8000/api/threats?severity=critical"
```

### Run compliance audit
```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  http://localhost:8000/api/compliance/cis/audit
```

### Trigger incident response
```bash
curl -X POST \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{"action":"quarantine"}' \
  http://localhost:8000/api/threats/threat-001/respond
```

## Webhooks

Configure webhooks for automatic notifications:

```bash
POST /integrations/webhook/register
{
  "url": "https://your-system.com/webhook",
  "events": ["threat_detected", "compliance_failed"],
  "secret": "webhook_secret"
}
```

## SDK Examples

### Python
```python
import requests

api_url = "http://localhost:8000/api"
headers = {"Authorization": "Bearer token"}

# Get threats
response = requests.get(f"{api_url}/threats", headers=headers)
threats = response.json()
```

### JavaScript
```javascript
const apiUrl = "http://localhost:8000/api";
const headers = { "Authorization": "Bearer token" };

// Get threats
fetch(`${apiUrl}/threats`, { headers })
  .then(r => r.json())
  .then(data => console.log(data));
```

### cURL
```bash
curl -H "Authorization: Bearer token" \
  http://localhost:8000/api/threats
```
