# Slack Incident Response Bot

Automated incident response bot for Slack integration with security tools and workflows. Streamlines incident management, team coordination, and response automation.

## Overview

This bot provides real-time incident response capabilities through Slack, enabling security teams to manage incidents efficiently with automated workflows, tool integrations, and collaborative features.

## Features

- **Real-time Alert Processing** - Automated incident detection and notification
- **Interactive Incident Management** - Slack-based incident workflow management
- **Tool Integration** - SIEM, ticketing, and security tool connectivity
- **Automated Response Actions** - Predefined response workflows and remediation
- **Team Collaboration** - Centralized communication and coordination
- **Reporting and Metrics** - Incident tracking and performance analytics

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SIEM/Alerts   │───▶│  Response Bot   │───▶│  Slack Channel  │
│                 │    │                 │    │                 │
│ • Wazuh         │    │ • Alert Parser  │    │ • Notifications │
│ • Splunk        │    │ • Workflow Mgr  │    │ • Interactions  │
│ • Custom Tools  │    │ • Tool APIs     │    │ • Collaboration │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  External APIs  │
                    │                 │
                    │ • ServiceNow    │
                    │ • Jira          │
                    │ • PagerDuty     │
                    │ • Custom APIs   │
                    └─────────────────┘
```

## Installation

### Prerequisites
```bash
# Python 3.8+
python3 --version

# Required packages
pip install slack-bolt flask requests python-dotenv
```

### Slack App Setup
1. **Create Slack App**
   - Go to [Slack API](https://api.slack.com/apps)
   - Create new app "Incident Response Bot"
   - Note App ID and signing secret

2. **Configure Bot Permissions**
   ```
   OAuth Scopes:
   - chat:write
   - chat:write.public
   - channels:read
   - groups:read
   - im:read
   - mpim:read
   - users:read
   - files:write
   - reactions:write
   ```

3. **Install App to Workspace**
   - Install app to your Slack workspace
   - Note Bot User OAuth Token

### Environment Configuration
```bash
# Create environment file
cp .env.example .env

# Configure environment variables
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_SIGNING_SECRET=your-signing-secret
SLACK_APP_TOKEN=xapp-your-app-token

# External API configurations
SERVICENOW_URL=https://your-instance.service-now.com
SERVICENOW_USER=your-username
SERVICENOW_PASS=your-password

WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
```

### Quick Start
```bash
# Clone repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/1-Cybersecurity/Incident-Response/remediation-bot-slack

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Start the bot
python bot.py
```

## Bot Commands

### Incident Management Commands

#### `/incident create`
Create a new security incident
```
/incident create --type malware --severity high --description "Suspicious file detected on workstation"
```

#### `/incident status`
Check incident status and details
```
/incident status INC-2024-0115-001
```

#### `/incident assign`
Assign incident to team member
```
/incident assign INC-2024-0115-001 @john.doe
```

#### `/incident escalate`
Escalate incident to higher severity
```
/incident escalate INC-2024-0115-001 --to critical --reason "Data breach confirmed"
```

#### `/incident close`
Close resolved incident
```
/incident close INC-2024-0115-001 --resolution "Malware removed, system cleaned"
```

### Response Action Commands

#### `/isolate`
Isolate compromised systems
```
/isolate host workstation-001 --reason "Malware infection"
/isolate ip 192.168.1.100 --duration 24h
```

#### `/block`
Block malicious indicators
```
/block domain malicious-site.com
/block ip 10.0.0.1 --source "Threat intelligence"
```

#### `/investigate`
Launch investigation workflows
```
/investigate host workstation-001 --type forensics
/investigate user john.doe --type "privilege escalation"
```

### Information Commands

#### `/status`
Show overall security status
```
/status
# Returns: Active incidents, system health, recent alerts
```

#### `/alerts`
Display recent security alerts
```
/alerts --last 24h --severity high
```

#### `/metrics`
Show incident response metrics
```
/metrics --period week
# Returns: MTTR, incident count, resolution rates
```

## Interactive Features

### Incident Workflow Buttons
When an incident is created, interactive buttons are provided:

```
🚨 New Incident: INC-2024-0115-001
Type: Malware Detection
Severity: High
Affected System: workstation-001

[Acknowledge] [Assign to Me] [Escalate] [Get Details]
```

### Alert Triage Interface
Security alerts include triage options:

```
⚠️ Security Alert
Source: Wazuh SIEM
Rule: Suspicious PowerShell Activity
Host: server-web-01

[True Positive] [False Positive] [Needs Investigation] [Suppress]
```

### Response Action Confirmations
Critical actions require confirmation:

```
⚠️ Confirmation Required
Action: Isolate host server-db-01
Impact: Database services will be unavailable
Duration: Until manual restoration

[Confirm Isolation] [Cancel] [Schedule for Maintenance Window]
```

## Configuration

### Bot Configuration (`config/bot_config.yaml`)
```yaml
bot:
  name: "IR-Bot"
  emoji: ":robot_face:"
  default_channel: "#security-incidents"
  
incidents:
  auto_create_channel: true
  channel_prefix: "incident-"
  severity_colors:
    critical: "#FF0000"
    high: "#FF8C00"
    medium: "#FFD700"
    low: "#90EE90"

integrations:
  servicenow:
    enabled: true
    auto_create_ticket: true
    sync_status: true
  
  wazuh:
    enabled: true
    alert_threshold: 7
    auto_acknowledge: false

notifications:
  executive_escalation:
    severity: ["critical", "high"]
    delay_minutes: 30
  
  customer_notification:
    severity: ["critical"]
    auto_draft: true
```

### Alert Processing Rules (`config/alert_rules.yaml`)
```yaml
rules:
  - name: "Critical Malware Detection"
    conditions:
      - field: "rule.level"
        operator: ">="
        value: 12
      - field: "rule.groups"
        operator: "contains"
        value: "malware"
    actions:
      - type: "create_incident"
        severity: "critical"
      - type: "isolate_host"
        auto_confirm: false
      - type: "notify_team"
        channel: "#security-incidents"

  - name: "Failed Login Attempts"
    conditions:
      - field: "rule.id"
        operator: "in"
        value: ["5503", "5551"]
      - field: "data.srcip"
        operator: "not_in"
        value: ["192.168.1.0/24"]
    actions:
      - type: "create_alert"
        severity: "medium"
      - type: "block_ip"
        duration: "1h"
```

## Integration Examples

### SIEM Integration (Wazuh)
```python
import requests
from datetime import datetime

class WazuhIntegration:
    def __init__(self, api_url, username, password):
        self.api_url = api_url
        self.auth_token = self.authenticate(username, password)
    
    def authenticate(self, username, password):
        """Authenticate with Wazuh API"""
        auth_url = f"{self.api_url}/security/user/authenticate"
        response = requests.post(
            auth_url,
            json={"username": username, "password": password},
            verify=False
        )
        return response.json()["data"]["token"]
    
    def get_alerts(self, last_minutes=5):
        """Fetch recent alerts from Wazuh"""
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        params = {
            "limit": 100,
            "sort": "-timestamp",
            "q": f"timestamp>{datetime.now().isoformat()}"
        }
        
        response = requests.get(
            f"{self.api_url}/security/alerts",
            headers=headers,
            params=params,
            verify=False
        )
        
        return response.json()["data"]["affected_items"]
    
    def process_alert(self, alert):
        """Process individual alert and determine actions"""
        severity = self.calculate_severity(alert)
        
        if severity >= 10:
            return {
                "action": "create_incident",
                "severity": "critical",
                "auto_isolate": True
            }
        elif severity >= 7:
            return {
                "action": "create_incident", 
                "severity": "high",
                "auto_isolate": False
            }
        else:
            return {
                "action": "log_alert",
                "severity": "medium"
            }
```

### ServiceNow Integration
```python
import requests
import json

class ServiceNowIntegration:
    def __init__(self, instance_url, username, password):
        self.instance_url = instance_url
        self.auth = (username, password)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def create_incident(self, incident_data):
        """Create incident ticket in ServiceNow"""
        url = f"{self.instance_url}/api/now/table/incident"
        
        ticket_data = {
            "short_description": incident_data["title"],
            "description": incident_data["description"],
            "urgency": self.map_severity_to_urgency(incident_data["severity"]),
            "impact": self.map_severity_to_impact(incident_data["severity"]),
            "category": "Security",
            "subcategory": incident_data["type"],
            "caller_id": incident_data.get("reporter", "ir-bot"),
            "assignment_group": "Security Operations"
        }
        
        response = requests.post(
            url,
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(ticket_data)
        )
        
        if response.status_code == 201:
            ticket = response.json()["result"]
            return {
                "success": True,
                "ticket_number": ticket["number"],
                "sys_id": ticket["sys_id"]
            }
        else:
            return {
                "success": False,
                "error": response.text
            }
    
    def update_incident(self, sys_id, update_data):
        """Update existing incident ticket"""
        url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
        
        response = requests.patch(
            url,
            auth=self.auth,
            headers=self.headers,
            data=json.dumps(update_data)
        )
        
        return response.status_code == 200
```

### Slack Bot Implementation
```python
import os
import json
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request

# Initialize Slack app
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
)

# Initialize Flask app for webhooks
flask_app = Flask(__name__)
handler = SlackRequestHandler(app)

class IncidentResponseBot:
    def __init__(self):
        self.incidents = {}
        self.wazuh = WazuhIntegration(
            os.environ.get("WAZUH_API_URL"),
            os.environ.get("WAZUH_USER"),
            os.environ.get("WAZUH_PASS")
        )
        self.servicenow = ServiceNowIntegration(
            os.environ.get("SERVICENOW_URL"),
            os.environ.get("SERVICENOW_USER"),
            os.environ.get("SERVICENOW_PASS")
        )
    
    def create_incident(self, incident_data):
        """Create new security incident"""
        incident_id = f"INC-{datetime.now().strftime('%Y-%m%d-%H%M%S')}"
        
        incident = {
            "id": incident_id,
            "type": incident_data["type"],
            "severity": incident_data["severity"],
            "description": incident_data["description"],
            "status": "open",
            "created_at": datetime.now().isoformat(),
            "assigned_to": None,
            "channel_id": None
        }
        
        # Create ServiceNow ticket
        ticket_result = self.servicenow.create_incident(incident_data)
        if ticket_result["success"]:
            incident["ticket_number"] = ticket_result["ticket_number"]
            incident["ticket_sys_id"] = ticket_result["sys_id"]
        
        self.incidents[incident_id] = incident
        return incident

# Slack command handlers
@app.command("/incident")
def handle_incident_command(ack, respond, command):
    ack()
    
    args = command["text"].split()
    action = args[0] if args else "help"
    
    if action == "create":
        # Parse incident creation parameters
        incident_data = parse_incident_args(args[1:])
        incident = bot.create_incident(incident_data)
        
        # Send incident notification
        blocks = create_incident_blocks(incident)
        respond(blocks=blocks)
        
    elif action == "status":
        incident_id = args[1] if len(args) > 1 else None
        if incident_id and incident_id in bot.incidents:
            incident = bot.incidents[incident_id]
            blocks = create_status_blocks(incident)
            respond(blocks=blocks)
        else:
            respond("Incident not found or ID not provided")
    
    elif action == "help":
        respond(get_help_text())

@app.action("acknowledge_incident")
def handle_acknowledge(ack, body, client):
    ack()
    
    incident_id = body["actions"][0]["value"]
    user_id = body["user"]["id"]
    
    # Update incident status
    if incident_id in bot.incidents:
        bot.incidents[incident_id]["status"] = "acknowledged"
        bot.incidents[incident_id]["assigned_to"] = user_id
        
        # Update Slack message
        updated_blocks = create_incident_blocks(bot.incidents[incident_id])
        client.chat_update(
            channel=body["channel"]["id"],
            ts=body["message"]["ts"],
            blocks=updated_blocks
        )

@app.action("escalate_incident")
def handle_escalate(ack, body, client):
    ack()
    
    incident_id = body["actions"][0]["value"]
    
    # Show escalation modal
    client.views_open(
        trigger_id=body["trigger_id"],
        view=create_escalation_modal(incident_id)
    )

# Webhook endpoint for external alerts
@flask_app.route("/webhook/alerts", methods=["POST"])
def handle_alert_webhook():
    alert_data = request.json
    
    # Process alert and determine response
    response_action = bot.wazuh.process_alert(alert_data)
    
    if response_action["action"] == "create_incident":
        incident_data = {
            "type": alert_data.get("rule", {}).get("groups", ["unknown"])[0],
            "severity": response_action["severity"],
            "description": f"Alert: {alert_data.get('rule', {}).get('description', 'Unknown')}",
            "source_alert": alert_data
        }
        
        incident = bot.create_incident(incident_data)
        
        # Send to Slack
        blocks = create_incident_blocks(incident)
        app.client.chat_postMessage(
            channel="#security-incidents",
            blocks=blocks
        )
    
    return {"status": "processed"}

# Helper functions
def create_incident_blocks(incident):
    """Create Slack blocks for incident display"""
    severity_color = {
        "critical": "#FF0000",
        "high": "#FF8C00", 
        "medium": "#FFD700",
        "low": "#90EE90"
    }.get(incident["severity"], "#808080")
    
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"🚨 *New Security Incident*\n*ID:* {incident['id']}\n*Type:* {incident['type']}\n*Severity:* {incident['severity']}\n*Description:* {incident['description']}"
            },
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": "View Details"},
                "action_id": "view_incident_details",
                "value": incident["id"]
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Acknowledge"},
                    "action_id": "acknowledge_incident",
                    "value": incident["id"],
                    "style": "primary"
                },
                {
                    "type": "button", 
                    "text": {"type": "plain_text", "text": "Assign to Me"},
                    "action_id": "assign_incident",
                    "value": incident["id"]
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Escalate"},
                    "action_id": "escalate_incident", 
                    "value": incident["id"],
                    "style": "danger"
                }
            ]
        }
    ]

# Initialize bot instance
bot = IncidentResponseBot()

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=3000, debug=True)
```

## Deployment

### Docker Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 3000

CMD ["python", "bot.py"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  ir-bot:
    build: .
    ports:
      - "3000:3000"
    environment:
      - SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}
      - SLACK_SIGNING_SECRET=${SLACK_SIGNING_SECRET}
      - SERVICENOW_URL=${SERVICENOW_URL}
      - SERVICENOW_USER=${SERVICENOW_USER}
      - SERVICENOW_PASS=${SERVICENOW_PASS}
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    restart: unless-stopped

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  redis_data:
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ir-bot
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ir-bot
  template:
    metadata:
      labels:
        app: ir-bot
    spec:
      containers:
      - name: ir-bot
        image: ir-bot:latest
        ports:
        - containerPort: 3000
        env:
        - name: SLACK_BOT_TOKEN
          valueFrom:
            secretKeyRef:
              name: slack-secrets
              key: bot-token
        - name: SLACK_SIGNING_SECRET
          valueFrom:
            secretKeyRef:
              name: slack-secrets
              key: signing-secret
---
apiVersion: v1
kind: Service
metadata:
  name: ir-bot-service
spec:
  selector:
    app: ir-bot
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
```

## Monitoring and Metrics

### Bot Performance Metrics
```python
import time
from functools import wraps

def track_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        # Log performance metrics
        logger.info(f"Function {func.__name__} took {end_time - start_time:.2f} seconds")
        
        return result
    return wrapper

class BotMetrics:
    def __init__(self):
        self.metrics = {
            "incidents_created": 0,
            "alerts_processed": 0,
            "commands_executed": 0,
            "response_times": [],
            "error_count": 0
        }
    
    def increment_counter(self, metric_name):
        if metric_name in self.metrics:
            self.metrics[metric_name] += 1
    
    def record_response_time(self, response_time):
        self.metrics["response_times"].append(response_time)
    
    def get_average_response_time(self):
        if self.metrics["response_times"]:
            return sum(self.metrics["response_times"]) / len(self.metrics["response_times"])
        return 0
    
    def generate_report(self):
        return {
            "total_incidents": self.metrics["incidents_created"],
            "total_alerts": self.metrics["alerts_processed"],
            "average_response_time": self.get_average_response_time(),
            "error_rate": self.metrics["error_count"] / max(self.metrics["commands_executed"], 1)
        }
```

### Health Check Endpoint
```python
@flask_app.route("/health")
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check Slack API connectivity
        slack_status = app.client.api_test()
        
        # Check external integrations
        servicenow_status = bot.servicenow.test_connection()
        wazuh_status = bot.wazuh.test_connection()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "slack": slack_status["ok"],
                "servicenow": servicenow_status,
                "wazuh": wazuh_status
            },
            "metrics": bot.metrics.generate_report()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, 500
```

## Security Considerations

### Authentication and Authorization
- Use OAuth tokens with minimal required scopes
- Implement role-based access control for bot commands
- Rotate API keys and tokens regularly
- Audit bot access and command usage

### Data Protection
- Encrypt sensitive data in transit and at rest
- Implement data retention policies
- Sanitize sensitive information in logs
- Use secure communication channels

### Operational Security
- Monitor bot activity and performance
- Implement rate limiting and abuse protection
- Maintain audit logs of all actions
- Regular security assessments and updates

## Troubleshooting

### Common Issues

1. **Bot Not Responding**
   ```bash
   # Check bot status
   curl http://localhost:3000/health
   
   # Check Slack connectivity
   python -c "from slack_sdk import WebClient; client = WebClient(token='your-token'); print(client.api_test())"
   ```

2. **Integration Failures**
   ```bash
   # Test ServiceNow connection
   curl -u username:password https://instance.service-now.com/api/now/table/incident?sysparm_limit=1
   
   # Test Wazuh API
   curl -k -X POST https://wazuh-manager:55000/security/user/authenticate
   ```

3. **Performance Issues**
   ```bash
   # Monitor resource usage
   docker stats ir-bot
   
   # Check logs for errors
   docker logs ir-bot --tail 100
   ```

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.