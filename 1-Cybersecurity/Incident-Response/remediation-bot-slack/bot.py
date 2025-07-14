#!/usr/bin/env python3
"""
Slack Incident Response Bot
Author: Giovanni Oliveira
Description: Automated incident response bot for Slack integration
"""

import os
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import requests
from functools import wraps

# Slack SDK imports
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request, jsonify

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ir_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Slack app
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET")
)

# Initialize Flask app for webhooks
flask_app = Flask(__name__)
handler = SlackRequestHandler(app)

class BotMetrics:
    """Track bot performance and usage metrics"""
    
    def __init__(self):
        self.metrics = {
            "incidents_created": 0,
            "alerts_processed": 0,
            "commands_executed": 0,
            "response_times": [],
            "error_count": 0,
            "start_time": datetime.now()
        }
    
    def increment_counter(self, metric_name: str):
        """Increment a counter metric"""
        if metric_name in self.metrics:
            self.metrics[metric_name] += 1
    
    def record_response_time(self, response_time: float):
        """Record response time for performance tracking"""
        self.metrics["response_times"].append(response_time)
        # Keep only last 100 response times
        if len(self.metrics["response_times"]) > 100:
            self.metrics["response_times"] = self.metrics["response_times"][-100:]
    
    def get_average_response_time(self) -> float:
        """Calculate average response time"""
        if self.metrics["response_times"]:
            return sum(self.metrics["response_times"]) / len(self.metrics["response_times"])
        return 0.0
    
    def generate_report(self) -> Dict:
        """Generate metrics report"""
        uptime = datetime.now() - self.metrics["start_time"]
        return {
            "uptime_hours": uptime.total_seconds() / 3600,
            "total_incidents": self.metrics["incidents_created"],
            "total_alerts": self.metrics["alerts_processed"],
            "total_commands": self.metrics["commands_executed"],
            "average_response_time": round(self.get_average_response_time(), 2),
            "error_rate": round(self.metrics["error_count"] / max(self.metrics["commands_executed"], 1) * 100, 2)
        }

class ServiceNowIntegration:
    """ServiceNow integration for ticket management"""
    
    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url
        self.auth = (username, password)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def test_connection(self) -> bool:
        """Test ServiceNow API connectivity"""
        try:
            url = f"{self.instance_url}/api/now/table/incident?sysparm_limit=1"
            response = requests.get(url, auth=self.auth, headers=self.headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"ServiceNow connection test failed: {e}")
            return False
    
    def create_incident(self, incident_data: Dict) -> Dict:
        """Create incident ticket in ServiceNow"""
        try:
            url = f"{self.instance_url}/api/now/table/incident"
            
            # Map severity to ServiceNow urgency/impact
            severity_mapping = {
                "critical": {"urgency": "1", "impact": "1"},
                "high": {"urgency": "2", "impact": "2"},
                "medium": {"urgency": "3", "impact": "3"},
                "low": {"urgency": "4", "impact": "4"}
            }
            
            mapping = severity_mapping.get(incident_data["severity"], {"urgency": "3", "impact": "3"})
            
            ticket_data = {
                "short_description": incident_data["title"],
                "description": incident_data["description"],
                "urgency": mapping["urgency"],
                "impact": mapping["impact"],
                "category": "Security",
                "subcategory": incident_data.get("type", "Unknown"),
                "caller_id": incident_data.get("reporter", "ir-bot"),
                "assignment_group": "Security Operations",
                "work_notes": f"Created by IR Bot from Slack incident {incident_data.get('id', 'Unknown')}"
            }
            
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                data=json.dumps(ticket_data),
                timeout=30
            )
            
            if response.status_code == 201:
                ticket = response.json()["result"]
                return {
                    "success": True,
                    "ticket_number": ticket["number"],
                    "sys_id": ticket["sys_id"],
                    "url": f"{self.instance_url}/nav_to.do?uri=incident.do?sys_id={ticket['sys_id']}"
                }
            else:
                logger.error(f"ServiceNow ticket creation failed: {response.text}")
                return {"success": False, "error": response.text}
                
        except Exception as e:
            logger.error(f"ServiceNow integration error: {e}")
            return {"success": False, "error": str(e)}
    
    def update_incident(self, sys_id: str, update_data: Dict) -> bool:
        """Update existing incident ticket"""
        try:
            url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
            
            response = requests.patch(
                url,
                auth=self.auth,
                headers=self.headers,
                data=json.dumps(update_data),
                timeout=30
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"ServiceNow update error: {e}")
            return False

class WazuhIntegration:
    """Wazuh SIEM integration for alert processing"""
    
    def __init__(self, api_url: str, username: str, password: str):
        self.api_url = api_url
        self.username = username
        self.password = password
        self.auth_token = None
        self.token_expiry = None
    
    def authenticate(self) -> bool:
        """Authenticate with Wazuh API"""
        try:
            auth_url = f"{self.api_url}/security/user/authenticate"
            response = requests.post(
                auth_url,
                json={"username": self.username, "password": self.password},
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()["data"]
                self.auth_token = data["token"]
                self.token_expiry = datetime.now() + timedelta(minutes=15)  # Tokens expire in 15 minutes
                return True
            else:
                logger.error(f"Wazuh authentication failed: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Wazuh authentication error: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Wazuh API connectivity"""
        try:
            if not self.auth_token or datetime.now() >= self.token_expiry:
                if not self.authenticate():
                    return False
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(
                f"{self.api_url}/",
                headers=headers,
                verify=False,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Wazuh connection test failed: {e}")
            return False
    
    def get_recent_alerts(self, minutes: int = 5) -> List[Dict]:
        """Fetch recent alerts from Wazuh"""
        try:
            if not self.auth_token or datetime.now() >= self.token_expiry:
                if not self.authenticate():
                    return []
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            # Calculate timestamp for filtering
            since_time = datetime.now() - timedelta(minutes=minutes)
            timestamp_filter = since_time.strftime("%Y-%m-%dT%H:%M:%S")
            
            params = {
                "limit": 100,
                "sort": "-timestamp",
                "q": f"timestamp>{timestamp_filter}"
            }
            
            response = requests.get(
                f"{self.api_url}/security/alerts",
                headers=headers,
                params=params,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()["data"]["affected_items"]
            else:
                logger.error(f"Failed to fetch Wazuh alerts: {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Wazuh alert fetch error: {e}")
            return []
    
    def process_alert(self, alert: Dict) -> Dict:
        """Process alert and determine response actions"""
        try:
            rule_level = alert.get("rule", {}).get("level", 0)
            rule_groups = alert.get("rule", {}).get("groups", [])
            
            # Determine severity based on rule level and groups
            if rule_level >= 12 or "critical" in rule_groups:
                severity = "critical"
                auto_actions = ["create_incident", "notify_team"]
            elif rule_level >= 10 or "high" in rule_groups:
                severity = "high"
                auto_actions = ["create_incident"]
            elif rule_level >= 7 or "medium" in rule_groups:
                severity = "medium"
                auto_actions = ["create_alert"]
            else:
                severity = "low"
                auto_actions = ["log_alert"]
            
            # Check for specific threat types
            threat_indicators = {
                "malware": ["malware", "virus", "trojan", "ransomware"],
                "intrusion": ["intrusion", "attack", "exploit"],
                "authentication": ["authentication", "login", "brute_force"]
            }
            
            threat_type = "unknown"
            for category, indicators in threat_indicators.items():
                if any(indicator in " ".join(rule_groups).lower() for indicator in indicators):
                    threat_type = category
                    break
            
            return {
                "severity": severity,
                "threat_type": threat_type,
                "actions": auto_actions,
                "rule_level": rule_level,
                "rule_groups": rule_groups,
                "source_ip": alert.get("data", {}).get("srcip"),
                "destination_ip": alert.get("data", {}).get("dstip"),
                "agent_name": alert.get("agent", {}).get("name")
            }
            
        except Exception as e:
            logger.error(f"Alert processing error: {e}")
            return {"severity": "low", "actions": ["log_alert"], "error": str(e)}

class IncidentResponseBot:
    """Main incident response bot class"""
    
    def __init__(self):
        self.incidents = {}
        self.metrics = BotMetrics()
        
        # Initialize integrations
        self.servicenow = None
        self.wazuh = None
        
        # Initialize ServiceNow if configured
        if all([os.environ.get("SERVICENOW_URL"), 
                os.environ.get("SERVICENOW_USER"), 
                os.environ.get("SERVICENOW_PASS")]):
            self.servicenow = ServiceNowIntegration(
                os.environ.get("SERVICENOW_URL"),
                os.environ.get("SERVICENOW_USER"),
                os.environ.get("SERVICENOW_PASS")
            )
            logger.info("ServiceNow integration initialized")
        
        # Initialize Wazuh if configured
        if all([os.environ.get("WAZUH_API_URL"),
                os.environ.get("WAZUH_USER"),
                os.environ.get("WAZUH_PASS")]):
            self.wazuh = WazuhIntegration(
                os.environ.get("WAZUH_API_URL"),
                os.environ.get("WAZUH_USER"),
                os.environ.get("WAZUH_PASS")
            )
            logger.info("Wazuh integration initialized")
    
    def generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"INC-{timestamp}"
    
    def create_incident(self, incident_data: Dict) -> Dict:
        """Create new security incident"""
        try:
            incident_id = self.generate_incident_id()
            
            incident = {
                "id": incident_id,
                "title": incident_data.get("title", f"{incident_data['type']} - {incident_data['severity']}"),
                "type": incident_data["type"],
                "severity": incident_data["severity"],
                "description": incident_data["description"],
                "status": "open",
                "created_at": datetime.now().isoformat(),
                "created_by": incident_data.get("created_by", "ir-bot"),
                "assigned_to": None,
                "channel_id": None,
                "ticket_number": None,
                "ticket_sys_id": None,
                "source_alert": incident_data.get("source_alert"),
                "affected_systems": incident_data.get("affected_systems", []),
                "timeline": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "action": "incident_created",
                        "user": "ir-bot",
                        "details": "Incident created automatically"
                    }
                ]
            }
            
            # Create ServiceNow ticket if integration is available
            if self.servicenow:
                ticket_result = self.servicenow.create_incident(incident)
                if ticket_result["success"]:
                    incident["ticket_number"] = ticket_result["ticket_number"]
                    incident["ticket_sys_id"] = ticket_result["ticket_sys_id"]
                    incident["ticket_url"] = ticket_result["url"]
                    
                    incident["timeline"].append({
                        "timestamp": datetime.now().isoformat(),
                        "action": "ticket_created",
                        "user": "ir-bot",
                        "details": f"ServiceNow ticket {ticket_result['ticket_number']} created"
                    })
            
            self.incidents[incident_id] = incident
            self.metrics.increment_counter("incidents_created")
            
            logger.info(f"Created incident {incident_id}: {incident['title']}")
            return incident
            
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
            self.metrics.increment_counter("error_count")
            raise
    
    def update_incident(self, incident_id: str, updates: Dict, user: str = "ir-bot") -> bool:
        """Update existing incident"""
        try:
            if incident_id not in self.incidents:
                return False
            
            incident = self.incidents[incident_id]
            
            # Track changes for timeline
            changes = []
            for key, value in updates.items():
                if key in incident and incident[key] != value:
                    changes.append(f"{key}: {incident[key]} → {value}")
                incident[key] = value
            
            # Add timeline entry
            if changes:
                incident["timeline"].append({
                    "timestamp": datetime.now().isoformat(),
                    "action": "incident_updated",
                    "user": user,
                    "details": "; ".join(changes)
                })
            
            # Update ServiceNow ticket if available
            if self.servicenow and incident.get("ticket_sys_id"):
                servicenow_updates = {}
                if "status" in updates:
                    status_mapping = {
                        "open": "1",
                        "in_progress": "2", 
                        "resolved": "6",
                        "closed": "7"
                    }
                    servicenow_updates["state"] = status_mapping.get(updates["status"], "1")
                
                if "assigned_to" in updates:
                    servicenow_updates["assigned_to"] = updates["assigned_to"]
                
                if servicenow_updates:
                    self.servicenow.update_incident(incident["ticket_sys_id"], servicenow_updates)
            
            logger.info(f"Updated incident {incident_id}: {changes}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating incident {incident_id}: {e}")
            self.metrics.increment_counter("error_count")
            return False
    
    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Get incident by ID"""
        return self.incidents.get(incident_id)
    
    def list_active_incidents(self) -> List[Dict]:
        """Get list of active incidents"""
        return [
            incident for incident in self.incidents.values()
            if incident["status"] in ["open", "in_progress"]
        ]
    
    def process_webhook_alert(self, alert_data: Dict) -> Dict:
        """Process incoming webhook alert"""
        try:
            self.metrics.increment_counter("alerts_processed")
            
            # Use Wazuh integration if available, otherwise basic processing
            if self.wazuh:
                response_action = self.wazuh.process_alert(alert_data)
            else:
                # Basic alert processing
                response_action = {
                    "severity": "medium",
                    "threat_type": "unknown",
                    "actions": ["create_alert"]
                }
            
            # Create incident if required
            if "create_incident" in response_action.get("actions", []):
                incident_data = {
                    "type": response_action.get("threat_type", "security_alert"),
                    "severity": response_action["severity"],
                    "title": f"Security Alert: {alert_data.get('rule', {}).get('description', 'Unknown')}",
                    "description": self._format_alert_description(alert_data),
                    "source_alert": alert_data,
                    "affected_systems": [alert_data.get("agent", {}).get("name")] if alert_data.get("agent") else []
                }
                
                incident = self.create_incident(incident_data)
                return {
                    "action_taken": "incident_created",
                    "incident_id": incident["id"],
                    "severity": incident["severity"]
                }
            
            return {
                "action_taken": "alert_logged",
                "severity": response_action["severity"]
            }
            
        except Exception as e:
            logger.error(f"Error processing webhook alert: {e}")
            self.metrics.increment_counter("error_count")
            return {"action_taken": "error", "error": str(e)}
    
    def _format_alert_description(self, alert_data: Dict) -> str:
        """Format alert data into readable description"""
        try:
            rule = alert_data.get("rule", {})
            agent = alert_data.get("agent", {})
            data = alert_data.get("data", {})
            
            description_parts = []
            
            if rule.get("description"):
                description_parts.append(f"Rule: {rule['description']}")
            
            if rule.get("level"):
                description_parts.append(f"Level: {rule['level']}")
            
            if agent.get("name"):
                description_parts.append(f"Agent: {agent['name']}")
            
            if data.get("srcip"):
                description_parts.append(f"Source IP: {data['srcip']}")
            
            if data.get("dstip"):
                description_parts.append(f"Destination IP: {data['dstip']}")
            
            return "\n".join(description_parts) if description_parts else "Security alert detected"
            
        except Exception as e:
            logger.error(f"Error formatting alert description: {e}")
            return "Security alert detected (formatting error)"

# Initialize bot instance
bot = IncidentResponseBot()

# Performance tracking decorator
def track_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            bot.metrics.increment_counter("commands_executed")
            return result
        except Exception as e:
            bot.metrics.increment_counter("error_count")
            raise
        finally:
            end_time = time.time()
            bot.metrics.record_response_time(end_time - start_time)
    return wrapper

# Slack command handlers
@app.command("/incident")
@track_performance
def handle_incident_command(ack, respond, command, client):
    """Handle /incident slash command"""
    ack()
    
    try:
        args = command["text"].split() if command["text"] else []
        action = args[0] if args else "help"
        user_id = command["user_id"]
        
        if action == "create":
            # Parse incident creation parameters
            incident_data = parse_incident_args(args[1:])
            incident_data["created_by"] = user_id
            
            incident = bot.create_incident(incident_data)
            
            # Send incident notification
            blocks = create_incident_blocks(incident)
            respond(blocks=blocks)
            
            # Also post to security channel
            try:
                client.chat_postMessage(
                    channel="#security-incidents",
                    blocks=blocks,
                    text=f"New incident created: {incident['id']}"
                )
            except Exception as e:
                logger.error(f"Failed to post to security channel: {e}")
        
        elif action == "status":
            incident_id = args[1] if len(args) > 1 else None
            if incident_id:
                incident = bot.get_incident(incident_id)
                if incident:
                    blocks = create_status_blocks(incident)
                    respond(blocks=blocks)
                else:
                    respond(f"❌ Incident {incident_id} not found")
            else:
                # Show all active incidents
                active_incidents = bot.list_active_incidents()
                if active_incidents:
                    blocks = create_active_incidents_blocks(active_incidents)
                    respond(blocks=blocks)
                else:
                    respond("✅ No active incidents")
        
        elif action == "assign":
            if len(args) >= 3:
                incident_id = args[1]
                assignee = args[2]
                
                if bot.update_incident(incident_id, {"assigned_to": assignee}, user_id):
                    respond(f"✅ Incident {incident_id} assigned to {assignee}")
                else:
                    respond(f"❌ Failed to assign incident {incident_id}")
            else:
                respond("❌ Usage: /incident assign <incident_id> <assignee>")
        
        elif action == "close":
            if len(args) >= 2:
                incident_id = args[1]
                resolution = " ".join(args[2:]) if len(args) > 2 else "Resolved"
                
                updates = {
                    "status": "resolved",
                    "resolution": resolution,
                    "resolved_at": datetime.now().isoformat()
                }
                
                if bot.update_incident(incident_id, updates, user_id):
                    respond(f"✅ Incident {incident_id} closed: {resolution}")
                else:
                    respond(f"❌ Failed to close incident {incident_id}")
            else:
                respond("❌ Usage: /incident close <incident_id> [resolution]")
        
        elif action == "help":
            respond(get_help_text())
        
        else:
            respond(f"❌ Unknown action: {action}. Use `/incident help` for usage information.")
    
    except Exception as e:
        logger.error(f"Error handling incident command: {e}")
        respond(f"❌ Error processing command: {str(e)}")

@app.command("/status")
@track_performance
def handle_status_command(ack, respond):
    """Handle /status slash command"""
    ack()
    
    try:
        active_incidents = bot.list_active_incidents()
        metrics = bot.metrics.generate_report()
        
        # Check integration status
        integrations_status = []
        if bot.servicenow:
            status = "✅" if bot.servicenow.test_connection() else "❌"
            integrations_status.append(f"{status} ServiceNow")
        
        if bot.wazuh:
            status = "✅" if bot.wazuh.test_connection() else "❌"
            integrations_status.append(f"{status} Wazuh")
        
        status_text = f"""
🤖 **IR Bot Status**

**Active Incidents:** {len(active_incidents)}
**Uptime:** {metrics['uptime_hours']:.1f} hours
**Commands Processed:** {metrics['total_commands']}
**Average Response Time:** {metrics['average_response_time']}s
**Error Rate:** {metrics['error_rate']}%

**Integrations:**
{chr(10).join(integrations_status) if integrations_status else "No integrations configured"}
        """
        
        respond(status_text.strip())
    
    except Exception as e:
        logger.error(f"Error handling status command: {e}")
        respond(f"❌ Error getting status: {str(e)}")

@app.command("/alerts")
@track_performance
def handle_alerts_command(ack, respond):
    """Handle /alerts slash command"""
    ack()
    
    try:
        if not bot.wazuh:
            respond("❌ Wazuh integration not configured")
            return
        
        # Get recent alerts
        alerts = bot.wazuh.get_recent_alerts(minutes=60)
        
        if not alerts:
            respond("✅ No recent alerts in the last hour")
            return
        
        # Group alerts by severity
        alert_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for alert in alerts:
            rule_level = alert.get("rule", {}).get("level", 0)
            if rule_level >= 12:
                alert_summary["critical"] += 1
            elif rule_level >= 10:
                alert_summary["high"] += 1
            elif rule_level >= 7:
                alert_summary["medium"] += 1
            else:
                alert_summary["low"] += 1
        
        alert_text = f"""
🚨 **Recent Alerts (Last Hour)**

**Critical:** {alert_summary['critical']}
**High:** {alert_summary['high']}
**Medium:** {alert_summary['medium']}
**Low:** {alert_summary['low']}

**Total:** {len(alerts)} alerts
        """
        
        respond(alert_text.strip())
    
    except Exception as e:
        logger.error(f"Error handling alerts command: {e}")
        respond(f"❌ Error getting alerts: {str(e)}")

# Interactive button handlers
@app.action("acknowledge_incident")
def handle_acknowledge(ack, body, client):
    """Handle incident acknowledgment"""
    ack()
    
    try:
        incident_id = body["actions"][0]["value"]
        user_id = body["user"]["id"]
        
        updates = {
            "status": "in_progress",
            "assigned_to": f"<@{user_id}>",
            "acknowledged_at": datetime.now().isoformat()
        }
        
        if bot.update_incident(incident_id, updates, user_id):
            # Update the message
            incident = bot.get_incident(incident_id)
            updated_blocks = create_incident_blocks(incident)
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks
            )
            
            # Send confirmation
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=user_id,
                text=f"✅ You have acknowledged incident {incident_id}"
            )
        else:
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=user_id,
                text=f"❌ Failed to acknowledge incident {incident_id}"
            )
    
    except Exception as e:
        logger.error(f"Error handling acknowledge action: {e}")

@app.action("assign_incident")
def handle_assign(ack, body, client):
    """Handle incident assignment"""
    ack()
    
    try:
        incident_id = body["actions"][0]["value"]
        user_id = body["user"]["id"]
        
        updates = {
            "assigned_to": f"<@{user_id}>",
            "status": "in_progress"
        }
        
        if bot.update_incident(incident_i, updates, user_id):
            # Update the message
            incident = bot.get_incident(incident_id)
            updated_blocks = create_incident_blocks(incident)
            
            client.chat_update(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                blocks=updated_blocks
            )
            
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=user_id,
                text=f"✅ Incident {incident_id} assigned to you"
            )
        else:
            client.chat_postEphemeral(
                channel=body["channel"]["id"],
                user=user_id,
                text=f"❌ Failed to assign incident {incident_id}"
            )
    
    except Exception as e:
        logger.error(f"Error handling assign action: {e}")

@app.action("escalate_incident")
def handle_escalate(ack, body, client):
    """Handle incident escalation"""
    ack()
    
    try:
        incident_id = body["actions"][0]["value"]
        
        # Show escalation modal
        client.views_open(
            trigger_id=body["trigger_id"],
            view=create_escalation_modal(incident_id)
        )
    
    except Exception as e:
        logger.error(f"Error handling escalate action: {e}")

# Flask routes for webhooks
@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    """Handle Slack events"""
    return handler.handle(request)

@flask_app.route("/webhook/alerts", methods=["POST"])
def handle_alert_webhook():
    """Handle incoming security alerts"""
    try:
        alert_data = request.json
        
        if not alert_data:
            return jsonify({"error": "No data provided"}), 400
        
        # Process the alert
        result = bot.process_webhook_alert(alert_data)
        
        # If an incident was created, notify Slack
        if result.get("action_taken") == "incident_created":
            incident = bot.get_incident(result["incident_id"])
            blocks = create_incident_blocks(incident)
            
            try:
                app.client.chat_postMessage(
                    channel="#security-incidents",
                    blocks=blocks,
                    text=f"New security incident: {incident['id']}"
                )
            except Exception as e:
                logger.error(f"Failed to post incident to Slack: {e}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error handling alert webhook: {e}")
        return jsonify({"error": str(e)}), 500

@flask_app.route("/health")
def health_check():
    """Health check endpoint"""
    try:
        # Test Slack connectivity
        slack_test = app.client.api_test()
        
        # Test integrations
        integrations = {}
        if bot.servicenow:
            integrations["servicenow"] = bot.servicenow.test_connection()
        if bot.wazuh:
            integrations["wazuh"] = bot.wazuh.test_connection()
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "slack_connected": slack_test.get("ok", False),
            "integrations": integrations,
            "metrics": bot.metrics.generate_report(),
            "active_incidents": len(bot.list_active_incidents())
        })
    
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

# Helper functions
def parse_incident_args(args: List[str]) -> Dict:
    """Parse incident creation arguments"""
    incident_data = {
        "type": "security_incident",
        "severity": "medium",
        "description": "Security incident"
    }
    
    i = 0
    while i < len(args):
        if args[i] == "--type" and i + 1 < len(args):
            incident_data["type"] = args[i + 1]
            i += 2
        elif args[i] == "--severity" and i + 1 < len(args):
            incident_data["severity"] = args[i + 1]
            i += 2
        elif args[i] == "--description" and i + 1 < len(args):
            # Join remaining args as description
            incident_data["description"] = " ".join(args[i + 1:])
            break
        else:
            i += 1
    
    return incident_data

def create_incident_blocks(incident: Dict) -> List[Dict]:
    """Create Slack blocks for incident display"""
    severity_colors = {
        "critical": "#FF0000",
        "high": "#FF8C00",
        "medium": "#FFD700", 
        "low": "#90EE90"
    }
    
    severity_emojis = {
        "critical": "🔴",
        "high": "🟠", 
        "medium": "🟡",
        "low": "🟢"
    }
    
    color = severity_colors.get(incident["severity"], "#808080")
    emoji = severity_emojis.get(incident["severity"], "⚪")
    
    # Main incident info
    main_text = f"{emoji} *{incident['title']}*\n"
    main_text += f"*ID:* {incident['id']}\n"
    main_text += f"*Type:* {incident['type']}\n"
    main_text += f"*Severity:* {incident['severity']}\n"
    main_text += f"*Status:* {incident['status']}\n"
    
    if incident.get("assigned_to"):
        main_text += f"*Assigned:* {incident['assigned_to']}\n"
    
    if incident.get("ticket_number"):
        main_text += f"*Ticket:* {incident['ticket_number']}\n"
    
    main_text += f"*Created:* {incident['created_at'][:19]}\n"
    main_text += f"*Description:* {incident['description']}"
    
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": main_text
            }
        }
    ]
    
    # Action buttons (only show if incident is not closed)
    if incident["status"] not in ["resolved", "closed"]:
        action_elements = []
        
        if incident["status"] == "open":
            action_elements.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "Acknowledge"},
                "action_id": "acknowledge_incident",
                "value": incident["id"],
                "style": "primary"
            })
        
        if not incident.get("assigned_to"):
            action_elements.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "Assign to Me"},
                "action_id": "assign_incident",
                "value": incident["id"]
            })
        
        action_elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "Escalate"},
            "action_id": "escalate_incident",
            "value": incident["id"],
            "style": "danger"
        })
        
        if action_elements:
            blocks.append({
                "type": "actions",
                "elements": action_elements
            })
    
    return blocks

def create_status_blocks(incident: Dict) -> List[Dict]:
    """Create detailed status blocks for incident"""
    blocks = create_incident_blocks(incident)
    
    # Add timeline if available
    if incident.get("timeline"):
        timeline_text = "*Timeline:*\n"
        for entry in incident["timeline"][-5:]:  # Show last 5 entries
            timestamp = entry["timestamp"][:19]
            timeline_text += f"• {timestamp} - {entry['action']} by {entry['user']}\n"
            if entry.get("details"):
                timeline_text += f"  _{entry['details']}_\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": timeline_text
            }
        })
    
    return blocks

def create_active_incidents_blocks(incidents: List[Dict]) -> List[Dict]:
    """Create blocks for active incidents summary"""
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 Active Incidents ({len(incidents)})"
            }
        }
    ]
    
    for incident in incidents[:10]:  # Show max 10 incidents
        severity_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡", 
            "low": "🟢"
        }
        
        emoji = severity_emojis.get(incident["severity"], "⚪")
        
        incident_text = f"{emoji} *{incident['id']}* - {incident['title']}\n"
        incident_text += f"Status: {incident['status']} | "
        incident_text += f"Severity: {incident['severity']}"
        
        if incident.get("assigned_to"):
            incident_text += f" | Assigned: {incident['assigned_to']}"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": incident_text
            }
        })
    
    if len(incidents) > 10:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"... and {len(incidents) - 10} more incidents"
                }
            ]
        })
    
    return blocks

def create_escalation_modal(incident_id: str) -> Dict:
    """Create escalation modal view"""
    return {
        "type": "modal",
        "callback_id": "escalate_incident_modal",
        "title": {
            "type": "plain_text",
            "text": "Escalate Incident"
        },
        "submit": {
            "type": "plain_text",
            "text": "Escalate"
        },
        "close": {
            "type": "plain_text",
            "text": "Cancel"
        },
        "blocks": [
            {
                "type": "input",
                "block_id": "severity_block",
                "element": {
                    "type": "static_select",
                    "action_id": "severity_select",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Select new severity"
                    },
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": "Critical"},
                            "value": "critical"
                        },
                        {
                            "text": {"type": "plain_text", "text": "High"},
                            "value": "high"
                        }
                    ]
                },
                "label": {
                    "type": "plain_text",
                    "text": "New Severity Level"
                }
            },
            {
                "type": "input",
                "block_id": "reason_block",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "reason_input",
                    "multiline": True,
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Reason for escalation..."
                    }
                },
                "label": {
                    "type": "plain_text",
                    "text": "Escalation Reason"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Incident ID: {incident_id}"
                    }
                ]
            }
        ],
        "private_metadata": incident_id
    }

def get_help_text() -> str:
    """Get help text for bot commands"""
    return """
🤖 **Incident Response Bot Help**

**Incident Management:**
• `/incident create --type <type> --severity <level> --description <text>` - Create new incident
• `/incident status [incident_id]` - Show incident status or list active incidents
• `/incident assign <incident_id> <user>` - Assign incident to user
• `/incident close <incident_id> [resolution]` - Close incident with resolution

**Information Commands:**
• `/status` - Show bot and system status
• `/alerts` - Show recent security alerts (requires Wazuh)

**Severity Levels:** critical, high, medium, low
**Incident Types:** malware, intrusion, data_breach, dos, insider_threat, security_incident

**Examples:**
• `/incident create --type malware --severity high --description "Suspicious file detected"`
• `/incident status INC-20240115123456`
• `/incident assign INC-20240115123456 @john.doe`
• `/incident close INC-20240115123456 Malware removed and system cleaned`
    """

if __name__ == "__main__":
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    logger.info("Starting Incident Response Bot...")
    logger.info(f"Slack integration: {'✅' if os.environ.get('SLACK_BOT_TOKEN') else '❌'}")
    logger.info(f"ServiceNow integration: {'✅' if bot.servicenow else '❌'}")
    logger.info(f"Wazuh integration: {'✅' if bot.wazuh else '❌'}")
    
    # Start Flask app
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 3000)), debug=False)