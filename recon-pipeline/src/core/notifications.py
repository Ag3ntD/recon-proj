#!/usr/bin/env python3
"""
Notification Module for Slack, Discord, Telegram
"""

import requests
import json
from typing import Dict, Any, List, Optional
from datetime import datetime


class NotificationManager:
    """
    Manage notifications across multiple platforms
    """
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.notification_config = config.get('notifications', {})
        self.enabled = self.notification_config.get('enabled', False)
        self.min_severity = self.notification_config.get('min_severity', 'high')
        
        # Severity levels for filtering
        self.severity_levels = {
            'info': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
    
    def should_notify(self, severity: str) -> bool:
        """
        Check if notification should be sent based on severity
        
        Args:
            severity: Finding severity
            
        Returns:
            True if should notify
        """
        if not self.enabled:
            return False
        
        finding_level = self.severity_levels.get(severity.lower(), 0)
        min_level = self.severity_levels.get(self.min_severity.lower(), 3)
        
        return finding_level >= min_level
    
    def notify_finding(self, finding: Dict[str, Any]):
        """
        Send notification for a finding
        
        Args:
            finding: Finding dictionary
        """
        severity = finding.get('severity', 'unknown')
        
        if not self.should_notify(severity):
            return
        
        # Send to all enabled platforms
        if self.notification_config.get('slack', {}).get('enabled', False):
            self.send_slack(finding)
        
        if self.notification_config.get('discord', {}).get('enabled', False):
            self.send_discord(finding)
        
        if self.notification_config.get('telegram', {}).get('enabled', False):
            self.send_telegram(finding)
    
    def notify_batch(self, findings: List[Dict[str, Any]]):
        """
        Send batch notification
        
        Args:
            findings: List of findings
        """
        # Filter by severity
        notify_findings = [
            f for f in findings 
            if self.should_notify(f.get('severity', 'unknown'))
        ]
        
        if not notify_findings:
            return
        
        # Group by severity
        by_severity = {}
        for finding in notify_findings:
            sev = finding.get('severity', 'unknown')
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(finding)
        
        # Send summary
        if self.notification_config.get('slack', {}).get('enabled', False):
            self.send_slack_summary(by_severity)
        
        if self.notification_config.get('discord', {}).get('enabled', False):
            self.send_discord_summary(by_severity)
    
    def send_slack(self, finding: Dict[str, Any]):
        """
        Send finding to Slack
        
        Args:
            finding: Finding dictionary
        """
        webhook_url = self.notification_config.get('slack', {}).get('webhook_url', '')
        if not webhook_url:
            return
        
        # Format message
        severity = finding.get('severity', 'unknown').upper()
        emoji = self._get_severity_emoji(severity)
        
        message = {
            "text": f"{emoji} New {severity} Finding",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {severity}: {finding.get('title', 'Unknown')}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Type:*\n{finding.get('finding_type', 'unknown')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{severity}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Host:*\n{finding.get('host', 'unknown')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Tool:*\n{finding.get('tool', 'unknown')}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*URL:*\n`{finding.get('url', 'N/A')}`"
                    }
                }
            ]
        }
        
        # Add CVE if present
        if finding.get('cve_id'):
            message["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*CVE:*\n{finding['cve_id']}"
                }
            })
        
        try:
            response = requests.post(
                webhook_url,
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Slack notification sent successfully")
            else:
                self.logger.error(f"Slack notification failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Slack notification error: {str(e)}")
    
    def send_slack_summary(self, findings_by_severity: Dict[str, List[Dict[str, Any]]]):
        """
        Send summary to Slack
        
        Args:
            findings_by_severity: Findings grouped by severity
        """
        webhook_url = self.notification_config.get('slack', {}).get('webhook_url', '')
        if not webhook_url:
            return
        
        total = sum(len(findings) for findings in findings_by_severity.values())
        
        message = {
            "text": f"🔍 Scan Complete - {total} Findings",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔍 Scan Complete - {total} High/Critical Findings"
                    }
                }
            ]
        }
        
        # Add severity breakdown
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in findings_by_severity:
                count = len(findings_by_severity[severity])
                emoji = self._get_severity_emoji(severity)
                message["blocks"].append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{severity.upper()}:* {count} findings"
                    }
                })
        
        try:
            requests.post(webhook_url, json=message, timeout=10)
        except:
            pass
    
    def send_discord(self, finding: Dict[str, Any]):
        """
        Send finding to Discord
        
        Args:
            finding: Finding dictionary
        """
        webhook_url = self.notification_config.get('discord', {}).get('webhook_url', '')
        if not webhook_url:
            return
        
        severity = finding.get('severity', 'unknown').upper()
        color = self._get_severity_color(severity)
        
        embed = {
            "title": f"{finding.get('title', 'Unknown Vulnerability')}",
            "description": finding.get('description', '')[:200],
            "color": color,
            "fields": [
                {
                    "name": "Severity",
                    "value": severity,
                    "inline": True
                },
                {
                    "name": "Type",
                    "value": finding.get('finding_type', 'unknown'),
                    "inline": True
                },
                {
                    "name": "Tool",
                    "value": finding.get('tool', 'unknown'),
                    "inline": True
                },
                {
                    "name": "Host",
                    "value": finding.get('host', 'unknown'),
                    "inline": False
                },
                {
                    "name": "URL",
                    "value": f"```{finding.get('url', 'N/A')}```",
                    "inline": False
                }
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if finding.get('cve_id'):
            embed["fields"].append({
                "name": "CVE",
                "value": finding['cve_id'],
                "inline": True
            })
        
        message = {"embeds": [embed]}
        
        try:
            response = requests.post(
                webhook_url,
                json=message,
                timeout=10
            )
            
            if response.status_code in [200, 204]:
                self.logger.info("Discord notification sent successfully")
            else:
                self.logger.error(f"Discord notification failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Discord notification error: {str(e)}")
    
    def send_discord_summary(self, findings_by_severity: Dict[str, List[Dict[str, Any]]]):
        """
        Send summary to Discord
        
        Args:
            findings_by_severity: Findings grouped by severity
        """
        webhook_url = self.notification_config.get('discord', {}).get('webhook_url', '')
        if not webhook_url:
            return
        
        total = sum(len(findings) for findings in findings_by_severity.values())
        
        description = "**Scan Summary**\n\n"
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in findings_by_severity:
                count = len(findings_by_severity[severity])
                emoji = self._get_severity_emoji(severity)
                description += f"{emoji} **{severity.upper()}:** {count} findings\n"
        
        embed = {
            "title": f"🔍 Scan Complete - {total} Findings",
            "description": description,
            "color": 3447003,  # Blue
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            requests.post(webhook_url, json={"embeds": [embed]}, timeout=10)
        except:
            pass
    
    def send_telegram(self, finding: Dict[str, Any]):
        """
        Send finding to Telegram
        
        Args:
            finding: Finding dictionary
        """
        bot_token = self.notification_config.get('telegram', {}).get('bot_token', '')
        chat_id = self.notification_config.get('telegram', {}).get('chat_id', '')
        
        if not bot_token or not chat_id:
            return
        
        severity = finding.get('severity', 'unknown').upper()
        emoji = self._get_severity_emoji(severity)
        
        message = f"""
{emoji} *{severity} Finding*

*Title:* {finding.get('title', 'Unknown')}
*Type:* {finding.get('finding_type', 'unknown')}
*Host:* {finding.get('host', 'unknown')}
*Tool:* {finding.get('tool', 'unknown')}
*URL:* `{finding.get('url', 'N/A')}`
"""
        
        if finding.get('cve_id'):
            message += f"\n*CVE:* {finding['cve_id']}"
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                self.logger.info("Telegram notification sent successfully")
            else:
                self.logger.error(f"Telegram notification failed: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Telegram notification error: {str(e)}")
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emoji_map = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️'
        }
        return emoji_map.get(severity.upper(), '⚪')
    
    def _get_severity_color(self, severity: str) -> int:
        """Get Discord color for severity level"""
        color_map = {
            'CRITICAL': 0xFF0000,  # Red
            'HIGH': 0xFF6600,      # Orange
            'MEDIUM': 0xFFCC00,    # Yellow
            'LOW': 0x00FF00,       # Green
            'INFO': 0x00FFFF       # Cyan
        }
        return color_map.get(severity.upper(), 0x808080)  # Gray default
