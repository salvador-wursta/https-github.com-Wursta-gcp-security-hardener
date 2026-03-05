#!/usr/bin/env python3
"""
Set up FREE Cloud Monitoring alert for firewall rule changes
No cost - uses free tier quotas
"""

import sys
from google.oauth2 import service_account
from googleapiclient.discovery import build

def create_firewall_alert(project_id, credentials, email):
    """Create a free Cloud Monitoring alert for firewall changes"""
    
    print(f"\n{'='*80}")
    print(f"SETTING UP FREE FIREWALL CHANGE ALERT")
    print(f"{'='*80}\n")
    
    try:
        monitoring = build('monitoring', 'v3', credentials=credentials)
        
        # Step 1: Create email notification channel (FREE)
        print(f"[STEP 1] Creating email notification channel...")
        
        channel_config = {
            "type": "email",
            "displayName": f"Firewall Change Alerts",
            "labels": {
                "email_address": email
            },
            "enabled": True
        }
        
        try:
            # Create notification channel
            channel = monitoring.projects().notificationChannels().create(
                name=f"projects/{project_id}",
                body=channel_config
            ).execute()
            
            channel_name = channel['name']
            print(f"✅ Email channel created: {email}")
            
        except Exception as e:
            if 'already exists' in str(e).lower():
                # List channels to find existing one
                channels = monitoring.projects().notificationChannels().list(
                    name=f"projects/{project_id}"
                ).execute()
                
                # Find email channel
                channel_name = None
                for ch in channels.get('notificationChannels', []):
                    if ch.get('labels', {}).get('email_address') == email:
                        channel_name = ch['name']
                        print(f"✅ Using existing email channel: {email}")
                        break
                
                if not channel_name and channels.get('notificationChannels'):
                    channel_name = channels['notificationChannels'][0]['name']
                    print(f"⚠️  Using first available channel")
            else:
                raise
        
        # Step 2: Create log-based metric (FREE)
        print(f"\n[STEP 2] Creating log-based metric...")
        
        logging_service = build('logging', 'v2', credentials=credentials)
        
        metric_config = {
            "name": f"projects/{project_id}/metrics/firewall_changes",
            "description": "Count of firewall rule modifications",
            "filter": (
                'protoPayload.serviceName="compute.googleapis.com" AND '
                '(protoPayload.methodName="v1.compute.firewalls.insert" OR '
                'protoPayload.methodName="v1.compute.firewalls.update" OR '
                'protoPayload.methodName="v1.compute.firewalls.delete" OR '
                'protoPayload.methodName="v1.compute.firewalls.patch")'
            ),
            "metricDescriptor": {
                "metricKind": "DELTA",
                "valueType": "INT64"
            }
        }
        
        try:
            metric = logging_service.projects().metrics().create(
                parent=f"projects/{project_id}",
                body=metric_config
            ).execute()
            print(f"✅ Log metric created: firewall_changes")
        except Exception as e:
            if 'already exists' in str(e).lower():
                print(f"✅ Log metric already exists: firewall_changes")
            else:
                raise
        
        # Step 3: Create alert policy (FREE)
        print(f"\n[STEP 3] Creating alert policy...")
        
        alert_policy = {
            "displayName": "Firewall Rule Modified",
            "documentation": {
                "content": (
                    "**SECURITY ALERT**: A firewall rule was modified!\n\n"
                    "Action required: Review the change and approve or revert.\n\n"
                    "Check logs at: https://console.cloud.google.com/logs/query"
                ),
                "mimeType": "text/markdown"
            },
            "conditions": [
                {
                    "displayName": "Firewall change detected",
                    "conditionThreshold": {
                        "filter": f'resource.type="global" AND metric.type="logging.googleapis.com/user/firewall_changes"',
                        "comparison": "COMPARISON_GT",
                        "thresholdValue": 0,
                        "duration": "0s",
                        "aggregations": [
                            {
                                "alignmentPeriod": "60s",
                                "perSeriesAligner": "ALIGN_RATE"
                            }
                        ]
                    }
                }
            ],
            "combiner": "OR",
            "enabled": True,
            "notificationChannels": [channel_name],
            "alertStrategy": {
                "autoClose": "3600s"  # Auto-close after 1 hour
            }
        }
        
        try:
            policy = monitoring.projects().alertPolicies().create(
                name=f"projects/{project_id}",
                body=alert_policy
            ).execute()
            print(f"✅ Alert policy created!")
            print(f"\nAlert details:")
            print(f"  Name: Firewall Rule Modified")
            print(f"  Trigger: Any firewall create/update/delete")
            print(f"  Notification: Email to {email}")
            print(f"  Cost: $0 (free tier)")
            
        except Exception as e:
            if 'already exists' in str(e).lower():
                print(f"✅ Alert policy already exists")
            else:
                raise
        
        print(f"\n{'='*80}")
        print(f"SUCCESS!")
        print(f"{'='*80}")
        print(f"\nYou will now receive email alerts when firewall rules are modified.")
        print(f"Cost: $0/month (uses free Cloud Monitoring quotas)")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    if len(sys.argv) < 4:
        print("Usage: python setup_free_firewall_alert.py <project_id> <credentials_path> <email>")
        sys.exit(1)
    
    project_id = sys.argv[1]
    creds_path = sys.argv[2]
    email = sys.argv[3]
    
    credentials = service_account.Credentials.from_service_account_file(
        creds_path,
        scopes=['https://www.googleapis.com/auth/cloud-platform']
    )
    
    success = create_firewall_alert(project_id, credentials, email)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
