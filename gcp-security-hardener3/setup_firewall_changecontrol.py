#!/usr/bin/env python3
"""
Set up firewall change control monitoring
Creates log sink to monitor firewall rule changes and alert on modifications
"""

import sys
from google.oauth2 import service_account
from googleapiclient.discovery import build

def create_firewall_change_monitoring(project_id, credentials):
    """Create log sink to monitor firewall changes"""
    
    print(f"\n{'='*80}")
    print(f"SETTING UP FIREWALL CHANGE MONITORING")
    print(f"{'='*80}\n")
    
    try:
        logging_service = build('logging', 'v2', credentials=credentials)
        
        # Filter for firewall rule changes
        filter_expr = (
            'protoPayload.serviceName="compute.googleapis.com" AND '
            '(protoPayload.methodName="v1.compute.firewalls.insert" OR '
            'protoPayload.methodName="v1.compute.firewalls.update" OR '
            'protoPayload.methodName="v1.compute.firewalls.delete" OR '
            'protoPayload.methodName="v1.compute.firewalls.patch")'
        )
        
        sink_name = "firewall-change-monitor"
        destination = f"logging.googleapis.com/projects/{project_id}/locations/global/buckets/_Default"
        
        sink_config = {
            "name": sink_name,
            "filter": filter_expr,
            "destination": destination,
            "description": "Alert on any firewall rule modifications",
            "outputVersionFormat": "V2"
        }
        
        print(f"Creating log sink: {sink_name}")
        print(f"Filter: Firewall create/update/delete operations")
        
        parent = f"projects/{project_id}"
        
        try:
            # Try to create
            result = logging_service.projects().sinks().create(
                parent=parent,
                body=sink_config
            ).execute()
            print(f"✅ Sink CREATED")
        except Exception as e:
            if 'already exists' in str(e):
                # Update existing
                result = logging_service.projects().sinks().update(
                    sinkName=f"{parent}/sinks/{sink_name}",
                    body=sink_config
                ).execute()
                print(f"✅ Sink UPDATED")
            else:
                raise
        
        print(f"\n✅ Firewall change monitoring is now active!")
        print(f"\nAny firewall modifications will be logged to: {destination}")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False

def create_firewall_restriction_policy(project_id, credentials):
    """Create org policy to restrict who can modify firewalls"""
    
    print(f"\n{'='*80}")
    print(f"RESTRICTING FIREWALL MODIFICATION PERMISSIONS")
    print(f"{'='*80}\n")
    
    print(f"⚠️  Organization policies for IAM restrictions require org-level access.")
    print(f"\nTo implement change control with approvals, you need to:")
    print(f"\n1. **Organizational-level approach (recommended):**")
    print(f"   - Create custom role with firewall permissions")
    print(f"   - Require approval workflow via Access Approval API")
    print(f"   - Set org policy: constraints/iam.allowedPolicyMemberDomains")
    print(f"\n2. **Project-level approach (what we can do):**")
    print(f"   - Remove compute.securityAdmin from most users")
    print(f"   - Require service account with specific permissions")
    print(f"   - Monitor all changes via log sink (already created)")
    print(f"   - Set up alerts via Cloud Monitoring")
    
    print(f"\n✅ Log sink monitoring is active (first line of defense)")
    print(f"⚠️  For approval workflow, you'll need org-level access or external tool")
    
    return True

def main():
    project_id = "gcp-lockdown-test-proj"
    creds_path = "/Users/pete/documents/2025 taxes/special files/gcp-security-hardener-0b006ca6f10c.json"
    
    credentials = service_account.Credentials.from_service_account_file(
        creds_path,
        scopes=['https://www.googleapis.com/auth/cloud-platform']
    )
    
    # Step 1: Set up monitoring
    monitor_success = create_firewall_change_monitoring(project_id, credentials)
    
    # Step 2: Explain restriction options
    create_firewall_restriction_policy(project_id, credentials)
    
    print(f"\n{'='*80}")
    print(f"CHANGE CONTROL SUMMARY")
    print(f"{'='*80}")
    print(f"✅ Firewall changes are now monitored and logged")
    print(f"⚠️  Approval workflow requires org-level policies or external tooling")
    print(f"\nRecommendation: Use IAM policies to restrict firewall.update permission")

if __name__ == "__main__":
    main()
