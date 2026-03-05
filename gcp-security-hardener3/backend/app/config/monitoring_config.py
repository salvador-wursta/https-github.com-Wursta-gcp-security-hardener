"""
Shared Monitoring Configuration
contains alert definitions used by both the backend service and script generator.
"""

EXTENDED_ALERTS = [
    {
        "display_name": "New API Enabled",
        "doc_content": "A new API was enabled in the project.",
        "filter": 'protoPayload.methodName="google.serviceusage.v1.ServiceUsage.EnableService"',
        "condition_name": "API enabled"
    },
    {
        "display_name": "Org Policy Modified",
        "doc_content": "An Organization Policy was modified.",
        "filter": 'protoPayload.methodName:"SetOrgPolicy" OR protoPayload.methodName:"CreatePolicy" OR protoPayload.methodName:"UpdatePolicy" OR protoPayload.methodName:"DeletePolicy"',
        "condition_name": "Org Policy change"
    },
    {
        "display_name": "Billing Budget Modified",
        "doc_content": "A billing budget was modified or created.",
        "filter": 'protoPayload.serviceName="billing.googleapis.com" AND (protoPayload.methodName:"UpdateBudget" OR protoPayload.methodName:"CreateBudget")',
        "condition_name": "Budget change"
    },
    {
        "display_name": "Firewall Rule Modified",
        "doc_content": "A firewall rule was updated, patched, or deleted.",
        "filter": 'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"patch" OR protoPayload.methodName:"update" OR protoPayload.methodName:"delete")',
        "condition_name": "Firewall change"
    },
    {
        "display_name": "Inbound RDP Enabled",
        "doc_content": "A firewall rule allowing RDP (port 3389) was created.",
        "filter": 'resource.type="gce_firewall_rule" AND protoPayload.methodName:"insert" AND protoPayload.request.alloweds.ports="3389"',
        "condition_name": "RDP enabled"
    },
    {
        "display_name": "Project Created",
        "doc_content": "A new GCP project was created.",
        "filter": 'protoPayload.methodName:"CreateProject"',
        "condition_name": "Project created"
    }
]
