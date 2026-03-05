# Cost Control Policy

## Policy

**ALWAYS use FREE security methods. NEVER enable paid APIs without explicit user approval.**

## Implementation

### Cost-Aware API Service

Location: [`backend/app/services/cost_aware_api_service.py`](file:///Users/pete/GCP-Security-Hardener2/backend/app/services/cost_aware_api_service.py)

**Features:**
- Maintains list of paid/expensive APIs
- Blocks enablement unless explicitly approved
- Provides free alternatives for each paid feature
- Integrated into API enablement service

### Free APIs (Auto-Approved)

These APIs can be enabled automatically:
- Cloud Resource Manager
- Organization Policy
- IAM
- Cloud Billing (API is free, usage monitoring is free)
- Billing Budgets  
- Cloud Logging (free tier: 50 GB/month)
- Cloud Monitoring (free tier: 50 MB/month)
- Compute Engine (API is free)
- Service Usage
- Cloud KMS
- Secret Manager
- Cloud Storage (API is free)

### Paid APIs (Blocked Without Approval)

**Premium/Enterprise Only:**
- `accessapproval.googleapis.com` - Requires Premium Support ($12,500+/month)
- `accesscontextmanager.googleapis.com` - VPC Service Controls (~$5,000+/month)
- `assuredworkloads.googleapis.com` - Assured Workloads (~$2,500+/month)

**Pay-Per-Use:**
- `videointelligence.googleapis.com`
- `speech.googleapis.com`  
- `translate.googleapis.com`

## Free Alternatives Used

| Paid Feature | Free Alternative | Implementation |
|--------------|------------------|----------------|
| Access Approval API | IAM policies + manual approval | Restrict permissions, document process |
| Cloud Monitoring Alerts | Log sinks + log-based metrics | `firewall-change-monitor` sink |
| Premium Logging | Standard logging (50 GB/month free) | Use _Default bucket |
| VPC Service Controls | VPC firewall rules | `deny-external-ingress` rule |

## Monitoring Setup (FREE)

When VPC firewall rules are created, we automatically set up:

1. **Log Sink** - `firewall-change-monitor`
   - Captures all firewall create/update/delete operations
   - Routes to _Default log bucket (free tier)
   - Cost: $0/month

2. **Audit Trail**
   - View firewall changes in Cloud Logging
   - Query logs programmatically
   - Cost: $0/month (within free tier)

## Cost: $0/month

All security hardening features use only free-tier services.

## Future: User Approval Required

If a feature requires a paid API:
1. Block automatic enablement
2. Show cost information to user
3. Provide free alternative
4. Request explicit approval via UI
5. Only enable if user approves

**Example UI Flow:**
```
⚠️ This feature requires Access Approval API
Cost: $12,500+/month (Premium Support required)

Free alternative: Use IAM policies + manual approval workflow

[ Use Free Alternative ] [ Approve Paid API ]
```
