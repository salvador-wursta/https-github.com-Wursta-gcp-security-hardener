
export const DOCS_DATA: Record<string, { title: string; content: string }> = {
  "RISK_CATALOG": {
    title: "Risk Capabilities Catalog",
    content: `# Security Scan Risk Catalog

This catalog documents all security risks identified by the GCP Security Hardener, including their descriptions, default severity levels, and remediation recommendations.

## 1. Identity & Access Management (IAM)

| Risk ID | Title | Default Severity | Description | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| \`iam_mfa_scc_confirmed\` | **MFA Not Enforced** | **CRITICAL** | Multi-Factor Authentication is not enforced for users in the project. This is a primary vector for account takeover. | Enable MFA in Google Workspace / Cloud Identity immediately. |
| \`service_account_keys_allowed\` | **Service Account Key Creation Enabled** | **CRITICAL** | The organization policy to disable service account key creation is not enforced. | Enforce \`constraints/iam.disableServiceAccountKeyCreation\`. |
| \`iam_sa_keys\` | **Risky Service Account Keys** | **CRITICAL** | User-managed service account keys older than 90 days were found. Leaked keys are a top compromise vector. | Rotate keys immediately and move to workload identity where possible. |
| \`iam_basic_roles\` | **Primitive IAM Roles (Owner)** | **CRITICAL** | Users found with the primitive 'Owner' role. Owners have unlimited access to all resources and billing. | Replace with predefined or custom roles (Least Privilege). |
| \`iam_basic_roles\` | **Primitive IAM Roles (Editor)** | **HIGH** | Users found with the primitive 'Editor' role. Editors have broad modification rights across the project. | Replace with predefined roles (e.g., Compute Admin, Storage Admin). |
| \`iam_org_admin_direct_access\` | **Org Admin Direct Access** | **HIGH** | Organization Administrators have direct IAM bindings on the project. This violates separation of duties. | Remove direct access; Org Admins are implicitly super-users. |
| \`default_service_accounts\` | **Default Service Account Risks** | **HIGH** | Default Service Accounts (e.g., Compute Engine default) have automatic 'Editor' rights. | Disable automatic role grants and restrict permissions. |

## 2. Network Security

| Risk ID | Title | Default Severity | Description | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| \`firewall_config_critical\` | **Public Management Ports** | **CRITICAL** | Firewall rules expose management ports (SSH/22, RDP/3389) to the public internet (\`0.0.0.0/0\`). | Restrict access to specific management IPs or use IAP (Identity-Aware Proxy). |
| \`no_network_hardening\` | **Missing Default Deny Rule** | **CRITICAL** | The VPC does not have a \`deny-external-ingress\` rule (priority 65535) to explicitly block all traffic not allowed. | Create a low-priority deny-all ingress rule. |
| \`missing_advanced_security\` | **Advanced Network Security Missing** | **HIGH** | Public-facing resources (External IPs) detected without Cloud Armor or Cloud IDS protection. | Enable Cloud Armor for WAF/DDoS protection and Cloud IDS for threat detection. |
| \`firewall_config_risk\` | **Broad Firewall Rules** | **HIGH** | Firewall rules allow broad access (e.g., internal ranges) without strict protocol limits. | Tighten rules to least privilege (specific ports/protocols). |

## 3. Monitoring & Logging

| Risk ID | Title | Default Severity | Description | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| \`missing_alert_*\` | **Missing CIS Critical Alerts** | **MEDIUM** | Missing alert policies for critical CIS Benchmark metrics (e.g., Project Ownership changes, Audit Config changes). | Enable standard CIS alert policies. |
| \`monitoring_disabled\` | **Monitoring APIs Disabled** | **LOW** | Cloud Monitoring or Logging APIs are not enabled. | Enable \`monitoring.googleapis.com\` and \`logging.googleapis.com\`. |

## 4. Billing & Governance

| Risk ID | Title | Default Severity | Description | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| \`no_billing_account\` | **No Billing Account Linked** | **MEDIUM** | The project has no linked billing account, preventing budget alerts. | Link a valid billing account. |
| \`no_budgets\` | **No Budget Limits** | **HIGH** | A billing account exists but no budgets are configured. Risk of unexpected cost spikes. | Create a billing budget with email alerts. |
| \`poor_change_control\` | **Ad-Hoc Change Management** | **HIGH** | Frequent manual changes detected (ClickOps) instead of IaC (Terraform). | Adopt Infrastructure as Code (Terraform) pipelines. |
| \`risky_api_*\` | **High Risk API Enabled** | **VARIES** | Dangerous APIs (e.g., \`admin.googleapis.com\`) are enabled but potentially unused. | Disable APIs that are not strictly required. |

## 5. Security Command Center (SCC)

| Risk ID | Title | Default Severity | Description | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| \`scc_findings_detected\` | **SCC Findings** | **Per Finding** | Aggregates findings from Google's native Security Command Center. | Review SCC dashboard; specific findings like MFA are elevated to IAM risks above. |`
  },
  "README": {
    title: "Project Overview",
    content: `# GCP Security Hardener

A security hardening application designed for non-technical SMBs using Google Workspace or Vertex AI. This application protects GCP tenants from privilege escalation attacks and crypto-mining exploits by implementing automated security policies, billing limits, and kill switches.

## 🎯 Problem Statement

When a GCP tenant is not properly locked down, a hijacked Workspace Super Admin account can be used to:
- Elevate privileges
- Enable expensive APIs (like Compute Engine)
- Launch crypto-mining attacks
- Cause massive financial damage

## 🛡️ Solution

This application acts as a "Guardian" for your cloud environment by:
- Setting billing limits and alerts
- Enforcing "kill switches" to prevent runaway costs
- Removing the ability to enable risky APIs
- Applying security best practices automatically

## 🔐 Security Principles

1. **Least Privilege:** Temporary Service Accounts use minimum required roles
2. **Tenant Isolation:** Firestore paths use \`Users/{UserID}/...\` for data separation
3. **Encryption:** Sensitive data (Auth Tokens) are never logged to console
4. **Secure by Design:** All security constraints are applied automatically

## 🔐 Required Permissions (Least Privilege)

The application uses two distinct Service Accounts to maintain security separation:

### 1. Scanner Account (Read-Only)
Used for discovering risks. It **CANNOT** make changes.
- **Project Level:**
  - \`roles/viewer\`
  - \`roles/iam.securityReviewer\`
  - \`roles/billing.viewer\`
- **Organization Level (if applicable):**
  - \`roles/resourcemanager.organizationViewer\`
  - \`roles/securitycenter.assetsViewer\`
  - \`roles/securitycenter.findingsViewer\`
  - \`roles/serviceusage.serviceUsageViewer\`

### 2. Admin Account (Remediation)
Used only when you click "Apply Fixes".
- **Project Level:**
  - \`roles/editor\`
  - \`roles/iam.securityAdmin\`
  - \`roles/monitoring.admin\`
- **Organization Level (if applicable):**
  - \`roles/securitycenter.admin\` (for configuring SCC)
  - \`roles/orgpolicy.policyAdmin\``
  },
  "SECURE_CODE": {
    title: "Secure Coding Guide",
    content: `# Secure Coding Quick Reference Guide

**For:** GCP Security Hardener Development Team  
**Purpose:** Quick reference for common security patterns

---

## 1. Input Validation

### ✅ DO

\`\`\`python
# Use Pydantic validators
from pydantic import BaseModel, Field, validator, EmailStr

class UserRequest(BaseModel):
    email: EmailStr  # Built-in email validation
    age: int = Field(..., ge=0, le=150)  # Bounded integers
    username: str = Field(..., min_length=3, max_length=20, pattern=r'^[a-zA-Z0-9_]+$')
\`\`\`

### ❌ DON'T

\`\`\`python
# Don't trust user input
project_id = request.project_id  # No validation
query = f"SELECT * FROM projects WHERE id = '{project_id}'"  # SQL injection!
\`\`\`

## 2. Authentication & Authorization

### ✅ DO

\`\`\`python
# Use dependency injection for auth
from fastapi import Depends, HTTPException, Header

async def verify_token(authorization: str = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization")
    return FirebaseAuthService.verify_firebase_token(token)
\`\`\`

## 3. Data Protection

### ✅ DO

\`\`\`python
# Encrypt sensitive data at rest
from cryptography.fernet import Fernet

key = os.getenv("ENCRYPTION_KEY")
cipher = Fernet(key)
encrypted = cipher.encrypt(sensitive_data.encode())
\`\`\`

### ❌ DON'T

\`\`\`python
# Don't log sensitive data
logger.info(f"User token: {token}")  # NEVER!
\`\`\`
`
  },
  "GCP_HARDENING_OVERVIEW": {
    title: "GCP Security Hardening",
    content: `# GCP Security Hardening & Monitoring: Overview

This document explains the security architecture applied by the GCP Security Hardener, including Organization Policies, Centralized Logging, and the Real-Time Alerting system.

---

## 1. Organization Security Policies
These constraints are applied at either the **Organization** or **Project** level. They act as "Guardrails" that prevent risky configurations, even for users with high-level permissions.

| Policy Constraint | Description | Impact on Projects |
|:---|:---|:---|
| **Disable SA Key Creation** | Prevents the creation of new Service Account JSON keys. | Reduces the risk of "leaked credentials" by forcing the use of Short-Lived tokens (OIDC/Workload Identity). |
| **API Whitelisting** | Restricts which GCP services (APIs) can be enabled. | Prevents "Shadow IT" and limits the attack surface to only approved services. |
| **Resource Locations** | Restricts where Cloud resources (VMs, Buckets, etc.) can be created. | Enforces **Data Residency** and regional governance by locking resources to specific approved regions (e.g., \`us-central1\`). |
| **Firewall Hardening** | Automatically configures baseline deny rules and restricts dangerous ports. | Protects resources from common internet-based attacks (like brute-force RDP/SSH). |

---

## 2. Centralized Organization Monitoring
The solution implements an **Aggregated Logging Architecture**. This allows a single "Security Hub" project to monitor activities across 100+ projects in your organization.

### How it Works:
1.  **Aggregated Sink**: An "Organization-Level Sink" is created. It captures Audit Logs from **ALL** child projects using the \`--include-children\` flag.
2.  **Central Log Bucket**: These logs are routed to a dedicated, high-security bucket (\`security-org-logs\`) in your central monitoring project.
3.  **Log-Based Metrics**: Specialized metrics scan this bucket for specific security events:
    *   API Enablement
    *   Org Policy violations/changes
    *   Billing/Budget adjustments
    *   Firewall modifications
    *   Inbound RDP (Port 3389) enablement
4.  **Label Extraction**: Our metrics are "Smart." They don't just count events; they extract the **Impacted Project ID**, the **Action Taken**, and the **User (Principal)** who did it.

---

## 3. Real-Time Alerting System
When the system detects a security event, it triggers a **Warning** alert within 2-5 minutes.

### What it Protects You From:
*   **Unauthorized Access**: Seeing which user enabled a dangerous API or opened a firewall port.
*   **Cost Spikes**: Detecting budget or quota changes before they lead to massive bills.
*   **Policy Drift**: Getting alerted immediately if someone tries to weaken an Organization Policy.
*   **Shadow IT**: Visibility into new project creations or resource sprawl in unapproved regions.

### Alert Content:
Each notification includes:
*   **Severity**: Labeled as \`WARNING\` for clear triage.
*   **Identity**: The exact email address of the person who made the change.
*   **Context**: The specific project and service that were affected.
*   **Actionable Links**: A direct link to the **Cloud Logging Explorer**, pre-filtered to the exact log entry for fast investigation.
`
  },
  "PRIVILEGE_MODEL": {
    title: "Privilege Escalation Model",
    content: `# GCP Security Hardener: Required Privileges

This application uses a "Just-In-Time" (JIT) Privilege Escalation model. It requires two distinct Service Accounts to operate securely:

1.  **Scanner Account**: Has read-only access to audit your environment. It cannot make changes.
2.  **Admin Account**: Has write access to apply "lockdowns" (fix issues). This account is only used when you explicitly click "Fix" or "Apply Lockdown".

## 1. Scanner Account (\`gcp-hardener-scanner\`)

**Purpose**: Continuous auditing, risk detection, and reporting.

### Project Level Roles
| Role | ID | Why it's needed |
| :--- | :--- | :--- |
| **Viewer** | \`roles/viewer\` | Basic read access to most GCP resources. |
| **Security Reviewer** | \`roles/iam.securityReviewer\` | To audit IAM policies and permissions. |
| **Billing Viewer** | \`roles/billing.viewer\` | To analyze cost anomalies and waste. |

### Organization Level Roles (Optional but Recommended)
If you are scanning multiple projects in an Organization:
| Role | ID | Why it's needed |
| :--- | :--- | :--- |
| **Org Viewer** | \`roles/resourcemanager.organizationViewer\` | To list all projects in the organization. |
| **Folder Viewer** | \`roles/resourcemanager.folderViewer\` | To list projects within folders. |
| **Service Usage Viewer** | \`roles/serviceusage.serviceUsageViewer\` | To determine which APIs are enabled. |
| **Compute Viewer** | \`roles/compute.viewer\` | To check VM instances and quotas. |

---

## 2. Admin Account (\`gcp-hardener-admin\`)

**Purpose**: Applying security fixes (Lockdown).

### Project Level Roles
| Role | ID | Why it's needed |
| :--- | :--- | :--- |
| **Editor** | \`roles/editor\` | Broad modification rights for standard resources. |
| **Security Admin** | \`roles/iam.securityAdmin\` | To modify IAM policies (e.g., revoking keys). |
| **Service Usage Admin** | \`roles/serviceusage.serviceUsageAdmin\` | To disable risky/unused APIs. |
| **Logging Config Writer** | \`roles/logging.configWriter\` | To create secure logging buckets and sinks. |
| **Monitoring Admin** | \`roles/monitoring.admin\` | To create Alert Policies and Channels. |
| **Compute Security Admin** | \`roles/compute.securityAdmin\` | To create/modify Firewall rules. |

### Organization Level Roles
| Role | ID | Why it's needed |
| :--- | :--- | :--- |
| **Org Policy Admin** | \`roles/orgpolicy.policyAdmin\` | To enforce constraints (e.g., disable key creation). |
| **Compute Network Admin** | \`roles/compute.networkAdmin\` | To manage shared VPC firewalls. |

## Least Privilege Principle
The application never stores the Admin keys permanently. They are:
1.  Uploaded to the session memory.
2.  Used only during the active session (20-minute timeout).
3.  **Purged automatically** when the session expires or you generate the Executive Report.
`
  },
  "TECHNICAL_REFERENCE": {
    title: "GCP Security Scanner",
    content: `# GCP Security Scanner: Technical Reference

This document provides a technical breakdown of the vulnerabilities identified by the GCP Security Scanner, the threats they represent, and the precise mitigation strategies applied during the lockdown process.

---

## 1. Compute & API Vulnerabilities

### Risky API Enablement
*   **What we scan for**: Status of high-cost services including **Compute Engine**, **GKE (Kubernetes)**, **Vertex AI**, and **Dataflow**.
*   **The Threat**: "Resource Jacking." Attackers with compromised credentials prioritize these APIs because they allow for the rapid deployment of massive, expensive compute clusters.
*   **Technical Solution**: **API Whitelisting**. The hardener implementation disables all services except a strictly defined "Security Profile" (e.g., *Google Workspace Only* or *Vertex AI Only*).
*   **Identification**: The scanner cross-references enabled APIs against known high-risk service IDs.

### Unmanaged GPU Quotas
*   **What we scan for**: Total GPU quota limits across all active regions.
*   **The Threat**: **Crypto-mining**. GPUs are the primary target for malicious mining scripts. Even a "standard" quota can lead to thousands of dollars in debt in a single weekend.
*   **Technical Solution**: **Quota Capping**. The system programmatically requests a reduction of GPU quotas to \`0\` across all regions unless specifically authorized.
*   **Identification**: Queries the \`compute.v1.regionQuotas\` API to sum \`GPUS_ALL_REGIONS\`.

---

## 2. Identity & Access Management (IAM)

### Service Account Key Creation
*   **What we scan for**: Enforcement status of the \`iam.disableServiceAccountKeyCreation\` organization policy.
*   **The Threat**: **Credential Persistence**. SA Keys (.json files) are "forever passwords." If downloaded and leaked, they provide permanent access that bypasses MFA and is difficult to rotate without breaking production.
*   **Technical Solution**: **Org Policy Enforcement**. We apply the \`constraints/iam.disableServiceAccountKeyCreation\` boolean constraint at the project or organization level.
*   **Identification**: Checks the current effective policy for the IAM constraint via the Organization Policy V2 API.

---

## 3. Network & Perimeter Security

### External Surface Exposure
*   **What we scan for**: Presence of VPC firewall rules that allow broad ingress from \`0.0.0.0/0\`.
*   **The Threat**: **Brute-Force & Lateral Movement**. Open RDP (3389) or SSH (22) ports are constantly scanned by automated botnets. Once a single VM is breached, the attacker can move laterally to the rest of your GCP environment.
*   **Technical Solution**: **VPC Hardening**. We deploy a high-priority \`deny-external-ingress\` rule that blocks all non-load-balanced traffic from the internet while preserving internal VPC communication.
*   **Identification**: Scans the \`compute.firewalls\` list for rules with \`IPProtocol: all\` or specific management ports targeting external ranges.

### Firewall Configuration Check
*   **What we scan for**: Presence of a high-priority "Deny All" ingress rule.
*   **The Threat**: **Implicit Trust**. Without an explicit "Deny All" rule, the network relies solely on "Allow" rules. Any misconfiguration or forgotten rule becomes an instant vulnerability.
*   **Technical Solution**: **Zero Trust Baseline**. We verify that a firewall rule exists with priority < 1000, action \`DENY\`, and source range \`0.0.0.0/0\`, ensuring all traffic is blocked by default unless explicitly allowed.
*   **Identification**: Analyzes the project's firewall policy for a matching "Deny All" configuration.

---

## 4. Financial & Monitoring Governance

### Missing Billing Guardrails
*   **What we scan for**: Presence of Billing Budgets, the current month's spending trend, and valid notification channels.
*   **The Threat**: **Financial Exhaustion**. Without a budget, there is no "circuit breaker." An attack or a configuration error can continue to accrue costs until the credit card is maxed out.
*   **Technical Solution**: **Centralized Alerting & Budgets**. We create a Multi-Project Budget with real-time Pub/Sub notifications that can trigger automated responses or notify administrators immediately.
*   **Identification**: Orchestrates calls to the Cloud Billing Budget API to verify filter coverage and threshold settings.

### Idle Resource Waste
*   **What we scan for**: Underutilized VMs, unattached disks, and idle IP addresses using the Google Recommender API.
*   **The Threat**: **Ghost Costs**. Abandoned resources continue to cost money and provide an unmonitored entry point for attackers.
*   **Technical Solution**: **Cleanup Recommendations**. The scanner provides an automated report of "Waste" resources to be triaged or automatically deleted.
*   **Identification**: Consumes the \`google.recommender.v1\` service to identify \`IDLE_RESOURCE\` and \`RIGHTSIZING\` opportunities.
`
  },
  "SETUP_GUIDE": {
    title: "Setup Guide",
    content: `# 🚀 Quick Setup - Start Here!

## What's Ready

✅ **Backend**: All APIs implemented and ready  
✅ **Frontend**: All UI components built  
✅ **Environment Files**: Created with placeholders  
✅ **Documentation**: Complete setup guides  

## What You Need to Do

### 1. Configure Backend (2 minutes)

Edit \`backend/.env\`:
\`\`\`env
GCP_PROJECT_ID=your-actual-project-id
\`\`\`

### 2. Get OAuth Client ID (5 minutes)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. APIs & Services → Credentials → Create OAuth Client ID
3. See \`GET_OAUTH_CLIENT_ID.md\` for details

### 3. Configure Frontend (1 minute)

Edit \`frontend/.env.local\`:
\`\`\`env
NEXT_PUBLIC_GOOGLE_CLIENT_ID=paste-your-client-id-here
\`\`\`

### 4. Start Everything

**Terminal 1 - Backend:**
\`\`\`bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload
\`\`\`

**Terminal 2 - Frontend:**
\`\`\`bash
cd frontend
npm run dev
\`\`\`

### 5. Test It!

1. Open \`http://localhost:3000\`
2. Complete the wizard
3. Connect Google Cloud
4. View scan results
5. Apply security lockdown
`
  },
  "WINDOWS_GUIDE": {
    title: "Windows Setup Guide",
    content: `# Running on Windows

This guide explains how to compile and run the GCP Security Hardener on Microsoft Windows.

## Prerequisites

1.  **Python 3.10+**: Must be installed and added to PATH. [Download Here](https://www.python.org/downloads/)
2.  **Node.js 18+**: Required for the frontend interface. [Download Here](https://nodejs.org/en/download)

## Option 1: Quick Start (Developer Mode)

To run the application immediately without compiling:

1.  Open Command Prompt (cmd) or PowerShell.
2.  Navigate to this folder.
3.  Run the backend:
    \`\`\`cmd
    cd backend
    python -m venv venv
    venv\\Scripts\\activate
    pip install -r requirements.txt
    python -m app.main
    \`\`\`
4.  In a **new** terminal window, run the frontend:
    \`\`\`cmd
    cd frontend
    npm install
    npm run dev
    \`\`\`
5.  Open [http://localhost:3000](http://localhost:3000)
`
  },
  "CAI_PLAN": {
    title: "Plan: Security Architect Agent",
    content: `# Implementation Plan: Cloud Asset Inventory & AI Security Architect

## 🎯 Objective
Upgrade the scanner from **Iterative Scanning** (slow, finding-by-finding) to **Snapshot-Based Scanning** using the **Cloud Asset Inventory (CAI) API**. This data will then be fed into an AI Security Agent to generate high-level "Architectural Recommendations" rather than just individual alerts.

## 🏗️ Proposed Architecture

\`\`\`mermaid
graph TD
    A[User Starts Scan] --> B[Backend: CAI Service]
    B -->|SearchAllResources| C[Google Cloud Asset Inventory]
    B -->|SearchAllIamPolicies| C
    C -->|Return Asset Dump| B
    B -->|Save JSON| D[Local Asset Store]
    D -->|Feed Data| E[AI Security Agent (Gemini)]
    E -->|Analyze Architecture| F[Architectural Report]
    F -->|Display| G[Frontend: Architecture View]
\`\`\`

---

## 📅 Implementation Phases

### Phase 1: Data Ingestion (The "Snapshot")
Instead of checking 50 different APIs, we will use **Cloud Asset Inventory (CAI)** to grab a complete snapshot of the environment in seconds.

1.  **Enable API**: \`cloudasset.googleapis.com\`
2.  **Permissions**: Add \`roles/cloudasset.viewer\` to the Scanner Service Account.
3.  **New Service**: Create \`app/services/asset_inventory_service.py\`.
4.  **Methods**:
    *   \`fetch_network_topology()\`: Use \`SearchAllResources\` filtering for \`compute.googleapis.com/Network\`, \`Subnetwork\`, \`Firewall\`, \`Route\`.
    *   \`fetch_identity_map()\`: Use \`SearchAllIamPolicies\` to get a complete map of who has what access.
    *   \`fetch_compute_inventory()\`: Get all VMs, Disks, and databases.
5.  **Storage**: Save these raw snapshots to \`backend/data/cai_snapshots/{scan_id}/\` as \`topology.json\`, \`iam.json\`, etc.

### Phase 2: The "Security Agent" (Analysis Engine)
We will create a specialized AI flow that acts as a **Solutions Architect**.

1.  **Prompt Engineering**: Create system prompts for specific domains.
    *   *Network Architect Prompt*: "Analyze this VPC topology. Identify hub-spoke violations, public database exposure, and lack of subnet isolation."
    *   *Identity Architect Prompt*: "Analyze this IAM map. Identify separation of duty violations, over-privileged default accounts, and non-rotatable keys."
2.  **Context Window Management**:
    *   CAI data can be large. We will summarize the JSON (removing non-essential fields like \`etag\`, \`createTime\`) before sending it to Gemini.
3.  **Output Format**: The Agent will return structured JSON:
    \`\`\`json
    {
      "architectural_finding": "Flat Network Topology",
      "severity": "HIGH",
      "description": "All resources are in a single 'default' VPC network.",
      "recommendation": "Migrate to a Hub-and-Spoke topology with a Shared VPC for better isolation."
    }
    \`\`\`

### Phase 3: Reporting & UI
A new section in the report called **"Architectural Review"**.

1.  **Frontend**: Create a new tab/page \`Architectural Review\`.
2.  **Visualization**: Use the CAI data to (optionally) render a visual graph of the network.
3.  **Strategic vs. Tactical**:
    *   *Existing Scanner*: Shows "Firewall rule 123 is bad." (Tactical)
    *   *New Agent*: Shows "Your network design is fundamentally insecure." (Strategic)

---

## ⚠️ Requirements & Challenges

1.  **Latency**: CAI data is usually "eventually consistent" (a few minutes lag), but \`SearchAll\` APIs are near real-time.
2.  **Permissions**: The user must explicitly grant \`cloudasset.viewer\`. We need to handle the "Permission Denied" error gracefully if they haven't enabled it.
3.  **Cost**: CAI is free for basic usage, but AI token costs will increase slightly (though negligible for typical use cases).

## ✅ Success Criteria
*   [ ] Scanner can fetch full IAM policy for a project in < 2 seconds.
*   [ ] AI Agent successfully identifies a "Flat Network" design flaw from the JSON dump.
*   [ ] Recommendations are stored and retained in the Scan History.
`
  }
};
