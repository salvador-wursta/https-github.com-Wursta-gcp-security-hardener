# GCP Security Hardener

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

## 🏗️ Architecture

### Frontend
- **Framework:** Next.js 14 (App Router)
- **Styling:** Tailwind CSS
- **Icons:** Lucide React
- **Authentication:** Firebase Authentication (Google Provider)
- **Hosting:** Firebase Hosting

### Backend
- **Framework:** FastAPI (Python 3.11+)
- **Validation:** Pydantic
- **GCP Integration:** Google Cloud Client Libraries
- **Hosting:** Cloud Run

## 📁 Project Structure

```
gcp-security-hardener/
├── frontend/                 # Next.js application
│   ├── app/                  # App Router pages
│   ├── components/           # React components
│   ├── lib/                  # Utility functions
│   ├── public/              # Static assets
│   └── package.json
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── main.py          # FastAPI app entry point
│   │   ├── models/          # Pydantic models
│   │   └── services/        # GCP service integrations
│   └── requirements.txt
└── README.md
```

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ and npm
- Python 3.11+
- Google Cloud Platform account
- Firebase project

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at `http://localhost:3000`

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend API will be available at `http://localhost:8000`

## 🔐 Security Principles

1. **Least Privilege:** Temporary Service Accounts use minimum required roles
2. **Tenant Isolation:** Firestore paths use `Users/{UserID}/...` for data separation
3. **Encryption:** Sensitive data (Auth Tokens) are never logged to console
4. **Secure by Design:** All security constraints are applied automatically

## 🔐 Required Permissions (Least Privilege)

The application uses two distinct Service Accounts to maintain security separation:

### 1. Scanner Account (Read-Only)
Used for discovering risks. It **CANNOT** make changes.
- **Project Level:**
  - `roles/viewer`
  - `roles/iam.securityReviewer`
  - `roles/billing.viewer`
- **Organization Level (if applicable):**
  - `roles/resourcemanager.organizationViewer`
  - `roles/securitycenter.assetsViewer`
  - `roles/securitycenter.findingsViewer`
  - `roles/serviceusage.serviceUsageViewer`

### 2. Admin Account (Remediation)
Used only when you click "Apply Fixes".
- **Project Level:**
  - `roles/editor`
  - `roles/iam.securityAdmin`
  - `roles/monitoring.admin`
- **Organization Level (if applicable):**
  - `roles/securitycenter.admin` (for configuring SCC)
  - `roles/orgpolicy.policyAdmin`

## 📋 Phase 2 Implementation Status

- [x] Step 1: Project structure and dependencies
- [x] Step 2: JIT Credential Access (Zero-Trust)
- [x] Step 3: Deep Scan (Backend Logic for Network, IAM, Billing, SCC)
- [x] Step 4: Modular Dashboard (Frontend)
- [ ] Step 5: Automated Remediation

## 📝 License

Proprietary - All rights reserved

