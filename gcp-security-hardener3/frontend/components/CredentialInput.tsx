/**
 * Credential Input Component
 * Supports TWO authentication methods:
 * 1. Service Account JSON (traditional method)
 * 2. Google Workspace Superadmin username/password (JIT privilege escalation)
 */
'use client';

import { useState, useEffect } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle2, Eye, EyeOff, KeyRound, Shield } from 'lucide-react';

interface CredentialInputProps {
  onCredentialsProvided: (credentials: any) => void;
  onCancel: () => void;
}

type AuthMode = 'service-account' | 'superadmin';

export default function CredentialInput({ onCredentialsProvided, onCancel }: CredentialInputProps) {
  const [authMode, setAuthMode] = useState<AuthMode>('superadmin'); // JIT only - service account method removed for security

  // Service Account fields
  const [credentialJson, setCredentialJson] = useState<string>('');
  const [showJson, setShowJson] = useState<boolean>(true);

  // Superadmin fields
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [orgId, setOrgId] = useState<string>('');

  // Common fields
  const [error, setError] = useState<string>('');
  const [isValidating, setIsValidating] = useState<boolean>(false);

  useEffect(() => {
    console.log('[CredentialInput] Component mounted');
  }, []);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.json')) {
      setError('Please upload a JSON file');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string;
        const json = JSON.parse(content);
        setCredentialJson(content);
        setError('');
      } catch (err) {
        setError('Invalid JSON file. Please check the file format.');
      }
    };
    reader.readAsText(file);
  };

  const validateServiceAccount = () => {
    try {
      if (!credentialJson.trim()) {
        setError('Please provide service account credentials');
        return false;
      }

      const credentials = JSON.parse(credentialJson);

      if (!credentials.type || credentials.type !== 'service_account') {
        setError('This does not appear to be a service account key. Expected type: "service_account"');
        return false;
      }

      if (!credentials.project_id) {
        setError('Service account key is missing project_id');
        return false;
      }

      if (!credentials.private_key || !credentials.client_email) {
        setError('Service account key is missing required fields (private_key or client_email)');
        return false;
      }

      return credentials;
    } catch (err: any) {
      setError(`Invalid JSON: ${err.message}`);
      return false;
    }
  };

  const validateSuperadmin = () => {
    // For JIT dual-service-account mode, we're reusing username/password fields
    // username = scanner JSON content
    // password = admin JSON content

    if (!username.trim()) {
      setError('Please upload Scanner Account JSON file');
      return false;
    }

    if (!password.trim()) {
      setError('Please upload Admin Account JSON file');
      return false;
    }

    try {
      const scannerCreds = JSON.parse(username);
      const adminCreds = JSON.parse(password);

      // Validate both are service accounts
      if (scannerCreds.type !== 'service_account' || adminCreds.type !== 'service_account') {
        setError('Both files must be service account JSON files');
        return false;
      }

      return {
        auth_type: 'dual-service-account',
        scanner_credentials: scannerCreds,
        admin_credentials: adminCreds
      };
    } catch (err) {
      setError('Invalid JSON file format. Please upload valid service account keys.');
      return false;
    }
  };

  const handleSubmit = () => {
    setError('');
    setIsValidating(true);

    setTimeout(() => {
      let credentials;

      if (authMode === 'service-account') {
        credentials = validateServiceAccount();
      } else {
        credentials = validateSuperadmin();
      }

      if (credentials) {
        setIsValidating(false);
        onCredentialsProvided(credentials);
      } else {
        setIsValidating(false);
      }
    }, 100);
  };

  return (
    <div className="p-6 bg-white border border-gray-200 rounded-lg">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <Shield className="w-6 h-6 text-primary-600" />
        <div>
          <h2 className="text-xl font-semibold text-gray-900">
            Enter Service Account Credentials
          </h2>
          <p className="text-sm text-gray-600">
            Provide JIT service account credentials for secure authentication
          </p>
        </div>
      </div>


      {/* Error Display */}
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-red-600" />
            <p className="text-sm text-red-900">{error}</p>
          </div>
        </div>
      )}

      {/* JIT Setup Instructions & Upload */}
      {authMode === 'superadmin' && (
        <div className="space-y-4">
          <div className="p-4 bg-blue-50 border-2 border-blue-200 rounded-lg">
            <div className="flex items-start gap-3">
              <Shield className="w-6 h-6 text-blue-600 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="font-semibold text-blue-900 mb-2">
                  Secure JIT Authentication
                </h3>
                <p className="text-sm text-blue-700 mb-3">
                  Using dual service account method: Scanner (read-only) + Admin (lockdown execution)
                </p>
                <div className="bg-white/60 rounded border border-blue-200 p-3">
                  <p className="text-sm text-blue-800 font-medium mb-1">JIT Privilege Escalation Setup</p>
                  <p className="text-sm text-blue-700">
                    For maximum security, create two service accounts with different permission levels.
                    This script grants ALL required permissions including org-wide access for scanning and billing.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Cloud Shell Instructions */}
          <div className="border border-gray-200 rounded-lg p-4 bg-white">
            <h4 className="font-medium text-gray-900 mb-3">📋 Quick Setup (30 seconds)</h4>

            <ol className="space-y-3 text-sm">
              <li className="flex gap-2">
                <span className="font-bold text-blue-600 min-w-[20px]">1.</span>
                <div>
                  <p className="font-medium">Open Google Cloud Shell</p>
                  <p className="text-gray-600">Go to <a href="https://console.cloud.google.com" target="_blank" className="text-blue-600 underline">console.cloud.google.com</a> → Click <code className="bg-gray-100 px-1 rounded">{'>'}_</code> icon (top right)</p>
                </div>
              </li>

              <li className="flex gap-2">
                <span className="font-bold text-blue-600 min-w-[20px]">2.</span>
                <div className="w-full">
                  <p className="font-medium">Copy and paste this script</p>
                  <details className="mt-2">
                    <summary className="cursor-pointer text-blue-600 hover:text-blue-800 text-sm font-medium">
                      Click to show script →
                    </summary>
                    <div className="mt-2 bg-gray-900 text-green-400 p-3 rounded font-mono text-xs overflow-x-auto max-h-64">
                      <pre>{`#!/bin/bash
# GCP Security Hardener - JIT Service Account Setup
# SIMPLIFIED VERSION - Copy/paste this entire script into Cloud Shell

set -e  # Exit on error

echo "=================================================="
echo "GCP Security Hardener - JIT Setup"
echo "=================================================="
echo ""

# Get project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: No project selected"
    echo ""
    echo "Please run this first:"
    echo "  gcloud config set project YOUR_PROJECT_ID"
    echo ""
    exit 1
fi

echo "✓ Project: \${PROJECT_ID}"
echo ""

# Create scanner service account (minimal permissions)
echo "[1/6] Creating scanner service account..."
if gcloud iam service-accounts describe gcp-hardener-scanner@\${PROJECT_ID}.iam.gserviceaccount.com --project=\${PROJECT_ID} >/dev/null 2>&1; then
    echo "   (already exists, skipping)"
else
    gcloud iam service-accounts create gcp-hardener-scanner \\
        --display-name="GCP Security Hardener - Scanner" \\
        --description="Read-only access for scanning GCP resources" \\
        --project=\${PROJECT_ID}
fi

SCANNER_EMAIL="gcp-hardener-scanner@\${PROJECT_ID}.iam.gserviceaccount.com"
echo "   ✓ Scanner: \${SCANNER_EMAIL}"

# Create admin service account (full permissions)
echo "[2/6] Creating admin service account..."
if gcloud iam service-accounts describe gcp-hardener-admin@\${PROJECT_ID}.iam.gserviceaccount.com --project=\${PROJECT_ID} >/dev/null 2>&1; then
    echo "   (already exists, skipping)"
else
    gcloud iam service-accounts create gcp-hardener-admin \\
        --display-name="GCP Security Hardener - Admin" \\
        --description="Administrative access for applying security hardening" \\
        --project=\${PROJECT_ID}
fi

ADMIN_EMAIL="gcp-hardener-admin@\${PROJECT_ID}.iam.gserviceaccount.com"
echo "   ✓ Admin: \${ADMIN_EMAIL}"

# Assign scanner roles (view-only)
echo "[3/6] Assigning scanner permissions (read-only)..."
gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${SCANNER_EMAIL}" \\
    --role="roles/viewer" \\
    --condition=None \\
    --quiet 2>/dev/null || true

gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${SCANNER_EMAIL}" \\
    --role="roles/iam.securityReviewer" \\
    --condition=None \\
    --quiet 2>/dev/null || true

echo "   ✓ Scanner roles assigned"

# Assign admin roles (full access)
echo "[4/6] Assigning admin permissions..."
gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${ADMIN_EMAIL}" \\
    --role="roles/editor" \\
    --condition=None \\
    --quiet 2>/dev/null || true

gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${ADMIN_EMAIL}" \\
    --role="roles/iam.securityAdmin" \\
    --condition=None \\
    --quiet 2>/dev/null || true

# Add Service Usage Admin for API enablement/disablement on Host Project
gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${ADMIN_EMAIL}" \\
    --role="roles/serviceusage.serviceUsageAdmin" \\
    --condition=None \\
    --quiet 2>/dev/null || true

# Add Logging Config Writer for creating log buckets and metrics (org monitoring)
gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${ADMIN_EMAIL}" \\
    --role="roles/logging.configWriter" \\
    --condition=None \\
    --quiet 2>/dev/null || true

# Add Monitoring Admin for creating notification channels and alert policies
gcloud projects add-iam-policy-binding \${PROJECT_ID} \\
    --member="serviceAccount:\${ADMIN_EMAIL}" \\
    --role="roles/monitoring.admin" \\
    --condition=None \\
    --quiet 2>/dev/null || true

echo "   ✓ Admin roles assigned on Host Project (\${PROJECT_ID})"

# --------------------------------------------------------------------------------
# ORGANIZATION LEVEL PERMISSIONS (Crucial for Multi-Project Hardening)
# --------------------------------------------------------------------------------
echo ""
echo "[4.5/6] Checking for Organization Level permissions..."
ORG_ID=$(gcloud projects describe \${PROJECT_ID} --format="value(parent.id)" 2>/dev/null)

if [ -n "$ORG_ID" ]; then
    echo "   Detected Organization ID: $ORG_ID"
    echo "   Granting Organization-level Admin permissions..."
    echo "   (This handles cross-project access automatically)"

    # --- SCANNER PERMISSIONS (Read-Only) ---
    echo "   -> Granting Scanner visibility..."
    # Organization Viewer - Required to list all projects in the org
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${SCANNER_EMAIL}" \\
        --role="roles/resourcemanager.organizationViewer" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Org Viewer to Scanner"
    
    # Folder Viewer - listing projects in folders
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${SCANNER_EMAIL}" \\
        --role="roles/resourcemanager.folderViewer" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Folder Viewer to Scanner"

    # Browser - Access to browse resources hierarchy
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${SCANNER_EMAIL}" \\
        --role="roles/browser" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Browser role to Scanner"

    # Service Usage Viewer - Required to list enabled APIs on all projects
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${SCANNER_EMAIL}" \\
        --role="roles/serviceusage.serviceUsageViewer" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Service Usage Viewer to Scanner"

    # Security Reviewer - Required to view IAM policies on all projects
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${SCANNER_EMAIL}" \\
        --role="roles/iam.securityReviewer" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Security Reviewer to Scanner"
    
    # Compute Viewer - Required to scan VM instances and quotas
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${SCANNER_EMAIL}" \\
        --role="roles/compute.viewer" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Compute Viewer to Scanner"

    # --- ADMIN PERMISSIONS (Full Access) ---
    echo "   -> Granting Admin permissions..."
    
    # Browser - Admin also needs to see the hierarchy
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${ADMIN_EMAIL}" \\
        --role="roles/browser" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Browser role to Admin"
    
    # Org Policy Admin - Required to set constraints on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${ADMIN_EMAIL}" \\
        --role="roles/orgpolicy.policyAdmin" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Org Policy Admin (You might not be an Org Admin)"

    # Service Usage Admin - Required to disable APIs on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${ADMIN_EMAIL}" \\
        --role="roles/serviceusage.serviceUsageAdmin" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Service Usage Admin at Org level"

    # Compute Network Admin - Required for firewall rules on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${ADMIN_EMAIL}" \\
        --role="roles/compute.networkAdmin" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Network Admin at Org level"

    # Security Admin - Required to modify IAM policies on any project
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${ADMIN_EMAIL}" \\
        --role="roles/iam.securityAdmin" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Security Admin at Org level"

    # Logging Config Writer - Required for org-level aggregated log sinks
    gcloud organizations add-iam-policy-binding $ORG_ID \\
        --member="serviceAccount:\${ADMIN_EMAIL}" \\
        --role="roles/logging.configWriter" \\
        --condition=None \\
        --quiet 2>/dev/null || echo "   ⚠️  Could not grant Logging Config Writer at Org level"
        
    echo "   ✓ Organization roles attempt complete"
else
    echo "   ⚠️  No Organization ID found (Project might be standalone)"
    echo "   NOTE: For multi-project hardening, you MUST manually grant this Service Account access to target projects."
fi

# --------------------------------------------------------------------------------
# PRE-FLIGHT: DISABLE KEY CREATION RESTRICTIONS
# --------------------------------------------------------------------------------
echo ""
echo "[5/7] Ensuring key creation is allowed..."
gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyCreation --project=\${PROJECT_ID} --quiet 2>/dev/null || echo "   (Note: Could not disable key creation restriction. If key creation fails, this policy is likely the cause.)"

# Create and download scanner key
echo "[6/7] Creating scanner key..."
echo "   (Waiting 10s for IAM propagation...)"
sleep 10
rm -f scanner-key.json
gcloud iam service-accounts keys create scanner-key.json \\
    --iam-account=\${SCANNER_EMAIL} \\
    --project=\${PROJECT_ID}

if [ ! -s scanner-key.json ]; then
    echo "❌ Error: scanner-key.json is empty. Service Account might not exist or quota exceeded."
    read -p "Press Enter to exit..." wait_input
    exit 1
fi
echo "   ✓ scanner-key.json created"

# Create and download admin key
echo "[6/7] Creating admin key..."
echo "   (Waiting 5s...)"
sleep 5
rm -f admin-key.json
gcloud iam service-accounts keys create admin-key.json \\
    --iam-account=\${ADMIN_EMAIL} \\
    --project=\${PROJECT_ID}

if [ ! -s admin-key.json ]; then
    echo "❌ Error: admin-key.json is empty."
    read -p "Press Enter to exit..." wait_input
    exit 1
fi
echo "   ✓ admin-key.json created"

# Enable required APIs in scanner's project
echo ""
echo "[7/7] Enabling required APIs in scanner's project..."
echo "   (This allows the scanner to list projects and access billing)"
gcloud services enable cloudresourcemanager.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable serviceusage.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable billingbudgets.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable cloudbilling.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable recommender.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable orgpolicy.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable compute.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable logging.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable monitoring.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
gcloud services enable pubsub.googleapis.com --project=\${PROJECT_ID} 2>/dev/null || true
echo "   ✓ All required APIs enabled"

echo ""
echo "=================================================="
echo "✅ Setup Complete!"
echo "=================================================="
echo ""
echo "Two JSON key files have been created:"
echo "  📄 scanner-key.json  (read-only access)"
echo "  📄 admin-key.json    (admin access, time-limited)"
echo ""
echo "📥 DOWNLOAD THESE FILES:"
echo "  1. Click the ⋮ menu (top right of Cloud Shell)"
echo "  2. Select 'Download file'"
echo "  3. Type: scanner-key.json  (press Enter)"
echo "  4. Type: admin-key.json    (press Enter)"
echo ""
echo "🔒 KEEP SECURE:"
echo "  • These files grant access to your GCP project"
echo "  • Never commit them to version control"
echo "  • Store them like passwords"
echo ""
echo "▶️  NEXT STEP:"
echo "  Upload both files to GCP Security Hardener app"
echo ""

read -p "Press [Enter] to exit setup..." wait_input
`}</pre>
                    </div>
                  </details>
                  <p className="text-gray-600 mt-2 text-xs">Copy entire script → Paste in Cloud Shell → Press Enter</p>

                  <div className="mt-3 p-2 bg-blue-50 border border-blue-200 rounded">
                    <p className="text-blue-900 font-semibold text-xs mb-1">✓ Verify files were created:</p>
                    <code className="text-xs bg-gray-800 text-green-400 px-2 py-1 rounded block">ls -lh *.json</code>
                    <p className="text-blue-800 text-xs mt-1">Should show two non-empty files (~2.3KB each)</p>
                  </div>
                </div>
              </li>

              <li className="flex gap-2">
                <span className="font-bold text-blue-600 min-w-[20px]">3.</span>
                <div>
                  <p className="font-medium">Download the JSON keys</p>
                  <div className="mt-2 space-y-2 text-xs">
                    <div className="p-2 bg-orange-50 border border-orange-200 rounded">
                      <p className="text-orange-900 font-semibold">⚠️ If script showed "Error creating key":</p>
                      <p className="text-orange-800">Use Option B below (create keys manually)</p>
                    </div>

                    <p className="text-gray-700 font-medium mt-3">Option A: Download from Cloud Shell</p>
                    <p className="text-gray-600">Only if script succeeded - no errors shown</p>
                    <ol className="list-decimal list-inside space-y-1 text-gray-600 ml-2">
                      <li>In Cloud Shell, click ⋮ menu (top right)</li>
                      <li>Download file → Type: scanner-key.json</li>
                      <li>Download file → Type: admin-key.json</li>
                    </ol>

                    <p className="text-gray-700 font-medium mt-3">Option B: Create keys via GCP Console</p>
                    <p className="text-gray-600">Use this if you saw "Error creating key"</p>
                    <ol className="list-decimal list-inside space-y-1 text-gray-600 ml-2">
                      <li>Open: <a href="https://console.cloud.google.com/iam-admin/serviceaccounts" target="_blank" className="text-blue-600 underline">IAM & Admin → Service Accounts</a></li>
                      <li>Click <code className="bg-gray-100 px-1">gcp-hardener-scanner</code></li>
                      <li>Click "Keys" tab</li>
                      <li>Add Key → Create new key → JSON → Create</li>
                      <li>File downloads as JSON - rename to <code className="bg-gray-100 px-1">scanner-key.json</code></li>
                      <li>Go back, click <code className="bg-gray-100 px-1">gcp-hardener-admin</code></li>
                      <li>Repeat steps 3-5, rename to <code className="bg-gray-100 px-1">admin-key.json</code></li>
                    </ol>
                  </div>
                </div>
              </li>

              <li className="flex gap-2">
                <span className="font-bold text-blue-600 min-w-[20px]">4.</span>
                <div>
                  <p className="font-medium">Upload below</p>
                  <p className="text-gray-600">Upload both scanner-key.json and admin-key.json</p>
                </div>
              </li>
            </ol>
          </div>

          {/* Scanner Account Upload */}
          <div className="border border-blue-200 bg-blue-50 rounded-lg p-4">
            <label className="block text-sm font-medium text-gray-900 mb-2">
              <Eye className="w-4 h-4 inline mr-1" />
              Scanner Account (Read-Only)
            </label>
            <p className="text-xs text-gray-600 mb-2">This account is used for safe scanning operations</p>
            <input
              type="file"
              accept=".json"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  const reader = new FileReader();
                  reader.onload = (ev) => {
                    try {
                      const content = ev.target?.result as string;
                      JSON.parse(content); // Validate
                      setUsername(content); // Reusing field for scanner JSON
                      setError('');
                    } catch {
                      setError('Invalid JSON file for scanner account');
                    }
                  };
                  reader.readAsText(file);
                }
              }}
              className="block w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-white focus:outline-none"
            />
            {username && (
              <p className="text-xs text-green-600 mt-1">✓ Scanner account loaded</p>
            )}
          </div>

          {/* Admin Account Upload */}
          <div className="border border-orange-200 bg-orange-50 rounded-lg p-4">
            <label className="block text-sm font-medium text-gray-900 mb-2">
              <Shield className="w-4 h-4 inline mr-1" />
              Admin Account (Full Access - Time-Limited)
            </label>
            <p className="text-xs text-gray-600 mb-2">This account is used only during 5-minute lockdown windows</p>
            <input
              type="file"
              accept=".json"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  const reader = new FileReader();
                  reader.onload = (ev) => {
                    try {
                      const content = ev.target?.result as string;
                      JSON.parse(content); // Validate
                      setPassword(content); // Reusing field for admin JSON
                      setError('');
                    } catch {
                      setError('Invalid JSON file for admin account');
                    }
                  };
                  reader.readAsText(file);
                }
              }}
              className="block w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-white focus:outline-none"
            />
            {password && (
              <p className="text-xs text-green-600 mt-1">✓ Admin account loaded</p>
            )}
          </div>

          {/* Security Info */}
          <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-xs text-yellow-900">
              <strong>🔒 Security Model:</strong> App uses Scanner (read-only) by default.
              Admin credentials activate only for 5-minute windows during lockdown operations,
              then automatically revert to Scanner.
            </p>
          </div>
        </div>
      )}

      {/* Service Account JSON Form */}
      {authMode === 'service-account' && (
        <div className="space-y-4">
          <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <p className="text-sm text-blue-900">
              <strong>What you need:</strong>
            </p>
            <ul className="mt-2 text-sm text-blue-800 list-disc list-inside space-y-1">
              <li>A service account key JSON file with required roles</li>
              <li>Or a service account with full permissions for scan and lockdown</li>
            </ul>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Upload Service Account Key (JSON file)
            </label>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors cursor-pointer">
                <Upload className="w-4 h-4" />
                Choose File
                <input
                  type="file"
                  accept=".json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
              <span className="text-sm text-gray-600">
                {credentialJson ? '✓ File loaded' : 'No file selected'}
              </span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-gray-700">
                Or Paste Service Account Key JSON
              </label>
              <button
                onClick={() => setShowJson(!showJson)}
                className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-900"
              >
                {showJson ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                {showJson ? 'Hide' : 'Show'} JSON
              </button>
            </div>
            <textarea
              value={credentialJson}
              onChange={(e) => {
                setCredentialJson(e.target.value);
                setError('');
              }}
              placeholder='Paste your service account key JSON here...'
              className={`w-full h-48 p-3 border ${error ? 'border-red-300' : 'border-gray-300'} rounded-lg font-mono text-xs bg-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent`}
              style={{ fontFamily: 'monospace', resize: 'vertical' }}
            />
          </div>

          <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-xs text-yellow-900">
              <strong>🔒 Security:</strong> JSON credentials are transmitted securely and used only for GCP API calls.
            </p>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex justify-end gap-3 mt-6">
        <button
          onClick={onCancel}
          className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={isValidating || (authMode === 'service-account' && !credentialJson.trim()) || (authMode === 'superadmin' && (!username || !password))}
          className="px-8 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center gap-2 min-w-[200px]"
        >
          {isValidating ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Validating...
            </>
          ) : (
            <>
              <CheckCircle2 className="w-4 h-4" />
              {authMode === 'superadmin' ? 'Use JIT Accounts' : 'Use These Credentials'}
            </>
          )}
        </button>
      </div>
    </div>
  );
}
