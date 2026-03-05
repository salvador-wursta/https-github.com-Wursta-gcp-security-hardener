'use client';
import React, { useState, useRef } from 'react';
import ActionBtn from './ActionBtn';

interface JITSetupModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSessionStarted: (token: string) => void;
}

export default function JITSetupModal({ isOpen, onClose, onSessionStarted }: JITSetupModalProps) {
    const [step, setStep] = useState<1 | 2>(1); // 1: Instructions, 2: Upload
    const [scannerFile, setScannerFile] = useState<File | null>(null);
    const [adminFile, setAdminFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [skipAdmin, setSkipAdmin] = useState(false);

    if (!isOpen) return null;

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, type: 'scanner' | 'admin') => {
        if (e.target.files && e.target.files[0]) {
            if (type === 'scanner') setScannerFile(e.target.files[0]);
            else setAdminFile(e.target.files[0]);
        }
    };

    const handleStartSession = async () => {
        if (!scannerFile) {
            setError("Scanner key file is required.");
            return;
        }

        if (!skipAdmin && !adminFile) {
            setError("Please upload the Admin key or select 'Skip for now'.");
            return;
        }

        try {
            setLoading(true);
            setError(null);

            // Read files as text
            const scannerContent = await scannerFile.text();

            // Only read admin file if processed
            let adminContent = null;
            if (adminFile && !skipAdmin) {
                adminContent = await adminFile.text();
            }

            // Send to backend
            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
            console.log(`[DEBUG] Initiating session start at: ${backendUrl}/api/v1/session/start`);

            const response = await fetch(`${backendUrl}/api/v1/session/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scanner_key_content: scannerContent,
                    admin_key_content: adminContent
                })
            });

            console.log(`[DEBUG] Response status: ${response.status} ${response.statusText}`);

            if (!response.ok) {
                const data = await response.json();
                console.error(`[DEBUG] Session start failed:`, data);
                throw new Error(data.detail || "Failed to start session");
            }

            const { token } = await response.json();
            console.log(`[DEBUG] Session started successfully. Token: ${token.substring(0, 8)}...`);
            onSessionStarted(token);
            onClose();

        } catch (err: any) {
            console.error(`[DEBUG] Fetch error:`, err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden flex flex-col max-h-[90vh]">
                {/* Header */}
                <div className="bg-gray-50 px-6 py-4 border-b border-gray-100 flex justify-between items-center">
                    <h3 className="text-lg font-bold text-gray-800">
                        {step === 1 ? "Step 1: Setup Project & JIT Accounts" : "Step 2: Start Secure Session"}
                    </h3>
                    <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
                        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                </div>

                {/* Content */}
                <div className="p-6 overflow-y-auto">
                    {error && (
                        <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                            {error}
                        </div>
                    )}

                    {step === 1 ? (
                        <div className="space-y-4">
                            <div className="p-4 bg-blue-50 border-2 border-blue-200 rounded-lg">
                                <div className="flex items-start gap-3">
                                    <div className="p-2 bg-blue-100 rounded-full shrink-0">
                                        <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                                    </div>
                                    <div>
                                        <h4 className="font-semibold text-blue-900">Secure JIT Authentication</h4>
                                        <p className="text-sm text-blue-700 mt-1">
                                            This app uses a zero-trust model with two transient service accounts:
                                            <span className="font-medium"> Scanner (Read-Only)</span> and
                                            <span className="font-medium"> Admin (Lockdown)</span>.
                                            Keys are held in memory and valid only for this session.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div className="border border-gray-200 rounded-lg p-4 bg-white">
                                <h4 className="font-medium text-gray-900 mb-3">📋 Quick Setup (30 seconds)</h4>

                                <ol className="space-y-4 text-sm">
                                    <li className="flex gap-3">
                                        <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-full bg-blue-100 text-blue-600 font-bold text-xs border border-blue-200">1</span>
                                        <div>
                                            <p className="font-medium text-gray-900">Prepare a Safety Project (Recommended)</p>
                                            <p className="text-gray-600 mt-0.5 text-xs">
                                                Create a fresh project named <code className="bg-gray-100 border border-gray-300 rounded px-1 text-gray-800">gcp-security-hardener-host</code> to isolate this scanner from your production data.
                                            </p>
                                        </div>
                                    </li>

                                    <li className="flex gap-3">
                                        <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-full bg-blue-100 text-blue-600 font-bold text-xs border border-blue-200">2</span>
                                        <div>
                                            <p className="font-medium text-gray-900">Open Cloud Shell</p>
                                            <p className="text-gray-600 mt-0.5 text-xs">
                                                Go to <a href="https://console.cloud.google.com" target="_blank" rel="noopener noreferrer" className="text-blue-600 underline hover:text-blue-800">console.cloud.google.com</a>
                                                <span className="mx-1">→</span>
                                                Click the <code className="bg-gray-100 px-1.5 py-0.5 rounded text-gray-800 border border-gray-200 font-mono text-xs">{'>'}_</code> icon.
                                            </p>
                                        </div>
                                    </li>

                                    <li className="flex gap-3">
                                        <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-full bg-blue-100 text-blue-600 font-bold text-xs border border-blue-200">3</span>
                                        <div className="w-full min-w-0">
                                            <p className="font-medium text-gray-900">Run Setup Script (Creates Project + Accounts)</p>
                                            <p className="text-gray-600 text-xs mt-0.5 mb-2">
                                                Paste this script into Cloud Shell. It will help you create a SAFE environment (new project) and generate the keys.
                                            </p>

                                            <div className="relative group">
                                                <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                    <button
                                                        onClick={() => {
                                                            navigator.clipboard.writeText(`#!/bin/bash
# GCP Security Hardener - JIT Service Account Setup
set -e

echo "=================================================="
echo "GCP Security Hardener - JIT Setup"
echo "=================================================="
echo ""

# --- STEP 0: Project Safety Check ---
# Ensure we are in a safe environment or ask user to create one
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)
echo "Current Project: $CURRENT_PROJECT"
echo "⚠️  IMPORTANT: It is recommended to create a NEW project for this scanner."
echo "   Example: gcloud projects create gcp-security-scanner-host"
echo "   Then:    gcloud config set project gcp-security-scanner-host"
echo ""
read -p "Are you sure you want to create accounts in '$CURRENT_PROJECT'? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Get project ID
PROJECT_ID=$CURRENT_PROJECT

# 1. Enable APIs (Critical Step)
echo "[1/4] Enabling required APIs..."
APIS="serviceusage.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com recommender.googleapis.com orgpolicy.googleapis.com compute.googleapis.com logging.googleapis.com monitoring.googleapis.com pubsub.googleapis.com cloudasset.googleapis.com apikeys.googleapis.com securitycenter.googleapis.com ids.googleapis.com"

for api in \${APIS}; do
  echo "   Enabling \${api}..."
  gcloud services enable "\${api}" --project="\${PROJECT_ID}" --quiet || echo "   ⚠️  Failed to enable \${api} (Proceeding...)"
done

# 2. Create Scanner SA
echo ""
echo "[2/4] Creating Scanner account..."
if ! gcloud iam service-accounts describe gcp-hardener-scanner@\${PROJECT_ID}.iam.gserviceaccount.com --project=\${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create gcp-hardener-scanner --display-name="GCP Hardener Scanner" --project=\${PROJECT_ID} --quiet
fi
SCANNER_EMAIL="gcp-hardener-scanner@\${PROJECT_ID}.iam.gserviceaccount.com"

# 3. Create Admin SA
echo ""
echo "[3/4] Creating Admin account..."
if ! gcloud iam service-accounts describe gcp-hardener-admin@\${PROJECT_ID}.iam.gserviceaccount.com --project=\${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create gcp-hardener-admin --display-name="GCP Hardener Admin" --project=\${PROJECT_ID} --quiet
fi
ADMIN_EMAIL="gcp-hardener-admin@\${PROJECT_ID}.iam.gserviceaccount.com"

# 4. Grant Permissions
echo ""
echo "[4/4] Granting permissions..."
# Scanner: Viewer + Security Reviewer
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/viewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/iam.securityReviewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/cloudasset.viewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/serviceusage.serviceUsageConsumer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/serviceusage.apiKeysViewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/securitycenter.findingsViewer" --quiet >/dev/null

# Admin Roles
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/editor" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/iam.securityAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/serviceusage.serviceUsageAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/serviceusage.apiKeysAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/logging.configWriter" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/monitoring.admin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/compute.securityAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/cloudasset.owner" --quiet >/dev/null

# 5. Create Keys
echo ""
echo "Generating keys..."
rm -f scanner-key.json admin-key.json
gcloud iam service-accounts keys create scanner-key.json --iam-account=\${SCANNER_EMAIL} --project=\${PROJECT_ID} --quiet
gcloud iam service-accounts keys create admin-key.json --iam-account=\${ADMIN_EMAIL} --project=\${PROJECT_ID} --quiet

echo ""
echo "✅ Setup Complete!"
echo "Download the files:"
echo "cloudshell download scanner-key.json admin-key.json"`).then(() => alert("Script copied to clipboard!"));
                                                        }}
                                                        className="bg-white text-gray-800 px-3 py-1 rounded shadow text-xs font-medium hover:bg-gray-50 border border-gray-200"
                                                    >
                                                        Copy Script
                                                    </button>
                                                </div>
                                                <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-xs overflow-x-auto whitespace-pre h-64 border border-gray-700 custom-scrollbar">
                                                    {`#!/bin/bash
# GCP Security Hardener - JIT Service Account Setup
# This script creates service accounts, enables required APIs, and assigns permissions.
set -e

echo "=================================================="
echo "GCP Security Hardener - JIT Setup"
echo "=================================================="
echo ""

# Get project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: No project selected"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "✓ Project: \${PROJECT_ID}"

# 1. Enable APIs (Critical Step)
echo "[1/4] Enabling required APIs..."
APIS="serviceusage.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com recommender.googleapis.com orgpolicy.googleapis.com compute.googleapis.com logging.googleapis.com monitoring.googleapis.com pubsub.googleapis.com cloudasset.googleapis.com apikeys.googleapis.com securitycenter.googleapis.com ids.googleapis.com"

for api in \${APIS}; do
  echo "   Enabling \${api}..."
  gcloud services enable "\${api}" --project="\${PROJECT_ID}" --quiet || echo "   ⚠️  Failed to enable \${api} (Proceeding...)"
done

# 2. Create Scanner SA
echo ""
echo "[2/4] Creating Scanner account..."
if ! gcloud iam service-accounts describe gcp-hardener-scanner@\${PROJECT_ID}.iam.gserviceaccount.com --project=\${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create gcp-hardener-scanner --display-name="GCP Hardener Scanner" --project=\${PROJECT_ID} --quiet
fi
SCANNER_EMAIL="gcp-hardener-scanner@\${PROJECT_ID}.iam.gserviceaccount.com"

# 3. Create Admin SA
echo ""
echo "[3/4] Creating Admin account..."
if ! gcloud iam service-accounts describe gcp-hardener-admin@\${PROJECT_ID}.iam.gserviceaccount.com --project=\${PROJECT_ID} >/dev/null 2>&1; then
    gcloud iam service-accounts create gcp-hardener-admin --display-name="GCP Hardener Admin" --project=\${PROJECT_ID} --quiet
fi
ADMIN_EMAIL="gcp-hardener-admin@\${PROJECT_ID}.iam.gserviceaccount.com"

# 4. Grant Permissions
echo ""
echo "[4/4] Granting permissions..."
# Scanner Roles
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/viewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/iam.securityReviewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/cloudasset.viewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/serviceusage.serviceUsageConsumer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/serviceusage.apiKeysViewer" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${SCANNER_EMAIL}" --role="roles/securitycenter.findingsViewer" --quiet >/dev/null

# Admin Roles
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/editor" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/iam.securityAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/serviceusage.serviceUsageAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/serviceusage.apiKeysAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/logging.configWriter" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/monitoring.admin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/compute.securityAdmin" --quiet >/dev/null
gcloud projects add-iam-policy-binding \${PROJECT_ID} --member="serviceAccount:\${ADMIN_EMAIL}" --role="roles/cloudasset.owner" --quiet >/dev/null

# 5. Create Keys
echo ""
echo "Generating keys..."
rm -f scanner-key.json admin-key.json
gcloud iam service-accounts keys create scanner-key.json --iam-account=\${SCANNER_EMAIL} --project=\${PROJECT_ID} --quiet
gcloud iam service-accounts keys create admin-key.json --iam-account=\${ADMIN_EMAIL} --project=\${PROJECT_ID} --quiet

echo ""
echo "✅ Setup Complete!"
echo "Download the files:"
echo "cloudshell download scanner-key.json admin-key.json"`}
                                                </pre>
                                            </div>
                                        </div>
                                    </li>

                                    <li className="flex gap-3">
                                        <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-full bg-blue-100 text-blue-600 font-bold text-xs border border-blue-200">4</span>
                                        <div>
                                            <p className="font-medium text-gray-900">Download Keys & Upload</p>
                                            <p className="text-gray-600 text-xs mt-0.5">
                                                The script will prompt you to download the keys. Once downloaded, click <b>Next</b> to upload them here.
                                            </p>
                                        </div>
                                    </li>
                                </ol>
                            </div>
                        </div>
                    ) : (
                        <div className="space-y-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {/* Scanner Upload */}
                                <div className={`border-2 border-dashed rounded-xl p-6 text-center transition-colors ${scannerFile ? 'border-green-300 bg-green-50' : 'border-gray-300 hover:border-blue-400'}`}>
                                    <div className="mb-3 flex justify-center">
                                        {scannerFile ? (
                                            <svg className="w-10 h-10 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                                        ) : (
                                            <svg className="w-10 h-10 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                                        )}
                                    </div>
                                    <h4 className="font-semibold text-gray-900">Scanner Key (Required)</h4>
                                    <p className="text-xs text-gray-500 mb-4">{scannerFile ? scannerFile.name : "Role: Viewer + Security Reviewer"}</p>
                                    <input
                                        type="file"
                                        accept=".json"
                                        onChange={(e) => handleFileChange(e, 'scanner')}
                                        className="hidden"
                                        id="scanner-upload"
                                    />
                                    <label htmlFor="scanner-upload" className="cursor-pointer text-sm text-blue-600 hover:underline">
                                        {scannerFile ? "Change file" : "Select scanner-key.json"}
                                    </label>
                                </div>

                                {/* Admin Upload */}
                                <div className={`border-2 border-dashed rounded-xl p-6 text-center transition-colors relative ${skipAdmin ? 'border-gray-200 bg-gray-50 opacity-50' : adminFile ? 'border-green-300 bg-green-50' : 'border-gray-300 hover:border-blue-400'}`}>
                                    {skipAdmin && <div className="absolute inset-0 z-10 cursor-not-allowed" />}
                                    <div className="mb-3 flex justify-center">
                                        <svg className="w-10 h-10 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                                    </div>
                                    <h4 className="font-semibold text-gray-900">Admin Key (Optional)</h4>
                                    <p className="text-xs text-gray-500 mb-4">{adminFile ? adminFile.name : "Role: Editor + Security Admin"}</p>
                                    <input
                                        type="file"
                                        accept=".json"
                                        onChange={(e) => handleFileChange(e, 'admin')}
                                        className="hidden"
                                        id="admin-upload"
                                        disabled={skipAdmin}
                                    />
                                    <label htmlFor="admin-upload" className={`cursor-pointer text-sm ${skipAdmin ? 'text-gray-400' : 'text-blue-600 hover:underline'}`}>
                                        {adminFile ? "Change file" : "Select admin-key.json"}
                                    </label>
                                </div>
                            </div>

                            {/* Skip Checkbox */}
                            <div className="flex justify-end">
                                <label className="flex items-center gap-2 cursor-pointer text-sm text-gray-600 select-none">
                                    <input
                                        type="checkbox"
                                        checked={skipAdmin}
                                        onChange={(e) => setSkipAdmin(e.target.checked)}
                                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                    />
                                    Skip Admin Key (Scan only mode)
                                </label>
                            </div>
                            {skipAdmin && (
                                <div className="bg-yellow-50 border border-yellow-200 p-3 rounded-lg text-xs text-yellow-800">
                                    ⚠️ Without the Admin key, you will be able to <strong>scan</strong> and view risks, but you cannot apply automatic fixes or generate remediation scripts.
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="bg-gray-50 px-6 py-4 border-t border-gray-100 flex justify-end gap-3">
                    {step === 2 && (
                        <ActionBtn variant="ghost" onClick={() => setStep(1)}>
                            Back
                        </ActionBtn>
                    )}
                    {step === 1 ? (
                        <ActionBtn onClick={() => setStep(2)}>
                            Next: Upload Keys
                        </ActionBtn>
                    ) : (
                        <ActionBtn
                            onClick={handleStartSession}
                            disabled={!scannerFile || (!skipAdmin && !adminFile)}
                            loading={loading}
                        >
                            Start Secure Session
                        </ActionBtn>
                    )}
                </div>
            </div>
        </div>
    );
}
