/**
 * Setup Wizard Component
 * Automatically creates bootstrap service account
 */
'use client';

import { useState } from 'react';
import { Loader2, CheckCircle2, AlertCircle, Download, Copy, Shield } from 'lucide-react';
import { getFirebaseIdToken } from '@/lib/firebase-auth';
import { getGCPAccessToken } from '@/lib/gcp-oauth-browser';

interface SetupWizardProps {
  projectId: string;
  onComplete: () => void;
  onCancel: () => void;
}

export default function SetupWizard({ projectId, onComplete, onCancel }: SetupWizardProps) {
  const [step, setStep] = useState<'intro' | 'creating' | 'success' | 'error'>('intro');
  const [serviceAccountKey, setServiceAccountKey] = useState<any>(null);
  const [serviceAccountEmail, setServiceAccountEmail] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [instructions, setInstructions] = useState<string>('');

  const handleSetup = async () => {
    setStep('creating');
    setError('');

    try {
      // Get both tokens
      const [firebaseToken, gcpToken] = await Promise.all([
        getFirebaseIdToken(),
        getGCPAccessToken().catch(() => ''), // Optional
      ]);

      const combinedToken = gcpToken ? `${firebaseToken}|${gcpToken}` : firebaseToken;

      // Call setup API
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
      const response = await fetch(`${backendUrl}/api/v1/setup/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          project_id: projectId,
          access_token: combinedToken,
        }),
      });

      if (!response.ok) {
        let errorData;
        try {
          errorData = await response.json();
        } catch {
          const text = await response.text();
          throw new Error(`Setup failed: ${response.status} ${response.statusText}. ${text}`);
        }

        // Format the error message nicely (preserve newlines)
        const errorMessage = errorData.detail || errorData.message || 'Setup failed';
        throw new Error(errorMessage);
      }

      const data = await response.json();

      setServiceAccountKey(data.service_account_key);
      setServiceAccountEmail(data.service_account_email);
      setInstructions(data.instructions);
      setStep('success');
    } catch (err: any) {
      setError(err.message || 'Setup failed');
      setStep('error');
    }
  };

  const handleDownloadKey = () => {
    if (!serviceAccountKey) return;

    const blob = new Blob([JSON.stringify(serviceAccountKey, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bootstrap-service-account.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyKey = () => {
    if (!serviceAccountKey) return;
    navigator.clipboard.writeText(JSON.stringify(serviceAccountKey, null, 2));
    alert('Service account key copied to clipboard!');
  };

  if (step === 'intro') {
    return (
      <div className="p-6 bg-white border border-gray-200 rounded-lg">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-primary-600" />
          <div>
            <h2 className="text-xl font-semibold text-gray-900">
              Initial Setup Required
            </h2>
            <p className="text-sm text-gray-600">
              We need to create a bootstrap service account to get started
            </p>
          </div>
        </div>

        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <p className="text-sm text-blue-900">
            <strong>What we'll do:</strong>
          </p>
          <ul className="mt-2 text-sm text-blue-800 list-disc list-inside space-y-1">
            <li>Use your organization admin account to create a service account</li>
            <li>Grant it the necessary permissions</li>
            <li>Create and download the key file</li>
            <li>Configure your backend automatically</li>
          </ul>
        </div>

        <div className="flex gap-3">
          <button
            onClick={handleSetup}
            className="flex-1 px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors"
          >
            Start Setup
          </button>
          <button
            onClick={onCancel}
            className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (step === 'creating') {
    return (
      <div className="p-6 bg-white border border-gray-200 rounded-lg">
        <div className="flex items-center gap-3">
          <Loader2 className="w-6 h-6 text-primary-600 animate-spin" />
          <div>
            <h2 className="text-xl font-semibold text-gray-900">
              Setting Up...
            </h2>
            <p className="text-sm text-gray-600">
              Creating bootstrap service account and configuring permissions
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (step === 'success') {
    return (
      <div className="p-6 bg-white border border-gray-200 rounded-lg">
        <div className="flex items-center gap-3 mb-4">
          <CheckCircle2 className="w-6 h-6 text-green-600" />
          <div>
            <h2 className="text-xl font-semibold text-gray-900">
              Setup Complete!
            </h2>
            <p className="text-sm text-gray-600">
              Bootstrap service account created: {serviceAccountEmail}
            </p>
          </div>
        </div>

        <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
          <p className="text-sm text-green-900 whitespace-pre-line">
            {instructions}
          </p>
        </div>

        <div className="mb-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <p className="text-sm text-blue-900 font-semibold mb-2">
            ⚠️ Important: Restart Required
          </p>
          <p className="text-sm text-blue-800">
            The backend has been automatically configured. Please restart your backend server now:
          </p>
          <div className="mt-3 p-3 bg-white border border-blue-200 rounded font-mono text-xs text-gray-800">
            <div className="mb-1"># Stop the backend (Ctrl+C if running)</div>
            <div className="mb-1">cd backend</div>
            <div className="mb-1">source venv/bin/activate</div>
            <div>uvicorn app.main:app --reload</div>
          </div>
        </div>

        <div className="mb-4">
          <details className="border border-gray-200 rounded-lg">
            <summary className="p-3 cursor-pointer text-sm font-medium text-gray-700 hover:bg-gray-50">
              View Service Account Key (Optional - for backup)
            </summary>
            <div className="p-4 border-t border-gray-200">
              <div className="flex gap-2 mb-2">
                <button
                  onClick={handleDownloadKey}
                  className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Download Key
                </button>
                <button
                  onClick={handleCopyKey}
                  className="flex items-center gap-2 px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors"
                >
                  <Copy className="w-4 h-4" />
                  Copy Key
                </button>
              </div>
              <textarea
                readOnly
                value={JSON.stringify(serviceAccountKey, null, 2)}
                className="w-full h-48 p-3 border border-gray-300 rounded-lg font-mono text-xs bg-gray-50"
              />
            </div>
          </details>
        </div>

        <button
          onClick={onComplete}
          className="w-full px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors"
        >
          Continue
        </button>
      </div>
    );
  }

  if (step === 'error') {
    return (
      <div className="p-6 bg-white border border-red-200 rounded-lg">
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="w-6 h-6 text-red-600" />
          <div>
            <h2 className="text-xl font-semibold text-red-900">
              Setup Failed
            </h2>
            <p className="text-sm text-red-700">{error}</p>
          </div>
        </div>

        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-sm text-red-900 font-semibold mb-2">
            Error Details:
          </p>
          <pre className="text-xs text-red-800 whitespace-pre-wrap bg-red-100 p-3 rounded border border-red-200 mb-3">
            {error}
          </pre>
          <p className="text-sm text-red-900 font-semibold mb-2">
            Possible solutions:
          </p>
          <ul className="mt-2 text-sm text-red-800 list-disc list-inside space-y-1">
            <li>Ensure you're signed in with an organization admin account</li>
            <li>Check that you have permissions to create service accounts</li>
            <li>Try running: <code className="bg-red-100 px-1 rounded">gcloud auth application-default login</code></li>
            <li>Or set up a service account manually (see BOOTSTRAP_SERVICE_ACCOUNT.md)</li>
            <li>Or configure Google OAuth Client ID in frontend/.env.local</li>
          </ul>
        </div>

        <div className="flex gap-3">
          <button
            onClick={handleSetup}
            className="flex-1 px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors"
          >
            Try Again
          </button>
          <button
            onClick={onCancel}
            className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  return null;
}

