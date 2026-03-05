/**
 * Lockdown Progress Component
 * Shows step-by-step progress of security lockdown
 */
'use client';

import { LockdownResponse, BackoutRequest, downloadBackoutScript, uploadCredentials } from '@/lib/api';
import { CheckCircle, XCircle, Loader2, Shield, RotateCcw, Download } from 'lucide-react';

interface LockdownProgressProps {
  response: LockdownResponse;
  onBackout?: () => void;
  showBackout?: boolean;
  projectId: string;
  serviceAccountCredentials?: any;
}

export default function LockdownProgress({
  response,
  onBackout,
  showBackout = false,
  projectId,
  serviceAccountCredentials
}: LockdownProgressProps) {
  const handleDownloadBackoutScript = async () => {
    if (!serviceAccountCredentials) {
      alert('Service account credentials are required to generate backout script');
      return;
    }

    try {
      // Upload credentials and get secure token
      console.log('[LockdownProgress] Uploading credentials for backout script...');
      const { credential_token } = await uploadCredentials(serviceAccountCredentials);

      const request: BackoutRequest = {
        project_id: projectId,
        access_token: '',
        credential_token, // Use secure token
        confirm_backout: false, // Just for script generation
      };
      await downloadBackoutScript(request);
    } catch (error: any) {
      alert(`Failed to download backout script: ${error.message || 'Unknown error'}`);
    }
  };
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-6 h-6 text-green-600" />;
      case 'failed':
        return <XCircle className="w-6 h-6 text-red-600" />;
      case 'in_progress':
        return <Loader2 className="w-6 h-6 text-blue-600 animate-spin" />;
      default:
        return <Loader2 className="w-6 h-6 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-8 h-8 text-primary-600" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Security Lockdown Complete</h2>
            <p className="text-gray-600">We've applied security settings to protect your cloud.</p>
          </div>
        </div>

        <div className="mt-6 space-y-4">
          {response.steps.map((step, index) => (
            <div
              key={step.step_id}
              className={`p-4 border-2 rounded-lg ${step.status === 'completed'
                ? 'border-green-200 bg-green-50'
                : step.status === 'failed'
                  ? 'border-red-200 bg-red-50'
                  : 'border-gray-200 bg-gray-50'
                }`}
            >
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">{getStatusIcon(step.status)}</div>
                <div className="flex-1">
                  <div className="font-semibold text-gray-900 mb-1">{step.name}</div>
                  <div className="text-sm text-gray-700 mb-2">{step.description}</div>

                  {/* Detailed Execution Logs */}
                  {step.details && Object.keys(step.details).length > 0 && (
                    <div className="mt-3 bg-white bg-opacity-60 rounded p-3 text-sm font-mono border border-gray-200">
                      <div className="font-semibold text-gray-700 mb-2 border-b border-gray-200 pb-1">Execution Details:</div>
                      {Object.entries(step.details).map(([key, value]) => {
                        // Skip internal keys if any
                        if (!value) return null;

                        // Format key for display (e.g., "disabled_apis" -> "Disabled Apis")
                        const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

                        if (Array.isArray(value)) {
                          if (value.length === 0) return null;
                          return (
                            <div key={key} className="mb-2">
                              <span className="font-semibold text-gray-600">{label}:</span>
                              <ul className="list-disc list-inside pl-2 mt-1 text-xs">
                                {value.map((item, i) => (
                                  <li key={i} className="break-all">{String(item)}</li>
                                ))}
                              </ul>
                            </div>
                          );
                        } else if (typeof value === 'object') {
                          return (
                            <div key={key} className="mb-2">
                              <span className="font-semibold text-gray-600">{label}:</span>
                              <pre className="text-xs mt-1 overflow-x-auto">{JSON.stringify(value, null, 2)}</pre>
                            </div>
                          );
                        } else {
                          return (
                            <div key={key} className="mb-1">
                              <span className="font-semibold text-gray-600">{label}:</span> <span className="text-gray-800">{String(value)}</span>
                            </div>
                          );
                        }
                      })}
                    </div>
                  )}

                  {step.security_benefit && (
                    <div className="text-xs text-gray-600 italic mt-2">
                      Why this helps: {step.security_benefit}
                    </div>
                  )}
                  {step.error && (
                    <div className="mt-2 text-sm text-red-700 font-bold">
                      Error: {step.error}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 p-4 bg-gray-50 rounded-lg">
          <div className="text-sm font-semibold text-gray-900 mb-2">Summary:</div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <div className="text-gray-600">Completed</div>
              <div className="text-2xl font-bold text-green-600">{response.summary.completed}</div>
            </div>
            <div>
              <div className="text-gray-600">Failed</div>
              <div className="text-2xl font-bold text-red-600">{response.summary.failed}</div>
            </div>
            <div>
              <div className="text-gray-600">Total</div>
              <div className="text-2xl font-bold text-gray-900">{response.summary.total}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Executive Report Button */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border-2 border-blue-200 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900 mb-1">Executive Report</h3>
            <p className="text-sm text-gray-600">
              Generate a professional report with success metrics, visualizations, and detailed changes for stakeholders.
            </p>
          </div>
          <button
            onClick={() => window.dispatchEvent(new CustomEvent('showExecutiveReport'))}
            className="px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transition-all transform hover:scale-105 flex items-center gap-3"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            View Executive Report
          </button>
        </div>
      </div>

      {response.errors.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="font-semibold text-red-900 mb-2">Errors:</div>
          <ul className="list-disc list-inside text-sm text-red-700 space-y-1">
            {response.errors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </div>
      )}

      {showBackout && onBackout && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="mb-4">
            <h3 className="text-xl font-bold text-gray-900 mb-2">Need to Rollback Changes?</h3>
            <p className="text-gray-600 mb-4">
              If the security changes are too aggressive or causing issues, you can rollback all changes.
              This will remove all security protections that were just applied.
            </p>
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 mb-4">
              <div className="flex items-start gap-2">
                <XCircle className="w-5 h-5 text-orange-600 mt-0.5" />
                <div className="text-sm text-orange-800">
                  <strong>Warning:</strong> Rolling back will remove all security protections and make your project vulnerable again.
                </div>
              </div>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleDownloadBackoutScript}
              className="flex-1 px-6 py-3 bg-gray-600 text-white rounded-lg font-medium hover:bg-gray-700 transition-colors flex items-center justify-center gap-2"
            >
              <Download className="w-5 h-5" />
              Download Backout Script
            </button>
            <button
              onClick={onBackout}
              className="flex-1 px-6 py-3 bg-orange-600 text-white rounded-lg font-medium hover:bg-orange-700 transition-colors flex items-center justify-center gap-2"
            >
              <RotateCcw className="w-5 h-5" />
              Rollback All Changes
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

