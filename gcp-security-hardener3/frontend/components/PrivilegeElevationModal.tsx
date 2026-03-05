/**
 * PrivilegeElevationModal Component
 * Modal shown when privileges are elevated with proceed button
 */
'use client';

import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, XCircle, Loader2, Shield } from 'lucide-react';
import PrivilegeTimer from './PrivilegeTimer';

interface PrivilegeElevationModalProps {
    open: boolean;
    timerId: string;
    expiresAt: string;
    serviceAccountEmail: string;
    onProceed: () => void;
    onCancel: () => void;
}

interface TestResult {
    testName: string;
    success: boolean;
    error?: string;
}

export default function PrivilegeElevationModal({
    open,
    timerId,
    expiresAt,
    serviceAccountEmail,
    onProceed,
    onCancel
}: PrivilegeElevationModalProps) {
    const [testing, setTesting] = useState(true);
    const [testResults, setTestResults] = useState<TestResult[]>([]);
    const [allTestsPassed, setAllTestsPassed] = useState(false);

    useEffect(() => {
        if (open) {
            // Simulate privilege testing
            setTesting(true);

            const tests: TestResult[] = [
                { testName: 'Create organization policies', success: true },
                { testName: 'Create billing budgets', success: true },
                { testName: 'Manage firewall rules', success: true },
                { testName: 'Create log sinks', success: true },
                { testName: 'Modify IAM policies', success: true }
            ];

            // Simulate async testing
            let currentIndex = 0;
            const interval = setInterval(() => {
                if (currentIndex < tests.length) {
                    setTestResults(prev => [...prev, tests[currentIndex]]);
                    currentIndex++;
                } else {
                    clearInterval(interval);
                    setTesting(false);
                    setAllTestsPassed(tests.every(t => t.success));
                }
            }, 300);

            return () => clearInterval(interval);
        } else {
            setTestResults([]);
            setTesting(true);
            setAllTestsPassed(false);
        }
    }, [open]);

    if (!open) return null;

    const failedTests = testResults.filter(t => !t.success);

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
            <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-hidden">
                {/* Header */}
                <div className="p-6 border-b bg-orange-50">
                    <div className="flex items-center gap-3 mb-4">
                        <div className="p-2 bg-orange-100 rounded-full">
                            <Shield className="w-6 h-6 text-orange-600" />
                        </div>
                        <div>
                            <h2 className="text-xl font-semibold text-gray-900">
                                Privileges Elevated
                            </h2>
                            <p className="text-sm text-gray-600">
                                Service Account: <code className="text-xs bg-white px-2 py-1 rounded">{serviceAccountEmail}</code>
                            </p>
                        </div>
                    </div>

                    {/* Timer */}
                    <PrivilegeTimer expiresAt={expiresAt} />
                </div>

                {/* Content */}
                <div className="p-6 overflow-y-auto max-h-[calc(90vh-300px)]">
                    {/* Warning */}
                    <div className="flex gap-3 p-4 bg-yellow-50 border border-yellow-200 rounded-lg mb-6">
                        <AlertTriangle className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
                        <div className="text-sm text-yellow-900">
                            <p className="font-medium mb-1">This escalation will last for 5 minutes</p>
                            <p>
                                After 5 minutes, privileges will automatically revert to read-only access.
                                Make sure your lockdown operations complete within this time window.
                            </p>
                        </div>
                    </div>

                    {/* Testing Status */}
                    <div className="space-y-4">
                        <h3 className="font-medium text-gray-900">Testing Privileges...</h3>

                        {testResults.map((result, index) => (
                            <div key={index} className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                                {result.success ? (
                                    <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
                                ) : (
                                    <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                                )}
                                <div className="flex-1">
                                    <span className="text-sm text-gray-900">{result.testName}</span>
                                    {result.error && (
                                        <p className="text-xs text-red-600 mt-1">{result.error}</p>
                                    )}
                                </div>
                            </div>
                        ))}

                        {testing && (
                            <div className="flex items-center gap-3 p-3">
                                <Loader2 className="w-5 h-5 text-blue-600 animate-spin" />
                                <span className="text-sm text-gray-600">Running tests...</span>
                            </div>
                        )}
                    </div>

                    {/* Error Report */}
                    {!testing && failedTests.length > 0 && (
                        <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                            <h4 className="font-medium text-red-900 mb-2">Missing Permissions</h4>
                            <ul className="text-sm text-red-800 space-y-1">
                                {failedTests.map((test, index) => (
                                    <li key={index}>• {test.testName}: {test.error}</li>
                                ))}
                            </ul>
                            <p className="text-sm text-red-700 mt-3">
                                Contact your administrator to grant these permissions before proceeding.
                            </p>
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="p-6 border-t bg-gray-50 flex gap-3 justify-end">
                    <button
                        onClick={onCancel}
                        className="px-6 py-2 border border-gray-300 rounded hover:bg-gray-100"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={onProceed}
                        disabled={testing || !allTestsPassed}
                        className={`px-6 py-2 rounded font-medium ${testing || !allTestsPassed
                                ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                                : 'bg-blue-600 text-white hover:bg-blue-700'
                            }`}
                    >
                        {testing ? 'Testing...' : 'Proceed with Lockdown'}
                    </button>
                </div>
            </div>
        </div>
    );
}
