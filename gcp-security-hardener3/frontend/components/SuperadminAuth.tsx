/**
 * SuperadminAuth Component
 * Google Workspace superadmin OAuth flow
 */
'use client';

import React, { useState } from 'react';
import { KeyRound, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

interface SuperadminAuthProps {
    onAuthComplete: (result: {
        serviceAccountEmail: string;
        orgId: string;
    }) => void;
}

export default function SuperadminAuth({ onAuthComplete }: SuperadminAuthProps) {
    const [orgId, setOrgId] = useState('');
    const [authenticating, setAuthenticating] = useState(false);
    const [error, setError] = useState('');
    const [step, setStep] = useState<'input' | 'authenticating' | 'creating' | 'complete'>('input');

    const handleAuthenticate = async () => {
        if (!orgId.trim()) {
            setError('Please enter your Organization ID');
            return;
        }

        setError('');
        setStep('authenticating');
        setAuthenticating(true);

        try {
            // In production, this would initiate OAuth flow
            // For now, simulating the process

            // Step 1: OAuth authentication
            await new Promise(resolve => setTimeout(resolve, 1500));

            setStep('creating');

            // Step 2: Create service account
            await new Promise(resolve => setTimeout(resolve, 1500));

            setStep('complete');
            setAuthenticating(false);

            // Notify parent
            onAuthComplete({
                serviceAccountEmail: `svc-lockdown-tmp@org-${orgId}-admin.iam.gserviceaccount.com`,
                orgId: orgId
            });

        } catch (err) {
            setError('Authentication failed. Please try again.');
            setStep('input');
            setAuthenticating(false);
        }
    };

    const getStepIcon = () => {
        if (step === 'complete') return <CheckCircle className="w-6 h-6 text-green-600" />;
        if (error) return <AlertCircle className="w-6 h-6 text-red-600" />;
        if (authenticating) return <Loader2 className="w-6 h-6 text-blue-600 animate-spin" />;
        return <KeyRound className="w-6 h-6 text-gray-400" />;
    };

    const getStepMessage = () => {
        switch (step) {
            case 'authenticating':
                return 'Authenticating with Google Workspace...';
            case 'creating':
                return 'Creating temporary service account...';
            case 'complete':
                return 'Authentication successful!';
            default:
                return 'Enter your Google Workspace Organization ID';
        }
    };

    return (
        <div className="max-w-md mx-auto">
            <div className="bg-white rounded-lg border shadow-sm p-6">
                {/* Header */}
                <div className="flex items-center gap-3 mb-6">
                    {getStepIcon()}
                    <div>
                        <h3 className="font-semibold text-gray-900">Superadmin Authentication</h3>
                        <p className="text-sm text-gray-600">{getStepMessage()}</p>
                    </div>
                </div>

                {step === 'input' && (
                    <>
                        {/* Organization ID Input */}
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Organization ID
                                </label>
                                <input
                                    type="text"
                                    value={orgId}
                                    onChange={(e) => setOrgId(e.target.value)}
                                    placeholder="123456789012"
                                    className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                    disabled={authenticating}
                                />
                                <p className="text-xs text-gray-500 mt-1">
                                    Find this in Google Cloud Console → IAM & Admin → Settings
                                </p>
                            </div>

                            {error && (
                                <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
                                    <p className="text-sm text-red-800">{error}</p>
                                </div>
                            )}

                            <button
                                onClick={handleAuthenticate}
                                disabled={authenticating || !orgId.trim()}
                                className={`w-full py-2 px-4 rounded-lg font-medium ${authenticating || !orgId.trim()
                                        ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                                        : 'bg-blue-600 text-white hover:bg-blue-700'
                                    }`}
                            >
                                {authenticating ? 'Authenticating...' : 'Authenticate with Google Workspace'}
                            </button>
                        </div>

                        {/* Info Box */}
                        <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                            <p className="text-sm text-blue-900">
                                <strong>What happens next:</strong>
                            </p>
                            <ol className="text-sm text-blue-800 mt-2 space-y-1 list-decimal list-inside">
                                <li>You'll authorize with Google Workspace superadmin</li>
                                <li>A temporary service account will be created</li>
                                <li>You'll select which projects to scan</li>
                                <li>View-only permissions will be granted automatically</li>
                            </ol>
                        </div>
                    </>
                )}

                {(step === 'authenticating' || step === 'creating') && (
                    <div className="text-center py-8">
                        <Loader2 className="w-12 h-12 text-blue-600 animate-spin mx-auto mb-4" />
                        <p className="text-gray-600">{getStepMessage()}</p>
                    </div>
                )}

                {step === 'complete' && (
                    <div className="text-center py-8">
                        <CheckCircle className="w-16 h-16 text-green-600 mx-auto mb-4" />
                        <p className="text-lg font-medium text-gray-900 mb-2">All Set!</p>
                        <p className="text-gray-600">Proceeding to project selection...</p>
                    </div>
                )}
            </div>
        </div>
    );
}
