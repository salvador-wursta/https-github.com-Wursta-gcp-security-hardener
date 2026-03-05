'use client';

import { useState, useEffect, useRef, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import DefaultLayout from '@/components/coreui/DefaultLayout';
import OnboardingModal from '@/components/OnboardingModal';
import FinOpsModule from '@/components/modules/FinOpsModule';
import { useClient } from '@/context/ClientContext';
import { Loader2 } from 'lucide-react';

function SecurePageContent() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const { clientData } = useClient();

    // Params
    const finopsConcern = searchParams.get('finops') === 'true';
    const region = searchParams.get('region');
    const email = searchParams.get('email');

    // State
    const [showJitModal, setShowJitModal] = useState(false);
    const [jitToken, setJitToken] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [projectId, setProjectId] = useState<string>('');
    const [scanResults, setScanResults] = useState<any[]>([]);
    const [error, setError] = useState<string | null>(null);

    // prevent double scan
    const scanInitiated = useRef(false);

    useEffect(() => {
        // On mount, if no JIT token, prompt user
        if (!jitToken) {
            setShowJitModal(true);
        }
    }, [jitToken]);

    const handleVerified = (resourceId: string, scope: 'project' | 'organization') => {
        setJitToken(''); // Empty for ADC
        setShowJitModal(false);
        // For organization, runTargetedScan handles discovery within that org
        if (scope === 'organization') {
            runTargetedScan('', undefined, resourceId);
        } else {
            runTargetedScan('', resourceId);
        }
    };

    const handleSessionStarted = (token: string) => {
        setJitToken(token);
        setShowJitModal(false);
        runTargetedScan(token);
    };

    const runTargetedScan = async (token: string, forcedPid?: string, organizationId?: string) => {
        if (scanInitiated.current) return;
        scanInitiated.current = true;

        setLoading(true);
        setError(null);

        const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';

        try {
            let pid = forcedPid || '';

            if (!pid) {
                // Discover Project
                const projectResp = await fetch(`${backendUrl}/api/v1/projects/list`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        jit_token: token || null,
                        access_token: "",
                        organization_id: organizationId || null
                    })
                });

                const projectData = await projectResp.json();
                if (projectData.projects && projectData.projects.length > 0) {
                    pid = projectData.projects[0].project_id;
                }
            }

            if (!pid) throw new Error("Could not identify target project.");
            setProjectId(pid);

            // 2. Run Scan
            const modules = [];
            if (finopsConcern) modules.push('finops');
            modules.push('billing', 'iam', 'monitoring');

            const scanResp = await fetch(`${backendUrl}/api/v1/scan/multi`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    project_ids: [pid],
                    jit_token: token || null,
                    scan_modules: modules,
                    access_token: ""
                })
            });

            if (!scanResp.ok) throw new Error("Scan failed");

            const data = await scanResp.json();
            if (data.scans) {
                setScanResults(data.scans);
            }

        } catch (e: any) {
            console.error(e);
            setError(e.message || "Failed to secure environment.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <DefaultLayout
            jitActive={!!jitToken}
            onUploadClick={() => setShowJitModal(true)}
        >
            <OnboardingModal
                isOpen={showJitModal}
                onClose={() => { }}
                onVerified={handleVerified}
                initialSaEmail={jitToken}
            />

            <div className="max-w-6xl mx-auto py-8">
                <h1 className="text-3xl font-bold text-gray-900 mb-2">Automated Security Lockdown</h1>
                <p className="text-gray-600 mb-8">
                    Based on your answers, we are scanning and preparing remediation for **{projectId || 'your project'}**.
                </p>

                {loading ? (
                    <div className="flex flex-col items-center justify-center p-20 bg-white rounded-lg border border-gray-200">
                        <Loader2 className="w-12 h-12 text-blue-600 animate-spin mb-4" />
                        <h3 className="text-xl font-semibold text-gray-900">Scanning GCP Environment...</h3>
                        <p className="text-gray-500"> analyzing billing, IAM, and realtime alerts.</p>
                    </div>
                ) : error ? (
                    <div className="p-6 bg-red-50 text-red-800 rounded-lg">
                        <h3 className="font-bold">Error</h3>
                        <p>{error}</p>
                        <button onClick={() => window.location.reload()} className="mt-4 px-4 py-2 bg-red-100 rounded hover:bg-red-200">Retry</button>
                    </div>
                ) : (
                    <div className="space-y-8">
                        {/* Only show FinOps module if data exists */}
                        {scanResults.length > 0 ? (
                            <FinOpsModule
                                risks={scanResults[0].risks}
                                projectId={scanResults[0].project_id}
                                jitToken={jitToken!}
                            />
                        ) : (
                            <div className="p-12 text-center bg-gray-50 rounded-lg border border-gray-200">
                                <h3 className="text-xl font-semibold text-gray-800 mb-2">No Risks Detected</h3>
                                <p className="text-gray-600">Great news! Our scan didn't find any immediate FinOps or Security risks matching your criteria.</p>
                                <p className="text-sm text-gray-500 mt-4">Project ID: {projectId}</p>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </DefaultLayout>
    );
}

export default function SecurePage() {
    return (
        <Suspense fallback={
            <DefaultLayout>
                <div className="flex items-center justify-center min-h-[50vh]">
                    <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
                </div>
            </DefaultLayout>
        }>
            <SecurePageContent />
        </Suspense>
    );
}
