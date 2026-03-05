'use client';

import React, { useState, useEffect } from 'react';
import { Shield, Copy, Download, CheckCircle2, AlertCircle, Loader2, Layout, Building } from 'lucide-react';
import ActionBtn from './ActionBtn';

// ─── Backend URL resolution ──────────────────────────────────────────────────
// Use same-origin Next.js proxy routes (/api/*) to avoid CORS entirely.
// No hardcoded localhost port needed — the proxy routes forward server-side.

interface OnboardingModalProps {
    isOpen: boolean;
    onClose: () => void;
    onVerified: (resourceId: string, scope: 'project' | 'organization', saEmail: string) => void;
    /** Optional: pass an already-resolved SA email (e.g. from session/start) */
    initialSaEmail?: string | null;
}

export default function OnboardingModal({
    isOpen,
    onClose,
    onVerified,
    initialSaEmail,
}: OnboardingModalProps) {
    const [scope, setScope] = useState<'project' | 'organization'>('project');
    const [resourceId, setResourceId] = useState('');
    const [billingAccountId, setBillingAccountId] = useState('');

    // ── Identity state ───────────────────────────────────────────────────────
    const [saEmail, setSaEmail] = useState('');
    const [saPrefix, setSaPrefix] = useState('');
    const [identitySource, setIdentitySource] = useState('');
    const [hostCustomerId, setHostCustomerId] = useState('');
    const [loadingConfig, setLoadingConfig] = useState(true);

    // ── UX state ─────────────────────────────────────────────────────────────
    const [isVerifying, setIsVerifying] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [saCreatedSuccess, setSaCreatedSuccess] = useState(false);

    // ── Validation state ─────────────────────────────────────────────────────
    const [isValidating, setIsValidating] = useState(false);
    const [validationResults, setValidationResults] = useState<{ all_granted: boolean; roles: Record<string, boolean> } | null>(null);

    // ── 1. Fetch scanner identity on modal open ──────────────────────────────
    useEffect(() => {
        if (!isOpen) return;

        // If a session-specific SA was already resolved via sidebar, use it immediately.
        if (initialSaEmail) {
            setSaEmail(initialSaEmail);
            setIdentitySource('session');
            setLoadingConfig(false);
            return;
        }

        // Try to load cached SA from localStorage first
        const cachedSa = localStorage.getItem('scanner_sa_email');
        if (cachedSa) {
            setSaEmail(cachedSa);
            setIdentitySource('localStorage');
            setLoadingConfig(false);
            return;
        }

        setLoadingConfig(true);
        setSaEmail('');
        setIdentitySource('');

        // Same-origin proxy — no CORS
        fetch('/api/system-config', { signal: AbortSignal.timeout(8000) })
            .then((res) => {
                if (!res.ok) throw new Error(`Backend returned HTTP ${res.status}`);
                return res.json();
            })
            .then((data) => {
                const fetchedSa = data.service_account_email ?? 'unknown-identity';
                setSaEmail(fetchedSa);
                setIdentitySource(data.source ?? '');
                setHostCustomerId(data.host_customer_id ?? '');

                // Cache the backend-detected SA if it's usable
                if (fetchedSa && fetchedSa !== 'unknown-identity' && fetchedSa !== 'user-credentials-detected' && fetchedSa !== 'Backend Offline' && fetchedSa !== 'error-detecting-identity') {
                    localStorage.setItem('scanner_sa_email', fetchedSa);
                }
            })
            .catch((err) => {
                console.error('[OnboardingModal] identity fetch error:', err);
                setSaEmail('Backend Offline');
                setIdentitySource('error');
            })
            .finally(() => setLoadingConfig(false));
    }, [isOpen, initialSaEmail]);

    // Save custom SA inputs back into local storage
    const handleSaEmailChange = (val: string) => {
        setSaEmail(val);
        localStorage.setItem('scanner_sa_email', val);
        setIdentitySource('user-input');
    };


    // ── 2. gcloud command generators ─────────────────────────────────────────
    const target = resourceId || (scope === 'project' ? '[PROJECT_ID]' : '[ORG_ID]');
    const email = saEmail || '[SERVICE_ACCOUNT_EMAIL]';

    const getDisplayCommand = (): string => {
        const targetType = scope === 'project' ? 'projects' : 'organizations';
        const targetDesc = scope === 'project' ? 'Project' : 'Organization';
        // Extract host project from SA email e.g. scanner-x@HOST_PROJECT.iam.gserviceaccount.com
        const hostProject = email.includes('@') ? email.split('@')[1].replace('.iam.gserviceaccount.com', '') : '[HOST_PROJECT_ID]';

        return (
            `#!/bin/bash
# ${'═'.repeat(63)}
# GCP Security Scanner — ${targetDesc}-Level Access Setup
# Scanner SA : ${email}
# Target     : ${target}
# ${'═'.repeat(63)}

SA_EMAIL="${email}"
TARGET_ID="${target}"

echo "🔐 Granting Scanner SA read-only access to ${targetDesc} $TARGET_ID..."

gcloud ${targetType} add-iam-policy-binding "$TARGET_ID" \\
  --member="serviceAccount:$SA_EMAIL" \\
  --role="roles/browser"

gcloud ${targetType} add-iam-policy-binding "$TARGET_ID" \\
  --member="serviceAccount:$SA_EMAIL" \\
  --role="roles/iam.securityReviewer"

gcloud ${targetType} add-iam-policy-binding "$TARGET_ID" \\
  --member="serviceAccount:$SA_EMAIL" \\
  --role="roles/securitycenter.adminViewer"

gcloud ${targetType} add-iam-policy-binding "$TARGET_ID" \\
  --member="serviceAccount:$SA_EMAIL" \\
  --role="roles/iam.serviceAccountViewer"

echo "✅ Done! Scanner SA has read-only access to ${targetDesc.toLowerCase()} $TARGET_ID"

${billingAccountId ? `
echo "💰 Granting Scanner SA billing.viewer access directly on Billing Account ${billingAccountId}..."

gcloud beta billing accounts add-iam-policy-binding "${billingAccountId}" \\
  --member="serviceAccount:$SA_EMAIL" \\
  --role="roles/billing.viewer"

echo "✅ Done! Scanner SA has read-only access to Billing Account ${billingAccountId}"
` : ''}

${hostCustomerId ? `
echo "───────────────────────────────────────────────────────────────"
echo "⚠️ OPTIONAL: BYPASS DOMAIN RESTRICTED SHARING (If Needed)"
echo "If the commands above failed with an Org Policy constraint error,"
echo "you must temporarily allow the scanner's external identity."
echo "Run the command below FIRST, then re-run the script above."
echo ""
echo "gcloud resource-manager org-policies allow constraints/iam.allowedPolicyMemberDomains ${hostCustomerId} \\"
echo "  --${scope === 'project' ? 'project' : 'organization'}="$TARGET_ID""
echo "───────────────────────────────────────────────────────────────"
` : ''}
`
        );
    };

    const getSafeCommand = (): string => {
        return getDisplayCommand();
    };

    const handleCreateSa = async () => {
        let slug = saPrefix.trim();
        if (!slug) {
            setError('Please type a short name in the Scanner Name Prefix field first.');
            return;
        }

        // Clean just the prefix
        slug = slug.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        if (!slug) {
            setError('Invalid prefix name for SA. Use letters and numbers.');
            return;
        }

        try {
            setLoadingConfig(true);
            setError(null);
            // Use the Next.js proxy route to avoid CORS issues
            const res = await fetch('/api/session/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: slug })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Failed to create service account');

            handleSaEmailChange(data.sa_email);
            setIdentitySource('session');
            setSaCreatedSuccess(true);
            setTimeout(() => setSaCreatedSuccess(false), 5000); // Hide success message after 5s
        } catch (err: any) {
            setError(err.message || 'Failed to create SA');
        } finally {
            setLoadingConfig(false);
        }
    };

    // ── Handlers ──────────────────────────────────────────────────────────────
    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(getSafeCommand());
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy text: ', err);
            setError('Failed to copy command to clipboard');
        }
    };

    const handleDownload = () => {
        const target = resourceId || (scope === 'project' ? '[PROJECT_ID]' : '[ORG_ID]');
        const blob = new Blob([getSafeCommand()], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scanner-setup-${target}.sh`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const handleValidate = async (autoPollMs = 0) => {
        if (!saEmail || !resourceId) return;
        setIsValidating(true);
        setError(null);

        let attempts = 0;
        const maxAttempts = autoPollMs ? Math.ceil(autoPollMs / 5000) : 1;

        const tryValidate = async (): Promise<boolean> => {
            try {
                const res = await fetch(`/api/validate-permissions?sa_email=${encodeURIComponent(saEmail)}&target_id=${encodeURIComponent(resourceId)}&scope=${scope}`);
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Validation failed');

                setValidationResults(data);
                return data.all_granted === true;
            } catch (err: any) {
                setError(err.message);
                return false;
            }
        };

        try {
            let success = await tryValidate();
            while (!success && attempts < maxAttempts) {
                attempts++;
                await new Promise(r => setTimeout(r, 5000));
                success = await tryValidate();
            }
        } finally {
            setIsValidating(false);
        }
    };

    const handleVerify = async () => {
        try {
            setIsVerifying(true);
            setError(null);

            // 1. Activate backend session specifically for this SA and Target
            const activateRes = await fetch('/api/session/activate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sa_email: saEmail, target_id: resourceId, scope })
            });
            const activateData = await activateRes.json();
            if (!activateRes.ok) throw new Error(activateData.detail || 'Failed to activate scanner session');

            // 2. Persist the identity locally so it survives refreshes/restarts
            localStorage.setItem('scanner_sa_email', saEmail);

            // 3. Trigger parent callback to open scan page
            onVerified(resourceId, scope, saEmail);
            onClose();

        } catch (err: any) {
            setError(err.message ?? 'Failed to verify access. Ensure the command was run correctly.');
        } finally {
            setIsVerifying(false);
        }
    };

    if (!isOpen) return null;

    // ── Identity badge colour ─────────────────────────────────────────────────
    const identityOk = saEmail && saEmail !== 'Backend Offline' && saEmail !== 'error-detecting-identity';

    return (
        <div className="fixed inset-0 z-50 flex items-start sm:items-center justify-center bg-black/60 backdrop-blur-md p-4 sm:p-6 overflow-y-auto">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[92vh] my-auto animate-in fade-in zoom-in duration-300">

                {/* ── Header ─────────────────────────────────────────────── */}
                <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-8 py-6 text-white relative shrink-0">
                    <button
                        onClick={onClose}
                        className="absolute top-4 right-4 text-white/70 hover:text-white transition-colors"
                    >
                        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>

                    <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-white/20 rounded-lg">
                            <Shield className="w-6 h-6 text-white" />
                        </div>
                        <div>
                            <h2 className="text-2xl font-bold">Connect Your Environment</h2>

                            {/* Scanner identity badge */}
                            <div className="text-blue-100 text-[10px] sm:text-xs font-mono mt-1">
                                {loadingConfig ? (
                                    <span className="flex items-center gap-2">
                                        <Loader2 className="w-3 h-3 animate-spin" />
                                        Detecting scanner identity…
                                    </span>
                                ) : identityOk ? (
                                    <span className="flex items-center gap-1.5">
                                        <CheckCircle2 className="w-3 h-3 text-green-300" />
                                        Customer Scanner SA: {saEmail}
                                        {identitySource === 'GOOGLE_IMPERSONATE_SERVICE_ACCOUNT' && (
                                            <span className="ml-1 px-1.5 py-0.5 bg-green-500/30 rounded text-[9px] uppercase tracking-wide">
                                                Impersonated
                                            </span>
                                        )}
                                    </span>
                                ) : (
                                    <span className="flex items-center gap-1.5 text-yellow-200">
                                        <AlertCircle className="w-3 h-3" />
                                        {saEmail} — start the backend on port 8000
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                </div>

                {/* ── Content ────────────────────────────────────────────── */}
                <div className="p-8 space-y-6 flex-1 overflow-y-auto min-h-0">
                    {error && (
                        <div className="flex items-start gap-3 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 animate-in slide-in-from-top-2 shrink-0">
                            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
                            <p className="text-sm font-medium">{error}</p>
                        </div>
                    )}

                    {/* Step 1 — Scanner Identity */}
                    <div className="space-y-6 shrink-0">
                        {/* 1A. Create SA Field */}
                        <div className="p-4 bg-gray-50 border border-gray-200 rounded-xl space-y-3">
                            <label className="flex items-center justify-between text-sm font-semibold text-gray-700">
                                <span className="flex items-center gap-2">
                                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs shadow-sm">1</span>
                                    Create New Target SA
                                </span>
                            </label>
                            <p className="text-xs text-gray-500 ml-7">Type a short name below (e.g. <code>domain333</code>) and we will automatically generate the full Service Account in our host project.</p>

                            <div className="ml-7 flex flex-col sm:flex-row gap-3">
                                <input
                                    type="text"
                                    value={saPrefix}
                                    onChange={(e) => setSaPrefix(e.target.value)}
                                    placeholder="Scanner Name Prefix (e.g. domain333)"
                                    className="flex-1 px-4 py-2.5 bg-white text-gray-900 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all font-mono text-sm shadow-sm"
                                />
                                <button
                                    onClick={handleCreateSa}
                                    disabled={loadingConfig || !saPrefix.trim()}
                                    className="shrink-0 text-sm font-semibold text-white transition-all flex justify-center items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {loadingConfig ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                                    Create SA
                                </button>
                            </div>

                            {/* Success Notification */}
                            {saCreatedSuccess && (
                                <div className="ml-7 flex items-center gap-1.5 text-xs text-green-600 animate-in fade-in slide-in-from-top-1">
                                    <CheckCircle2 className="w-4 h-4" />
                                    <span className="font-medium">Service account successfully created!</span>
                                </div>
                            )}
                        </div>

                        {/* 1B. Confirm Identity Output */}
                        <div className="space-y-3">
                            <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-gray-200 text-gray-600 text-xs">2</span>
                                Confirm Scanner Identity
                            </label>
                            <p className="text-xs text-gray-500 ml-7">This is the final generated Service Account Email. This will be automatically injected into your authorization script.</p>
                            <div className="ml-7 relative">
                                <input
                                    type="text"
                                    value={saEmail}
                                    readOnly // Make this read-only since it's the confirmed output
                                    placeholder="Pending creation... (e.g. scanner-prefix@your-host-project.iam.gserviceaccount.com)"
                                    className="w-full pl-4 pr-12 py-3 bg-white text-gray-900 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all font-mono text-sm shadow-sm"
                                />
                                <button
                                    onClick={() => {
                                        navigator.clipboard.writeText(saEmail);
                                        setCopied(true);
                                        setTimeout(() => setCopied(false), 2000);
                                    }}
                                    disabled={!saEmail}
                                    className="absolute right-3 top-2.5 p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md transition-colors disabled:opacity-30"
                                    title="Copy email to clipboard"
                                >
                                    {copied ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Step 3 — Target Scope & ID */}
                    <div className="space-y-4 shrink-0">
                        <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs">3</span>
                            Select Target Scope &amp; ID
                        </label>

                        {/* Scope Tabs */}
                        <div className="ml-7 flex p-1 bg-gray-100 rounded-xl">
                            <button
                                onClick={() => setScope('project')}
                                className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-all ${scope === 'project' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500 hover:text-gray-700'}`}
                            >
                                <Layout className="w-4 h-4" /> Single Project
                            </button>
                            <button
                                onClick={() => setScope('organization')}
                                className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-all ${scope === 'organization' ? 'bg-white shadow-sm text-blue-600' : 'text-gray-500 hover:text-gray-700'}`}
                            >
                                <Building className="w-4 h-4" /> Organization
                            </button>
                        </div>

                        <div className="ml-7">
                            <input
                                type="text"
                                value={resourceId}
                                onChange={(e) => setResourceId(e.target.value)}
                                placeholder={scope === 'project' ? 'e.g. my-production-project-123' : 'e.g. 1234567890'}
                                className="w-full px-4 py-3 bg-gray-50 text-gray-900 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all font-mono text-sm"
                            />
                        </div>
                    </div>

                    {/* Step 4 — Optional Billing Account ID */}
                    <div className="space-y-3 shrink-0">
                        <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs">4</span>
                            Link Billing Account ID (Optional)
                        </label>
                        <p className="text-xs text-gray-500 ml-7">
                            Required to scan budgets, cost alerts, and billing health. Find this in the GCP Console under <strong>Billing &gt; Account Management</strong>.
                        </p>
                        <div className="ml-7">
                            <input
                                type="text"
                                value={billingAccountId}
                                onChange={(e) => setBillingAccountId(e.target.value)}
                                placeholder="e.g. 0118DE-1E52C9-F51A1B"
                                className="w-full px-4 py-3 bg-gray-50 text-gray-900 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all font-mono text-sm"
                            />
                        </div>
                    </div>

                    {/* Step 5 — Authorize */}
                    <div className="space-y-3 shrink-0">
                        <div className="flex items-center justify-between">
                            <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs">5</span>
                                Authorize App Identity
                            </label>
                            <button
                                onClick={handleDownload}
                                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors border border-blue-200"
                            >
                                <Download className="w-3.5 h-3.5" /> Save Script
                            </button>
                        </div>

                        <p className="text-xs text-gray-500 ml-7 leading-relaxed">
                            Run the commands below in Cloud Shell (or your terminal) <strong>authenticated as an admin of the target {scope === 'project' ? 'project' : 'organization'}</strong>.
                            They grant the scanner <strong>Security Reviewer</strong>, <strong>SCC Admin</strong>, and <strong>Billing Viewer</strong> access.
                        </p>
                        <div className="ml-7 p-3 bg-amber-50 border border-amber-200 rounded-lg">
                            <p className="text-xs text-amber-700 font-medium">
                                ⚠️ <strong>Important:</strong> These commands must be run by a user who has <code>Owner</code> or <code>IAM Admin</code> on the target {scope === 'project' ? 'project' : 'organization'}.
                                If your account lacks this permission, share the script with the client&apos;s admin to run it.
                            </p>
                        </div>

                        <div className="ml-7 relative group">
                            <button
                                onClick={handleCopy}
                                className="absolute top-3 right-3 p-2 bg-white/10 hover:bg-white/20 rounded-lg backdrop-blur-sm transition-all text-white border border-white/20 z-10"
                                title="Copy to clipboard"
                            >
                                {copied ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                            </button>
                            <div className="w-full bg-gray-900 text-green-400 p-5 rounded-xl font-mono text-[10px] sm:text-xs overflow-auto max-h-[250px] border border-gray-800 shadow-inner">
                                {loadingConfig ? (
                                    <div className="flex justify-center p-4">
                                        <Loader2 className="animate-spin w-5 h-5 text-gray-500" />
                                    </div>
                                ) : (
                                    <pre className="whitespace-pre-wrap break-all leading-relaxed">{getDisplayCommand()}</pre>
                                )}
                            </div>
                        </div>

                        {/* Step 4 — Validate */}
                        <div className="mt-6 pt-4 border-t border-gray-100 flex flex-col gap-3">
                            <div className="flex items-center justify-between">
                                <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs">4</span>
                                    Validate Permissions
                                </label>
                                <button
                                    onClick={() => handleValidate(60000)} // Auto-poll for up to 60 seconds
                                    disabled={!resourceId.trim() || !saEmail || isValidating}
                                    className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg shadow-sm transition-all flex items-center gap-2"
                                >
                                    {isValidating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                                    {isValidating ? 'Checking...' : 'Check Access'}
                                </button>
                            </div>

                            {validationResults && (
                                <div className={`ml-7 p-4 border rounded-xl shadow-sm ${validationResults.all_granted ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                                    <h4 className={`text-sm font-bold flex items-center gap-2 mb-3 ${validationResults.all_granted ? 'text-green-800' : 'text-red-800'}`}>
                                        {validationResults.all_granted ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
                                        {validationResults.all_granted ? 'All Required Roles Granted' : 'Missing Required Roles'}
                                    </h4>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                                        {Object.entries(validationResults.roles).map(([role, hasRole]) => (
                                            <div key={role} className="flex items-center gap-2 bg-white/60 p-2 rounded-lg border border-black/5">
                                                {hasRole ? (
                                                    <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0" />
                                                ) : (
                                                    <span className="flex items-center justify-center w-4 h-4 rounded-full bg-red-100 text-red-500 font-bold text-[10px] shrink-0">✕</span>
                                                )}
                                                <span className={`font-mono truncate ${hasRole ? 'text-gray-700' : 'text-red-600 font-medium'}`}>{role}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* ── Footer ─────────────────────────────────────────────── */}
                <div className="px-8 py-6 bg-gray-50 border-t border-gray-100 flex justify-end items-center gap-4 shrink-0">
                    <button
                        onClick={onClose}
                        className="px-6 py-2.5 text-sm font-semibold text-gray-600 hover:text-gray-900 transition-colors"
                    >
                        Cancel
                    </button>
                    <ActionBtn
                        onClick={handleVerify}
                        disabled={!resourceId.trim() || isVerifying || loadingConfig}
                        loading={isVerifying}
                        className="min-w-[180px] shadow-lg shadow-blue-500/20"
                    >
                        Verify &amp; Start Scan
                    </ActionBtn>
                </div>
            </div>
        </div>
    );
}
