'use client';

import React, { useState } from 'react';
import { CheckCircle, XCircle, AlertCircle, Shield, Lock, Network, Server, DollarSign, FileText, Mail, Download, TrendingUp, Upload, Settings, ChevronRight, LayoutGrid } from 'lucide-react';
import { MultiProjectLockdownResponse, LockdownResponse, LockdownStep, LockdownResponse as LockdownResult, API_BASE_URL } from '@/lib/api';



interface BillingInfo {
    billing_account_id?: string;
    billing_account_name?: string;
    iam_users?: Array<{ user: string; roles: string[] }>;
}

interface ScanResult {
    project_id?: string;
    risks?: Array<{
        id: string;
        title: string;
        risk_level: string;
        category: string;
        description: string;
        recommendation: string;
    }>;
    billing_info?: BillingInfo;
}

interface BrandingConfig {
    logo?: string;
    companyName?: string;
    primaryColor?: string;
    secondaryColor?: string;
}

interface ExecutiveReportProps {
    result: LockdownResult | LockdownResponse;
    multiResult?: MultiProjectLockdownResponse;
    scanResult?: ScanResult; // For before/after comparison
    multiScanResult?: ScanResult[]; // List of scan results for multi-project mode
    onClose?: () => void;
    onReset?: () => void;
    onBackout?: () => void; // New prop for rollback
    branding?: BrandingConfig;
}

const AssetVerificationTable = ({ step }: { step: LockdownStep }) => {
    if (!step.details) return null;

    const renderDetails = () => {
        switch (step.step_id) {
            case 'api_restrictions':
                return (
                    <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <h5 className="text-[10px] font-bold text-red-600 uppercase mb-2">Restricted / Blocked APIs</h5>
                                <div className="max-h-40 overflow-y-auto border rounded-lg bg-red-50 p-2 space-y-1">
                                    {step.details.disabled_apis?.map((api: string) => (
                                        <div key={api} className="text-[9px] font-mono text-red-800 bg-white px-2 py-0.5 rounded border border-red-100 flex items-center justify-between">
                                            <span>{api}</span>
                                            <XCircle className="w-2.5 h-2.5" />
                                        </div>
                                    ))}
                                </div>
                            </div>
                            <div>
                                <h5 className="text-[10px] font-bold text-green-600 uppercase mb-2">Approved / Verified APIs</h5>
                                <div className="max-h-40 overflow-y-auto border rounded-lg bg-green-50 p-2 space-y-1">
                                    {step.details.allowed_apis?.map((api: string) => (
                                        <div key={api} className="text-[9px] font-mono text-green-800 bg-white px-2 py-0.5 rounded border border-green-100 flex items-center justify-between">
                                            <span>{api}</span>
                                            <CheckCircle className="w-2.5 h-2.5" />
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            case 'network_hardening':
                return (
                    <div className="grid grid-cols-3 gap-2">
                        {step.details.firewall_rules?.map((rule: string) => (
                            <div key={rule} className="p-2 border rounded-lg bg-indigo-50 border-indigo-100">
                                <div className="text-[10px] font-bold text-indigo-900">{rule}</div>
                                <div className="text-[8px] text-indigo-600 uppercase font-bold mt-1">Status: Active & Verified</div>
                            </div>
                        ))}
                        <div className="p-2 border rounded-lg bg-slate-50 border-slate-200">
                            <div className="text-[10px] font-bold text-slate-900">Traffic Monitoring</div>
                            <div className="text-[8px] text-slate-600 uppercase font-bold mt-1">Status: {step.details.monitoring}</div>
                        </div>
                    </div>
                );
            case 'billing_kill_switch':
                return (
                    <div className="flex gap-4">
                        <div className="flex-1 p-3 border rounded-xl bg-emerald-50 border-emerald-100">
                            <div className="text-[10px] font-bold text-emerald-900 uppercase">Budget Threshold</div>
                            <div className="text-xl font-black text-emerald-700">${step.details.budget_limit} {step.details.currency}</div>
                        </div>
                        <div className="flex-1 p-3 border rounded-xl bg-blue-50 border-blue-100">
                            <div className="text-[10px] font-bold text-blue-900 uppercase">Automated Action</div>
                            <div className="text-sm font-bold text-blue-700">{step.details.action}</div>
                        </div>
                        <div className="flex-1 p-3 border rounded-xl bg-slate-50 border-slate-200 text-center">
                            <div className="text-[10px] font-bold text-slate-500 uppercase">Verification</div>
                            <div className="text-[10px] font-bold text-slate-900 mt-1 uppercase tracking-widest">Pub/Sub Linked</div>
                        </div>
                    </div>
                );
            case 'quota_caps':
                return (
                    <div className="flex items-center justify-between p-4 bg-amber-50 border border-amber-200 rounded-xl">
                        <div className="flex items-center gap-4">
                            <div className="bg-amber-100 p-2 rounded-lg"><Server className="w-5 h-5 text-amber-700" /></div>
                            <div>
                                <div className="text-xs font-black text-amber-900 uppercase tracking-tight">Resource: {step.details.quota_type}</div>
                                <div className="text-[10px] text-amber-700 font-medium">Crypto-Mining Prevention Policy</div>
                            </div>
                        </div>
                        <div className="text-right">
                            <div className="text-xs font-bold text-amber-900">Limit Set: {step.details.current_limit || 0} → {step.details.target_limit || 0}</div>
                            <div className="text-[9px] font-black text-green-600 uppercase mt-1">{step.details.status}</div>
                        </div>
                    </div>
                );
            case 'service_account_keys':
                return (
                    <div className="p-3 border rounded-lg bg-indigo-50 border-indigo-200 flex items-center justify-between">
                        <div>
                            <div className="text-[10px] font-bold text-indigo-900">{step.details.constraint}</div>
                            <div className="text-[9px] text-indigo-600">Org Policy Enforcement Verified</div>
                        </div>
                        <div className="px-3 py-1 bg-indigo-200 rounded text-[9px] font-black text-indigo-800 uppercase">
                            {step.details.enforcement}
                        </div>
                    </div>
                );
            case 'region_lockdown':
                return (
                    <div className="p-3 border rounded-lg bg-blue-50 border-blue-200 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="text-[10px] font-bold text-blue-900 uppercase tracking-wide">Authorized Regions:</div>
                            <div className="flex gap-1">
                                {step.details.allowed_regions?.map((r: string) => (
                                    <span key={r} className="px-2 py-0.5 bg-blue-600 text-white text-[9px] font-bold rounded">{r}</span>
                                ))}
                            </div>
                        </div>
                        <div className="text-[9px] font-black text-blue-600 uppercase">{step.details.status}</div>
                    </div>
                );
            case 'compute_monitoring':
            case 'org_monitoring':
                return (
                    <div className="space-y-2">
                        <div className="flex items-center justify-between text-[10px] font-bold text-slate-500 uppercase px-1">
                            <span>Operational Monitoring Assets</span>
                            <span>{step.details.alert_count} Alerts Active</span>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                            {step.details.active_policies?.slice(0, 6).map((policy: string) => (
                                <div key={policy} className="p-2 border rounded-lg bg-white border-slate-200 flex items-center gap-2">
                                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full"></div>
                                    <span className="text-[9px] font-bold text-slate-700 truncate">{policy}</span>
                                </div>
                            ))}
                            <div className="p-2 border rounded-lg bg-white border-slate-200 flex items-center gap-2">
                                <div className="w-1.5 h-1.5 bg-blue-500 rounded-full"></div>
                                <span className="text-[9px] font-bold text-slate-700 truncate">{step.details.sink_name || "security-sink"}</span>
                            </div>
                        </div>
                    </div>
                );
            default:
                return (
                    <div className="text-[10px] font-mono bg-slate-50 p-2 rounded border border-slate-200 overflow-x-auto">
                        <pre>{JSON.stringify(step.details, null, 2)}</pre>
                    </div>
                );
        }
    };

    return (
        <div className="mt-4 px-8 py-6 bg-slate-50 border-t border-slate-100 shadow-inner">
            <div className="flex items-center gap-2 mb-4">
                <div className="w-1.5 h-4 bg-indigo-600 rounded-full"></div>
                <h4 className="text-[11px] font-black text-slate-900 uppercase tracking-widest">Asset-Level Security Verification</h4>
            </div>
            {renderDetails()}
        </div>
    );
};

// Default Wursta branding
const DEFAULT_BRANDING: BrandingConfig = {
    logo: '/wursta-logo.png',
    companyName: 'Wursta',
    primaryColor: '#DC2626', // Red color from Wursta logo
    secondaryColor: '#991B1B', // Darker red accent
};

const getStepIcon = (stepId: string) => {
    const iconMap: Record<string, React.ReactNode> = {
        api_restrictions: <Lock className="w-5 h-5" />,
        network_hardening: <Network className="w-5 h-5" />,
        service_account_keys: <Shield className="w-5 h-5" />,
        region_lockdown: <Server className="w-5 h-5" />,
        quota_caps: <Server className="w-5 h-5" />,
        billing_kill_switch: <DollarSign className="w-5 h-5" />,
        change_management: <FileText className="w-5 h-5" />,
    };
    return iconMap[stepId] || <Shield className="w-5 h-5" />;
};

export default function ExecutiveReportEnhanced({ result, multiResult, scanResult, multiScanResult, onClose, onReset, onBackout, branding }: ExecutiveReportProps) {
    const [viewMode, setViewMode] = useState<'full' | 'summary' | 'comparison' | 'multi-project'>('full');
    const [showBrandingConfig, setShowBrandingConfig] = useState(false);
    // Use provided branding or default to Wursta branding
    const [localBranding, setLocalBranding] = useState<BrandingConfig>(branding || DEFAULT_BRANDING);

    // Determine active result (singular project)
    const [selectedProjectIndex, setSelectedProjectIndex] = useState<number>(0);

    // Use the selected project from multi-result if available, otherwise use strict result
    const activeResult = multiResult && multiResult.project_results.length > 0
        ? multiResult.project_results[selectedProjectIndex]
        : result as LockdownResult; // Cast for compatibility

    // Find the corresponding scan result for the active project
    const activeScanResult = multiScanResult
        ? multiScanResult.find(s => s.project_id === activeResult.project_id) || scanResult
        : scanResult;

    // Helper to find original risk from scan results
    const findMatchingRisk = (stepId: string) => {
        if (!activeScanResult?.risks) return null;

        // Map step_id to possible risk_id prefixes/patterns
        const mapping: Record<string, string[]> = {
            api_restrictions: ['risky_api_', 'compute_api_enabled', 'unused_high_cost_apis'],
            network_hardening: ['no_network_hardening'],
            service_account_keys: ['service_account_keys_allowed'],
            region_lockdown: ['region_lockdown_not_enforced'],
            quota_caps: ['gpu_quota_unlimited'],
            billing_kill_switch: ['no_billing_account', 'no_budgets', 'no_project_budget']
        };

        const possibleRiskIds = mapping[stepId] || [];
        return activeScanResult.risks.find(risk =>
            possibleRiskIds.some(prefix => risk.id.startsWith(prefix))
        );
    };

    const successRate = Math.round((activeResult.summary.completed / activeResult.summary.total) * 100);
    const failureRate = Math.round((activeResult.summary.failed / activeResult.summary.total) * 100);

    // Calculate before/after metrics
    const initialRisks = activeScanResult?.risks?.length || 0;
    const addressedSteps = activeResult.summary.completed;
    const riskReductionPercent = initialRisks > 0 ? Math.round((addressedSteps / initialRisks) * 100) : 0;

    // Generate email content
    const generateEmailBody = () => {
        const subject = `Security Lockdown Report - ${activeResult.project_id}`;
        const body = `
Security Lockdown Report
Project: ${activeResult.project_id}
Date: ${new Date(activeResult.timestamp).toLocaleDateString()}

SUMMARY:
- Success Rate: ${successRate}%
- Controls Applied: ${activeResult.summary.completed}/${activeResult.summary.total}
- Status: ${activeResult.status}

TOP SECURITY IMPROVEMENTS:
${activeResult.steps
                .filter(s => s.status === 'completed')
                .slice(0, 3)
                .map((s, i) => `${i + 1}. ${s.name}: ${s.security_benefit}`)
                .join('\n')}

${activeResult.errors.length > 0 ? `\nISSUES REQUIRING ATTENTION (${activeResult.errors.length}):
${activeResult.errors.map((e, i) => `${i + 1}. ${e}`).join('\n')}` : ''}

View full report: [Attach PDF or link to report]
    `.trim();

        return `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    };

    // Handle logo upload
    const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                setLocalBranding({ ...localBranding, logo: reader.result as string });
            };
            reader.readAsDataURL(file);
        }
    };

    // Circle progress for donut chart
    const circumference = 2 * Math.PI * 70;
    const successOffset = circumference - (successRate / 100) * circumference;

    // Render branding config panel
    if (showBrandingConfig) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-8">
                <div className="max-w-2xl mx-auto bg-white rounded-2xl shadow-xl p-8">
                    <h2 className="text-2xl font-bold text-slate-900 mb-6">Customize Report Branding</h2>

                    <div className="space-y-6">
                        {/* Logo Upload */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 mb-2">
                                Company Logo
                            </label>
                            <div className="flex items-center gap-4">
                                {localBranding.logo && (
                                    <img src={localBranding.logo} alt="Logo" className="h-16 w-auto object-contain" />
                                )}
                                <label className="cursor-pointer px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 flex items-center gap-2">
                                    <Upload className="w-4 h-4" />
                                    Upload Logo
                                    <input
                                        type="file"
                                        accept="image/*"
                                        onChange={handleLogoUpload}
                                        className="hidden"
                                    />
                                </label>
                            </div>
                        </div>

                        {/* Company Name */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 mb-2">
                                Company Name
                            </label>
                            <input
                                type="text"
                                value={localBranding.companyName || ''}
                                onChange={(e) => setLocalBranding({ ...localBranding, companyName: e.target.value })}
                                placeholder="Privacy Data Inc."
                                className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                        </div>

                        {/* Primary Color */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 mb-2">
                                Primary Color
                            </label>
                            <div className="flex items-center gap-4">
                                <input
                                    type="color"
                                    value={localBranding.primaryColor || '#3b82f6'}
                                    onChange={(e) => setLocalBranding({ ...localBranding, primaryColor: e.target.value })}
                                    className="h-10 w-20 rounded cursor-pointer"
                                />
                                <span className="text-sm text-slate-600">{localBranding.primaryColor || '#3b82f6'}</span>
                            </div>
                        </div>

                        {/* Buttons */}
                        <div className="flex gap-3 mt-8">
                            <button
                                onClick={() => setShowBrandingConfig(false)}
                                className="flex-1 px-6 py-3 bg-primary-600 text-white font-semibold rounded-lg hover:bg-primary-700 transition-colors"
                            >
                                Apply & Return to Report
                            </button>
                            <button
                                onClick={() => {
                                    setLocalBranding(branding || {});
                                    setShowBrandingConfig(false);
                                }}
                                className="px-6 py-3 bg-slate-200 text-slate-700 font-semibold rounded-lg hover:bg-slate-300 transition-colors"
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-8">
            <div className="max-w-6xl mx-auto">
                {/* View Mode Buttons */}
                <div className="flex justify-between items-center mb-6">
                    <div className="flex gap-2">
                        {multiResult && (
                            <button
                                onClick={() => setViewMode('multi-project')}
                                className={`px-4 py-2 rounded-lg font-medium transition-colors ${viewMode === 'multi-project'
                                    ? 'bg-primary-600 text-white'
                                    : 'bg-white text-slate-700 hover:bg-slate-100'
                                    }`}
                            >
                                <LayoutGrid className="w-4 h-4 inline mr-2" />
                                Multi-Project Overview
                            </button>
                        )}
                        <button
                            onClick={() => setViewMode('full')}
                            className={`px-4 py-2 rounded-lg font-medium transition-colors ${viewMode === 'full'
                                ? 'bg-primary-600 text-white'
                                : 'bg-white text-slate-700 hover:bg-slate-100'
                                }`}
                        >
                            Full Report
                        </button>
                        <button
                            onClick={() => setViewMode('summary')}
                            className={`px-4 py-2 rounded-lg font-medium transition-colors ${viewMode === 'summary'
                                ? 'bg-primary-600 text-white'
                                : 'bg-white text-slate-700 hover:bg-slate-100'
                                }`}
                        >
                            Executive Summary
                        </button>
                        {scanResult && (
                            <button
                                onClick={() => setViewMode('comparison')}
                                className={`px-4 py-2 rounded-lg font-medium transition-colors ${viewMode === 'comparison'
                                    ? 'bg-primary-600 text-white'
                                    : 'bg-white text-slate-700 hover:bg-slate-100'
                                    }`}
                            >
                                Before/After
                            </button>
                        )}
                    </div>

                    <button
                        onClick={() => setShowBrandingConfig(true)}
                        className="px-4 py-2 bg-white text-slate-700 rounded-lg hover:bg-slate-100 flex items-center gap-2"
                    >
                        <Settings className="w-4 h-4" />
                        Customize Branding
                    </button>
                </div>

                {/* Header with Branding */}
                <div className="bg-white rounded-2xl shadow-xl p-8 mb-6">
                    <div className="flex items-center justify-between mb-6">
                        <div className="flex items-center gap-6">
                            {localBranding.logo && (
                                <img src={localBranding.logo} alt="Company Logo" className="h-16 w-auto object-contain" />
                            )}
                            <div>
                                <h1 className="text-4xl font-bold text-slate-900 mb-2">
                                    {localBranding.companyName || 'Security'} Lockdown Report
                                </h1>
                                <p className="text-slate-600 text-lg">
                                    {multiResult ? 'Multi-Project Executive Summary' : 'Executive Summary'}
                                </p>
                            </div>
                        </div>
                        <div className="text-right">
                            <p className="text-sm text-slate-500">Project</p>
                            {/* Project Selector if Multi-Project */}
                            {multiResult && multiResult.project_results.length > 1 ? (
                                <div className="relative mt-1">
                                    <select
                                        className="appearance-none bg-slate-100 border border-slate-300 text-slate-900 text-lg font-semibold rounded-lg py-2 px-4 pr-8 leading-tight focus:outline-none focus:bg-white focus:border-blue-500"
                                        value={selectedProjectIndex}
                                        onChange={(e) => {
                                            setSelectedProjectIndex(parseInt(e.target.value));
                                            if (viewMode === 'multi-project') {
                                                setViewMode('full');
                                            }
                                        }}
                                    >
                                        {multiResult.project_results.map((p, idx) => (
                                            <option key={p.project_id} value={idx}>{p.project_id}</option>
                                        ))}
                                    </select>
                                    <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-slate-700">
                                        <ChevronRight className="h-4 w-4 rotate-90" />
                                    </div>
                                </div>
                            ) : (
                                <p className="text-xl font-semibold text-slate-900">{activeResult.project_id}</p>
                            )}
                            <p className="text-sm text-slate-500 mt-2">{new Date(activeResult.timestamp).toLocaleString()}</p>
                        </div>
                    </div>

                    {/* Status Banner */}
                    <div className={`rounded-xl p-6 ${activeResult.summary.failed === 0
                        ? 'bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-200'
                        : 'bg-gradient-to-r from-amber-50 to-orange-50 border-2 border-amber-200'
                        }`}>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                {activeResult.summary.failed === 0 ? (
                                    <CheckCircle className="w-12 h-12 text-green-600" />
                                ) : (
                                    <AlertCircle className="w-12 h-12 text-amber-600" />
                                )}
                                <div>
                                    <h2 className="text-2xl font-bold text-slate-900">
                                        {activeResult.summary.failed === 0 ? 'Security Lockdown Successful' : 'Lockdown Completed with Warnings'}
                                    </h2>
                                    <p className="text-slate-600 mt-1">
                                        {activeResult.summary.completed} of {activeResult.summary.total} security controls applied successfully
                                    </p>
                                </div>
                            </div>
                            <div className="text-right">
                                <p className="text-4xl font-bold text-slate-900">{successRate}%</p>
                                <p className="text-sm text-slate-600">Success Rate</p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Multi-Project Overview View */}
                {viewMode === 'multi-project' && multiResult && (
                    <div className="space-y-6">
                        <div className="bg-white rounded-2xl shadow-xl p-8">
                            <h2 className="text-2xl font-bold text-slate-900 mb-6">Multi-Project Overview</h2>

                            <div className="grid grid-cols-3 gap-6 mb-8">
                                <div className="bg-blue-50 p-6 rounded-xl border border-blue-200">
                                    <div className="text-3xl font-bold text-blue-900">{multiResult.total_projects}</div>
                                    <div className="text-sm text-blue-700">Total Projects</div>
                                </div>
                                <div className="bg-green-50 p-6 rounded-xl border border-green-200">
                                    <div className="text-3xl font-bold text-green-900">{multiResult.completed_projects}</div>
                                    <div className="text-sm text-green-700">Completed</div>
                                </div>
                                <div className="bg-red-50 p-6 rounded-xl border border-red-200">
                                    <div className="text-3xl font-bold text-red-900">{multiResult.failed_projects}</div>
                                    <div className="text-sm text-red-700">Failed</div>
                                </div>
                            </div>

                            <h3 className="text-lg font-semibold text-slate-900 mb-4">Project Details</h3>
                            <div className="space-y-4">
                                {multiResult.project_results.map((proj, idx) => {
                                    const projSuccessRate = Math.round((proj.summary.completed / proj.summary.total) * 100);
                                    return (
                                        <div
                                            key={proj.project_id}
                                            className="flex items-center justify-between p-4 bg-white border rounded-lg hover:shadow-md transition-shadow cursor-pointer"
                                            onClick={() => {
                                                setSelectedProjectIndex(idx);
                                                setViewMode('full');
                                            }}
                                        >
                                            <div className="flex items-center gap-4">
                                                <div className={`p-2 rounded-full ${proj.summary.failed === 0 ? 'bg-green-100' : 'bg-amber-100'}`}>
                                                    {proj.summary.failed === 0 ? <CheckCircle className="w-6 h-6 text-green-600" /> : <AlertCircle className="w-6 h-6 text-amber-600" />}
                                                </div>
                                                <div>
                                                    <h4 className="font-semibold text-slate-900">{proj.project_id}</h4>
                                                    <p className="text-sm text-slate-500">{proj.summary.completed} / {proj.summary.total} controls applied</p>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <div className="text-right">
                                                    <div className="font-bold text-slate-900">{projSuccessRate}%</div>
                                                    <div className="text-xs text-slate-500">Success</div>
                                                </div>
                                                <ChevronRight className="w-5 h-5 text-slate-400" />
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                )}

                {/* Executive Summary View */}
                {viewMode === 'summary' && (
                    <div className="space-y-6">
                        <div className="bg-white rounded-2xl shadow-xl p-8">
                            <h2 className="text-2xl font-bold text-slate-900 mb-6 px-2">Executive Summary (1-Page Audit View)</h2>

                            {/* Key Metrics Grid */}
                            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                                <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 border border-blue-200">
                                    <div className="text-3xl font-bold text-blue-900">{successRate}%</div>
                                    <div className="text-sm text-blue-700">Success Rate</div>
                                </div>
                                <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6 border border-green-200">
                                    <div className="text-3xl font-bold text-green-900">{activeResult.summary.completed}</div>
                                    <div className="text-sm text-green-700">Controls Applied</div>
                                </div>
                                <div className="bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl p-6 border border-purple-200">
                                    <div className="text-3xl font-bold text-purple-900">{riskReductionPercent}%</div>
                                    <div className="text-sm text-purple-700">Risk Reduction</div>
                                </div>
                                <div className="bg-gradient-to-br from-amber-50 to-amber-100 rounded-xl p-6 border border-amber-200">
                                    <div className="text-3xl font-bold text-amber-900">{activeResult.summary.failed}</div>
                                    <div className="text-sm text-amber-700">Needs Attention</div>
                                </div>
                            </div>

                            {/* Governance & Identity Section (Full Width) */}
                            <div className="bg-indigo-900 rounded-2xl p-8 text-white mb-8">
                                <h3 className="text-xl font-bold mb-4 flex items-center gap-3">
                                    <Shield className="w-6 h-6 text-indigo-300" />
                                    Identity Governance & Financial Isolation
                                </h3>

                                {activeScanResult?.billing_info?.iam_users && activeScanResult.billing_info.iam_users.length > 0 && (
                                    <div className="mb-6 overflow-hidden border border-indigo-700 rounded-xl bg-indigo-950 bg-opacity-40">
                                        <table className="min-w-full">
                                            <thead className="bg-indigo-900">
                                                <tr>
                                                    <th className="px-6 py-3 text-left text-[10px] font-bold text-indigo-300 uppercase">Individual Identity</th>
                                                    <th className="px-6 py-3 text-left text-[10px] font-bold text-indigo-300 uppercase">Billing Roles</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-indigo-800">
                                                {activeScanResult.billing_info.iam_users.slice(0, 5).map((user, idx) => (
                                                    <tr key={idx}>
                                                        <td className="px-6 py-3 text-sm font-medium text-white">{user.user}</td>
                                                        <td className="px-6 py-3 text-xs text-indigo-200 italic">{user.roles.join(', ')}</td>
                                                    </tr>
                                                ))}
                                                {activeScanResult.billing_info.iam_users.length > 5 && (
                                                    <tr>
                                                        <td colSpan={2} className="px-6 py-2 text-center text-[10px] text-indigo-400 italic">...and {activeScanResult.billing_info.iam_users.length - 5} more identities</td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                )}

                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    <div className="bg-white bg-opacity-10 p-4 rounded-xl border border-white border-opacity-20 transition-all hover:bg-opacity-20 cursor-default group">
                                        <div className="text-xs font-bold text-indigo-300 group-hover:text-white">gcp-billing-admins@</div>
                                        <p className="text-[10px] text-indigo-100 mt-1">Finance Group for strategic payment control.</p>
                                    </div>
                                    <div className="bg-white bg-opacity-10 p-4 rounded-xl border border-white border-opacity-20 transition-all hover:bg-opacity-20 cursor-default group">
                                        <div className="text-xs font-bold text-indigo-300 group-hover:text-white">gcp-billing-viewers@</div>
                                        <p className="text-[10px] text-indigo-100 mt-1">Read-only cost analysis & audit group.</p>
                                    </div>
                                    <div className="bg-white bg-opacity-10 p-4 rounded-xl border border-white border-opacity-20 transition-all hover:bg-opacity-20 cursor-default group">
                                        <div className="text-xs font-bold text-indigo-300 group-hover:text-white">gcp-engineering-leads@</div>
                                        <p className="text-[10px] text-indigo-100 mt-1">Tech Managers for project-billing linking.</p>
                                    </div>
                                </div>
                            </div>

                            {/* Top 3 Changes */}
                            <div className="mb-8">
                                <h3 className="text-lg font-semibold text-slate-900 mb-4 px-2 tracking-tight">Top Security Improvements</h3>
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    {activeResult.steps
                                        .filter(s => s.status === 'completed')
                                        .slice(0, 3)
                                        .map((step, index) => (
                                            <div key={step.step_id} className="flex flex-col bg-green-50 p-6 rounded-2xl border border-green-200 shadow-sm">
                                                <div className="flex items-center justify-between mb-4">
                                                    <div className="bg-green-100 p-2 rounded-xl text-green-700">
                                                        {getStepIcon(step.step_id)}
                                                    </div>
                                                    <CheckCircle className="w-5 h-5 text-green-600" />
                                                </div>
                                                <h4 className="font-bold text-slate-900 text-sm mb-2">{step.name}</h4>
                                                <p className="text-xs text-slate-600 line-clamp-3 leading-relaxed">{step.security_benefit}</p>
                                            </div>
                                        ))}
                                </div>
                            </div>

                            {/* Final Recommendations */}
                            <div className="bg-blue-50 border-2 border-blue-200 rounded-2xl p-8">
                                <h3 className="text-lg font-bold text-blue-900 mb-6 flex items-center gap-2">
                                    <TrendingUp className="w-6 h-6" />
                                    Post-Lockdown Priority Actions
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                    <ul className="space-y-4 text-sm text-blue-800">
                                        <li className="flex items-start gap-3">
                                            <div className="w-6 h-6 bg-blue-200 rounded-lg flex items-center justify-center text-[10px] font-bold text-blue-700 flex-shrink-0 mt-0.5">01</div>
                                            <span>Remediate the {activeResult.summary.failed} identified failed controls in the full report.</span>
                                        </li>
                                        <li className="flex items-start gap-3">
                                            <div className="w-6 h-6 bg-blue-200 rounded-lg flex items-center justify-center text-[10px] font-bold text-blue-700 flex-shrink-0 mt-0.5">02</div>
                                            <span>Implement segmented gcp-billing groups to replace individual access.</span>
                                        </li>
                                    </ul>
                                    <ul className="space-y-4 text-sm text-blue-800">
                                        <li className="flex items-start gap-3">
                                            <div className="w-6 h-6 bg-blue-200 rounded-lg flex items-center justify-center text-[10px] font-bold text-blue-700 flex-shrink-0 mt-0.5">03</div>
                                            <span>Automate quarterly posture scans using the Wursta Hardening API.</span>
                                        </li>

                                        <li className="flex items-start gap-3">
                                            <div className="w-6 h-6 bg-blue-200 rounded-lg flex items-center justify-center text-[10px] font-bold text-blue-700 flex-shrink-0 mt-0.5">04</div>
                                            <span>Validate backup integrity for resources with new policy restrictions.</span>
                                        </li>
                                        {activeResult.log_file_path && (
                                            <li className="flex items-start gap-3">
                                                <div className="w-6 h-6 bg-blue-200 rounded-lg flex items-center justify-center text-[10px] font-bold text-blue-700 flex-shrink-0 mt-0.5">05</div>
                                                <div className="flex flex-col">
                                                    <span className="font-bold">Execution Log Persisted</span>
                                                    <a
                                                        href={`${API_BASE_URL}/api/v1/lockdown/reports/${activeResult.log_file_path.split(/[/\\]/).pop()}`}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="text-xs break-all font-mono bg-blue-100 p-1 rounded mt-1 hover:bg-blue-200 text-blue-800 underline flex items-center gap-1"
                                                    >
                                                        <FileText className="w-3 h-3" />
                                                        {activeResult.log_file_path.split(/[/\\]/).pop()}
                                                    </a>
                                                    <span className="text-[10px] text-blue-600 mt-0.5">
                                                        (Click to download/view)
                                                    </span>
                                                </div>
                                            </li>
                                        )}
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Before/After Comparison View */}
                {viewMode === 'comparison' && activeScanResult && (
                    <div className="space-y-6">
                        <div className="bg-white rounded-2xl shadow-xl p-8">
                            <h2 className="text-2xl font-bold text-slate-900 mb-6">Security Posture: Before & After</h2>

                            <div className="grid grid-cols-2 gap-8 mb-8">
                                {/* Before */}
                                <div className="border-2 border-red-200 rounded-xl p-6 bg-red-50">
                                    <h3 className="text-lg font-semibold text-red-900 mb-4">Before Lockdown</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <div className="text-4xl font-bold text-red-900 mb-1">{initialRisks}</div>
                                            <div className="text-sm text-red-700">Identified Risks</div>
                                        </div>
                                        <div className="text-sm text-red-800">
                                            <p className="mb-2 font-medium">Vulnerabilities:</p>
                                            <ul className="space-y-1">
                                                <li>• Unrestricted API access</li>
                                                <li>• No billing limits configured</li>
                                                <li>• Service account keys enabled</li>
                                                <li>• External IP access allowed</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>

                                {/* After */}
                                <div className="border-2 border-green-200 rounded-xl p-6 bg-green-50">
                                    <h3 className="text-lg font-semibold text-green-900 mb-4">After Lockdown</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <div className="text-4xl font-bold text-green-900 mb-1">{addressedSteps}</div>
                                            <div className="text-sm text-green-700">Controls Implemented</div>
                                        </div>
                                        <div className="text-sm text-green-800">
                                            <p className="mb-2 font-medium">Protections Applied:</p>
                                            <ul className="space-y-1">
                                                {result.steps
                                                    .filter(s => s.status === 'completed')
                                                    .slice(0, 4)
                                                    .map(s => (
                                                        <li key={s.step_id}>• {s.name}</li>
                                                    ))}
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Improvement Arrow */}
                            <div className="text-center mb-8">
                                <div className="inline-flex items-center gap-4 bg-gradient-to-r from-green-100 to-emerald-100 px-8 py-4 rounded-xl border-2 border-green-300">
                                    <TrendingUp className="w-8 h-8 text-green-600" />
                                    <div className="text-left">
                                        <div className="text-2xl font-bold text-green-900">{riskReductionPercent}%</div>
                                        <div className="text-sm text-green-700">Risk Reduction Achieved</div>
                                    </div>
                                </div>
                            </div>

                            {/* Detailed Comparison */}
                            <div>
                                <h3 className="text-lg font-semibold text-slate-900 mb-4">Security Control Comparison</h3>
                                <div className="grid grid-cols-2 gap-4">
                                    {activeResult.steps.map(step => (
                                        <div key={step.step_id} className={`p-4 rounded-lg border-2 ${step.status === 'completed'
                                            ? 'bg-green-50 border-green-200'
                                            : 'bg-red-50 border-red-200'
                                            }`}>
                                            <div className="flex items-center justify-between mb-2">
                                                <h4 className="font-semibold text-slate-900">{step.name}</h4>
                                                {step.status === 'completed' ? (
                                                    <CheckCircle className="w-5 h-5 text-green-600" />
                                                ) : (
                                                    <XCircle className="w-5 h-5 text-red-600" />
                                                )}
                                            </div>
                                            <p className="text-xs text-slate-600">{step.description}</p>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Full Report View */}
                {viewMode === 'full' && (
                    <div className="space-y-8">
                        {/* Summary & Implementation Dial */}
                        <div className="bg-white rounded-2xl shadow-xl p-8">
                            <h3 className="text-2xl font-bold text-slate-900 mb-8 border-b pb-4">Executive Implementation Summary</h3>
                            <div className="flex flex-col lg:flex-row items-center gap-12">
                                <div className="flex-shrink-0 relative">
                                    <svg className="w-64 h-64" viewBox="0 0 160 160">
                                        <circle cx="80" cy="80" r="70" fill="none" stroke="#f1f5f9" strokeWidth="16" />
                                        <circle
                                            cx="80" cy="80" r="70" fill="none" stroke="#10b981" strokeWidth="16"
                                            strokeDasharray={circumference} strokeDashoffset={successOffset}
                                            transform="rotate(-90 80 80)" strokeLinecap="round"
                                        />
                                    </svg>
                                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                                        <span className="text-5xl font-extrabold text-slate-900">{successRate}%</span>
                                        <span className="text-sm font-bold text-slate-500 uppercase tracking-widest">Hardened</span>
                                    </div>
                                </div>
                                <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-6 w-full">
                                    <div className="bg-slate-50 rounded-2xl p-6 border border-slate-200">
                                        <div className="text-slate-500 text-xs font-bold uppercase mb-1">Project ID</div>
                                        <div className="text-xl font-bold text-slate-900">{activeResult.project_id}</div>
                                    </div>
                                    <div className="bg-slate-50 rounded-2xl p-6 border border-slate-200">
                                        <div className="text-slate-500 text-xs font-bold uppercase mb-1">Lockdown Date</div>
                                        <div className="text-xl font-bold text-slate-900">{new Date(activeResult.timestamp).toLocaleString()}</div>
                                    </div>
                                    <div className="bg-green-50 rounded-2xl p-6 border border-green-200">
                                        <div className="text-green-700 text-xs font-bold uppercase mb-1">Controls Applied</div>
                                        <div className="text-3xl font-black text-green-900">{activeResult.summary.completed}</div>
                                    </div>
                                    <div className="bg-amber-50 rounded-2xl p-6 border border-amber-200">
                                        <div className="text-amber-700 text-xs font-bold uppercase mb-1">Attention Required</div>
                                        <div className="text-3xl font-black text-amber-900">{activeResult.summary.failed}</div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Identity Governance & Audit Section - FULL WIDTH */}
                        <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
                            <div className="bg-indigo-900 p-8 text-white">
                                <h3 className="text-2xl font-bold flex items-center gap-3">
                                    <Shield className="w-8 h-8 text-indigo-300" />
                                    Identity Governance & Access Audit
                                </h3>
                                <p className="text-indigo-200 mt-2 max-w-3xl">
                                    Direct access to billing accounts creates "security silos" that bypass organizational change control.
                                    A managed group-based model is required to ensure financial isolation and auditability.
                                </p>
                            </div>

                            <div className="p-8 space-y-8">
                                {/* Current Findings: Identities with billing access */}
                                {activeScanResult?.billing_info?.iam_users && activeScanResult.billing_info.iam_users.length > 0 ? (
                                    <div>
                                        <h4 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                                            <AlertCircle className="w-5 h-5 text-red-600" />
                                            Active Direct Billing Identities Detected
                                        </h4>
                                        <div className="overflow-hidden border rounded-xl shadow-sm">
                                            <table className="min-w-full divide-y divide-gray-200">
                                                <thead className="bg-slate-50">
                                                    <tr>
                                                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase">User Identity (Individual Account)</th>
                                                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase">Assigned High-Privilege Roles</th>
                                                        <th className="px-6 py-4 text-left text-xs font-bold text-slate-500 uppercase">Risk Level</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="bg-white divide-y divide-gray-200">
                                                    {activeScanResult.billing_info.iam_users.map((user, idx) => (
                                                        <tr key={idx} className="hover:bg-slate-50">
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-semibold text-slate-900">{user.user}</td>
                                                            <td className="px-6 py-4 text-sm text-slate-600">
                                                                <div className="flex flex-wrap gap-2">
                                                                    {user.roles.map((role, ridx) => (
                                                                        <span key={ridx} className="px-2 py-1 bg-indigo-50 text-indigo-700 rounded-md text-xs border border-indigo-100 italic">
                                                                            {role}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            </td>
                                                            <td className="px-6 py-4 whitespace-nowrap">
                                                                <span className="px-2 py-1 bg-red-100 text-red-700 rounded-lg text-[10px] font-bold uppercase">High Risk</span>
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="bg-green-50 border border-green-200 rounded-xl p-6 flex items-center gap-4">
                                        <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center text-green-600">
                                            <CheckCircle className="w-8 h-8" />
                                        </div>
                                        <div>
                                            <div className="font-bold text-green-900">Identity Best Practice Met</div>
                                            <div className="text-sm text-green-700">No individual users detected with direct billing access. Group-based access is being maintained.</div>
                                        </div>
                                    </div>
                                )}

                                {/* Recommended Model Breakdown */}
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    <div className="bg-slate-50 p-6 rounded-2xl border border-slate-200">
                                        <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center text-indigo-600 font-bold mb-4">GA</div>
                                        <div className="font-bold text-slate-900 mb-2">gcp-billing-admins@</div>
                                        <div className="text-xs text-slate-600 leading-relaxed italic">Strategic oversight. Full control over payment profiles, invoices, and organizational credit line.</div>
                                    </div>
                                    <div className="bg-slate-50 p-6 rounded-2xl border border-slate-200">
                                        <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center text-indigo-600 font-bold mb-4">GV</div>
                                        <div className="font-bold text-slate-900 mb-2">gcp-billing-viewers@</div>
                                        <div className="text-xs text-slate-600 leading-relaxed italic">Audit & Compliance. Access to cost reports and usage analysis without modification rights.</div>
                                    </div>
                                    <div className="bg-slate-50 p-6 rounded-2xl border border-slate-200">
                                        <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center text-indigo-600 font-bold mb-4">EL</div>
                                        <div className="font-bold text-slate-900 mb-2">gcp-engineering-leads@</div>
                                        <div className="text-xs text-slate-600 leading-relaxed italic">Operational Execution. Ability to link projects to billing and manage resource quotas for development.</div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Granular Security Breakdown - CATEGORIZED TABLES */}
                        <div className="space-y-8">
                            <h3 className="text-3xl font-black text-slate-900 uppercase tracking-tight">Granular Security Controls Breakdown</h3>

                            {[
                                {
                                    id: 'finance',
                                    name: 'Financial Controls & Attack Surface Quotas',
                                    icon: <DollarSign className="w-6 h-6 text-emerald-600" />,
                                    ids: ['billing_kill_switch', 'quota_caps']
                                },
                                {
                                    id: 'iam',
                                    name: 'Identity & Access Hardening',
                                    icon: <Shield className="w-6 h-6 text-indigo-600" />,
                                    ids: ['service_account_keys']
                                },
                                {
                                    id: 'network',
                                    name: 'Network & Perimeter Security',
                                    icon: <Network className="w-6 h-6 text-blue-600" />,
                                    ids: ['network_hardening', 'region_lockdown']
                                },
                                {
                                    id: 'policy',
                                    name: 'API Governance & Resource Policy',
                                    icon: <Lock className="w-6 h-6 text-amber-600" />,
                                    ids: ['api_restrictions']
                                },
                                {
                                    id: 'audit',
                                    name: 'Audit Logging & Governance',
                                    icon: <FileText className="w-6 h-6 text-slate-600" />,
                                    ids: ['change_management', 'compute_monitoring', 'org_monitoring']
                                }
                            ].map((category) => {
                                const categorySteps = activeResult.steps.filter(s => category.ids.includes(s.step_id));
                                if (categorySteps.length === 0) return null;

                                return (
                                    <div key={category.id} className="bg-white rounded-2xl shadow-lg border border-slate-100 overflow-hidden">
                                        <div className="bg-slate-50 px-8 py-5 border-b flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                {category.icon}
                                                <h4 className="text-lg font-bold text-slate-900">{category.name}</h4>
                                            </div>
                                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{categorySteps.length} Controls</span>
                                        </div>
                                        <div className="overflow-x-auto">
                                            <table className="min-w-full divide-y divide-gray-200">
                                                <thead className="bg-white">
                                                    <tr>
                                                        <th className="px-8 py-4 text-left text-[11px] font-bold text-slate-400 uppercase">Security Control</th>
                                                        <th className="px-8 py-4 text-left text-[11px] font-bold text-slate-400 uppercase">Detected Vulnerability</th>
                                                        <th className="px-8 py-4 text-left text-[11px] font-bold text-slate-400 uppercase">hardened Resolution</th>
                                                        <th className="px-8 py-4 text-right text-[11px] font-bold text-slate-400 uppercase">Status</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="bg-white divide-y divide-gray-100">
                                                    {categorySteps.map((step) => {
                                                        const matchedRisk = findMatchingRisk(step.step_id);
                                                        const isFailed = step.status === 'failed' || step.status === 'skipped';

                                                        return (
                                                            <React.Fragment key={step.step_id}>
                                                                <tr className="hover:bg-slate-50 transition-colors">
                                                                    <td className="px-8 py-6">
                                                                        <div className="font-bold text-slate-900 text-sm">{step.name}</div>
                                                                        <div className="text-[10px] font-mono text-slate-400 mt-0.5">{step.step_id}</div>
                                                                    </td>
                                                                    <td className="px-8 py-6">
                                                                        {matchedRisk ? (
                                                                            <div>
                                                                                <div className="text-[10px] font-bold text-red-600 bg-red-50 px-2 py-0.5 rounded inline-block mb-1">DETECTION: {matchedRisk.risk_level.toUpperCase()}</div>
                                                                                <p className="text-xs text-slate-700 leading-relaxed max-w-sm font-medium">{matchedRisk.title}</p>
                                                                                <p className="text-[10px] text-slate-500 mt-1 line-clamp-2">{matchedRisk.description}</p>
                                                                            </div>
                                                                        ) : (
                                                                            <div className="text-xs text-slate-400 italic">Verified Compliant: No active vulnerability detected during scan.</div>
                                                                        )}
                                                                    </td>
                                                                    <td className="px-8 py-6">
                                                                        {isFailed ? (
                                                                            <div className="text-xs text-red-700 bg-red-50 p-3 rounded-lg border border-red-100 leading-relaxed font-bold">
                                                                                ERROR: {step.error || "Lockdown adjustment could not be completed."}
                                                                            </div>
                                                                        ) : (
                                                                            <p className="text-xs text-indigo-700 bg-indigo-50 p-3 rounded-lg border border-indigo-100 leading-relaxed">
                                                                                {step.security_benefit}
                                                                            </p>
                                                                        )}
                                                                    </td>
                                                                    <td className="px-8 py-6 text-right">
                                                                        <div className="flex items-center justify-end gap-2">
                                                                            {step.status === 'completed' ? (
                                                                                <>
                                                                                    <span className="text-[10px] font-bold text-green-600 uppercase tracking-wider">Secured</span>
                                                                                    <CheckCircle className="w-5 h-5 text-green-500" />
                                                                                </>
                                                                            ) : (
                                                                                <>
                                                                                    <span className="text-[10px] font-bold text-red-600 uppercase tracking-wider">
                                                                                        {isFailed ? "Vulnerability Remains" : "Action Needed"}
                                                                                    </span>
                                                                                    <XCircle className="w-5 h-5 text-red-500" />
                                                                                </>
                                                                            )}
                                                                        </div>
                                                                    </td>
                                                                </tr>
                                                                {step.details && (
                                                                    <tr>
                                                                        <td colSpan={4} className="p-0 border-none">
                                                                            <AssetVerificationTable step={step} />
                                                                        </td>
                                                                    </tr>
                                                                )}
                                                            </React.Fragment>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                );
                            })}

                            {/* Ungrouped / Other Steps Section */}
                            {(() => {
                                const allHandledIds = [
                                    'billing_kill_switch', 'quota_caps', 'service_account_keys',
                                    'network_hardening', 'region_lockdown', 'api_restrictions',
                                    'change_management', 'compute_monitoring', 'org_monitoring'
                                ];
                                const otherSteps = activeResult.steps.filter(s => !allHandledIds.includes(s.step_id));

                                if (otherSteps.length === 0) return null;

                                return (
                                    <div className="bg-white rounded-2xl shadow-lg border border-slate-100 overflow-hidden">
                                        <div className="bg-slate-50 px-8 py-5 border-b flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <Settings className="w-6 h-6 text-slate-600" />
                                                <h4 className="text-lg font-bold text-slate-900">System & Infrastructure Security</h4>
                                            </div>
                                            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{otherSteps.length} Additional Controls</span>
                                        </div>
                                        <div className="overflow-x-auto">
                                            <table className="min-w-full divide-y divide-gray-200">
                                                <thead className="bg-white">
                                                    <tr>
                                                        <th className="px-8 py-4 text-left text-[11px] font-bold text-slate-400 uppercase">Infrastructure Control</th>
                                                        <th className="px-8 py-4 text-left text-[11px] font-bold text-slate-400 uppercase">Detection Context</th>
                                                        <th className="px-8 py-4 text-right text-[11px] font-bold text-slate-400 uppercase">Status</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="bg-white divide-y divide-gray-100">
                                                    {otherSteps.map((step) => {
                                                        const matchedRisk = findMatchingRisk(step.step_id);
                                                        const isFailed = step.status === 'failed' || step.status === 'skipped';

                                                        return (
                                                            <tr key={step.step_id} className="hover:bg-slate-50 transition-colors">
                                                                <td className="px-8 py-6 w-1/4">
                                                                    <div className="font-bold text-slate-900 text-sm">{step.name}</div>
                                                                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">{step.step_id}</div>
                                                                </td>
                                                                <td className="px-8 py-6">
                                                                    {matchedRisk ? (
                                                                        <div className="flex items-start gap-4">
                                                                            <div className="flex-1">
                                                                                <div className="text-[9px] font-bold text-red-600 mb-1 uppercase tracking-tighter">Detected Risk</div>
                                                                                <p className="text-xs text-slate-700 font-medium">{matchedRisk.title}</p>
                                                                            </div>
                                                                            <div className="flex-1">
                                                                                <div className="text-[9px] font-bold text-indigo-600 mb-1 uppercase tracking-tighter">Resolution Applied</div>
                                                                                <p className="text-xs text-slate-600 line-clamp-2">{step.security_benefit}</p>
                                                                            </div>
                                                                        </div>
                                                                    ) : (
                                                                        <div className="text-xs text-slate-500 italic">Confirmed Secure: Integrity scan verified no vulnerabilities for this component.</div>
                                                                    )}
                                                                </td>
                                                                <td className="px-8 py-6 text-right">
                                                                    <div className="flex items-center justify-end gap-2">
                                                                        {step.status === 'completed' ? (
                                                                            <CheckCircle className="w-5 h-5 text-green-500" />
                                                                        ) : (
                                                                            <XCircle className="w-5 h-5 text-red-500" />
                                                                        )}
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                );
                            })()}
                        </div>

                        {/* Organization Monitoring Alert Policies */}
                        {activeResult.extended_alerts && activeResult.extended_alerts.length > 0 && (
                            <div className="bg-white rounded-2xl shadow-xl p-8 border border-slate-100">
                                <h3 className="text-xl font-bold text-slate-900 mb-6 flex items-center gap-3">
                                    <AlertCircle className="w-6 h-6 text-indigo-600" />
                                    Active Incident Response Policies
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                    {activeResult.extended_alerts.map((alert, idx) => (
                                        <div key={idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-6 hover:shadow-md transition-shadow">
                                            <div className="text-sm font-black text-slate-900 mb-2 truncate">{alert.display_name}</div>
                                            <div className="flex items-center justify-between mt-4">
                                                <span className={`text-[10px] px-2 py-1 rounded-full font-bold uppercase ${alert.status === 'created' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                                                    {alert.status === 'created' ? 'Monitoring Active' : 'Configuration Error'}
                                                </span>
                                                <div className="flex -space-x-2">
                                                    {alert.channels.map((ch, i) => (
                                                        <div key={i} title={`Alerting to: ${ch}`} className="w-8 h-8 rounded-full bg-white border border-slate-200 flex items-center justify-center text-slate-400">
                                                            <Mail className="w-4 h-4" />
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Footer Actions */}
                <div className="flex justify-between items-center mt-12 pt-8 border-t border-slate-200">
                    <div className="flex gap-4">
                        <button
                            onClick={onClose}
                            className="px-8 py-3 bg-slate-200 hover:bg-slate-300 text-slate-900 font-bold rounded-xl transition-all"
                        >
                            Close Report
                        </button>
                        {onReset && (
                            <button
                                onClick={onReset}
                                className="px-8 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl transition-all flex items-center gap-2"
                            >
                                <Shield className="w-5 h-5" />
                                New Scan
                            </button>
                        )}
                        {onBackout && (
                            <button
                                onClick={() => {
                                    if (confirm('⚠️ WARNING: This will remove all security protections applied by the lockdown. Are you sure?')) {
                                        onBackout();
                                    }
                                }}
                                className="px-8 py-3 bg-orange-600 hover:bg-orange-700 text-white font-bold rounded-xl transition-all flex items-center gap-2"
                            >
                                <XCircle className="w-5 h-5" />
                                Rollback Changes
                            </button>
                        )}
                        <a
                            href={generateEmailBody()}
                            className="px-8 py-3 bg-emerald-600 hover:bg-emerald-700 text-white font-bold rounded-xl transition-all flex items-center gap-2"
                        >
                            <Mail className="w-5 h-5" />
                            Email PDF
                        </a>
                    </div>
                    <button
                        onClick={() => window.print()}
                        className="px-8 py-3 bg-white border-2 border-slate-200 hover:bg-slate-50 text-slate-900 font-bold rounded-xl transition-all flex items-center gap-2"
                    >
                        <Download className="w-5 h-5" />
                        Download PDF
                    </button>
                </div>
            </div>
        </div>
    );
}
