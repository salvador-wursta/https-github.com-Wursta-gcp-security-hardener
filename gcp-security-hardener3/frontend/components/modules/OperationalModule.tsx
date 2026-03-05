import React from 'react';
import { Shield, AlertCircle, CheckCircle, Search } from 'lucide-react';

interface SCCInfo {
    status: string;
    tier: string;
    findings: SCCFinding[];
}

interface SCCFinding {
    category: string;
    state: string;
    severity: string;
    event_time: string;
    resource_name: string;
    external_uri: string;
}

interface OperationalModuleProps {
    data?: SCCInfo;
    loading?: boolean;
}

export default function OperationalModule({ data, loading }: OperationalModuleProps) {
    if (loading) {
        return (
            <div className="p-8 text-center animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-3/4 mx-auto mb-4"></div>
                <div className="h-32 bg-gray-100 rounded mb-4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/2 mx-auto"></div>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="p-8 text-center bg-gray-50 rounded-lg border border-gray-200">
                <p className="text-gray-500">No Security Command Center data available.</p>
                <p className="text-xs text-gray-400 mt-2">Ensure the SCC API is enabled and your service account has 'securitycenter.admin' permissions.</p>
            </div>
        );
    }

    const { status, tier, findings } = data;
    const isActive = status === 'ACTIVE';
    const isPremium = tier === 'PREMIUM';

    // Group findings by severity
    const severityCount = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Title Header */}
            <div>
                <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
                    <Shield className="w-6 h-6 text-gray-700" />
                    Operational & SCC
                </h2>
                <p className="text-gray-500 text-sm mt-1">Security Command Center findings and operational status.</p>
            </div>

            {/* Status Header */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className={`p-6 rounded-xl shadow-sm border ${isActive ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                    <div className="flex items-center gap-3 mb-2">
                        {isActive ? <CheckCircle className="w-5 h-5 text-green-600" /> : <AlertCircle className="w-5 h-5 text-red-600" />}
                        <p className={`text-sm font-medium uppercase tracking-wider ${isActive ? 'text-green-700' : 'text-red-700'}`}>
                            SCC Status
                        </p>
                    </div>
                    <h3 className={`text-2xl font-extrabold ${isActive ? 'text-green-900' : 'text-red-900'}`}>
                        {status || 'UNKNOWN'}
                    </h3>
                    <p className={`text-xs mt-2 ${isActive ? 'text-green-800' : 'text-red-800'}`}>
                        {isActive
                            ? "Security Command Center is monitoring your organization."
                            : "SCC is not active or could not be reached."}
                    </p>
                </div>

                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-2">Service Tier</p>
                    <div className="flex items-center gap-2">
                        <h3 className="text-2xl font-extrabold text-blue-900">{tier || 'UNKNOWN'}</h3>
                        {isPremium && <span className="px-2 py-0.5 bg-yellow-100 text-yellow-800 text-xs font-bold rounded-full">GOLD</span>}
                    </div>
                    <p className="text-xs text-gray-400 mt-2">
                        {tier === 'PREMIUM'
                            ? "Advanced threat detection (Event Threat Detection, Container Threat Detection) enabled."
                            : "Standard tier includes basic misconfiguration scanning."}
                    </p>
                </div>
            </div>

            {/* Findings Summary */}
            {findings.length > 0 && (
                <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                    <div className="px-6 py-4 border-b border-gray-100 bg-gray-50 flex justify-between items-center">
                        <h3 className="font-bold text-gray-900 flex items-center gap-2">
                            <Shield className="w-5 h-5 text-blue-600" />
                            Active Findings
                        </h3>
                        <div className="flex gap-2">
                            {Object.entries(severityCount).map(([sev, count]) => (
                                <span key={sev} className={`px-2 py-1 rounded text-xs font-bold
                                    ${sev === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                        sev === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                                            'bg-gray-100 text-gray-600'}`}>
                                    {sev}: {count}
                                </span>
                            ))}
                        </div>
                    </div>
                    <div className="px-6 py-4">
                        <p className="text-sm text-gray-500 mb-4">Most recent findings from Security Command Center:</p>
                        <div className="space-y-3">
                            {findings.slice(0, 5).map((finding, idx) => (
                                <div key={idx} className="flex justify-between items-start p-3 bg-gray-50 rounded-lg border border-gray-100 hover:bg-white hover:border-blue-200 hover:shadow-sm transition-all">
                                    <div className="flex-1 min-w-0 pr-4">
                                        <p className="font-bold text-gray-900 truncate">{finding.category}</p>
                                        <div className="overflow-x-auto pb-2 max-w-[250px] sm:max-w-md md:max-w-xl lg:max-w-2xl xl:max-w-4xl custom-scrollbar">
                                            <p className="text-xs text-gray-600 font-mono mt-0.5 whitespace-nowrap bg-gray-50/50 pr-4">
                                                {/* If it's an error message disguised as a finding, show full text. Otherwise show resource ID */}
                                                {finding.category.includes('Error') ? finding.resource_name : finding.resource_name.split('/').pop()}
                                            </p>
                                        </div>
                                        {finding.category.includes('Disabled') && (
                                            <a
                                                href={finding.external_uri}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="text-xs text-blue-600 hover:underline mt-1 inline-block"
                                            >
                                                Enable API →
                                            </a>
                                        )}
                                    </div>
                                    <div className="text-right">
                                        <span className={`px-2 py-0.5 rounded text-xs font-bold
                                            ${finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                                finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                                                    'bg-blue-50 text-blue-600'}`}>
                                            {finding.severity}
                                        </span>
                                        <p className="text-[10px] text-gray-400 mt-1">{new Date(finding.event_time).toLocaleDateString()}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                        {findings.length > 5 && (
                            <div className="mt-4 text-center">
                                <a href={findings[0].external_uri} target="_blank" rel="noopener noreferrer" className="text-sm text-blue-600 hover:underline flex items-center justify-center gap-1">
                                    View all {findings.length} findings in Cloud Console <Search className="w-3 h-3" />
                                </a>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
