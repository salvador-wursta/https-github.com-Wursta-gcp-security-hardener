import React from 'react';
import { Activity, Bell, FileText, CheckCircle, AlertTriangle, Eye, Shield } from 'lucide-react';

interface MonitoringModuleProps {
    scanData: any;
}

export default function MonitoringModule({ scanData }: MonitoringModuleProps) {
    // Graceful fallback if no monitoring data
    if (!scanData || !scanData.monitoring_analysis) {
        return (
            <div className="p-8 text-center text-gray-500 bg-white border rounded-xl border-dashed">
                <Activity className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                <p>Run a scan with the 'Monitoring' module selected to view details.</p>
            </div>
        );
    }

    const { apis_enabled, alert_policies, cis_benchmark_coverage } = scanData.monitoring_analysis;

    // Helper for status badge
    const StatusBadge = ({ active }: { active: boolean }) => (
        <span className={`px-2 py-0.5 rounded text-xs font-medium border flex items-center gap-1 w-fit ${active
            ? 'bg-green-100 text-green-800 border-green-200'
            : 'bg-red-100 text-red-800 border-red-200'
            }`}>
            {active ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
            {active ? 'Active' : 'Missing'}
        </span>
    );

    return (
        <div className="space-y-6 animate-in fade-in duration-500">

            {/* Header Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${apis_enabled.logging ? 'bg-blue-100' : 'bg-red-100'}`}>
                        <FileText className={`w-6 h-6 ${apis_enabled.logging ? 'text-blue-600' : 'text-red-600'}`} />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Cloud Logging API</p>
                        <p className="text-lg font-bold text-gray-900">{apis_enabled.logging ? 'Enabled' : 'Disabled'}</p>
                    </div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${apis_enabled.monitoring ? 'bg-indigo-100' : 'bg-red-100'}`}>
                        <Activity className={`w-6 h-6 ${apis_enabled.monitoring ? 'text-indigo-600' : 'text-red-600'}`} />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Cloud Monitoring API</p>
                        <p className="text-lg font-bold text-gray-900">{apis_enabled.monitoring ? 'Enabled' : 'Disabled'}</p>
                    </div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className="p-3 bg-purple-100 rounded-lg">
                        <Bell className="w-6 h-6 text-purple-600" />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Active Alert Policies</p>
                        <p className="text-lg font-bold text-gray-900">{alert_policies.length}</p>
                    </div>
                </div>
            </div>

            {/* CIS Benchmark Compliance Table */}
            <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
                <div className="bg-gray-50 px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                    <h3 className="font-bold text-gray-900 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-gray-500" />
                        CIS 2.0 Logging Benchmarks
                    </h3>
                    <span className="text-xs text-gray-500">Essential alerts for security compliance</span>
                </div>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Requirement</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Why it matters</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {[
                                { k: 'vpc_changes', label: 'VPC Network Changes', desc: 'Detects unauthorized firewall rule or route modifications.' },
                                { k: 'iam_changes', label: 'IAM/Role Changes', desc: 'Alerts when permissions are granted or custom roles modified.' },
                                { k: 'project_ownership', label: 'Project Ownership', desc: 'Critical: Alerts when a new Owner is added to the project.' },
                                { k: 'audit_config', label: 'Audit Config Changes', desc: 'Ensures nobody silently disables the audit logs themselves.' },
                                { k: 'crypto_keys', label: 'KMS Key Destruction', desc: 'Detects attempts to destroy encryption keys (data loss risk).' },
                            ].map((item) => (
                                <tr key={item.k} className="hover:bg-gray-50">
                                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{item.label}</td>
                                    <td className="px-6 py-4">
                                        <StatusBadge active={cis_benchmark_coverage[item.k]} />
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-500">{item.desc}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Existing Alert Policies List */}
            {alert_policies.length > 0 && (
                <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
                    <div className="bg-gray-50 px-6 py-4 border-b border-gray-200">
                        <h3 className="font-bold text-gray-900 flex items-center gap-2">
                            <Eye className="w-5 h-5 text-gray-500" />
                            Active Alert Policies
                        </h3>
                    </div>
                    <ul className="divide-y divide-gray-200">
                        {alert_policies.map((p: any) => (
                            <li key={p.name} className="px-6 py-4 flex items-center justify-between hover:bg-gray-50">
                                <div>
                                    <p className="text-sm font-medium text-gray-900">{p.display_name}</p>
                                    <p className="text-xs text-gray-500 font-mono mt-0.5">{p.name.split('/').pop()}</p>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className={`text-xs px-2 py-1 rounded ${p.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                                        {p.enabled ? 'Enabled' : 'Disabled'}
                                    </span>
                                </div>
                            </li>
                        ))}
                    </ul>

                    {/* Duplicate Detection Section */}
                    {(() => {
                        const duplicates = alert_policies.reduce((acc: any, p: any) => {
                            acc[p.display_name] = (acc[p.display_name] || []).concat(p);
                            return acc;
                        }, {});

                        const duplicateGroups = Object.entries(duplicates)
                            .filter(([_, policies]: [string, any]) => policies.length > 1);

                        if (duplicateGroups.length === 0) return null;

                        return (
                            <div className="bg-yellow-50 border-t border-yellow-200 p-6">
                                <h4 className="flex items-center gap-2 text-yellow-800 font-bold mb-2">
                                    <AlertTriangle className="w-5 h-5" />
                                    Duplicate Alerts Detected
                                </h4>
                                <p className="text-sm text-yellow-700 mb-4">
                                    The following alert policies appear to be duplicates. Having multiple alerts for the same condition can lead to notification spam.
                                    We recommend keeping only one active policy per condition and deleting the redundant ones.
                                </p>
                                <div className="space-y-4">
                                    {duplicateGroups.map(([name, policies]: [string, any]) => (
                                        <div key={name} className="bg-white border border-yellow-200 rounded-lg p-3 text-sm">
                                            <p className="font-semibold text-gray-900 mb-2">"{name}"</p>
                                            <p className="text-gray-500 mb-2">Found {policies.length} instances. Delete {policies.length - 1} of these:</p>
                                            <ul className="list-disc pl-5 space-y-1 text-gray-600 font-mono text-xs">
                                                {policies.map((p: any) => (
                                                    <li key={p.name}>
                                                        ID: {p.name.split('/').pop()} ({p.enabled ? 'Enabled' : 'Disabled'})
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        );
                    })()}
                </div>
            )}
        </div>
    );
}
