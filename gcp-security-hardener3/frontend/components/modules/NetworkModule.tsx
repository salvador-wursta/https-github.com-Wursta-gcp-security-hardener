import React from 'react';
import { Shield, AlertTriangle, CheckCircle, Server, Activity } from 'lucide-react';

interface RiskCard {
    id: string;
    title: string;
    description: string;
    risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
    category: string;
    recommendation: string;
    is_fixable?: boolean;
}

interface NetworkModuleProps {
    risks: RiskCard[];
    loading?: boolean;
}

export default function NetworkModule({ risks, loading }: NetworkModuleProps) {
    if (loading) {
        return (
            <div className="p-8 text-center animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-3/4 mx-auto mb-4"></div>
                <div className="h-32 bg-gray-100 rounded mb-4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/2 mx-auto"></div>
            </div>
        );
    }

    // Filter risks specific to network
    const networkRisks = risks.filter(r => r.category === 'network');
    const isSecure = networkRisks.length === 0;

    // Detect specific issues based on risk IDs (heuristic)
    const hasFirewallIssue = networkRisks.some(r => r.id.includes('firewall') || r.description.toLowerCase().includes('firewall'));
    const hasFlowLogIssue = networkRisks.some(r => r.id.includes('flow_log') || r.description.toLowerCase().includes('flow logs'));

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header / Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Card 1: Overall Status */}
                <div className={`p-6 rounded-xl shadow-sm border ${isSecure ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                    <div className="flex items-center gap-3 mb-2">
                        {isSecure ? <CheckCircle className="w-5 h-5 text-green-600" /> : <Shield className="w-5 h-5 text-red-600" />}
                        <p className={`text-sm font-medium uppercase tracking-wider ${isSecure ? 'text-green-700' : 'text-red-700'}`}>
                            Network Status
                        </p>
                    </div>
                    <h3 className={`text-2xl font-extrabold ${isSecure ? 'text-green-900' : 'text-red-900'}`}>
                        {isSecure ? 'Secure' : 'Needs Attention'}
                    </h3>
                    <p className={`text-xs mt-2 ${isSecure ? 'text-green-800' : 'text-red-800'}`}>
                        {isSecure
                            ? "No critical network vulnerabilities detected."
                            : `${networkRisks.length} vulnerabilities detected affecting your VPC.`}
                    </p>
                </div>

                {/* Card 2: Firewall Health */}
                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <div className="flex items-center gap-3 mb-2">
                        <Server className="w-5 h-5 text-blue-500" />
                        <p className="text-sm font-medium text-gray-500 uppercase tracking-wider">Firewall Rules</p>
                    </div>
                    {hasFirewallIssue ? (
                        <div className="mt-1">
                            <span className="text-xl font-bold text-red-600">Unprotected</span>
                            <p className="text-xs text-gray-400 mt-1">Default "allow-all" rules may be active. Missing "deny-external-ingress".</p>
                        </div>
                    ) : (
                        <div className="mt-1">
                            <span className="text-xl font-bold text-green-600">Protected</span>
                            <p className="text-xs text-gray-400 mt-1">External ingress blocked. Default rules sanitized.</p>
                        </div>
                    )}
                </div>

                {/* Card 3: Traffic Analysis */}
                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <div className="flex items-center gap-3 mb-2">
                        <Activity className="w-5 h-5 text-purple-500" />
                        <p className="text-sm font-medium text-gray-500 uppercase tracking-wider">VPC Flow Logs</p>
                    </div>
                    {hasFlowLogIssue ? (
                        <div className="mt-1">
                            <span className="text-xl font-bold text-yellow-600">Disabled</span>
                            <p className="text-xs text-gray-400 mt-1">Traffic is not being logged for auditing.</p>
                        </div>
                    ) : (
                        <div className="mt-1">
                            <span className="text-xl font-bold text-gray-400">Not Checked</span>
                            <p className="text-xs text-gray-400 mt-1">Flow log analysis requires extended scan.</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Findings Section */}
            {networkRisks.length > 0 ? (
                <div className="space-y-4">
                    <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                        <span className="text-xl">🚨</span> Network Vulnerabilities
                    </h3>
                    <div className="grid grid-cols-1 gap-4">
                        {networkRisks.map((risk, index) => (
                            <div key={`${risk.id}-${index}`} className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg">
                                <div className="flex justify-between items-start">
                                    <div>
                                        <h4 className="font-bold text-red-900">{risk.title}</h4>
                                        <p className="text-sm text-red-800 mt-1">{risk.description}</p>
                                    </div>
                                    <span className="bg-red-200 text-red-800 text-xs px-2 py-1 rounded font-bold uppercase">
                                        {risk.risk_level}
                                    </span>
                                </div>
                                <div className="mt-3 pt-3 border-t border-red-200">
                                    <p className="text-xs font-bold text-red-900 uppercase">Remediation:</p>
                                    <p className="text-sm text-red-800 mt-0.5">{risk.recommendation}</p>
                                </div>
                                {risk.is_fixable && (
                                    <div className="mt-3 flex justify-end">
                                        <span className="text-xs font-medium text-blue-700 bg-blue-100 px-2 py-1 rounded flex items-center gap-1">
                                            ⚡ Auto-fix available in Lockdown
                                        </span>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            ) : (
                <div className="p-8 bg-green-50 rounded-xl border border-green-200 text-center">
                    <div className="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-3">
                        <CheckCircle className="w-6 h-6 text-green-600" />
                    </div>
                    <h3 className="font-bold text-green-900">Network is Secure</h3>
                    <p className="text-green-700 mt-1">No critical network misconfigurations were found in the scanned VPCs.</p>
                </div>
            )}

            {/* General Best Practices Info */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
                    <h3 className="font-bold text-gray-900">Network Hardening Best Practices</h3>
                </div>
                <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6 text-sm text-gray-600">
                    <div className="flex gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 font-bold text-xs shrink-0">1</div>
                        <div>
                            <p className="font-medium text-gray-900">Deny External Ingress</p>
                            <p className="mt-1">Block all incoming traffic from 0.0.0.0/0 by default. Allow only specific IPs via IAP or VPN.</p>
                        </div>
                    </div>
                    <div className="flex gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 font-bold text-xs shrink-0">2</div>
                        <div>
                            <p className="font-medium text-gray-900">Use Identity-Aware Proxy (IAP)</p>
                            <p className="mt-1">Instead of opening Port 22 (SSH) or 3389 (RDP) to the world, use GCP IAP for secure remote access.</p>
                        </div>
                    </div>
                    <div className="flex gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 font-bold text-xs shrink-0">3</div>
                        <div>
                            <p className="font-medium text-gray-900">Enable VPC Flow Logs</p>
                            <p className="mt-1">Turn on Flow Logs for critical subnets to audit network traffic and detect anomalies.</p>
                        </div>
                    </div>
                    <div className="flex gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 font-bold text-xs shrink-0">4</div>
                        <div>
                            <p className="font-medium text-gray-900">Private Google Access</p>
                            <p className="mt-1">Enable Private Google Access to allow VMs without external IPs to reach Google APIs securely.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
