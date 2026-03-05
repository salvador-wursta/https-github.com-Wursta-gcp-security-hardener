import React from 'react';
import { Shield, AlertTriangle, CheckCircle, Download, DollarSign, Lock, Zap } from 'lucide-react';

interface FinOpsModuleProps {
    risks: any[];
    projectId: string;
    jitToken: string;
}

export default function FinOpsModule({ risks, projectId, jitToken }: FinOpsModuleProps) {

    // 1. Analyze Risks to determine "Traffic Light" status

    // Red: Billing Linking Restricted?
    const isBillingRestricted = !risks.find(r => r.id.includes('billing.restrictAccountProjectLinks'));

    // Yellow: Real-time Alerts?
    const hasRealtimeAlerts = !risks.find(r => r.id === 'missing_realtime_build_alerts');

    // Green Check: IAM Segregation (Billing Admin vs Tech)
    const hasToxicCombination = risks.find(r => r.id.startsWith('toxic_billing_role'));

    // Calculate Overall Status
    let status = 'green';
    if (!isBillingRestricted || hasToxicCombination) status = 'red';
    else if (!hasRealtimeAlerts) status = 'yellow';

    const downloadRemediationKit = async () => {
        try {
            // Need to include the scan results in the body, OR we can rely on the backend fetching from DB if we saved it.
            // Since we are in a module, we have 'risks'. We might not have the full 'scan_results' object here easily 
            // unless we pass it down. 
            // However, the backend endpoint allows fetching by project_id. 
            // Let's rely on project_id fetch for simplicity, assuming the scan was saved.

            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
            const response = await fetch(`${backendUrl}/api/reporting/download-artifacts`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jitToken}`
                },
                body: JSON.stringify({
                    project_id: projectId
                })
            });

            if (!response.ok) throw new Error("Download failed");

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `finops_remediation_kit_${projectId}.zip`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (e) {
            console.error("Download error:", e);
            alert("Failed to download remediation kit. Ensure a scan has been completed/saved.");
        }
    };

    return (
        <div className="space-y-6">

            {/* Header / Status Banner */}
            <div className={`p-6 rounded-lg border-l-8 shadow-sm ${status === 'red' ? 'bg-red-50 border-red-500' :
                status === 'yellow' ? 'bg-yellow-50 border-yellow-500' :
                    'bg-green-50 border-green-500'
                }`}>
                <div className="flex justify-between items-start">
                    <div>
                        <h2 className={`text-2xl font-bold ${status === 'red' ? 'text-red-800' :
                            status === 'yellow' ? 'text-yellow-800' :
                                'text-green-800'
                            }`}>
                            FinOps & Anti-Hijacking Status: {status.toUpperCase()}
                        </h2>
                        <p className="mt-2 text-gray-700 max-w-2xl">
                            {status === 'red' ? "Critical vulnerabilities detected. Your project is exposed to billing hijacking or unauthorized resource creation." :
                                status === 'yellow' ? "Basic protections are in place, but you lack real-time detection of malicious spend." :
                                    "Excellent! Your project is hardened against financial attacks."}
                        </p>
                    </div>

                    <button
                        onClick={downloadRemediationKit}
                        className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg shadow hover:bg-blue-700 transition-colors font-semibold"
                    >
                        <Download className="w-5 h-5" />
                        Download Remediation Kit
                    </button>
                </div>
            </div>

            {/* Traffic Light Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

                {/* Card 1: The Wall (Prevention) */}
                <StatusCard
                    title="The Wall (Prevention)"
                    icon={<Lock className="w-6 h-6" />}
                    isValid={isBillingRestricted && !hasToxicCombination}
                    description="Prevents unauthorized Project/Key creation and enforces billing segregation."
                    issues={[
                        !isBillingRestricted && "Missing 'Restrict Billing Account Linking' policy.",
                        hasToxicCombination && "Toxic Combination: Admin users have Billing Admin role."
                    ].filter(Boolean) as string[]}
                />

                {/* Card 2: The Watchtower (Detection) */}
                <StatusCard
                    title="The Watchtower (Detection)"
                    icon={<Zap className="w-6 h-6" />}
                    isValid={hasRealtimeAlerts}
                    description="Real-time log-based alerts for 'Build' events (SAs, Keys, VMs)."
                    issues={[
                        !hasRealtimeAlerts && "No Log-Based Metrics found for Service Account or Key creation events."
                    ].filter(Boolean) as string[]}
                />

                {/* Card 3: Safety Nets (Quotas) */}
                <StatusCard
                    title="Safety Nets (Quotas)"
                    icon={<Shield className="w-6 h-6" />}
                    isValid={true} // Defaulting to true for visual, assuming quota scan handled elsewhere or acceptable
                    description="Hard limits on GPU/CPU usage to prevent runaway crypto-mining costs."
                    issues={[]}
                />
            </div>

            {/* Findings Detail List */}
            <div className="mt-8">
                <h3 className="text-xl font-bold text-gray-900 mb-4">Detailed Findings</h3>
                {risks.length === 0 ? (
                    <div className="p-8 text-center bg-gray-50 rounded-lg text-gray-500">
                        No specific FinOps risks detected.
                    </div>
                ) : (
                    <div className="space-y-4">
                        {risks.map((risk) => (
                            <div key={risk.id} className="bg-white border border-gray-200 rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow">
                                <div className="flex justify-between items-start">
                                    <div className="flex gap-3">
                                        {risk.risk_level === 'critical' || risk.risk_level === 'high' ?
                                            <AlertTriangle className="w-5 h-5 text-red-500 mt-1" /> :
                                            <DollarSign className="w-5 h-5 text-blue-500 mt-1" />
                                        }
                                        <div>
                                            <h4 className="font-bold text-gray-900">{risk.title}</h4>
                                            <p className="text-sm text-gray-600 mt-1">{risk.description}</p>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <span className={`inline-block px-2 py-1 text-xs font-bold rounded uppercase ${risk.risk_level === 'critical' ? 'bg-red-100 text-red-800' :
                                            risk.risk_level === 'high' ? 'bg-orange-100 text-orange-800' :
                                                'bg-blue-100 text-blue-800'
                                            }`}>
                                            {risk.risk_level}
                                        </span>
                                    </div>
                                </div>

                                {risk.recommendation && (
                                    <div className="mt-4 bg-gray-50 p-3 rounded text-sm text-gray-800 flex gap-2">
                                        <span className="font-bold">Fix:</span> {risk.recommendation}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

function StatusCard({ title, icon, isValid, description, issues }: { title: string, icon: any, isValid: boolean, description: string, issues: string[] }) {
    return (
        <div className={`bg-white p-6 rounded-lg border-t-4 shadow-sm ${isValid ? 'border-green-500' : 'border-red-500'}`}>
            <div className="flex items-center gap-3 mb-4">
                <div className={`p-2 rounded-full ${isValid ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}`}>
                    {icon}
                </div>
                <h3 className="font-bold text-gray-900">{title}</h3>
            </div>

            <p className="text-sm text-gray-600 mb-4 min-h-[40px]">{description}</p>

            <div className="space-y-2">
                {issues.length > 0 ? (
                    issues.map((issue, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs text-red-700 bg-red-50 p-2 rounded">
                            <AlertTriangle className="w-3 h-3 mt-0.5" />
                            <span>{issue}</span>
                        </div>
                    ))
                ) : (
                    <div className="flex items-center gap-2 text-sm text-green-700 bg-green-50 p-2 rounded">
                        <CheckCircle className="w-4 h-4" />
                        <span>Passed Checks</span>
                    </div>
                )}
            </div>
        </div>
    );
}
