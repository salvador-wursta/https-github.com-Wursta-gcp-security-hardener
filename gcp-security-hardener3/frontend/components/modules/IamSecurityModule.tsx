import React from 'react';
import { ScanResponse } from '@/app/page'; // Need to import interfaces
import { Shield, Key, Users, AlertTriangle, CheckCircle, Lock } from 'lucide-react';

interface IamSecurityModuleProps {
    scanData: any; // Using any for now to match flexible ScanResponse
}

export default function IamSecurityModule({ scanData }: IamSecurityModuleProps) {
    console.log("IamSecurityModule scanData:", scanData);
    if (!scanData || !scanData.iam_analysis) {
        return (
            <div className="p-8 text-center text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                <p>Run a scan to view IAM security details.</p>
                <div className="text-xs text-gray-400 mt-2">No IAM analysis data found in scan results.</div>
            </div>
        );
    }

    const { iam_analysis } = scanData;
    const basicRoles = iam_analysis.basic_roles || [];
    const saKeys = iam_analysis.service_account_keys || [];
    const defaultSAs = iam_analysis.default_service_accounts || [];
    const externalMembers = iam_analysis.external_members || [];
    const narratives = iam_analysis.principal_narratives || {};

    // Merge narratives into items for display
    const enrich = (items: any[], keyField: string) => items.map(i => ({
        ...i,
        narrative: narratives[i[keyField]] || narratives[i.account] || "No specific narrative generated."
    }));

    const enrichedBasicRoles = enrich(basicRoles, 'member');
    const enrichedSaKeys = enrich(saKeys, 'account');
    const enrichedExternal = enrich(externalMembers, 'member');

    // Aggregate all principals for display
    const allPrincipals = iam_analysis.all_principals || [];
    const localSAs = iam_analysis.local_service_accounts || [];

    // Summary counts
    const saCount = allPrincipals.filter((p: any) => p.type === 'Service Account').length;
    const humanCount = allPrincipals.filter((p: any) => ['User', 'Group', 'Domain'].includes(p.type)).length;
    const publicCount = allPrincipals.filter((p: any) => p.type.includes('Public')).length;

    // Helper for risk badge
    const RiskBadge = ({ level }: { level: string }) => {
        const colors = {
            HIGH: 'bg-red-100 text-red-800 border-red-200',
            MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
            LOW: 'bg-blue-100 text-blue-800 border-blue-200',
            CRITICAL: 'bg-red-100 text-red-900 border-red-500 font-bold'
        }[level] || 'bg-gray-100 text-gray-800';

        return (
            <span className={`px-2 py-0.5 rounded text-xs border ${colors}`}>
                {level}
            </span>
        );
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header / Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className="p-3 bg-blue-100 rounded-lg">
                        <Users className="w-6 h-6 text-blue-600" />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Service Accounts</p>
                        <p className="text-2xl font-bold text-gray-900">{saCount}</p>
                    </div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${basicRoles.length > 0 ? 'bg-orange-100' : 'bg-green-100'}`}>
                        <Lock className={`w-6 h-6 ${basicRoles.length > 0 ? 'text-orange-600' : 'text-green-600'}`} />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Basic Roles Found</p>
                        <p className="text-2xl font-bold text-gray-900">{basicRoles.length}</p>
                    </div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${saKeys.length > 0 ? 'bg-red-100' : 'bg-green-100'}`}>
                        <Key className={`w-6 h-6 ${saKeys.length > 0 ? 'text-red-600' : 'text-green-600'}`} />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Old Keys Check</p>
                        <p className="text-2xl font-bold text-gray-900">{saKeys.length}</p>
                    </div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${externalMembers.length > 0 ? 'bg-yellow-100' : 'bg-green-100'}`}>
                        <Shield className={`w-6 h-6 ${externalMembers.length > 0 ? 'text-yellow-600' : 'text-green-600'}`} />
                    </div>
                    <div>
                        <p className="text-sm text-gray-500">Human Principals</p>
                        <p className="text-2xl font-bold text-gray-900">{humanCount}</p>
                    </div>
                </div>
            </div>

            {/* Top Level Risks (MFA, etc.) */}
            {(() => {
                const topLevelRisks = (scanData.risks || []).filter((r: any) =>
                    r.category === 'iam' &&
                    (r.id === 'iam_mfa_scc_confirmed' || r.id === 'iam_mfa_policy_missing')
                );

                if (topLevelRisks.length === 0) return null;

                return (
                    <div className="space-y-4">
                        {topLevelRisks.map((risk: any) => (
                            <div key={risk.id} className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg shadow-sm">
                                <div className="flex items-start">
                                    <AlertTriangle className="w-5 h-5 text-red-600 mt-0.5" />
                                    <div className="ml-3">
                                        <h3 className="text-sm font-medium text-red-900">{risk.title}</h3>
                                        <p className="mt-1 text-sm text-red-700">{risk.description}</p>
                                        <div className="mt-2 text-sm">
                                            <span className="font-semibold text-red-800">Recommendation:</span> <span className="text-red-700">{risk.recommendation}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                );
            })()}

            {/* Detailed Object Listings */}
            <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden mt-6">
                <div className="bg-blue-50 px-6 py-4 border-b border-blue-100 flex justify-between items-center">
                    <h3 className="font-bold text-blue-900 flex items-center gap-2">
                        <Users className="w-5 h-5" />
                        IAM Principals ({allPrincipals.length})
                    </h3>
                </div>
                {formattedTable(allPrincipals, ['Principal Identity', 'Type', 'Roles / Origin'], (item: any, index: number) => (
                    <tr key={`${item.member}-${index}`} className="group hover:bg-gray-50/50">
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">
                            <div className="flex flex-col">
                                <span>{item.email}</span>
                                <span className="text-[10px] text-gray-400 font-mono underline decoration-gray-200">{item.member}</span>
                            </div>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">
                            <span className={`px-2 py-1 rounded-full text-xs font-semibold ${item.type === 'User' || item.type === 'Group' ? 'bg-green-100 text-green-800' :
                                    item.type === 'Service Account' ? 'bg-blue-100 text-blue-800' :
                                        item.type.includes('Public') ? 'bg-red-100 text-red-800 animate-pulse' :
                                            'bg-gray-100 text-gray-700'
                                }`}>
                                {item.type}
                            </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600 font-mono text-xs">{(item.roles || []).join(', ')}</td>
                    </tr>
                ))}
            </div>

            {/* Service Account Keys Section */}
            <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
                <div className="bg-gray-50 px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                    <h3 className="font-bold text-gray-900 flex items-center gap-2">
                        <Key className="w-5 h-5 text-gray-500" />
                        Service Account Key Hygiene
                    </h3>
                    {saKeys.length === 0 && (
                        <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" /> No stale keys found
                        </span>
                    )}
                </div>

                {formattedTable(enrichedSaKeys, ['Account', 'Key ID', 'Age', 'Risk'], (item: any, index: number) => (
                    <React.Fragment key={`${item.key_id}-${index}`}>
                        <tr className="group hover:bg-gray-50/50">
                            <td className="px-6 pt-4 pb-1 text-sm text-gray-900 font-medium border-none">{item.account}</td>
                            <td className="px-6 pt-4 pb-1 text-sm text-gray-600 font-mono border-none">{item.key_id.substring(0, 12)}...</td>
                            <td className="px-6 pt-4 pb-1 text-sm text-gray-600 border-none">{item.age_days} days</td>
                            <td className="px-6 pt-4 pb-1 border-none"><RiskBadge level={item.risk_level} /></td>
                        </tr>
                        <tr className="hover:bg-gray-50/50 !border-t-0 relative top-[-1px]">
                            <td colSpan={4} className="px-6 pb-4 pt-1">
                                <div className="flex items-start gap-2 bg-blue-50/40 p-2.5 rounded-lg border border-blue-100/50">
                                    <span className="text-blue-700 font-semibold text-xs uppercase tracking-wide shrink-0 mt-0.5">Expert Analysis</span>
                                    <span className="text-blue-900 text-sm italic leading-snug">{item.narrative}</span>
                                </div>
                            </td>
                        </tr>
                    </React.Fragment>
                ))}
            </div>

            {/* Basic Roles Section */}
            <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
                <div className="bg-gray-50 px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                    <h3 className="font-bold text-gray-900 flex items-center gap-2">
                        <Lock className="w-5 h-5 text-gray-500" />
                        Primitive Role Usage (Owner/Editor)
                    </h3>
                    {basicRoles.length === 0 && (
                        <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" /> Least Privilege Followed
                        </span>
                    )}
                </div>

                {formattedTable(enrichedBasicRoles, ['Member', 'Role', 'Risk'], (item: any, index: number) => (
                    <React.Fragment key={`${item.member}-${item.role}-${index}`}>
                        <tr className="group hover:bg-gray-50/50">
                            <td className="px-6 pt-4 pb-1 text-sm text-gray-900 font-medium border-none">{item.member}</td>
                            <td className="px-6 pt-4 pb-1 text-sm text-gray-600 font-mono border-none">
                                <span className="bg-gray-100 px-2 py-0.5 rounded">{item.role}</span>
                            </td>
                            <td className="px-6 pt-4 pb-1 border-none"><RiskBadge level={item.risk_level} /></td>
                        </tr>
                        <tr className="hover:bg-gray-50/50 !border-t-0 relative top-[-1px]">
                            <td colSpan={3} className="px-6 pb-4 pt-1">
                                <div className="flex items-start gap-2 bg-blue-50/40 p-2.5 rounded-lg border border-blue-100/50">
                                    <span className="text-blue-700 font-semibold text-xs uppercase tracking-wide shrink-0 mt-0.5">Expert Analysis</span>
                                    <span className="text-blue-900 text-sm italic leading-snug">{item.narrative}</span>
                                </div>
                            </td>
                        </tr>
                    </React.Fragment>
                ))}
            </div>

            {/* Default Service Accounts */}
            {
                defaultSAs.length > 0 && (
                    <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
                        <div className="bg-red-50 px-6 py-4 border-b border-red-100 flex justify-between items-center">
                            <h3 className="font-bold text-red-900 flex items-center gap-2">
                                <AlertTriangle className="w-5 h-5" />
                                Risky Default Service Accounts
                            </h3>
                        </div>
                        <div className="p-6">
                            <p className="text-sm text-gray-600 mb-4">
                                The following default service accounts have <b>Editor</b> permissions.
                                This is a critical security risk because compromising a single VM could expose the entire project.
                            </p>
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Account</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {defaultSAs.map((item: any, index: number) => (
                                            <tr key={`${item.account}-${index}`} className="hover:bg-red-50">
                                                <td className="px-6 py-4 text-sm text-gray-900 font-medium">{item.account}</td>
                                                <td className="px-6 py-4 text-sm text-gray-600">{item.role}</td>
                                                <td className="px-6 py-4 text-sm text-red-600 font-bold">CRITICAL RISK</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                )
            }
        </div >
    );
}

// Helper for rendering empty or populated tables
function formattedTable(data: any[], headers: string[], rowRenderer: (item: any, index: number) => React.ReactNode) {
    if (data.length === 0) {
        return (
            <div className="p-8 text-center text-gray-500 italic bg-white">
                No issues found in this category.
            </div>
        );
    }
    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                    <tr>
                        {headers.map(h => (
                            <th key={h} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                    {data.map((item, index) => rowRenderer(item, index))}
                </tbody>
            </table>
        </div>
    );
}
