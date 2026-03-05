import React from 'react';
import { AlertCircle, CheckCircle, Smartphone, Server, Database, Cloud } from 'lucide-react';

interface ApiInfo {
    name: string;
    display_name: string;
    category: string;
    risk_level: string;
    can_disable: boolean;
    is_enabled: boolean;
    monthly_cost_estimate: string;
    reason_enabled: string;
    recommended_action: string;
}

interface ApiAnalysisData {
    enabled_apis: ApiInfo[];
    core_apis: string[];
    recommendations: {
        disable: string[];
        keep: string[];
        monitor: string[];
    };
    total_apis: number;
    high_risk_count: number;
}

interface ApiSecurityModuleProps {
    data?: ApiAnalysisData;
    risks: any[];
    loading?: boolean;
}

export default function ApiSecurityModule({ data, risks, loading }: ApiSecurityModuleProps) {
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
                <p className="text-gray-500">No API Analysis data available.</p>
            </div>
        );
    }

    const { enabled_apis, high_risk_count, total_apis } = data;
    const riskyApis = enabled_apis.filter(api => ['high', 'critical'].includes(api.risk_level.toLowerCase()));

    // Group APIs by category for better display
    const categoryIcons: Record<string, any> = {
        'compute': <Server className="w-4 h-4" />,
        'database': <Database className="w-4 h-4" />,
        'ai_ml': <Smartphone className="w-4 h-4" />, // Placeholder
        'storage': <Cloud className="w-4 h-4" />,
        'other': <CheckCircle className="w-4 h-4" />
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className={`p-6 rounded-xl shadow-sm border ${high_risk_count === 0 ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                    <div className="flex items-center gap-3 mb-2">
                        {high_risk_count === 0 ? <CheckCircle className="w-5 h-5 text-green-600" /> : <AlertCircle className="w-5 h-5 text-red-600" />}
                        <p className={`text-sm font-medium uppercase tracking-wider ${high_risk_count === 0 ? 'text-green-700' : 'text-red-700'}`}>
                            API Risk Profile
                        </p>
                    </div>
                    <h3 className={`text-2xl font-extrabold ${high_risk_count === 0 ? 'text-green-900' : 'text-red-900'}`}>
                        {high_risk_count === 0 ? 'Low Risk' : `${high_risk_count} Risky APIs`}
                    </h3>
                    <p className={`text-xs mt-2 ${high_risk_count === 0 ? 'text-green-800' : 'text-red-800'}`}>
                        {high_risk_count === 0
                            ? "No high-risk or expensive APIs enabled."
                            : "High-cost or sensitive APIs are enabled and should be reviewed."}
                    </p>
                </div>

                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-2">Total Enabled APIs</p>
                    <h3 className="text-2xl font-extrabold text-blue-900">{total_apis}</h3>
                    <p className="text-xs text-gray-400 mt-2">Active service endpoints in this project.</p>
                </div>

                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-2">Cost Impact</p>
                    <h3 className="text-2xl font-extrabold text-gray-900">
                        {riskyApis.length > 0 ? 'Monitor' : 'Low'}
                    </h3>
                    <p className="text-xs text-gray-400 mt-2">
                        {riskyApis.length > 0 ? 'Some enabled APIs have high potential costs.' : 'Enabled APIs typically have low entry costs.'}
                    </p>
                </div>
            </div>

            {/* Risky APIs Table */}
            {riskyApis.length > 0 && (
                <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                    <div className="px-6 py-4 border-b border-gray-100 bg-red-50/50 flex justify-between items-center">
                        <h3 className="font-bold text-red-900 flex items-center gap-2">
                            <AlertCircle className="w-5 h-5 text-red-600" />
                            High Risk / High Cost APIs
                        </h3>
                        <span className="text-xs text-red-600 font-medium px-2 py-1 bg-red-100 rounded-full">
                            Review Required
                        </span>
                    </div>
                    <table className="min-w-full divide-y divide-gray-100">
                        <thead className="bg-gray-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">API Name</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Est. Cost</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reason</th>
                                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-100">
                            {riskyApis.map((api) => (
                                <tr key={api.name} className="hover:bg-gray-50">
                                    <td className="px-6 py-4">
                                        <div className="flex items-center">
                                            <div className="flex-shrink-0 h-10 w-10 flex items-center justify-center rounded-lg bg-gray-100 text-gray-500">
                                                {categoryIcons[api.category] || <Server className="w-5 h-5" />}
                                            </div>
                                            <div className="ml-4">
                                                <div className="text-sm font-medium text-gray-900">{api.display_name}</div>
                                                <div className="text-xs text-gray-500 font-mono">{api.name}</div>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <span className={`px-2 py-0.5 inline-flex text-xs leading-5 font-semibold rounded-full 
                                            ${api.risk_level === 'critical' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'}`}>
                                            {api.risk_level.toUpperCase()}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                        {api.monthly_cost_estimate}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-gray-600 max-w-xs">
                                        {api.reason_enabled}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                        <span className="text-red-600 hover:text-red-900 cursor-pointer">Disable</span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* All Enabled APIs (Accordion or just list?) - Maybe just 'Other' APIs if risk list exists */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
                    <h3 className="font-bold text-gray-900">All Enabled APIs</h3>
                </div>
                <div className="p-0 overflow-x-auto">
                    <div className="max-h-96 overflow-y-auto">
                        <table className="min-w-full divide-y divide-gray-100 table-fixed">
                            <thead className="bg-gray-50 sticky top-0 z-10">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-1/2">API</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-1/4">Category</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-1/4">Status</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-100">
                                {enabled_apis
                                    .filter(a => !['high', 'critical'].includes(a.risk_level.toLowerCase()))
                                    .sort((a, b) => a.name.localeCompare(b.name))
                                    .map((api) => (
                                        <tr key={api.name} className="hover:bg-gray-50/50">
                                            <td className="px-6 py-3 text-sm text-gray-900 font-mono truncate" title={api.name}>{api.name}</td>
                                            <td className="px-6 py-3 text-sm text-gray-500 truncate">{api.category}</td>
                                            <td className="px-6 py-3">
                                                <span className="px-2 py-0.5 text-xs bg-green-100 text-green-800 rounded-full">Enabled</span>
                                            </td>
                                        </tr>
                                    ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
}
