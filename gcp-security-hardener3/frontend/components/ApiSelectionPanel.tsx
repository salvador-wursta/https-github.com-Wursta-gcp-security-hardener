/**
 * API Selection Panel Component
 * Allows granular selection of APIs to disable during lockdown
 */
import React, { useState, useMemo } from 'react';
import { Check, X, AlertTriangle, Shield, Database, Cloud, Network, Brain, Lock } from 'lucide-react';

interface ApiInfo {
    name: string;
    display_name: string;
    category: string;
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    can_disable: boolean;
    is_enabled: boolean;
    monthly_cost_estimate: string;
    reason_enabled?: string;
    recommended_action: 'disable' | 'keep' | 'monitor';
    used_by: string[];
}

interface ApiSelectionPanelProps {
    apis: ApiInfo[];
    selectedApis?: string[];
    onSelectionChange: (selectedApis: string[]) => void;
    onNext: () => void;
}

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
    compute: <Cloud className="w-4 h-4" />,
    storage: <Database className="w-4 h-4" />,
    ai_ml: <Brain className="w-4 h-4" />,
    database: <Database className="w-4 h-4" />,
    networking: <Network className="w-4 h-4" />,
    core: <Lock className="w-4 h-4" />,
    other: <Shield className="w-4 h-4" />,
};

const RISK_COLORS = {
    critical: 'text-red-600 bg-red-50 border-red-200',
    high: 'text-orange-600 bg-orange-50 border-orange-200',
    medium: 'text-yellow-600 bg-yellow-50 border-yellow-200',
    low: 'text-green-600 bg-green-50 border-green-200',
};

export function ApiSelectionPanel({ apis, selectedApis: externalSelectedApis, onSelectionChange, onNext }: ApiSelectionPanelProps) {
    const [selectedApis, setSelectedApis] = useState<Set<string>>(
        new Set(externalSelectedApis || apis.filter(api => api.recommended_action === 'disable' && api.can_disable).map(api => api.name))
    );

    // Group APIs by category
    const groupedApis = useMemo(() => {
        const groups: Record<string, ApiInfo[]> = {};
        apis.forEach(api => {
            if (!groups[api.category]) {
                groups[api.category] = [];
            }
            groups[api.category].push(api);
        });
        return groups;
    }, [apis]);

    // Sync initial selection to parent on mount/change
    React.useEffect(() => {
        // Only reset if we don't have external selections for this project
        if (externalSelectedApis && externalSelectedApis.length > 0) {
            setSelectedApis(new Set(externalSelectedApis));
        } else {
            const initialSelection = apis
                .filter(api => api.recommended_action === 'disable' && api.can_disable)
                .map(api => api.name);

            setSelectedApis(new Set(initialSelection));
            // IMPORTANT: Notify parent of the default selection immediately
            // This ensures the parent state matches the visual default state
            onSelectionChange(initialSelection);
        }
    }, [apis, externalSelectedApis, onSelectionChange]);

    const handleToggle = (apiName: string) => {
        const newSelected = new Set(selectedApis);
        if (newSelected.has(apiName)) {
            newSelected.delete(apiName);
        } else {
            newSelected.add(apiName);
        }
        setSelectedApis(newSelected);
        onSelectionChange(Array.from(newSelected));
    };

    const handleSelectAll = () => {
        const allDisableable = apis.filter(api => api.can_disable).map(api => api.name);
        setSelectedApis(new Set(allDisableable));
        onSelectionChange(allDisableable);
    };

    const handleDeselectAll = () => {
        setSelectedApis(new Set());
        onSelectionChange([]);
    };

    const handleSelectRecommended = () => {
        const recommended = apis.filter(api => api.recommended_action === 'disable' && api.can_disable).map(api => api.name);
        setSelectedApis(new Set(recommended));
        onSelectionChange(recommended);
    };

    const categoryNames: Record<string, string> = {
        compute: 'Compute & Infrastructure',
        storage: 'Storage',
        ai_ml: 'AI/ML',
        database: 'Databases',
        networking: 'Networking',
        core: 'Core APIs (Cannot Disable)',
        other: 'Other Services',
    };

    return (
        <div className="max-w-4xl mx-auto">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <div className="mb-6">
                    <h2 className="text-2xl font-bold text-gray-900 mb-2">
                        Select APIs to Disable
                    </h2>
                    <p className="text-gray-600">
                        Review and select which APIs should be disabled. Pre-selected APIs are recommended based on security scan.
                    </p>
                </div>

                {/* Quick Actions */}
                <div className="flex gap-2 mb-6 pb-6 border-b border-gray-200">
                    <button
                        onClick={handleSelectRecommended}
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition text-sm font-medium"
                    >
                        Select Recommended
                    </button>
                    <button
                        onClick={handleSelectAll}
                        className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition text-sm font-medium"
                    >
                        Select All
                    </button>
                    <button
                        onClick={handleDeselectAll}
                        className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition text-sm font-medium"
                    >
                        Deselect All
                    </button>
                    <div className="ml-auto text-sm text-gray-600 flex items-center gap-2">
                        <span className="font-semibold">{selectedApis.size}</span> of <span>{apis.filter(a => a.can_disable).length}</span> selected
                    </div>
                </div>

                {/* API List by Category */}
                <div className="space-y-6">
                    {Object.entries(groupedApis).map(([category, categoryApis]) => (
                        <div key={category} className="border border-gray-200 rounded-lg overflow-hidden">
                            <div className="bg-gray-50 px-4 py-3 border-b border-gray-200 flex items-center gap-2">
                                {CATEGORY_ICONS[category]}
                                <h3 className="font-semibold text-gray-900">{categoryNames[category] || category}</h3>
                                <span className="ml-auto text-sm text-gray-500">{categoryApis.length} APIs</span>
                            </div>

                            <div className="divide-y divide-gray-100">
                                {categoryApis.map(api => (
                                    <div
                                        key={api.name}
                                        className={`p-4 hover:bg-gray-50 transition ${!api.can_disable ? 'bg-gray-50 opacity-60' : ''}`}
                                    >
                                        <div className="flex items-start gap-3">
                                            <div className="flex items-center h-5 mt-1">
                                                <input
                                                    type="checkbox"
                                                    checked={selectedApis.has(api.name)}
                                                    onChange={() => handleToggle(api.name)}
                                                    disabled={!api.can_disable}
                                                    className="w-5 h-5 text-blue-600 border-gray-300 rounded focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                                                />
                                            </div>

                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="font-medium text-gray-900">{api.display_name}</span>
                                                    <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${RISK_COLORS[api.risk_level]}`}>
                                                        {api.risk_level.toUpperCase()}
                                                    </span>
                                                    {api.recommended_action === 'disable' && api.can_disable && (
                                                        <span className="px-2 py-0.5 text-xs font-medium text-blue-700 bg-blue-50 rounded-full border border-blue-200">
                                                            RECOMMENDED
                                                        </span>
                                                    )}
                                                    {!api.can_disable && (
                                                        <span className="px-2 py-0.5 text-xs font-medium text-gray-600 bg-gray-100 rounded-full border border-gray-300">
                                                            REQUIRED
                                                        </span>
                                                    )}
                                                </div>

                                                <p className="text-sm text-gray-600 mb-1">{api.name}</p>

                                                {api.reason_enabled && (
                                                    <p className="text-sm text-gray-500 mb-1">{api.reason_enabled}</p>
                                                )}

                                                <div className="flex items-center gap-4 text-xs text-gray-500">
                                                    <span>💰 {api.monthly_cost_estimate}</span>
                                                    {api.used_by.length > 0 && (
                                                        <span>📦 Used by: {api.used_by.join(', ')}</span>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>

                {/* Next Button */}
                <div className="mt-8 pt-6 border-t border-gray-200 flex justify-between items-center">
                    <div className="text-sm text-gray-600">
                        {selectedApis.size > 0 ? (
                            <span className="flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4 text-orange-500" />
                                {selectedApis.size} API{selectedApis.size !== 1 ? 's' : ''} will be disabled
                            </span>
                        ) : (
                            <span className="text-gray-500">No APIs selected for disabling</span>
                        )}
                    </div>
                    <button
                        onClick={onNext}
                        className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        Next: Preview Script →
                    </button>
                </div>
            </div>
        </div>
    );
}
