/**
 * OrgProjectSelector Component
 * For Phase 1 JIT Privilege System - Selects which org projects to assign service account to
 * This is DIFFERENT from ProjectSelector.tsx which selects projects AFTER scan for lockdown
 */
'use client';

import React, { useState } from 'react';
import { Info } from 'lucide-react';

interface OrgProject {
    project_id: string;
    project_name: string;
    project_number: string;
    status: string;
    billing_enabled?: boolean;
    enabled_api_count?: number;
    created_date?: string;
}

interface OrgProjectSelectorProps {
    projects: OrgProject[];
    onSelectionChange: (selectedIds: string[]) => void;
    onShowPrivilegeInfo: () => void;
}

export default function OrgProjectSelector({
    projects,
    onSelectionChange,
    onShowPrivilegeInfo
}: OrgProjectSelectorProps) {
    const [selected, setSelected] = useState<Set<string>>(new Set());

    const handleToggle = (projectId: string, checked: boolean) => {
        const newSelected = new Set(selected);
        if (checked) {
            newSelected.add(projectId);
        } else {
            newSelected.delete(projectId);
        }
        setSelected(newSelected);
        // Don't call onSelectionChange here - only when user clicks the button
    };

    const handleSelectAll = () => {
        const allIds = projects.map(p => p.project_id);
        setSelected(new Set(allIds));
        // Don't call onSelectionChange here - only when user clicks the button
    };

    const handleDeselectAll = () => {
        setSelected(new Set());
        // Don't call onSelectionChange here - only when user clicks the button
    };

    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <h3 className="text-lg font-semibold">Select Projects to Scan</h3>
                    <button
                        onClick={onShowPrivilegeInfo}
                        className="p-1 text-blue-600 hover:text-blue-800 rounded-full hover:bg-blue-50"
                        title="View privilege details"
                    >
                        <Info className="w-5 h-5" />
                    </button>
                </div>
                <div className="text-sm text-gray-600">
                    {selected.size} of {projects.length} selected
                </div>
            </div>

            <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-900">
                <strong>Note:</strong> The temporary service account (svc-lockdown-tmp) will be granted
                <strong> view-only access</strong> to these projects for scanning. You can select which
                projects to apply changes to after reviewing the scan results.
            </div>

            {/* Bulk Actions */}
            <div className="flex gap-2">
                <button
                    onClick={handleSelectAll}
                    className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded"
                >
                    Select All
                </button>
                <button
                    onClick={handleDeselectAll}
                    className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded"
                >
                    Deselect All
                </button>
            </div>

            {/* Project List */}
            <div className="border rounded-lg divide-y max-h-96 overflow-y-auto">
                {projects.map(project => (
                    <label
                        key={project.project_id}
                        className="flex items-start gap-3 p-4 hover:bg-gray-50 cursor-pointer"
                    >
                        <input
                            type="checkbox"
                            checked={selected.has(project.project_id)}
                            onChange={(e) => handleToggle(project.project_id, e.target.checked)}
                            className="mt-1 w-4 h-4 text-blue-600 rounded focus:ring-2 focus:ring-blue-500"
                        />
                        <div className="flex-1">
                            <div className="font-medium text-gray-900">
                                {project.project_name}
                            </div>
                            <div className="text-sm text-gray-600 space-x-3 mt-1">
                                <span>ID: {project.project_id}</span>
                                {project.enabled_api_count !== undefined && (
                                    <span>• APIs: {project.enabled_api_count}</span>
                                )}
                                {project.billing_enabled !== undefined && (
                                    <span>
                                        • Billing: {project.billing_enabled ? '✓' : '✗'}
                                    </span>
                                )}
                                <span
                                    className={`inline-block px-2 py-0.5 text-xs rounded ${project.status === 'ACTIVE'
                                        ? 'bg-green-100 text-green-800'
                                        : 'bg-gray-100 text-gray-800'
                                        }`}
                                >
                                    {project.status}
                                </span>
                            </div>
                        </div>
                    </label>
                ))}
            </div>

            {/* Continue Button */}
            <div className="flex justify-end">
                <button
                    onClick={() => onSelectionChange(Array.from(selected))}
                    disabled={selected.size === 0}
                    className={`px-8 py-3 rounded-lg font-medium min-w-[200px] ${selected.size === 0
                        ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                        : 'bg-blue-600 text-white hover:bg-blue-700'
                        }`}
                >
                    Grant View Access to {selected.size} project{selected.size !== 1 ? 's' : ''}
                </button>
            </div>
        </div>
    );
}
