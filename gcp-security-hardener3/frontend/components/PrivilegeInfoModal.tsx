/**
 * PrivilegeInfoModal Component
 * Displays detailed information about privileges granted to svc-lockdown-tmp
 */
'use client';

import React from 'react';
import { X, Info, Eye, Shield } from 'lucide-react';

interface PrivilegeInfoModalProps {
    open: boolean;
    onClose: () => void;
    privilegeLevel?: 'viewer' | 'elevated';
}

const VIEWER_ROLES = [
    {
        role: 'roles/viewer',
        purpose: 'Basic project viewing',
        permissions: ['List resources', 'Read configurations', 'View metadata']
    },
    {
        role: 'roles/orgpolicy.policyViewer',
        purpose: 'Read organization policies',
        permissions: ['View org policy constraints', 'Read policy enforcement status']
    },
    {
        role: 'roles/billing.viewer',
        purpose: 'Read billing information',
        permissions: ['View budgets', 'Read spending data', 'List billing accounts']
    },
    {
        role: 'roles/compute.viewer',
        purpose: 'Read compute resources',
        permissions: ['List VMs', 'View firewall rules', 'Read quotas']
    },
    {
        role: 'roles/logging.viewer',
        purpose: 'Read logs',
        permissions: ['View log sinks', 'Read log entries']
    },
    {
        role: 'roles/securitycenter.assetsViewer',
        purpose: 'View Security Assets',
        permissions: ['List assets', 'View asset metadata']
    },
    {
        role: 'roles/securitycenter.findingsViewer',
        purpose: 'View Security Findings',
        permissions: ['List findings', 'View sources']
    }
];

const ELEVATED_ROLES = [
    {
        role: 'roles/orgpolicy.policyAdmin',
        purpose: 'Modify organization policies',
        permissions: ['Create policies', 'Update policies', 'Delete policies']
    },
    {
        role: 'roles/billing.admin',
        purpose: 'Manage billing and budgets',
        permissions: ['Create budgets', 'Update budgets', 'Configure alerts']
    },
    {
        role: 'roles/compute.securityAdmin',
        purpose: 'Manage firewall rules',
        permissions: ['Create firewall rules', 'Update rules', 'Delete rules']
    },
    {
        role: 'roles/logging.configWriter',
        purpose: 'Configure logging',
        permissions: ['Create log sinks', 'Update sinks', 'Configure exports']
    },
    {
        role: 'roles/iam.securityAdmin',
        purpose: 'Manage IAM policies',
        permissions: ['Update IAM bindings', 'Grant roles', 'Revoke roles']
    },
    {
        role: 'roles/securitycenter.admin',
        purpose: 'Manage Security Command Center',
        permissions: ['Configure SCC Config', 'Update Organization Settings']
    }
];

export default function PrivilegeInfoModal({
    open,
    onClose,
    privilegeLevel = 'viewer'
}: PrivilegeInfoModalProps) {
    if (!open) return null;

    const roles = privilegeLevel === 'elevated' ? ELEVATED_ROLES : VIEWER_ROLES;
    const isReadOnly = privilegeLevel === 'viewer';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
            <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b">
                    <div className="flex items-center gap-3">
                        {isReadOnly ? (
                            <Eye className="w-6 h-6 text-blue-600" />
                        ) : (
                            <Shield className="w-6 h-6 text-orange-600" />
                        )}
                        <h2 className="text-xl font-semibold">
                            {isReadOnly ? 'View-Only' : 'Elevated'} Privileges for svc-lockdown-tmp
                        </h2>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-gray-100 rounded-full"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Content */}
                <div className="p-6 overflow-y-auto max-h-[calc(90vh-140px)]">
                    {/* Alert */}
                    <div className={`p-4 rounded-lg mb-6 ${isReadOnly
                        ? 'bg-blue-50 border border-blue-200'
                        : 'bg-orange-50 border border-orange-200'
                        }`}>
                        <div className="flex gap-2">
                            <Info className={`w-5 h-5 mt-0.5 flex-shrink-0 ${isReadOnly ? 'text-blue-600' : 'text-orange-600'
                                }`} />
                            <p className={`text-sm ${isReadOnly ? 'text-blue-900' : 'text-orange-900'
                                }`}>
                                {isReadOnly
                                    ? 'These are READ-ONLY permissions. No changes can be made with these privileges.'
                                    : 'These are ADMIN permissions. The service account can make changes to your GCP environment. These privileges expire after 5 minutes.'}
                            </p>
                        </div>
                    </div>

                    {/* Roles Table */}
                    <div className="space-y-4">
                        {roles.map((roleInfo, index) => (
                            <div
                                key={index}
                                className="border rounded-lg p-4 hover:bg-gray-50 transition"
                            >
                                <div className="flex items-start justify-between mb-2">
                                    <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded">
                                        {roleInfo.role}
                                    </code>
                                </div>
                                <p className="text-sm text-gray-700 mb-3">
                                    {roleInfo.purpose}
                                </p>
                                <div className="space-y-1">
                                    {roleInfo.permissions.map((permission, pIndex) => (
                                        <div key={pIndex} className="flex items-start gap-2 text-sm text-gray-600">
                                            <span className="text-blue-600 mt-1">•</span>
                                            <span>{permission}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Duration Info */}
                    <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                        <p className="text-sm text-gray-700">
                            <strong>Duration:</strong>{' '}
                            {isReadOnly
                                ? 'These privileges are active until you click "Finished" or the scan completes.'
                                : 'These ELEVATED privileges last for 5 minutes, then automatically revert to view-only.'}
                        </p>
                    </div>
                </div>

                {/* Footer */}
                <div className="p-6 border-t bg-gray-50">
                    <button
                        onClick={onClose}
                        className="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
}
