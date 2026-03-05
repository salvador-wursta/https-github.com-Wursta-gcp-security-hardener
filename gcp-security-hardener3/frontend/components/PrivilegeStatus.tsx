/**
 * PrivilegeStatus Component
 * Displays current privilege level badge
 */
'use client';

import React from 'react';
import { Eye, Shield, Ban } from 'lucide-react';

interface PrivilegeStatusProps {
    privilegeLevel: 'none' | 'viewer' | 'elevated';
    serviceAccountEmail?: string;
}

export default function PrivilegeStatus({
    privilegeLevel,
    serviceAccountEmail
}: PrivilegeStatusProps) {
    const getStatusConfig = () => {
        switch (privilegeLevel) {
            case 'elevated':
                return {
                    icon: Shield,
                    label: 'Elevated',
                    bgColor: 'bg-orange-100',
                    textColor: 'text-orange-800',
                    borderColor: 'border-orange-300'
                };
            case 'viewer':
                return {
                    icon: Eye,
                    label: 'View-Only',
                    bgColor: 'bg-blue-100',
                    textColor: 'text-blue-800',
                    borderColor: 'border-blue-300'
                };
            default:
                return {
                    icon: Ban,
                    label: 'No Access',
                    bgColor: 'bg-gray-100',
                    textColor: 'text-gray-800',
                    borderColor: 'border-gray-300'
                };
        }
    };

    const config = getStatusConfig();
    const Icon = config.icon;

    return (
        <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border ${config.bgColor} ${config.borderColor}`}>
            <Icon className={`w-4 h-4 ${config.textColor}`} />
            <span className={`text-sm font-medium ${config.textColor}`}>
                {config.label}
            </span>
            {serviceAccountEmail && (
                <span className={`text-xs ${config.textColor} opacity-75`}>
                    • {serviceAccountEmail.split('@')[0]}
                </span>
            )}
        </div>
    );
}
