/**
 * PrivilegeTimer Component
 * Displays countdown timer for privilege escalation
 */
'use client';

import React, { useState, useEffect } from 'react';
import { Clock, AlertCircle } from 'lucide-react';

interface PrivilegeTimerProps {
    expiresAt: string; // ISO timestamp
    onExpired?: () => void;
}

export default function PrivilegeTimer({ expiresAt, onExpired }: PrivilegeTimerProps) {
    const [remainingSeconds, setRemainingSeconds] = useState<number>(0);
    const [isExpired, setIsExpired] = useState(false);

    useEffect(() => {
        const calculateRemaining = () => {
            const now = new Date().getTime();
            const expires = new Date(expiresAt).getTime();
            const diff = Math.max(0, Math.floor((expires - now) / 1000));

            setRemainingSeconds(diff);

            if (diff === 0 && !isExpired) {
                setIsExpired(true);
                onExpired?.();
            }
        };

        calculateRemaining();
        const interval = setInterval(calculateRemaining, 1000);

        return () => clearInterval(interval);
    }, [expiresAt, isExpired, onExpired]);

    const minutes = Math.floor(remainingSeconds / 60);
    const seconds = remainingSeconds % 60;

    const getColorClass = () => {
        if (remainingSeconds > 180) return 'text-green-600 bg-green-50 border-green-200';
        if (remainingSeconds > 60) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
        return 'text-red-600 bg-red-50 border-red-200';
    };

    const getIconColor = () => {
        if (remainingSeconds > 180) return 'text-green-600';
        if (remainingSeconds > 60) return 'text-yellow-600';
        return 'text-red-600';
    };

    if (isExpired) {
        return (
            <div className="flex items-center gap-2 px-4 py-2 bg-red-50 border border-red-200 rounded-lg">
                <AlertCircle className="w-5 h-5 text-red-600" />
                <span className="text-sm font-medium text-red-900">
                    Privileges Expired
                </span>
            </div>
        );
    }

    return (
        <div className={`flex items-center gap-3 px-4 py-2 border rounded-lg ${getColorClass()}`}>
            <Clock className={`w-5 h-5 ${getIconColor()}`} />
            <div>
                <div className="text-xs font-medium opacity-75">Time Remaining</div>
                <div className="text-2xl font-mono font-bold">
                    {String(minutes).padStart(2, '0')}:{String(seconds).padStart(2, '0')}
                </div>
            </div>
        </div>
    );
}
