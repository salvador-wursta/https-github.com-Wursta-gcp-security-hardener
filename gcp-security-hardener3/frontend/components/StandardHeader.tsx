import React from 'react';

interface StandardHeaderProps {
    title: string;
    subtitle?: string | React.ReactNode;
    onBack?: () => void;
    backLabel?: string;
    actions?: React.ReactNode;
    className?: string;
}

/**
 * StandardHeader component for consistent layout across workflow stages.
 * 
 * Layout:
 * [Back Button?] [Title & Subtitle] .................... [Actions]
 */
export default function StandardHeader({
    title,
    subtitle,
    onBack,
    backLabel = "Back",
    actions,
    className = ""
}: StandardHeaderProps) {
    return (
        <div className={`p-6 border-b border-gray-100 flex justify-between items-center ${className}`}>
            <div className="flex items-center gap-3">
                {onBack && (
                    <button
                        onClick={onBack}
                        className="text-gray-400 hover:text-gray-600 p-1 mr-1 transition-colors"
                        title={backLabel}
                    >
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                        </svg>
                    </button>
                )}
                <div>
                    <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
                    {subtitle && <p className="text-sm text-gray-500">{subtitle}</p>}
                </div>
            </div>

            {actions && (
                <div className="flex items-center gap-6">
                    {actions}
                </div>
            )}
        </div>
    );
}
