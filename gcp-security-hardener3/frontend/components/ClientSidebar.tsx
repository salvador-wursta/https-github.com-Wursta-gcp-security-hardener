
"use client";

import React, { useState } from 'react';
import { useClient } from '../context/ClientContext';
import { History, Save, ChevronLeft, ChevronRight, User, Building, Mail, ShieldAlert, Plus, Trash2, CheckCircle, Loader2 } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const InputField = ({
    label,
    value,
    field,
    placeholder,
    icon: Icon,
    type = "text",
    errors,
    updateClientData,
    handleBlur
}: any) => {
    const hasError = !!errors[field];
    return (
        <div className="mb-2">
            <div className="flex justify-between items-baseline mb-0.5">
                <label className={`block text-[10px] font-bold uppercase ${hasError ? 'text-red-500' : 'text-gray-400'}`}>
                    {label}
                </label>
                {hasError && <span className="text-[9px] text-red-500 font-medium">{errors[field]}</span>}
            </div>
            <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-2 flex items-center pointer-events-none">
                    <Icon className={`h-3 w-3 ${hasError ? 'text-red-300' : 'text-gray-400'}`} />
                </div>
                <input
                    type={type}
                    value={value}
                    onChange={(e) => {
                        updateClientData({ [field]: e.target.value });
                        // We can't clear error inside here easily without passing setErrors, 
                        // but handleBlur will clear it on next blur, or we can assume parent handles it.
                        // For now, let's keep it simple. The focus fix is the priority.
                    }}
                    onBlur={(e) => handleBlur(field, e.target.value)}
                    placeholder={placeholder}
                    className={`w-full pl-7 pr-2 py-1 text-xs border rounded focus:ring-1 focus:outline-none transition-colors
                        ${hasError
                            ? 'border-red-300 bg-red-50 text-red-900 placeholder-red-300 focus:border-red-500 focus:ring-red-500'
                            : 'border-gray-300 bg-white focus:border-primary-500 focus:ring-primary-500'
                        }`}
                />
            </div>
        </div>
    );
};

export default function ClientSidebar() {
    const { clientData, updateClientData, saveClient, resetClient, isLoading } = useClient();
    const [isCollapsed, setIsCollapsed] = useState(false);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [isIdentityLoading, setIsIdentityLoading] = useState(false);
    const pathname = usePathname();
    const fileInputRef = React.useRef<HTMLInputElement>(null);

    const handleLogoClick = () => {
        fileInputRef.current?.click();
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                updateClientData({ logoUrl: reader.result as string });
            };
            reader.readAsDataURL(file);
        }
    };

    // Validation Logic
    const validateField = (field: string, value: string): string | null => {
        if (value.length > 100) return "Too long";
        if (/[<>{}]/.test(value)) return "Invalid chars";

        switch (field) {
            case 'companyName':
                if (!value.trim()) return "Required";
                break;
            case 'authEmail':
            case 'scannerEmail':
                if (value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                    return "Invalid email";
                }
                break;
        }
        return null;
    };

    // Auto-save when leaving a field (onBlur)
    const handleBlur = async (field: string, value: string) => {
        const error = validateField(field, value);
        setErrors(prev => ({ ...prev, [field]: error || '' }));

        if (!error && clientData.companyName) {
            const companyErr = validateField('companyName', clientData.companyName);
            if (!companyErr) {
                saveClient();

                // If company name changed and we don't have an identity, create one
                if (field === 'companyName' && value && !clientData.sessionSaEmail) {
                    await handleCreateIdentity(value);
                }
            }
        }
    };

    const handleCreateIdentity = async (companyName: string) => {
        setIsIdentityLoading(true);
        try {
            const domain = companyName.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';

            const res = await fetch(`${backendUrl}/api/session/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });

            const data = await res.json();
            if (data.sa_email) {
                updateClientData({
                    sessionSaEmail: data.sa_email,
                    sessionDomain: domain
                });
            }
        } catch (err) {
            console.error("Failed to create identity", err);
        } finally {
            setIsIdentityLoading(false);
        }
    };

    const handleDisconnect = async () => {
        if (!clientData.sessionSaEmail) return;
        if (!confirm(`Delete temporary identity ${clientData.sessionSaEmail}?`)) return;

        setIsIdentityLoading(true);
        try {
            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
            await fetch(`${backendUrl}/api/session/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sa_email: clientData.sessionSaEmail })
            });
            updateClientData({
                sessionSaEmail: null,
                sessionDomain: null
            });
        } catch (err) {
            console.error("Failed to delete identity", err);
        } finally {
            setIsIdentityLoading(false);
        }
    };

    // Note: removed internal InputField definition logic here


    return (
        <div
            className={`bg-gray-50 border-r border-gray-200 h-screen transition-all duration-300 flex flex-col ${isCollapsed ? 'w-12' : 'w-72'
                }`}
        >
            {/* Branding Header */}
            <div className={`flex items-center ${isCollapsed ? 'flex-col gap-4 py-4' : 'justify-between p-4'} border-b border-gray-200 bg-white mb-2`}>

                {/* Hidden File Input */}
                <input
                    type="file"
                    ref={fileInputRef}
                    className="hidden"
                    accept="image/*"
                    onChange={handleFileChange}
                />

                {/* Logo */}
                <div
                    className="flex items-center gap-2 cursor-pointer group"
                    onClick={handleLogoClick}
                    title="Click to change logo"
                >
                    <div className="bg-primary-600 p-1.5 rounded-lg overflow-hidden relative w-8 h-8 flex items-center justify-center">
                        {clientData.logoUrl ? (
                            // eslint-disable-next-line @next/next/no-img-element
                            <img src={clientData.logoUrl} alt="Logo" className="w-full h-full object-cover" />
                        ) : (
                            <ShieldAlert className="text-white w-5 h-5" />
                        )}
                        {/* Hover Overlay */}
                        <div className="absolute inset-0 bg-black/30 hidden group-hover:flex items-center justify-center">
                            <span className="text-white text-[8px] font-bold">EDIT</span>
                        </div>
                    </div>
                    {!isCollapsed && (
                        <span className="font-bold text-gray-900 tracking-tight text-sm">GCP Hardener</span>
                    )}
                </div>

                {/* Toggle Button */}
                <button
                    onClick={() => setIsCollapsed(!isCollapsed)}
                    className="p-1 rounded hover:bg-gray-100 text-gray-500 transition-colors"
                >
                    {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
                </button>
            </div>

            {!isCollapsed && (
                <div className="flex-1 overflow-y-auto p-3 pt-0">
                    <div className="flex justify-between items-end mb-3 border-b pb-2">
                        <h2 className="text-sm font-bold text-gray-800">Client Details</h2>
                        <button
                            onClick={resetClient}
                            className="text-[10px] font-bold text-primary-600 hover:text-primary-800 flex items-center gap-1 bg-primary-50 hover:bg-primary-100 px-2 py-0.5 rounded transition-colors"
                        >
                            <Plus size={12} />
                            NEW CUSTOMER
                        </button>
                    </div>

                    {/* Company */}
                    <div className="mb-3">
                        <div className="flex justify-between items-center mb-0.5 px-1">
                            <label className={`block text-[10px] font-bold uppercase ${errors['companyName'] ? 'text-red-500' : 'text-gray-400'}`}>
                                COMPANY NAME
                            </label>
                            {isIdentityLoading ? (
                                <Loader2 className="w-3 h-3 animate-spin text-blue-500" />
                            ) : clientData.sessionSaEmail ? (
                                <div className="flex items-center gap-1.5">
                                    <div className="flex items-center gap-1 bg-green-50 px-1.5 py-0.5 rounded border border-green-100" title={`Active: ${clientData.sessionSaEmail}`}>
                                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" /> {/* The "Green Dot" */}
                                        <CheckCircle className="w-3 h-3 text-green-600" />
                                    </div>
                                    <button
                                        onClick={handleDisconnect}
                                        className="text-gray-400 hover:text-red-500 transition-colors"
                                        title="Disconnect Sessions"
                                    >
                                        <Trash2 className="w-3 h-3" />
                                    </button>
                                </div>
                            ) : null}
                        </div>
                        <div className="relative">
                            <div className="absolute inset-y-0 left-0 pl-2 flex items-center pointer-events-none">
                                <Building className={`h-3 w-3 ${errors['companyName'] ? 'text-red-300' : 'text-gray-400'}`} />
                            </div>
                            <input
                                type="text"
                                value={clientData.companyName}
                                onChange={(e) => updateClientData({ companyName: e.target.value })}
                                onBlur={(e) => handleBlur('companyName', e.target.value)}
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                        (e.target as HTMLInputElement).blur();
                                    }
                                }}
                                placeholder="e.g. Acme Corp"
                                className={`w-full pl-7 pr-2 py-1 text-xs border rounded focus:ring-1 focus:outline-none transition-colors
                                    ${errors['companyName']
                                        ? 'border-red-300 bg-red-50 text-red-900 placeholder-red-300 focus:border-red-500 focus:ring-red-500'
                                        : 'border-gray-300 bg-white focus:border-primary-500 focus:ring-primary-500'
                                    }`}
                            />
                        </div>
                        {clientData.sessionSaEmail && (
                            <p className="text-[9px] text-green-600 mt-1 truncate font-mono px-1">
                                {clientData.sessionSaEmail}
                            </p>
                        )}
                        {errors['companyName'] && <span className="text-[9px] text-red-500 font-medium px-1">{errors['companyName']}</span>}
                    </div>

                    {/* Authorized By */}
                    <div className="mb-3">
                        <InputField
                            label="AUTHORIZED BY"
                            value={clientData.authName}
                            field="authName"
                            placeholder="Name"
                            icon={User}
                            errors={errors}
                            updateClientData={updateClientData}
                            handleBlur={handleBlur}
                        />
                        <InputField
                            label="AUTH EMAIL"
                            value={clientData.authEmail}
                            field="authEmail"
                            placeholder="Email"
                            icon={Mail}
                            type="email"
                            errors={errors}
                            updateClientData={updateClientData}
                            handleBlur={handleBlur}
                        />
                    </div>

                    {/* Security Analyst */}
                    <div className="mb-3">
                        <InputField
                            label="SECURITY ANALYST"
                            value={clientData.scannerName}
                            field="scannerName"
                            placeholder="Name"
                            icon={ShieldAlert}
                            errors={errors}
                            updateClientData={updateClientData}
                            handleBlur={handleBlur}
                        />
                        <InputField
                            label="ANALYST EMAIL"
                            value={clientData.scannerEmail}
                            field="scannerEmail"
                            placeholder="Email"
                            icon={Mail}
                            type="email"
                            errors={errors}
                            updateClientData={updateClientData}
                            handleBlur={handleBlur}
                        />
                    </div>

                    {/* Last Scan Info - Compact */}
                    <div className="mb-3 bg-primary-50 border border-primary-100 rounded p-2 flex justify-between items-center">
                        <div>
                            <div className="text-[10px] text-primary-600 font-bold uppercase">Last Scan</div>
                            <div className="text-xs text-gray-700 font-mono">
                                {clientData.lastScanDate
                                    ? new Date(clientData.lastScanDate).toLocaleString(undefined, {
                                        month: 'numeric',
                                        day: 'numeric',
                                        year: '2-digit',
                                        hour: 'numeric',
                                        minute: '2-digit'
                                    })
                                    : '---'}
                            </div>
                        </div>
                        {clientData.id && (
                            <Link
                                href={`/history?clientId=${clientData.id}`}
                                className="text-primary-600 hover:text-primary-800 bg-white p-1 rounded border border-primary-100 shadow-sm"
                                title="View History"
                            >
                                <History size={14} />
                            </Link>
                        )}
                    </div>

                    {/* Status Indicator */}
                    <div className="flex items-center justify-between text-[10px] text-gray-400">
                        <span>{isLoading ? 'Saving...' : 'Auto-saved'}</span>
                        {clientData.id && <span className="text-green-600 flex items-center"><Save size={10} className="mr-1" /> Synced</span>}
                    </div>
                </div>
            )}

            {/* Collapsed View Icons - Unchanged */}
            {isCollapsed && (
                <div className="flex flex-col items-center gap-4 mt-4">
                    <div className="w-8 h-8 rounded bg-gray-200 flex items-center justify-center cursor-pointer" title="Client Details">
                        <Building size={16} className="text-gray-600" />
                    </div>
                    {clientData.id && (
                        <Link href={`/history?clientId=${clientData.id}`}>
                            <div className="w-8 h-8 rounded bg-primary-100 flex items-center justify-center cursor-pointer" title="History">
                                <History size={16} className="text-primary-600" />
                            </div>
                        </Link>
                    )}
                </div>
            )}
        </div>
    );
}
