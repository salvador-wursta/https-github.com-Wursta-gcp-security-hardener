"use client";

import React, { useState, useRef } from 'react';
import { useClient } from '../../context/ClientContext';
import {
    CSidebar,
    CSidebarBrand,
    CSidebarNav,
    CSidebarHeader,
    CSidebarFooter,
    CSidebarToggler,
    CNavItem,
    CNavTitle,
    CBadge
} from '@coreui/react';
import CIcon from '@coreui/icons-react';
import { cilSpeedometer, cilUser, cilBuilding, cilEnvelopeClosed, cilShieldAlt, cilHistory, cilSave, cilPlus, cilMenu } from '@coreui/icons';
import Link from 'next/link';

// Helper Input Component adapted for CoreUI styling
const SidebarInput = ({
    label,
    value,
    field,
    placeholder,
    type = "text",
    errors,
    updateClientData,
    handleBlur
}: any) => {
    const hasError = !!errors[field];
    return (
        <div className="mb-3 px-3">
            <label className={`form-label text-[10px] font-bold uppercase mb-1 ${hasError ? 'text-danger' : 'text-white opacity-75'}`}>
                {label}
            </label>
            <input
                type={type}
                className={`form-control form-control-sm bg-dark text-white border-secondary ${hasError ? 'is-invalid' : ''}`}
                value={value || ''}
                onChange={(e) => updateClientData({ [field]: e.target.value })}
                onBlur={(e) => handleBlur(field, e.target.value)}
                placeholder={placeholder}
            />
            {hasError && <div className="invalid-feedback" style={{ display: 'block', fontSize: '10px' }}>{errors[field]}</div>}
        </div>
    );
};

interface AppSidebarProps {
    visible?: boolean;
    onVisibleChange?: (visible: boolean) => void;
    unfoldable?: boolean;
    onUnfoldableChange?: (unfoldable: boolean) => void;
}

export default function AppSidebar({ visible, onVisibleChange, unfoldable, onUnfoldableChange }: AppSidebarProps) {
    const { clientData, updateClientData, saveClient, resetClient, isLoading } = useClient();
    const [errors, setErrors] = useState<Record<string, string>>({});

    // Session state — set when Company Name triggers /api/session/start
    const [sessionStatus, setSessionStatus] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
    const [sessionStatusMsg, setSessionStatusMsg] = useState<string>('');
    // Removed logo upload functionality, standard link behavior handled by <CSidebarBrand href="/">

    // Validation Logic
    const validateField = (field: string, value: string): string | null => {
        if (value.length > 100) return "Too long";
        if (/[<>{}]/.test(value)) return "Invalid chars";
        switch (field) {
            case 'companyName': if (!value.trim()) return "Required"; break;
            case 'authEmail':
            case 'scannerEmail':
                if (value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "Invalid email";
                break;
        }
        return null;
    };

    const handleBlur = (field: string, value: string) => {
        const error = validateField(field, value);
        setErrors(prev => ({ ...prev, [field]: error || '' }));
        if (!error && clientData.companyName && !validateField('companyName', clientData.companyName)) {
            saveClient();
        }

        // When Company Name blurs successfully, start a backend session
        if (field === 'companyName' && !error && value.trim()) {
            // Use same-origin Next.js API route (/api/session/start) to avoid CORS.
            // Next.js forwards it server-side to the FastAPI backend.
            const domainSlug = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

            setSessionStatus('loading');
            setSessionStatusMsg('Creating scanner identity…');
            fetch('/api/session/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domainSlug }),
                signal: AbortSignal.timeout(30000),
            })
                .then((res) => {
                    if (!res.ok) throw new Error(`HTTP ${res.status}`);
                    return res.json();
                })
                .then((data) => {
                    console.log('[AppSidebar] session started:', data);
                    const email = data.sa_email ?? '';
                    // ✔ Write the per-customer SA email into ClientContext so
                    // page.tsx can pass it to OnboardingModal as initialSaEmail.
                    // This is the email that appears in the gcloud command.
                    updateClientData({
                        sessionSaEmail: email,
                        sessionDomain: domainSlug,
                    });
                    setSessionStatus('ok');
                    setSessionStatusMsg(email ? `Scanner SA ready: ${email}` : 'Session started');
                    setTimeout(() => setSessionStatus('idle'), 5000);
                })
                .catch((err) => {
                    console.error('[AppSidebar] session/start error:', err);
                    setSessionStatus('error');
                    setSessionStatusMsg('Backend offline — session not started');
                    setTimeout(() => setSessionStatus('idle'), 5000);
                });
        }
    };

    return (
        <CSidebar
            className="border-end d-flex flex-column bg-dark text-white"
            style={{
                width: unfoldable ? '4.5rem' : '16rem',
                transition: 'width 0.3s ease',
                zIndex: 1030,
                overflowX: unfoldable ? 'hidden' : 'visible'
            }}
            position="fixed"
            unfoldable={unfoldable}
            visible={visible}
            onVisibleChange={onVisibleChange}
        >
            <CSidebarHeader className={`border-bottom d-flex align-items-center ${unfoldable ? 'flex-column py-3 gap-3' : 'justify-content-between'}`}>
                <CSidebarBrand className="text-decoration-none d-flex" href="/">
                    <div className="d-flex align-items-center gap-2 cursor-pointer">
                        {clientData.logoUrl ? (
                            <img src={clientData.logoUrl} alt="Logo" style={{ height: 32, borderRadius: 4 }} />
                        ) : (
                            <CIcon icon={cilShieldAlt} height={32} className="text-danger" />
                        )}
                        <span className={`fw-bold text-white ${unfoldable ? 'd-none' : ''}`}>GCP Hardener</span>
                    </div>
                </CSidebarBrand>

                {/* Hamburger toggle inside Sidebar */}
                <CIcon
                    icon={cilMenu}
                    size="lg"
                    className={`cursor-pointer text-white ${unfoldable ? '' : 'ms-2'}`}
                    style={{ cursor: 'pointer', zIndex: 10 }}
                    onClick={(e) => {
                        e.stopPropagation();
                        onUnfoldableChange && onUnfoldableChange(!unfoldable);
                    }}
                />


            </CSidebarHeader>

            <CSidebarNav className={unfoldable ? 'd-none' : ''}>
                <CNavTitle className="text-white opacity-75">Client Details</CNavTitle>

                {/* Custom Content in Sidebar Nav */}
                <div className="pt-2">
                    <SidebarInput
                        label="Company Name"
                        value={clientData.companyName}
                        field="companyName"
                        placeholder="Acme Corp"
                        errors={errors}
                        updateClientData={updateClientData}
                        handleBlur={handleBlur}
                    />

                    {/* Session status badge — shown after companyName blur */}
                    {sessionStatus !== 'idle' && (
                        <div className={`mx-3 mb-2 px-2 py-1 rounded text-[10px] font-mono flex items-center gap-1.5 ${sessionStatus === 'loading' ? 'bg-blue-50 text-blue-600' :
                            sessionStatus === 'ok' ? 'bg-green-50 text-green-700 border border-green-200' :
                                'bg-red-50 text-red-700 border border-red-200'
                            }`}>
                            {sessionStatus === 'loading' && <span className="animate-spin inline-block w-3 h-3 border border-current border-t-transparent rounded-full" />}
                            {sessionStatus === 'ok' && <span>✓</span>}
                            {sessionStatus === 'error' && <span>✗</span>}
                            <span className="truncate max-w-[160px]" title={sessionStatusMsg}>{sessionStatusMsg}</span>
                        </div>
                    )}

                    <SidebarInput
                        label="Authorized By"
                        value={clientData.authName}
                        field="authName"
                        placeholder="Name"
                        errors={errors}
                        updateClientData={updateClientData}
                        handleBlur={handleBlur}
                    />

                    <SidebarInput
                        label="Auth Email"
                        value={clientData.authEmail}
                        field="authEmail"
                        placeholder="Email"
                        type="email"
                        errors={errors}
                        updateClientData={updateClientData}
                        handleBlur={handleBlur}
                    />

                    <CNavTitle className="text-white opacity-75">Analyst</CNavTitle>

                    <SidebarInput
                        label="Security Analyst"
                        value={clientData.scannerName}
                        field="scannerName"
                        placeholder="Name"
                        errors={errors}
                        updateClientData={updateClientData}
                        handleBlur={handleBlur}
                    />

                    <div className="mx-3 mt-3 p-2 bg-body-tertiary rounded border">
                        <div className="d-flex justify-content-between align-items-center">
                            <div>
                                <div className="text-[10px] fw-bold text-uppercase text-danger">Last Scan</div>
                                <div className="text-[10px] font-monospace text-white opacity-75">
                                    {clientData.lastScanDate ? new Date(clientData.lastScanDate).toLocaleDateString() : '---'}
                                </div>
                            </div>
                            {clientData.id && (
                                <Link href={`/history?clientId=${clientData.id}`}>
                                    <CIcon icon={cilHistory} className="text-danger" />
                                </Link>
                            )}
                        </div>
                    </div>

                    <div className="mx-3 mt-4 mb-4">
                        <button
                            className="btn btn-sm btn-outline-danger w-100 d-flex align-items-center justify-content-center gap-1 text-white border-secondary hover:bg-danger hover:text-white"
                            onClick={resetClient}
                        >
                            <CIcon icon={cilPlus} size="sm" />
                            New Customer
                        </button>
                    </div>

                    <div className="mx-3 text-[10px] text-white opacity-75 d-flex justify-content-between">
                        <span>{isLoading ? 'Saving...' : 'Auto-saved'}</span>
                        {clientData.id && <span className="text-success"><CIcon icon={cilSave} height={10} /> Synced</span>}
                    </div>
                </div>

            </CSidebarNav>

            <CSidebarFooter className="border-top d-flex">
                <CSidebarToggler
                    onClick={() => onUnfoldableChange && onUnfoldableChange(!unfoldable)}
                />
            </CSidebarFooter>
        </CSidebar>
    );
}
