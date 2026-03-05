"use client";

import React, { useEffect, useState } from 'react';
import {
    CHeader,
    CContainer,
    CHeaderNav,
    CNavItem,
    CNavLink,
    CButton,
    CHeaderToggler,
} from '@coreui/react';
import CIcon from '@coreui/icons-react';
import { cilShieldAlt, cilCloudUpload, cilUser, cilMenu } from '@coreui/icons';

interface AppHeaderProps {
    jitActive?: boolean;
    sessionTime?: number;
    onUploadClick?: () => void;
    onSidebarToggle?: () => void;
}

export default function AppHeader({ jitActive = false, sessionTime = 0, onUploadClick, onSidebarToggle }: AppHeaderProps) {
    const [appIdentity, setAppIdentity] = useState<string | null>(null);

    useEffect(() => {
        // Fetch current system bootstrap identity from backend
        // This is the underlying gcloud identity running the python server,
        // NOT the Scanner SA.
        const fetchIdentity = async () => {
            try {
                // Use the Next.js same-origin proxy route to avoid CORS and IPv6 issues
                const res = await fetch('/api/system-config');
                if (res.ok) {
                    const data = await res.json();
                    const fetchedSa = data.service_account_email;

                    if (fetchedSa && fetchedSa !== "user-credentials-detected" && fetchedSa !== "error-detecting-identity" && fetchedSa !== "unknown-identity") {
                        setAppIdentity(fetchedSa);
                    }
                }
            } catch (e) {
                console.error("Failed to fetch system identity", e);
            }
        };
        fetchIdentity();
    }, []);

    return (
        <CHeader position="sticky" className="mb-4 p-0 border-bottom">
            <CContainer fluid className="px-3 px-md-4 d-flex flex-wrap align-items-center justify-content-between">

                {/* Left Side: Dashboard Link */}
                <div className="d-flex align-items-center me-auto">
                    <CHeaderNav className="d-flex flex-row">
                        <CNavItem>
                            <CNavLink href="/" active className="px-2">Dashboard</CNavLink>
                        </CNavItem>
                        {/* Privileges link permanently removed as requested */}
                    </CHeaderNav>
                </div>

                {/* Right Side: Identity and Actions */}
                <CHeaderNav className="ms-auto d-flex flex-row align-items-center gap-2 gap-md-3 flex-wrap">

                    {/* Responsive Identity Display */}
                    {appIdentity && (
                        <CNavItem className="d-none d-md-block">
                            <div className="d-flex align-items-center gap-2 bg-light px-3 py-1 rounded-pill border border-secondary-subtle" title={`App Identity: ${appIdentity}`}>
                                <CIcon icon={cilUser} size="sm" className="text-secondary" />
                                <span className="small fw-medium text-secondary-emphasis font-monospace text-truncate" style={{ fontSize: '0.75rem', maxWidth: '300px' }}>
                                    {appIdentity} <span className="text-muted fw-normal">(App Identity)</span>
                                </span>
                            </div>
                        </CNavItem>
                    )}

                    <CNavItem>
                        {jitActive && (
                            <div className="d-flex align-items-center gap-2 bg-success-subtle px-2 px-md-3 py-1 rounded-pill border border-success-subtle">
                                <span className="spinner-grow spinner-grow-sm text-success" role="status" aria-hidden="true"></span>
                                <span className="small fw-bold text-success-emphasis d-none d-sm-inline">JIT Active</span>
                                <span className="small text-success">({Math.floor(sessionTime / 60)}m)</span>
                            </div>
                        )}
                    </CNavItem>
                </CHeaderNav>

            </CContainer>
        </CHeader>
    );
}
