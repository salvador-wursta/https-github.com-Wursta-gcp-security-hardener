"use client";

import React, { useState } from 'react';
import AppSidebar from './AppSidebar';
import AppHeader from './AppHeader';
import AppFooter from './AppFooter';
import { CContainer } from '@coreui/react';

interface DefaultLayoutProps {
    children: React.ReactNode;
    jitActive?: boolean;
    sessionTime?: number;
    onUploadClick?: () => void;
}

export default function DefaultLayout({
    children,
    jitActive,
    sessionTime,
    onUploadClick
}: DefaultLayoutProps) {
    const [sidebarVisible, setSidebarVisible] = useState(true); // Keep sidebar always on screen
    const [sidebarUnfoldable, setSidebarUnfoldable] = useState(false); // Controls fold/shrink state

    return (
        <div>
            <AppSidebar
                visible={true}
                onVisibleChange={() => setSidebarVisible(true)}
                unfoldable={sidebarUnfoldable}
                onUnfoldableChange={(u) => setSidebarUnfoldable(u)}
            />
            <div
                className="wrapper d-flex flex-column min-vh-100 bg-light"
                style={{
                    paddingLeft: sidebarUnfoldable ? '4.5rem' : '16rem',
                    transition: 'padding-left 0.3s ease',
                }}
            >
                <AppHeader
                    jitActive={jitActive}
                    sessionTime={sessionTime}
                    onUploadClick={onUploadClick}
                    onSidebarToggle={() => setSidebarUnfoldable(!sidebarUnfoldable)}
                />
                <div className="body flex-grow-1 px-3">
                    <CContainer lg>
                        {children}
                    </CContainer>
                </div>
                <AppFooter />
            </div>
        </div>
    );
}
