"use client";

import React from 'react';
import { CFooter, CLink } from '@coreui/react';

export default function AppFooter() {
    return (
        <CFooter className="px-4">
            <div>
                <CLink href="https://wursta.com" target="_blank" rel="noopener noreferrer">
                    Wursta
                </CLink>
                <span className="ms-1">&copy; 2026 GCP Hardener.</span>
            </div>
            <div className="ms-auto">
                <span className="me-1">Powered by</span>
                <CLink href="https://coreui.io/react" target="_blank" rel="noopener noreferrer">
                    CoreUI for React
                </CLink>
            </div>
        </CFooter>
    );
}
