
"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

// Define the shape of our client data
export interface ClientData {
    id?: string;
    companyName: string;
    authName: string;
    authEmail: string;
    scannerName: string;
    scannerEmail: string;
    lastScanDate?: string;
    logoUrl?: string;
    orgName?: string;
    orgId?: string;
    sessionSaEmail?: string | null;
    sessionDomain?: string | null;
}

interface ClientContextType {
    clientData: ClientData;
    updateClientData: (data: Partial<ClientData>) => void;
    saveClient: () => Promise<string | null>; // Returns ID on success
    saveScanResult: (summary: any, results: any) => Promise<void>;
    resetClient: () => void;
    isLoading: boolean;
}

const defaultClientData: ClientData = {
    companyName: '',
    authName: '',
    authEmail: '',
    scannerName: '',
    scannerEmail: '',
    orgName: '',
    orgId: '',
    sessionSaEmail: null,
    sessionDomain: null,
};

const ClientContext = createContext<ClientContextType | undefined>(undefined);

export function ClientProvider({ children }: { children: ReactNode }) {
    const [clientData, setClientData] = useState<ClientData>(defaultClientData);
    const [isLoading, setIsLoading] = useState(false);

    // Load from localStorage on mount
    useEffect(() => {
        const saved = localStorage.getItem('gcp_security_client_context');
        if (saved) {
            try {
                setClientData(JSON.parse(saved));
            } catch (e) {
                console.error("Failed to load saved client context", e);
            }
        }
    }, []);

    // Save to localStorage on change
    useEffect(() => {
        localStorage.setItem('gcp_security_client_context', JSON.stringify(clientData));
    }, [clientData]);

    const updateClientData = (data: Partial<ClientData>) => {
        setClientData(prev => ({ ...prev, ...data }));
    };

    const saveClient = async (): Promise<string | null> => {
        if (!clientData.companyName) return null;

        setIsLoading(true);
        try {
            // Generate a local ID if one doesn't exist
            const id = clientData.id || `local-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

            updateClientData({ id });

            // Data is already persisted to localStorage via the useEffect above
            return id;

        } catch (error) {
            console.error("Error saving client:", error);
            return null;
        } finally {
            setIsLoading(false);
        }
    };

    const saveScanResult = async (summary: any, results: any) => {
        if (!clientData.id) return;

        try {
            // Save scan results to localStorage
            const scanHistory = JSON.parse(localStorage.getItem('gcp_security_scan_history') || '[]');
            scanHistory.push({
                clientId: clientData.id,
                date: new Date().toISOString(),
                summary: {
                    ...summary,
                    org_name: clientData.orgName,
                    org_id: clientData.orgId
                },
                results
            });
            // Keep only latest 20 scan entries
            if (scanHistory.length > 20) scanHistory.splice(0, scanHistory.length - 20);
            localStorage.setItem('gcp_security_scan_history', JSON.stringify(scanHistory));

            // Update local last scan date
            updateClientData({ lastScanDate: new Date().toISOString() });

        } catch (error) {
            console.error("Error saving scan result:", error);
        }
    };

    const resetClient = () => {
        setClientData({
            ...defaultClientData
        });
    };

    return (
        <ClientContext.Provider value={{ clientData, updateClientData, saveClient, saveScanResult, resetClient, isLoading }}>
            {children}
        </ClientContext.Provider>
    );
}

export function useClient() {
    const context = useContext(ClientContext);
    if (context === undefined) {
        throw new Error('useClient must be used within a ClientProvider');
    }
    return context;
}
