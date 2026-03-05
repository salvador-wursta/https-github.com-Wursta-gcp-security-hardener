"use client";

import React, { useEffect, useState, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import DashboardLayout from '@/components/DashboardLayout';
import Link from 'next/link';
import { ArrowLeft, Download } from 'lucide-react';

function ScanDetailContent() {
    const searchParams = useSearchParams();
    const clientId = searchParams.get('clientId');
    const scanId = searchParams.get('scanId');
    const [scan, setScan] = useState<any>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchScan = async () => {
            if (!clientId || !scanId) return;
            try {
                const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
                const res = await fetch(`${backendUrl}/api/v1/clients/${clientId}/scans/${scanId}`);
                if (res.ok) {
                    const data = await res.json();
                    setScan(data);
                }
            } catch (e) {
                console.error("Failed to fetch scan detail", e);
            } finally {
                setLoading(false);
            }
        };

        if (clientId && scanId) {
            fetchScan();
        } else {
            setLoading(false);
        }
    }, [clientId, scanId]);

    if (loading) return <div className="p-10 text-center">Loading...</div>;

    if (!clientId || !scanId) {
        return <div className="p-10 text-center text-red-500">Missing Client ID or Scan ID</div>;
    }

    if (!scan) return <div className="p-10 text-center text-red-500">Scan not found</div>;

    // `scan.results` presumably contains `{ scans: [...] }`
    const projectScans = scan.results?.scans || [];

    return (
        <div className="max-w-6xl mx-auto py-8 px-4">
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-4">
                    <Link href={`/history?clientId=${clientId}`} className="p-2 hover:bg-gray-100 rounded-full text-gray-500">
                        <ArrowLeft size={20} />
                    </Link>
                    <div>
                        <h1 className="text-2xl font-bold text-gray-900">Scan Details</h1>
                        <p className="text-sm text-gray-500">
                            {new Date(scan.timestamp).toLocaleString()} • {scan.summary.ran_by}
                        </p>
                    </div>
                </div>
                <button
                    className="flex items-center gap-2 px-4 py-2 border border-blue-200 text-blue-600 rounded hover:bg-blue-50"
                    onClick={() => {
                        const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `scan-result-${scanId}.json`;
                        a.click();
                    }}
                >
                    <Download size={16} /> Download JSON
                </button>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm">
                    <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-2">Projects Scanned</h3>
                    <div className="text-3xl font-bold text-gray-900">{projectScans.length}</div>
                </div>
                <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm">
                    <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-2">Modules Run</h3>
                    <div className="flex flex-wrap gap-2 mt-2">
                        {scan.summary.modules?.map((m: string) => (
                            <span key={m} className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs font-semibold uppercase">{m}</span>
                        ))}
                    </div>
                </div>
                <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm">
                    <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-2">Status</h3>
                    <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-bold">
                        Completed
                    </span>
                </div>
            </div>

            {/* Detailed JSON View */}
            <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
                    <h3 className="text-lg font-bold text-gray-800">Results Data</h3>
                </div>
                <div className="p-0">
                    <pre className="p-4 bg-gray-900 text-gray-100 text-xs overflow-auto max-h-[600px] font-mono">
                        {JSON.stringify(projectScans, null, 2)}
                    </pre>
                </div>
            </div>
        </div>
    );
}

export default function ScanDetailPage() {
    return (
        <DashboardLayout>
            <Suspense fallback={<div className="text-center py-20">Loading...</div>}>
                <ScanDetailContent />
            </Suspense>
        </DashboardLayout>
    );
}
