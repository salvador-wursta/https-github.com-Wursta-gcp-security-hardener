"use client";

import React, { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import DashboardLayout from '@/components/DashboardLayout';
import { ArrowLeft, Calendar, ChevronRight } from 'lucide-react';
import Link from 'next/link';

interface ScanRecord {
    id: string;
    timestamp: string;
    status: string;
    summary: {
        ran_by?: string;
        project_count?: number;
        modules?: string[];
    };
}

function HistoryContent() {
    const searchParams = useSearchParams();
    const clientId = searchParams.get('clientId');
    const [scans, setScans] = useState<ScanRecord[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchScans = async () => {
            if (!clientId) return;
            try {
                const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
                const res = await fetch(`${backendUrl}/api/v1/clients/${clientId}/scans`);
                if (res.ok) {
                    const data = await res.json();
                    setScans(data);
                }
            } catch (e) {
                console.error("Failed to fetch history", e);
            } finally {
                setLoading(false);
            }
        };

        if (clientId) {
            fetchScans();
        } else {
            setLoading(false);
        }
    }, [clientId]);

    if (!clientId) {
        return (
            <div className="text-center py-20">
                <p className="text-gray-500">No Client ID specified.</p>
                <Link href="/" className="text-blue-600 hover:underline mt-4 inline-block">Return Home</Link>
            </div>
        );
    }

    return (
        <div className="max-w-5xl mx-auto py-8 px-4">
            <div className="flex items-center gap-4 mb-8">
                <Link href="/" className="p-2 hover:bg-gray-100 rounded-full text-gray-500">
                    <ArrowLeft size={20} />
                </Link>
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Scan History</h1>
                    <p className="text-sm text-gray-500">Past security assessments for this client.</p>
                </div>
            </div>

            {loading ? (
                <div className="text-center py-20">
                    <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-blue-600 border-r-transparent"></div>
                    <p className="mt-2 text-gray-500">Loading history...</p>
                </div>
            ) : scans.length === 0 ? (
                <div className="text-center py-20 bg-white rounded-lg border border-gray-200">
                    <div className="mx-auto w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mb-4">
                        <Calendar className="text-gray-400" />
                    </div>
                    <h3 className="text-lg font-medium text-gray-900">No scans recorded</h3>
                    <p className="text-gray-500 mt-1">Run a scan from the dashboard to see it here.</p>
                    <Link href="/">
                        <button className="mt-6 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                            Go to Dashboard
                        </button>
                    </Link>
                </div>
            ) : (
                <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Ran By</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Projects</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Modules</th>
                                <th className="px-6 py-3 relative">
                                    <span className="sr-only">View</span>
                                </th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {scans.map((scan) => (
                                <tr key={scan.id} className="hover:bg-gray-50 transition-colors">
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <div className="flex items-center">
                                            <div className="flex-shrink-0 h-8 w-8 bg-blue-50 rounded flex items-center justify-center text-blue-600">
                                                <Calendar size={16} />
                                            </div>
                                            <div className="ml-4">
                                                <div className="text-sm font-medium text-gray-900">
                                                    {new Date(scan.timestamp).toLocaleDateString()}
                                                </div>
                                                <div className="text-xs text-gray-500">
                                                    {new Date(scan.timestamp).toLocaleTimeString()}
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <div className="text-sm text-gray-900">{scan.summary?.ran_by || 'Unknown'}</div>
                                        <div className="text-xs text-gray-500">Scanner</div>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">
                                            {scan.summary?.project_count || 0} Projects
                                        </span>
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex flex-wrap gap-1">
                                            {(scan.summary?.modules || []).slice(0, 3).map((m: string) => (
                                                <span key={m} className="px-2 py-0.5 text-xs rounded border border-gray-200 text-gray-600">
                                                    {m}
                                                </span>
                                            ))}
                                            {(scan.summary?.modules || []).length > 3 && (
                                                <span className="text-xs text-gray-400 self-center">...</span>
                                            )}
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 text-right text-sm font-medium">
                                        {/* NOTE: We also need to fix the Detail view to use Query Params! */}
                                        <Link href={`/history/detail?clientId=${clientId}&scanId=${scan.id}`} className="text-blue-600 hover:text-blue-900 flex items-center justify-end gap-1">
                                            View Details <ChevronRight size={16} />
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

export default function ClientHistoryPage() {
    return (
        <DashboardLayout>
            <Suspense fallback={<div className="text-center py-20">Loading...</div>}>
                <HistoryContent />
            </Suspense>
        </DashboardLayout>
    );
}
