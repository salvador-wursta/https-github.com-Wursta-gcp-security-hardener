import React, { useState, useEffect } from 'react';
import { useClient } from '../context/ClientContext';
import {
    FileText, Shield, AlertTriangle, CheckCircle,
    BarChart2, PieChart, Info, Download, ChevronDown, ChevronRight, Loader
} from 'lucide-react';


interface ReportingInterfaceProps {
    scanResults: any[];
    jitToken: string;
    onClose: () => void;
}

// Simple Gauge Component using SVG
const Gauge = ({ value, label, color }: { value: number; label: string; color: string }) => {
    const angle = (value / 100) * 180 - 90;
    return (
        <div className="flex flex-col items-center">
            <div className="relative w-32 h-16 overflow-hidden mb-2">
                <div className="absolute top-0 left-0 w-32 h-32 rounded-full border-8 border-gray-200" style={{ boxSizing: 'border-box' }}></div>
                <div
                    className="absolute top-0 left-0 w-32 h-32 rounded-full border-8 border-transparent"
                    style={{
                        borderTopColor: color,
                        borderLeftColor: color,
                        transform: `rotate(${angle}deg)`,
                        transition: 'transform 1s ease-out',
                        boxSizing: 'border-box'
                    }}
                ></div>
            </div>
            <div className="w-24 h-24 rounded-full border-4 flex flex-col items-center justify-center shadow-sm" style={{ borderColor: color }}>
                <span className="text-2xl font-bold" style={{ color }}>{value}</span>
                <span className="text-xs text-gray-400">/ 100</span>
            </div>
            <p className="font-semibold text-gray-700 mt-2">{label}</p>
        </div>
    );
};

export default function ReportingInterface({ scanResults, jitToken, onClose }: ReportingInterfaceProps) {
    const { clientData } = useClient();
    const [report, setReport] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [pdfLoading, setPdfLoading] = useState(false);
    const [pdfError, setPdfError] = useState<string | null>(null);

    const generateReport = async () => {
        try {
            setLoading(true);
            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';

            // Extract a project ID from the scan results to identify the client context
            // In a real app, this would be passed as a prop or context
            const projectId = scanResults.length > 0 ? scanResults[0].project_id : null;
            const url = projectId
                ? `${backendUrl}/api/v1/report/generate?project_id=${projectId}`
                : `${backendUrl}/api/v1/report/generate`;

            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-JIT-Token': jitToken
                },
                body: JSON.stringify(scanResults) // We still send body as fallback/compat
            });

            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Session expired. Please lock session and re-authenticate.');
                }
                throw new Error('Failed to generate report');
            }

            const data = await response.json();
            setReport(data);
        } catch (err) {
            console.error(err);
            setError(err instanceof Error ? err.message : 'An error occurred');
        } finally {
            setLoading(false);
        }
    };

    const handleDownloadPDF = async () => {
        try {
            setPdfLoading(true);
            setPdfError(null);

            const params = new URLSearchParams();
            if (clientData?.companyName) params.set('org_name', clientData.companyName);
            if (clientData?.scannerName) params.set('analyst_name', clientData.scannerName);

            // Step 1: POST scan results → backend generates PDF and streams it directly
            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
            const res = await fetch(
                `${backendUrl}/api/v1/report/generate-pdf?${params.toString()}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(scanResults),
                }
            );

            if (!res.ok) {
                const text = await res.text();
                throw new Error(`PDF generation failed (${res.status}): ${text}`);
            }

            // Step 2: Read the streamed response as a Blob
            const blob = await res.blob();

            // Extract filename from Content-Disposition header if present, otherwise use a safe default
            const disposition = res.headers.get('Content-Disposition');
            let filename = `gcp_security_report_${new Date().toISOString().split('T')[0].replace(/-/g, '')}.pdf`;
            if (disposition && disposition.indexOf('filename=') !== -1) {
                const matches = /filename="([^"]+)"/.exec(disposition);
                if (matches != null && matches[1]) filename = matches[1];
            }

            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

        } catch (err: any) {
            console.error('PDF download error:', err);
            setPdfError(err.message || 'PDF download failed. Please try again.');
        } finally {
            setPdfLoading(false);
        }
    };


    useEffect(() => {
        if (scanResults && scanResults.length > 0) {
            generateReport();
        }
    }, [scanResults]);

    if (loading) {
        return (
            <div className="fixed inset-0 bg-gray-100 z-50 flex items-center justify-center">
                <div className="text-center">
                    <Loader className="w-12 h-12 text-indigo-600 animate-spin mx-auto mb-4" />
                    <h2 className="text-xl font-bold text-gray-900">Generating Executive Report...</h2>
                    <p className="text-gray-500"> analyzing {scanResults.length} projects</p>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="fixed inset-0 bg-gray-100 z-50 flex items-center justify-center">
                <div className="bg-white p-8 rounded-xl shadow-lg max-w-md text-center">
                    <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
                    <h2 className="text-xl font-bold text-gray-900 mb-2">Report Generation Failed</h2>
                    <p className="text-gray-600 mb-6">{error}</p>
                    <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg hover:bg-gray-300">Close</button>
                </div>
            </div>
        );
    }

    if (!report) return null;

    const { executive_summary, charts, top_risks, recommendations, all_findings } = report;

    // Color helpers
    const getRiskColor = (level: string) => {
        switch (level.toLowerCase()) {
            case 'critical': return 'text-red-600 bg-red-50 border-red-200';
            case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
            case 'medium': return 'text-blue-600 bg-blue-50 border-blue-200';
            case 'low': return 'text-green-600 bg-green-50 border-green-200';
            default: return 'text-gray-600 bg-gray-50 border-gray-200';
        }
    };

    // Helper for Risk Dial
    const getRiskScore = (rating: string) => {
        switch (rating?.toLowerCase()) {
            case 'critical': return { score: 95, color: '#EF4444' }; // Red
            case 'high': return { score: 75, color: '#F97316' }; // Orange
            case 'medium': return { score: 50, color: '#EAB308' }; // Yellow
            case 'low': return { score: 25, color: '#3B82F6' }; // Blue
            default: return { score: 10, color: '#9CA3AF' };
        }
    };

    // Helper for Maturity Dial
    const getMaturityScore = (rating: string) => {
        switch (rating?.toLowerCase()) {
            case 'high': return { score: 90, color: '#10B981' }; // Green
            case 'medium': return { score: 60, color: '#3B82F6' }; // Blue
            case 'low': return { score: 30, color: '#F97316' }; // Orange
            default: return { score: 15, color: '#EF4444' }; // Red
        }
    };

    const riskMeta = getRiskScore(executive_summary.risk_rating);
    const maturityMeta = getMaturityScore(executive_summary.maturity_rating);

    return (
        <>
            <style media="print">{`
                @page { size: landscape; margin: 5mm; }
                body { background: white; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
                
                /* Hide everything else */
                body * { visibility: hidden; }
                
                /* Show the report container */
                #printable-report-container, #printable-report-container * {
                    visibility: visible;
                }

                /* Position it correctly */
                #printable-report-container {
                    position: absolute;
                    left: 0;
                    top: 0;
                    width: 100%;
                    margin: 0;
                    padding: 10mm;
                    background: white;
                    overflow: visible !important;
                }

                /* Ensure grid works in print */
                .grid { display: grid !important; }
                
                /* Table Sizing */
                table { width: 100% !important; table-layout: fixed !important; }
                td, th { word-wrap: break-word; overflow-wrap: break-word; }

                /* Page Breaks */
                tr { page-break-inside: avoid; }
                h1, h2, h3, .card { page-break-after: avoid; }
                .break-after { page-break-after: always; }
            `}</style>
            <div className="fixed inset-0 bg-gray-100 z-40 overflow-y-auto print:static print:overflow-visible print:bg-white print:p-0 print:m-0">
                <div id="printable-report-container" className="max-w-6xl mx-auto py-12 px-6 print:max-w-none print:p-0 print:m-0 print:w-full font-sans">

                    {/* Header Actions */}
                    <div className="flex justify-between items-center mb-8 print:hidden">
                        <button onClick={onClose} className="text-gray-600 hover:text-gray-900 flex items-center gap-2">
                            ← Back to Dashboard
                        </button>
                        <div className="flex flex-col items-end gap-1">
                            <button
                                onClick={handleDownloadPDF}
                                disabled={pdfLoading}
                                className="px-4 py-2 bg-indigo-600 text-white rounded-lg shadow-sm hover:bg-indigo-700 flex items-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
                            >
                                {pdfLoading ? (
                                    <><Loader className="w-4 h-4 animate-spin" /> Generating PDF…</>
                                ) : (
                                    <><Download className="w-4 h-4" /> Export PDF</>
                                )}
                            </button>
                            {pdfError && (
                                <p className="text-xs text-red-600 max-w-sm text-right">{pdfError}</p>
                            )}
                        </div>
                    </div>

                    {/* REPORT CONTAINER */}
                    <div className="bg-white shadow-xl rounded-2xl overflow-hidden print:shadow-none print:rounded-none">

                        {/* Cover Page / Header */}
                        <div className="bg-gradient-to-r from-gray-900 to-indigo-900 text-white p-10 relative overflow-hidden print:p-8">
                            <div className="relative z-10 flex justify-between items-start">
                                <div className="text-left">
                                    {clientData.logoUrl && (
                                        <div className="mb-6 bg-white/10 p-2 rounded inline-block backdrop-blur-sm border border-white/20">
                                            {/* eslint-disable-next-line @next/next/no-img-element */}
                                            <img src={clientData.logoUrl} alt="Company Logo" className="h-12 w-auto object-contain" />
                                        </div>
                                    )}
                                    <h1 className="text-4xl font-bold mb-4">Executive Security Report</h1>
                                    <p className="text-indigo-200 text-lg mb-1">GCP Security Hardening Assessment</p>
                                    <p className="text-sm text-indigo-300">Generated: {new Date(report.generated_at).toLocaleDateString()}</p>
                                </div>

                                <div className="text-right bg-white/10 p-4 rounded-lg backdrop-blur-sm border border-white/10 min-w-[200px]">
                                    {clientData.companyName && (
                                        <div className="mb-3">
                                            <p className="text-[10px] uppercase tracking-widest text-indigo-200 font-semibold">Prepared For</p>
                                            <p className="font-bold text-lg">{clientData.companyName}</p>
                                        </div>
                                    )}
                                    {(clientData.scannerName) && (
                                        <div>
                                            <p className="text-[10px] uppercase tracking-widest text-indigo-200 font-semibold">Security Analyst</p>
                                            <p className="font-bold">{clientData.scannerName}</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="p-8 md:p-10 space-y-10 print:p-6 print:space-y-6">

                            {/* 1. Executive Summary & Dials */}
                            <section className="bg-gray-50 rounded-xl p-6 border border-gray-200 print:bg-white print:border-2">
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-center">
                                    {/* Dials Column */}
                                    <div className="md:col-span-3 flex justify-around items-center gap-4 py-4 border-b border-gray-200 mb-4 print:border-b-2">
                                        <Gauge
                                            value={executive_summary.overall_score}
                                            label="Security Score"
                                            color={executive_summary.overall_score > 80 ? '#10B981' : executive_summary.overall_score > 60 ? '#F59E0B' : '#EF4444'}
                                        />
                                        <div className="h-16 w-px bg-gray-300 print:bg-gray-400"></div>
                                        <Gauge
                                            value={riskMeta.score}
                                            label={`Risk: ${executive_summary.risk_rating}`}
                                            color={riskMeta.color}
                                        />
                                        <div className="h-16 w-px bg-gray-300 print:bg-gray-400"></div>
                                        <Gauge
                                            value={maturityMeta.score}
                                            label={`Maturity: ${executive_summary.maturity_rating}`}
                                            color={maturityMeta.color}
                                        />
                                    </div>

                                    {/* 2. Visualizations (Moved Up) */}
                                    <div className="md:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-8 print:grid-cols-2">
                                        {/* Bar Chart Logic */}
                                        <div className="bg-white p-4 rounded-xl border border-gray-200 print:border">
                                            <h4 className="text-sm font-bold text-gray-700 mb-4 uppercase tracking-wider">Severity Distribution</h4>
                                            <div className="space-y-3">
                                                {charts.risk_distribution.map((item: any) => (
                                                    <div key={item.name} className="flex items-center gap-3 text-xs">
                                                        <span className="w-16 font-medium text-gray-600">{item.name}</span>
                                                        <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden border border-gray-200">
                                                            <div
                                                                className="h-full rounded-full print:print-color-adjust-exact"
                                                                style={{ width: `${(item.value / Math.max(1, report.scope.total_risks_found)) * 100}%`, backgroundColor: item.color }}
                                                            ></div>
                                                        </div>
                                                        <span className="w-6 font-bold text-right">{item.value}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                        {/* Recommendations Summary */}
                                        <div className="bg-indigo-50 p-4 rounded-xl border border-indigo-100 print:bg-white print:border-indigo-200">
                                            <h4 className="text-sm font-bold text-indigo-900 mb-2 uppercase tracking-wider">Top Priority</h4>
                                            {recommendations.slice(0, 3).map((rec: any, i: number) => (
                                                <div key={i} className="mb-2 last:mb-0">
                                                    <div className="text-xs font-bold text-gray-900">
                                                        {i + 1}. {rec.title}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Executive Assessment Text */}
                                    <div className="md:col-span-3">
                                        <h2 className="text-xl font-bold text-gray-900 mb-2 flex items-center gap-2">
                                            <FileText className="w-5 h-5 text-indigo-600" />
                                            Executive Assessment
                                        </h2>
                                        <p className="text-gray-700 leading-relaxed text-sm whitespace-pre-wrap">
                                            {executive_summary.text}
                                        </p>
                                        <p className="mt-2 text-sm text-gray-500">
                                            Scope: {report.scope.projects_scanned} project(s) scanned. Identified {report.scope.total_risks_found} findings.
                                        </p>
                                    </div>
                                </div>
                            </section>

                            <hr className="border-gray-100 print:hidden" />

                            {/* 3. Findings Table */}
                            <section className="print:pt-4">
                                <div className="flex items-center gap-2 mb-4 border-b border-gray-200 pb-2">
                                    <AlertTriangle className="w-5 h-5 text-gray-700" />
                                    <h2 className="text-lg font-bold text-gray-900">Detailed Findings Log</h2>
                                </div>

                                <table className="w-full text-left text-xs border-collapse table-fixed">
                                    <thead>
                                        <tr className="bg-gray-100 text-gray-600 uppercase tracking-wider border-b-2 border-gray-300 print:bg-gray-200">
                                            <th className="px-2 py-2 w-24">Severity</th>
                                            <th className="px-2 py-2 w-32">Project</th>
                                            <th className="px-2 py-2 w-1/4">Finding</th>
                                            <th className="px-2 py-2 w-24">Category</th>
                                            <th className="px-2 py-2">Recommendation</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-200 border-b border-gray-200">
                                        {all_findings && all_findings.map((risk: any, i: number) => (
                                            <tr key={i} className="break-inside-avoid">
                                                <td className="px-2 py-3 align-top">
                                                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getRiskColor(risk.risk_level)} print:border-gray-300`}>
                                                        {risk.risk_level}
                                                    </span>
                                                </td>
                                                <td className="px-2 py-3 align-top font-mono text-gray-600 truncate">
                                                    {risk.project_id}
                                                </td>
                                                <td className="px-2 py-3 align-top font-bold text-gray-800">
                                                    {risk.title}
                                                    <div className="font-normal text-gray-500 mt-1 line-clamp-2">{risk.description}</div>
                                                </td>
                                                <td className="px-2 py-3 align-top text-gray-500 capitalize">
                                                    {risk.category}
                                                </td>
                                                <td className="px-2 py-3 align-top text-gray-600">
                                                    {risk.recommendation}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </section>

                            <div className="text-center pt-8 border-t border-gray-100">
                                <p className="text-sm text-gray-400">Generated by GCP Security Hardener AI • Confidential</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );

}
