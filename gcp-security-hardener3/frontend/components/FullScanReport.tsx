
import React, { useState } from 'react';
import BillingModule from '@/components/modules/BillingModule';
import NetworkModule from '@/components/modules/NetworkModule';
import ApiSecurityModule from '@/components/modules/ApiSecurityModule';
import IamSecurityModule from '@/components/modules/IamSecurityModule';
import MonitoringModule from '@/components/modules/MonitoringModule';
import ArchitecturalReviewModule from '@/components/modules/ArchitecturalReviewModule';
import ChangeControlAuditModule from '@/components/modules/ChangeControlAuditModule';
import { ScanResponse } from '@/app/page';
import { Download, X, Server, Loader } from 'lucide-react';

interface FullScanReportProps {
    scanResults: ScanResponse[];
    selectedModules: Set<string>;
    onClose: () => void;
    modulesDef: any[]; // Pass the module definitions (names, icons) from page.tsx
    jitToken: string;
}

export default function FullScanReport({ scanResults, selectedModules, onClose, modulesDef, jitToken }: FullScanReportProps) {
    const [pdfLoading, setPdfLoading] = useState(false);
    const [pdfError, setPdfError] = useState<string | null>(null);

    const handleDownloadPDF = async () => {
        try {
            setPdfLoading(true);
            setPdfError(null);

            // Step 1: POST scan results → backend generates PDF, saves to /tmp, returns download_id
            const res = await fetch('/api/v1/report/generate-pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanResults),
            });

            if (!res.ok) {
                const text = await res.text();
                throw new Error(`PDF generation failed (${res.status}): ${text}`);
            }

            const { download_id, filename } = await res.json();
            if (!download_id) throw new Error('Server did not return a download ID.');

            // Step 2: Fetch the PDF as a Blob to strictly enforce the filename and extension
            const safeFilename = filename ?? `gcp_security_report_${new Date().toISOString().split('T')[0].replace(/-/g, '')}.pdf`;

            const pdfRes = await fetch(`/api/v1/report/download/${download_id}`);
            if (!pdfRes.ok) throw new Error('Failed to pull PDF document stream');
            const blob = await pdfRes.blob();

            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = safeFilename;
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




    // Helper to render module content (duplicated from page.tsx for stability)
    const renderModuleResult = (result: ScanResponse, activeModule: string) => {
        switch (activeModule) {
            case 'billing':
                return (
                    <BillingModule
                        data={result.billing_info}
                        risks={result.risks || []}
                        loading={false}
                        projectId={result.project_id}
                        jitToken={jitToken}
                    />
                );
            case 'scc':
                return (
                    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
                        <div className="p-4 bg-gray-50 border-b border-gray-200 flex justify-between items-center">
                            <h4 className="font-semibold text-gray-800 flex items-center gap-2">
                                🚨 Operational & SCC Findings
                            </h4>
                            <span className={`px-2 py-1 rounded text-xs font-medium ${result.scc_info?.status === 'ACTIVE' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                                }`}>
                                {result.scc_info?.status || 'UNKNOWN'}
                            </span>
                        </div>

                        {!result.scc_info?.findings || result.scc_info.findings.length === 0 ? (
                            <div className="p-8 text-center text-gray-500">
                                <p>No active high-severity findings detected in SCC.</p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">State</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resource</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {result.scc_info.findings.map((f: any, idx: number) => (
                                            <tr key={idx} className="hover:bg-gray-50">
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${f.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                                        f.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                                                            f.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                                                                'bg-blue-100 text-blue-800'
                                                        }`}>
                                                        {f.severity}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{f.category}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{f.state}</td>
                                                <td className="px-6 py-4 text-sm font-mono text-gray-500">
                                                    <div className="overflow-x-auto pb-2 max-w-[300px] custom-scrollbar">
                                                        <span className="whitespace-nowrap">
                                                            {f.category.includes('Error') ? f.resource_name : f.resource_name.split('/').pop()}
                                                        </span>
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                );
            case 'network':
                return (
                    <NetworkModule
                        risks={result.risks || []}
                        loading={false}
                    />
                );
            case 'api':
                return (
                    <ApiSecurityModule
                        data={result.api_analysis}
                        risks={result.risks || []}
                        loading={false}
                    />
                );
            case 'iam':
                return (
                    <IamSecurityModule scanData={result} />
                );
            case 'monitoring':
                return (
                    <MonitoringModule scanData={result} />
                );
            case 'change_control':
                return (
                    <div className="p-4">
                        <h3 className="text-xl font-bold mb-4 text-gray-900">Remediation & Change Control</h3>
                        <ChangeControlAuditModule data={result.change_control_info} />
                    </div>
                );
            case 'architectural_foundations':
                return (
                    <ArchitecturalReviewModule data={result.architecture_info} />
                );
            default:
                // Fallback for generic risks
                const moduleRisks = (result.risks || []).filter(r =>
                    (activeModule === 'api' && r.category === 'api') ||
                    (activeModule === 'iam' && r.category === 'iam') ||
                    (activeModule === 'monitoring' && r.category === 'monitoring')
                );

                if (moduleRisks.length > 0) {
                    return (
                        <div className="space-y-4">
                            <h3 className="font-bold text-gray-800">Findings for {activeModule.toUpperCase()}</h3>
                            {moduleRisks.map((risk: any, idx: number) => (
                                <div key={idx} className="bg-white p-4 rounded-lg shadow-sm border border-gray-200 break-inside-avoid">
                                    <div className="flex justify-between items-start">
                                        <div className="flex gap-2 items-center">
                                            <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${risk.risk_level === 'critical' ? 'bg-red-200 text-red-800' : 'bg-yellow-200 text-yellow-800'}`}>
                                                {risk.risk_level}
                                            </span>
                                            <h4 className="font-bold text-gray-900">{risk.title}</h4>
                                        </div>
                                    </div>
                                    <p className="mt-2 text-sm text-gray-600 leading-relaxed">{risk.description}</p>
                                    <div className="mt-3 text-xs bg-gray-50 p-2.5 rounded border border-gray-100 text-gray-700">
                                        <span className="font-bold text-gray-900">Recommendation:</span> {risk.recommendation}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )
                }
                return null;
        }
    };

    return (
        <div id="full-scan-print-container" className="fixed inset-0 bg-gray-100 z-50 overflow-y-auto print:static print:bg-white print:p-0">
            <div className="max-w-7xl mx-auto py-12 px-6 print:max-w-none print:p-0 print:m-0 print:w-full">

                {/* Print/Exit Controls */}
                <div className="flex justify-between items-center mb-8 print:hidden bg-white p-4 rounded-xl shadow-sm border border-gray-200 sticky top-4 z-50">
                    <div>
                        <h2 className="text-xl font-bold text-gray-900">Full Data Export</h2>
                        <p className="text-sm text-gray-500">{scanResults.length} Projects • Full Detail View</p>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                        <div className="flex gap-4">
                            <button
                                onClick={handleDownloadPDF}
                                disabled={pdfLoading}
                                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2 font-medium disabled:opacity-60 disabled:cursor-not-allowed"
                            >
                                {pdfLoading ? (
                                    <><Loader className="w-4 h-4 animate-spin" /> Generating PDF…</>
                                ) : (
                                    <><Download className="w-4 h-4" /> Download PDF</>
                                )}
                            </button>
                            <button
                                onClick={onClose}
                                className="px-4 py-2 bg-gray-100 text-gray-600 rounded-lg hover:bg-gray-200 flex items-center gap-2"
                            >
                                <X className="w-4 h-4" />
                                Close
                            </button>
                        </div>
                        {pdfError && (
                            <p className="text-xs text-red-600 max-w-sm text-right">{pdfError}</p>
                        )}
                    </div>
                </div>

                {/* Header for Print — outside the project container so first-child works */}
                <div className="hidden print:block mb-8 text-center border-b pb-8">
                    <h1 className="text-3xl font-bold text-gray-900 mb-2">Detailed Security Scan Report</h1>
                    <p className="text-gray-500">Generated on {new Date().toLocaleDateString()}</p>
                </div>

                {/* Report Content */}
                <div className="space-y-12 print:space-y-8">
                    {scanResults.map(res => (
                        <div key={res.project_id} className="bg-white rounded-xl shadow-none print:shadow-none border border-gray-200 print:border-0 overflow-hidden print:overflow-visible break-before-page">

                            {/* Project Header */}
                            <div className="p-6 bg-gray-50 border-b border-gray-200 print:bg-gray-100 print:border-gray-300">
                                <div className="flex items-center gap-4">
                                    <div className={`w-12 h-12 rounded-full flex items-center justify-center text-2xl shrink-0 border-2 ${res.risks.length > 0 ? 'bg-red-50 text-red-500 border-red-200' : 'bg-green-50 text-green-500 border-green-200'}`}>
                                        {res.risks.length > 0 ? '⚠️' : '✓'}
                                    </div>
                                    <div>
                                        <h2 className="text-2xl font-extrabold text-gray-900 tracking-tight">{res.project_id}</h2>
                                        <div className="flex items-center gap-3 mt-1">
                                            <span className={`text-sm font-bold px-3 py-0.5 rounded-full ${res.risks.length > 0 ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                                                {res.risks.length} Issues Found
                                            </span>
                                            {res.billing_info?.billing_account_id && (
                                                <span className="text-sm font-mono text-gray-500">
                                                    Billing: {res.billing_info.billing_account_id}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Project Content */}
                            <div className="p-6 print:px-0 print:py-2 space-y-8">

                                {/* Inventory (if present) */}
                                {res.inventory_summary && (
                                    <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 break-inside-avoid">
                                        <h4 className="font-bold text-slate-800 mb-3 flex items-center gap-2 text-sm uppercase tracking-wide">
                                            <Server className="w-4 h-4" /> Infrastructure Snapshot
                                        </h4>
                                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                                            <div className="bg-white p-3 rounded border border-slate-100 shadow-sm">
                                                <span className="block text-gray-400 text-[10px] uppercase font-bold">Total Assets</span>
                                                <span className="font-mono text-xl font-bold text-gray-900">{res.inventory_summary.total_assets}</span>
                                            </div>
                                            <div className="bg-white p-3 rounded border border-slate-100 shadow-sm">
                                                <span className="block text-gray-400 text-[10px] uppercase font-bold">Public IPs</span>
                                                <span className={`font-mono text-xl font-bold ${res.inventory_summary.public_ip_count > 0 ? 'text-orange-600' : 'text-green-600'}`}>
                                                    {res.inventory_summary.public_ip_count}
                                                </span>
                                            </div>
                                            <div className="bg-white p-3 rounded border border-slate-100 shadow-sm">
                                                <span className="block text-gray-400 text-[10px] uppercase font-bold">Buckets</span>
                                                <span className="font-mono text-xl font-bold text-gray-900">{res.inventory_summary.storage_buckets}</span>
                                            </div>
                                            <div className="bg-white p-3 rounded border border-slate-100 shadow-sm">
                                                <span className="block text-gray-400 text-[10px] uppercase font-bold">SQL</span>
                                                <span className="font-mono text-xl font-bold text-gray-900">{res.inventory_summary.sql_instances}</span>
                                            </div>
                                            <div className="bg-white p-3 rounded border border-slate-100 shadow-sm">
                                                <span className="block text-gray-400 text-[10px] uppercase font-bold">Firewall Rules</span>
                                                <span className="font-mono text-xl font-bold text-gray-900">{res.inventory_summary.firewall_rules}</span>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Modules */}
                                <div className="space-y-8">
                                    {modulesDef.filter(m => selectedModules.has(m.id)).map(mod => {
                                        // Skip if nothing to show for this module? No, show it even if empty/safe
                                        // Unless we want strictly "risks only"? 
                                        // User asked for "just like scan results page", so we show modules.

                                        const content = renderModuleResult(res, mod.id);
                                        if (!content) return null;

                                        return (
                                            <div key={mod.id} className="">
                                                <h3
                                                    className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2 border-b border-gray-100 pb-2"
                                                    style={{ pageBreakAfter: 'avoid', breakAfter: 'avoid' }}
                                                >
                                                    <span className="text-xl opacity-75">{mod.icon}</span>
                                                    {mod.name}
                                                </h3>
                                                <div className="pl-4 border-l-2 border-gray-100">
                                                    {content}
                                                </div>
                                            </div>
                                        )
                                    })}
                                </div>

                            </div>

                        </div>
                    ))}
                </div>
            </div>

            <style media="print">{`
                @page { margin: 10mm; size: portrait; }
                body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: white !important; }

                /* Hide the sidebar, header, footer — anything not in the report */
                .sidebar, .header, .footer, nav {
                    display: none !important;
                }

                /* Reset the flex layout wrapper so it doesn't constrain printing */
                .d-flex {
                    display: block !important;
                }
                .wrapper {
                    margin-left: 0 !important;
                    padding: 0 !important;
                }

                /* Show our specific container */
                #full-scan-print-container {
                    position: absolute !important;
                    left: 0 !important;
                    top: 0 !important;
                    width: 100% !important;
                    margin: 0 !important;
                    padding: 0 !important;
                    background: white !important;
                    overflow: visible !important;
                    z-index: 99999 !important;
                }

                .break-before-page { page-break-before: always; }
                .break-before-page:first-child { page-break-before: auto; }
                .break-inside-avoid { page-break-inside: avoid; }
            `}</style>
        </div>
    );
}
