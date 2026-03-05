import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { LayoutTemplate, AlertTriangle, CheckCircle, BookOpen, ShieldAlert, BadgeCheck, Download } from 'lucide-react';

interface ArchitecturalFinding {
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    standard_violation: string;
    recommendation: string;
}

interface ArchitecturalData {
    findings: ArchitecturalFinding[];
    summary?: string;
    raw_data?: any;
}

interface ArchitecturalReviewModuleProps {
    data: ArchitecturalData | null;
}

export default function ArchitecturalReviewModule({ data }: ArchitecturalReviewModuleProps) {
    if (!data) {
        return null;
    }

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 'bg-red-50 border-red-200 text-red-900 icon-red-600';
            case 'HIGH': return 'bg-orange-50 border-orange-200 text-orange-900 icon-orange-600';
            case 'MEDIUM': return 'bg-yellow-50 border-yellow-200 text-yellow-900 icon-yellow-600';
            case 'LOW': return 'bg-blue-50 border-blue-200 text-blue-900 icon-blue-600';
            default: return 'bg-gray-50 border-gray-200 text-gray-900 icon-gray-600';
        }
    };

    const getBadgeColor = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 'bg-red-100 text-red-800 border-red-300';
            case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-300';
            case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-300';
            case 'LOW': return 'bg-blue-100 text-blue-800 border-blue-300';
            default: return 'bg-gray-100 text-gray-800 border-gray-300';
        }
    };

    const handleDownload = () => {
        if (!data.raw_data) return;
        const blob = new Blob([JSON.stringify(data.raw_data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `architectural-scan-raw-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    return (
        <div className="space-y-0 divide-y divide-gray-100">
            <div className="px-4 py-3 bg-indigo-50/50 rounded-t-lg border-b border-indigo-100 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-indigo-700">
                    <LayoutTemplate className="w-4 h-4" />
                    <span>Foundations based on Google Cloud Architecture Framework & NIST 800-53</span>
                </div>
                {data.raw_data && (
                    <button
                        onClick={handleDownload}
                        className="flex items-center gap-1.5 px-3 py-1 bg-white text-indigo-600 border border-indigo-200 rounded hover:bg-indigo-50 hover:border-indigo-300 transition-colors text-xs font-medium"
                        title="Download raw assets and policies collected for analysis"
                    >
                        <Download className="w-3.5 h-3.5" />
                        Raw JSON
                    </button>
                )}
            </div>

            <div className="divide-y divide-gray-100">
                {(data as any).error ? (
                    <div className="p-6 bg-red-50 text-red-700">
                        <div className="flex items-center gap-2 font-bold mb-2">
                            <AlertTriangle className="w-5 h-5" />
                            Scan Error
                        </div>
                        <div className="text-sm p-4 bg-red-50 text-red-800 rounded border border-red-200 mt-2 font-mono whitespace-pre-wrap break-all">
                            {(data as any).error}
                        </div>
                    </div>
                ) : (!data.findings || data.findings.length === 0) ? (
                    <div className="p-12 text-center text-gray-500">
                        <BadgeCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
                        <p className="font-medium">No architectural violations detected.</p>
                        <p className="text-sm mt-1">Your configuration aligns with the inspected best practices.</p>
                    </div>
                ) : (
                    data.findings.map((finding, idx) => (
                        <div key={idx} className="p-6 hover:bg-slate-50 transition-colors">
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-3">
                                    <h4 className="text-md font-bold text-gray-900">{finding.title}</h4>
                                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${getBadgeColor(finding.severity)}`}>
                                        {finding.severity}
                                    </span>
                                </div>
                                {finding.standard_violation && (
                                    <div className="flex items-center gap-1.5 px-3 py-1 bg-gray-100 rounded-full text-xs text-gray-600 border border-gray-200">
                                        <BookOpen className="w-3.5 h-3.5" />
                                        <span className="font-medium font-mono">{finding.standard_violation}</span>
                                    </div>
                                )}
                            </div>

                            <div className="prose prose-sm max-w-none text-gray-600 prose-headings:font-semibold prose-headings:text-gray-800 prose-code:text-blue-600 prose-code:bg-blue-50 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-pre:bg-gray-900 prose-pre:text-gray-50">
                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                    {finding.recommendation}
                                </ReactMarkdown>
                            </div>
                        </div>
                    ))
                )}
            </div>

            <div className="bg-gray-50 px-6 py-3 border-t border-gray-200 text-xs text-gray-500 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-gray-400" />
                <span>Automated architectural analysis generated by Gemini. Always validate recommendations with your security team.</span>
            </div>
        </div>
    );
}
