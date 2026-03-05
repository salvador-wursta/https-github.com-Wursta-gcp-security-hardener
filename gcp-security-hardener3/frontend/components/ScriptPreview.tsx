/**
 * Script Preview Component
 * Displays generated lockdown script with syntax highlighting and download option
 */
import React, { useState } from 'react';
import { Download, Play, ChevronLeft, FileCode, CheckCircle, AlertTriangle } from 'lucide-react';

interface ScriptPreviewProps {
    script: string;
    format: 'python' | 'terraform' | 'pulumi';
    summary: {
        steps?: number;
        apis_to_disable?: number;
        network_hardening?: boolean;
        org_policies?: boolean;
        resources?: number;
    };
    warnings: string[];
    estimatedDuration: string;
    onExecute: () => void;
    onExecuteAll?: () => void;
    onDownload: () => void;
    onBack: () => void;
}

const FORMAT_CONFIG = {
    python: {
        extension: 'py',
        language: 'Python',
        icon: '🐍',
        executeLabel: 'Execute Now',
    },
    terraform: {
        extension: 'tf',
        language: 'HCL',
        icon: '🏗️',
        executeLabel: 'Apply with Terraform',
    },
    pulumi: {
        extension: 'py',
        language: 'Python (Pulumi)',
        icon: '☁️',
        executeLabel: 'Deploy with Pulumi',
    },
};

export function ScriptPreview({
    script,
    format,
    summary,
    warnings,
    estimatedDuration,
    onExecute,
    onExecuteAll,
    onDownload,
    onBack,
}: ScriptPreviewProps) {
    const config = FORMAT_CONFIG[format] || FORMAT_CONFIG.python;
    const [showFullScript, setShowFullScript] = useState(false);

    const displayedScript = showFullScript ? script : script.split('\n').slice(0, 30).join('\n');
    const totalLines = script.split('\n').length;
    const truncated = !showFullScript && totalLines > 30;

    return (
        <div className="max-w-6xl mx-auto">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200">
                {/* Header */}
                <div className="p-6 border-b border-gray-200">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
                            <FileCode className="w-6 h-6" />
                            Review Generated Script
                        </h2>
                        <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-100 rounded-lg">
                            <span className="text-2xl">{config.icon}</span>
                            <span className="font-medium text-gray-700">{config.language}</span>
                        </div>
                    </div>

                    <p className="text-gray-600">
                        Review the generated {config.language} script before executing. This script will apply security hardening to your GCP project.
                    </p>
                </div>

                {/* Summary */}
                <div className="p-6 bg-gray-50 border-b border-gray-200">
                    <h3 className="font-semibold text-gray-900 mb-3">What This Script Will Do:</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        {summary.apis_to_disable !== undefined && summary.apis_to_disable > 0 && (
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-5 h-5 text-blue-600" />
                                <div>
                                    <div className="font-semibold text-gray-900">{summary.apis_to_disable}</div>
                                    <div className="text-sm text-gray-600">APIs to Disable</div>
                                </div>
                            </div>
                        )}

                        {summary.network_hardening && (
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-5 h-5 text-blue-600" />
                                <div>
                                    <div className="font-semibold text-gray-900">2</div>
                                    <div className="text-sm text-gray-600">Firewall Rules</div>
                                </div>
                            </div>
                        )}

                        {summary.org_policies && (
                            <div className="flex items-center gap-2">
                                <CheckCircle className="w-5 h-5 text-blue-600" />
                                <div>
                                    <div className="font-semibold text-gray-900">Enabled</div>
                                    <div className="text-sm text-gray-600">Org Policies</div>
                                </div>
                            </div>
                        )}

                        <div className="flex items-center gap-2">
                            <CheckCircle className="w-5 h-5 text-blue-600" />
                            <div>
                                <div className="font-semibold text-gray-900">{estimatedDuration}</div>
                                <div className="text-sm text-gray-600">Est. Duration</div>
                            </div>
                        </div>
                    </div>

                    {/* Warnings */}
                    {warnings.length > 0 && (
                        <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                            <div className="flex items-start gap-2">
                                <AlertTriangle className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
                                <div className="flex-1">
                                    <h4 className="font-semibold text-yellow-900 mb-2">Important Warnings:</h4>
                                    <ul className="space-y-1 text-sm text-yellow-800">
                                        {warnings.map((warning, idx) => (
                                            <li key={idx}>• {warning}</li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Script Display */}
                <div className="p-6">
                    <div className="mb-3 flex items-center justify-between">
                        <span className="text-sm font-medium text-gray-700">
                            {totalLines} lines • {(script.length / 1024).toFixed(1)} KB
                        </span>
                        {truncated && (
                            <button
                                onClick={() => setShowFullScript(!showFullScript)}
                                className="text-sm text-blue-600 hover:text-blue-700 font-medium"
                            >
                                {showFullScript ? 'Show Less' : `Show All ${totalLines} Lines`}
                            </button>
                        )}
                    </div>

                    <div className="bg-gray-900 rounded-lg overflow-hidden">
                        <div className="bg-gray-800 px-4 py-2 flex items-center justify-between">
                            <span className="text-sm text-gray-300 font-mono">lockdown_script.{config.extension}</span>
                            <button
                                onClick={onDownload}
                                className="text-gray-300 hover:text-white transition flex items-center gap-1 text-sm"
                            >
                                <Download className="w-4 h-4" />
                                Download
                            </button>
                        </div>
                        <div className="p-4 overflow-x-auto">
                            <pre className="text-sm text-gray-100 font-mono leading-relaxed">
                                <code>{displayedScript}</code>
                            </pre>
                            {truncated && !showFullScript && (
                                <div className="mt-4 text-center">
                                    <button
                                        onClick={() => setShowFullScript(true)}
                                        className="text-blue-400 hover:text-blue-300 text-sm"
                                    >
                                        ... {totalLines - 30} more lines ...
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Actions */}
                <div className="p-6 bg-gray-50 border-t border-gray-200 flex items-center justify-between">
                    <button
                        onClick={onBack}
                        className="flex items-center gap-2 px-4 py-2 text-gray-700 hover:text-gray-900 transition"
                    >
                        <ChevronLeft className="w-4 h-4" />
                        Back to API Selection
                    </button>

                    <div className="flex items-center gap-3">
                        <button
                            onClick={onDownload}
                            className="px-6 py-3 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition font-medium flex items-center gap-2"
                        >
                            <Download className="w-4 h-4" />
                            Download Script
                        </button>

                        <button
                            onClick={onExecute}
                            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition font-medium flex items-center gap-2"
                        >
                            <Play className="w-4 h-4" />
                            {config.executeLabel}
                        </button>

                        {onExecuteAll && (
                            <button
                                onClick={onExecuteAll}
                                className="px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition font-medium flex items-center gap-2"
                            >
                                <Play className="w-4 h-4" />
                                Run All Scripts
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* Format-Specific Instructions */}
            {
                format !== 'python' && (
                    <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                        <h4 className="font-semibold text-blue-900 mb-2">
                            {format === 'terraform' ? 'Terraform' : 'Pulumi'} Deployment Instructions:
                        </h4>
                        <ol className="space-y-1 text-sm text-blue-800 list-decimal list-inside">
                            {format === 'terraform' ? (
                                <>
                                    <li>Download the generated .tf file</li>
                                    <li>Run <code className="bg-blue-100 px-1 py-0.5 rounded">terraform init</code> to initialize</li>
                                    <li>Run <code className="bg-blue-100 px-1 py-0.5 rounded">terraform plan</code> to review changes</li>
                                    <li>Run <code className="bg-blue-100 px-1 py-0.5 rounded">terraform apply</code> to deploy</li>
                                </>
                            ) : (
                                <>
                                    <li>Download the generated __main__.py file</li>
                                    <li>Run <code className="bg-blue-100 px-1 py-0.5 rounded">pulumi stack init</code> to create stack</li>
                                    <li>Run <code className="bg-blue-100 px-1 py-0.5 rounded">pulumi preview</code> to review changes</li>
                                    <li>Run <code className="bg-blue-100 px-1 py-0.5 rounded">pulumi up</code> to deploy</li>
                                </>
                            )}
                        </ol>
                    </div>
                )
            }
        </div >
    );
}
