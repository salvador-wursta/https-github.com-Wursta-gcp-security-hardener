import React from 'react';
import { GitBranch, Shield, AlertTriangle, CheckCircle, Terminal, Activity, FileCode } from 'lucide-react';

interface ChangeControlAuditModuleProps {
    data?: {
        score: number;
        level: string;
        signals: {
            manual_changes?: {
                human_ratio: number;
                total: number;
            };
            iac_usage?: boolean;
            ci_cd_adoption?: boolean;
            approval_gates?: boolean;
        };
        recommendations: string[];
        maturity_plan?: {
            title: string;
            description: string;
            immediate_actions: string[];
            long_term_goals: string[];
        };
    };
}

export default function ChangeControlAuditModule({ data }: ChangeControlAuditModuleProps) {
    if (!data) {
        return (
            <div className="p-6 bg-gray-50 border border-gray-200 rounded-xl text-center">
                <p className="text-gray-500">No change control audit data available.</p>
            </div>
        );
    }

    const { score, level, signals, recommendations } = data;

    const getScoreColor = (s: number) => {
        if (s >= 80) return 'text-green-600 bg-green-50 border-green-200';
        if (s >= 50) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
        return 'text-red-600 bg-red-50 border-red-200';
    };

    return (
        <div className="space-y-6 mb-8">
            <div className={`p-6 rounded-xl border flex items-center justify-between ${getScoreColor(score)}`}>
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-white rounded-full shadow-sm">
                        <GitBranch className="w-8 h-8" />
                    </div>
                    <div>
                        <h3 className="text-lg font-bold">Change Control Maturity: {level}</h3>
                        <p className="text-sm opacity-90">Score: {score}/100</p>
                    </div>
                </div>
                {score < 50 && (
                    <div className="flex items-center gap-2 px-3 py-1 bg-white/50 rounded text-sm font-medium">
                        <AlertTriangle className="w-4 h-4" />
                        Action Required
                    </div>
                )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Manual Changes Signal */}
                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
                    <div className="flex items-center gap-3 mb-2">
                        <Activity className="w-5 h-5 text-purple-500" />
                        <h4 className="font-semibold text-gray-900">Manual Change Activity</h4>
                    </div>
                    <div className="mt-2 text-sm text-gray-600">
                        {signals.manual_changes ? (
                            <>
                                <p>Human-initiated changes: <strong className={signals.manual_changes.human_ratio > 0.3 ? 'text-red-600' : 'text-green-600'}>
                                    {(signals.manual_changes.human_ratio * 100).toFixed(1)}%
                                </strong></p>
                                <div className="w-full bg-gray-200 rounded-full h-2.5 mt-2">
                                    <div className="bg-purple-600 h-2.5 rounded-full" style={{ width: `${signals.manual_changes.human_ratio * 100}%` }}></div>
                                </div>
                            </>
                        ) : (
                            <p className="text-gray-400 italic">Log data unavailable</p>
                        )}
                    </div>
                </div>

                {/* Automation Signals */}
                <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm space-y-3">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
                            <Terminal className="w-4 h-4" />
                            CI/CD Pipelines
                        </div>
                        {signals.ci_cd_adoption ? <CheckCircle className="w-5 h-5 text-green-500" /> : <AlertTriangle className="w-5 h-5 text-red-500" />}
                    </div>

                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
                            <FileCode className="w-4 h-4" />
                            Infrastructure as Code
                        </div>
                        {signals.iac_usage ? <CheckCircle className="w-5 h-5 text-green-500" /> : <AlertTriangle className="w-5 h-5 text-red-500" />}
                    </div>

                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
                            <Shield className="w-4 h-4" />
                            Approval Gates (BinAuth)
                        </div>
                        {signals.approval_gates ? <CheckCircle className="w-5 h-5 text-green-500" /> : <span className="text-xs text-gray-400 font-mono">Not Enforced</span>}
                    </div>
                </div>
            </div>

            {/* Maturity Plan Section */}
            {data.maturity_plan && (
                <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm">
                    <div className="bg-indigo-50 px-6 py-4 border-b border-indigo-100">
                        <h4 className="flex items-center gap-2 text-indigo-900 font-bold">
                            <Activity className="w-5 h-5 text-indigo-600" />
                            Strategic Roadmap: {data.maturity_plan.title}
                        </h4>
                    </div>
                    <div className="p-6 space-y-6">
                        <p className="text-gray-600 italic">"{data.maturity_plan.description}"</p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <div>
                                <h5 className="text-sm font-bold text-gray-900 uppercase tracking-wider mb-3 border-b pb-2">Immediate Actions</h5>
                                <ul className="space-y-3">
                                    {data.maturity_plan.immediate_actions.map((action: string, i: number) => (
                                        <li key={i} className="flex gap-3 text-sm text-gray-700">
                                            <span className="text-indigo-500 font-bold step-index">{i + 1}.</span>
                                            <span dangerouslySetInnerHTML={{
                                                // Simple parser for **bold**
                                                __html: action.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                                            }} />
                                        </li>
                                    ))}
                                </ul>
                            </div>

                            <div>
                                <h5 className="text-sm font-bold text-gray-900 uppercase tracking-wider mb-3 border-b pb-2">Long-Term Goals</h5>
                                <ul className="space-y-3">
                                    {data.maturity_plan.long_term_goals.map((goal: string, i: number) => (
                                        <li key={i} className="flex gap-3 text-sm text-gray-700">
                                            <CheckCircle className="w-4 h-4 text-green-500 shrink-0 mt-0.5" />
                                            <span>{goal}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
