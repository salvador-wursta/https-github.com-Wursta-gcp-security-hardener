
'use client';

import { useState } from 'react';
import { setupOrgMonitoring, OrgMonitoringSetupRequest } from '../lib/api';
import { Loader2, ShieldCheck, AlertTriangle } from 'lucide-react';

interface OrgMonitoringSetupProps {
    defaultProjectId?: string;
    defaultEmail?: string;
    credentialToken: string;  // Required for service account authentication
    onClose: () => void;
}

export default function OrgMonitoringSetup({ defaultProjectId, defaultEmail, credentialToken, onClose }: OrgMonitoringSetupProps) {
    const [formData, setFormData] = useState<OrgMonitoringSetupRequest>({
        org_id: '',
        project_id: defaultProjectId || '',
        billing_account_id: '',
        alert_emails: defaultEmail ? [defaultEmail] : [],
        region: 'global',
        credential_token: credentialToken
    });

    const [status, setStatus] = useState<'idle' | 'submitting' | 'success' | 'error'>('idle');
    const [logs, setLogs] = useState<string[]>([]);
    const [errorMsg, setErrorMsg] = useState('');

    const handleEmailChange = (val: string) => {
        // Simple comma-separated split for now
        setFormData({ ...formData, alert_emails: val.split(',').map(e => e.trim()).filter(Boolean) });
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setStatus('submitting');
        setLogs(['Starting organization setup...']);
        setErrorMsg('');

        try {
            const response = await setupOrgMonitoring(formData);

            if (response.success) {
                setStatus('success');
                setLogs(prev => [...prev, ...response.steps_completed.map(s => `✓ Completed: ${s}`)]);
                setLogs(prev => [...prev, '✅ Organization Monitoring Enabled Successfully!']);
            } else {
                setStatus('error');
                setErrorMsg(response.errors.join(', '));
                setLogs(prev => [...prev, ...response.errors.map(err => `❌ Error: ${err}`)]);
            }
        } catch (err: any) {
            setStatus('error');
            setErrorMsg(err.message || 'Unknown error occurred');
            setLogs(prev => [...prev, `❌ Exception: ${err.message}`]);
        }
    };

    return (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                <div className="p-6 border-b border-gray-100 flex justify-between items-center">
                    <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                        <ShieldCheck className="w-6 h-6 text-indigo-600" />
                        Enable Organization-Level Monitoring
                    </h2>
                    <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
                        <span className="sr-only">Close</span>
                        ✕
                    </button>
                </div>

                <div className="p-6">
                    {status === 'idle' || status === 'submitting' ? (
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div className="bg-blue-50 p-4 rounded-lg flex gap-3 text-sm text-blue-800 mb-6">
                                <ShieldCheck className="w-5 h-5 flex-shrink-0" />
                                <div>
                                    <p className="font-semibold">Best Practice Deployment</p>
                                    <p>This will configure an Aggregated Log Sink, Central Log Bucket, and Billing Alerts ($0.10 threshold) to monitor your entire organization for security events free of charge (within limits).</p>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">Organization ID</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="e.g. 123456789012"
                                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500"
                                        value={formData.org_id}
                                        onChange={e => setFormData({ ...formData, org_id: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">Billing Account ID</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="000000-000000-000000"
                                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500"
                                        value={formData.billing_account_id}
                                        onChange={e => setFormData({ ...formData, billing_account_id: e.target.value })}
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Destination Project ID (Security Project)</label>
                                <input
                                    type="text"
                                    required
                                    placeholder="my-security-project"
                                    className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500"
                                    value={formData.project_id}
                                    onChange={e => setFormData({ ...formData, project_id: e.target.value })}
                                />
                                <p className="text-xs text-gray-500 mt-1">Logs will be routed here. We recommend a dedicated project.</p>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">Log Bucket Region</label>
                                    <select
                                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500"
                                        value={formData.region}
                                        onChange={e => setFormData({ ...formData, region: e.target.value })}
                                    >
                                        <option value="global">Global (Default)</option>
                                        <option value="us-central1">us-central1</option>
                                        <option value="europe-west1">europe-west1</option>
                                        <option value="asia-northeast1">asia-northeast1</option>
                                        {/* Add more as needed */}
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">Alert Emails</label>
                                    <input
                                        type="text"
                                        required
                                        placeholder="admin@example.com, security@example.com"
                                        className="w-full px-3 py-2 border rounded-md focus:ring-2 focus:ring-indigo-500"
                                        value={formData.alert_emails.join(', ')}
                                        onChange={e => handleEmailChange(e.target.value)}
                                    />
                                </div>
                            </div>

                            <div className="flex justify-end pt-4">
                                <button
                                    type="submit"
                                    disabled={status === 'submitting'}
                                    className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 flex items-center gap-2 disabled:opacity-50"
                                >
                                    {status === 'submitting' && <Loader2 className="w-4 h-4 animate-spin" />}
                                    {status === 'submitting' ? 'Configuring...' : 'Enable Monitoring'}
                                </button>
                            </div>
                        </form>
                    ) : (
                        <div className="space-y-4">
                            <div className={`p-4 rounded-lg flex gap-3 ${status === 'success' ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'}`}>
                                {status === 'success' ? <ShieldCheck className="w-6 h-6" /> : <AlertTriangle className="w-6 h-6" />}
                                <div>
                                    <h3 className="font-bold">{status === 'success' ? 'Setup Complete' : 'Setup Failed'}</h3>
                                    <p className="text-sm">{status === 'success' ? 'Your organization is now monitored.' : errorMsg}</p>
                                </div>
                            </div>

                            <div className="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-sm max-h-60 overflow-y-auto">
                                {logs.map((log, i) => (
                                    <div key={i}>{log}</div>
                                ))}
                            </div>

                            <div className="flex justify-end pt-2">
                                <button onClick={onClose} className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                                    Close
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
