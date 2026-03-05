'use client';

import React from 'react';
import Link from 'next/link';
import DashboardLayout from '@/components/DashboardLayout';
import { Shield, Lock, Eye, Terminal } from 'lucide-react';

export default function PrivilegesPage() {
    return (
        <DashboardLayout>
            <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500">

                {/* Header */}
                <div className="border-b border-gray-200 pb-6">
                    <div className="flex items-center gap-2 text-sm text-blue-600 mb-2 font-medium">
                        <Link href="/" className="hover:underline">← Back to Dashboard</Link>
                    </div>
                    <h1 className="text-3xl font-bold text-gray-900">JIT Access Privileges</h1>
                    <p className="text-gray-600 mt-2 text-lg">
                        Understanding the permissions granted to the temporary Service Accounts.
                    </p>
                </div>

                {/* Introduction */}
                <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-blue-900 flex items-center gap-2">
                        <Shield className="w-5 h-5" />
                        Zero-Trust Design
                    </h3>
                    <p className="text-blue-800 mt-2">
                        This application creates <b>Just-In-Time (JIT)</b> service accounts that exist only for the duration of your session.
                        Keys are held in browser memory and are wiped immediately upon session lock or window close.
                        We segregate duties between a "Scanner" (Read-Only) and an "Admin" (Write) account to ensure the principle of least privilege.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

                    {/* Scanner Account */}
                    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100 flex items-center gap-2">
                            <div className="bg-green-100 p-2 rounded-lg">
                                <Eye className="w-5 h-5 text-green-700" />
                            </div>
                            <div>
                                <h2 className="font-bold text-gray-900">Scanner Account</h2>
                                <p className="text-xs text-gray-500 font-mono">gcp-hardener-scanner@...</p>
                            </div>
                        </div>
                        <div className="p-6 space-y-4">
                            <p className="text-sm text-gray-600">
                                This account is used for initial discovery and risk assessment. It cannot modify any resources.
                            </p>

                            <div>
                                <h4 className="font-semibold text-gray-900 text-sm uppercase tracking-wider mb-2">IAM Roles Granted</h4>
                                <ul className="space-y-2">
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/viewer</span>
                                        <span className="text-gray-600">Read-only access to all GCP resources (Compute, Network, Storage, etc).</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/iam.securityReviewer</span>
                                        <span className="text-gray-600">Ability to view (but not edit) IAM policies and organization settings.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/billing.viewer</span>
                                        <span className="text-gray-600">Read-only access to billing account usage and cost data.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/securitycenter.assetsViewer</span>
                                        <span className="text-gray-600">View security assets and inventory.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/securitycenter.findingsViewer</span>
                                        <span className="text-gray-600">View security findings and vulnerabilities.</span>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>

                    {/* Admin Account */}
                    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100 flex items-center gap-2">
                            <div className="bg-red-100 p-2 rounded-lg">
                                <Terminal className="w-5 h-5 text-red-700" />
                            </div>
                            <div>
                                <h2 className="font-bold text-gray-900">Admin Account</h2>
                                <p className="text-xs text-gray-500 font-mono">gcp-hardener-admin@...</p>
                            </div>
                        </div>
                        <div className="p-6 space-y-4">
                            <p className="text-sm text-gray-600">
                                This account is <b>optional</b>. It is used only when you explicitly request to apply a fix or generate Terraform code.
                            </p>

                            <div>
                                <h4 className="font-semibold text-gray-900 text-sm uppercase tracking-wider mb-2">IAM Roles Granted</h4>
                                <ul className="space-y-2">
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/editor</span>
                                        <span className="text-gray-600">Edit access to most resources (required to change configurations).</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/iam.securityAdmin</span>
                                        <span className="text-gray-600">Ability to modify IAM policies (required to revoke dangerous permissions).</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/serviceusage.serviceUsageAdmin</span>
                                        <span className="text-gray-600">Ability to enable/disable APIs.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/logging.configWriter</span>
                                        <span className="text-gray-600">Ability to create and manage logging sinks and buckets.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/monitoring.admin</span>
                                        <span className="text-gray-600">Ability to create alert policies and notification channels.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/compute.securityAdmin</span>
                                        <span className="text-gray-600">Ability to create and modify firewall rules.</span>
                                    </li>
                                    <li className="flex items-start gap-2 text-sm">
                                        <span className="bg-gray-100 text-gray-800 px-2 py-0.5 rounded font-mono text-xs mt-0.5">roles/securitycenter.admin</span>
                                        <span className="text-gray-600">Ability to configure Security Command Center settings.</span>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Security Note */}
                <div className="bg-gray-50 rounded-xl p-6 border border-gray-200">
                    <h3 className="text-gray-900 font-bold mb-2 flex items-center gap-2">
                        <Lock className="w-4 h-4" />
                        Clean Up Process
                    </h3>
                    <p className="text-gray-600 text-sm">
                        When you close the browser tab or click "Lock Session", the keys are deleted from local memory.
                        The service accounts themselves remain in your project (so you don't have to re-run the script every time) but <b>they have no active keys</b> other than the ones you temporarily generated and held in memory.
                        You can manually delete these service accounts from your GCP IAM console at any time.
                    </p>
                </div>

            </div>
        </DashboardLayout>
    );
}
