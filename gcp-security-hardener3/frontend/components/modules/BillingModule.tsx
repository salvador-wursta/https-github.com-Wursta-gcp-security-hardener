import React from 'react';

// Define interfaces matching the backend ScanResponse -> billing_info
interface BillingBudget {
    display_name: string;
    amount: number;
    projects: string[]; // "projects/123..." or empty for all
}

interface BillingIAMUser {
    user: string;
    roles: string[];
}

interface BillingInfo {
    billing_account_id: string;
    billing_account_name: string;
    has_project_billing: boolean;
    has_org_billing: boolean;
    budgets: BillingBudget[];
    current_budget_limit: number | null;
    budget_recommendation: string | null;
    current_month_spend: number | null;
    prior_month_spend: number | null;
    spend_trend: string; // "increasing", "decreasing", "stable"
    iam_users: BillingIAMUser[];
}

interface RiskCard {
    id: string;
    title: string;
    description: string;
    risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
    category: string;
    recommendation: string;
}

export interface BillingModuleProps {
    data: BillingInfo | null;
    risks: RiskCard[];
    loading?: boolean;
    projectId?: string;
    jitToken?: string;
}

export default function BillingModule({ data, risks, loading, projectId, jitToken }: BillingModuleProps) {
    const [newBudgetAmount, setNewBudgetAmount] = React.useState<string>('');
    const [isUpdating, setIsUpdating] = React.useState(false);
    const [updateStatus, setUpdateStatus] = React.useState<{ type: 'success' | 'error', message: string } | null>(null);

    if (loading) {
        return (
            <div className="p-8 text-center animate-pulse">
                <div className="h-4 bg-gray-200 rounded w-3/4 mx-auto mb-4"></div>
                <div className="h-32 bg-gray-100 rounded mb-4"></div>
                <div className="h-4 bg-gray-200 rounded w-1/2 mx-auto"></div>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="p-6 bg-yellow-50 border border-yellow-200 rounded-lg text-yellow-800">
                <h3 className="font-bold">Billing Data Unavailable</h3>
                <p className="text-sm mt-1 mb-4">
                    The backend did not return any billing information because the active Service Account is missing permissions.
                    <br /><strong>To use a dedicated scanning Service Account with read-only access</strong>, run this exact script in your terminal (replace <code>YOUR_PROJECT_ID</code> and <code>YOUR_ORG_ID</code>):
                </p>
                <div className="bg-white p-3 rounded text-xs font-mono text-gray-800 border overflow-x-auto mb-2 whitespace-pre">
                    {`# 1. Create the dedicated scanner Service Account
gcloud iam service-accounts create gcp-scanner-sa \\
    --display-name="GCP Security Scanner" \\
    --project="YOUR_PROJECT_ID"

# 2. Define Variables
SA_EMAIL="gcp-scanner-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com"
ORG_ID="YOUR_ORG_ID"

# 3. Grant required Read-Only Permissions at the Organization level
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/browser"
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/iam.securityReviewer"
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/billing.viewer"
gcloud organizations add-iam-policy-binding $ORG_ID --member="serviceAccount:$SA_EMAIL" --role="roles/securitycenter.adminViewer"

# 4. Authenticate your local environment to use this Service Account (No JSON keys needed)
gcloud auth application-default login --impersonate-service-account=$SA_EMAIL`}
                </div>
            </div>
        );
    }

    // Safe iam_users fallback — backend may omit it on permission failures
    const iamUsers = data.iam_users ?? [];

    const handleSetBudget = async () => {
        if (!newBudgetAmount || isNaN(Number(newBudgetAmount)) || Number(newBudgetAmount) <= 0) {
            setUpdateStatus({ type: 'error', message: "Please enter a valid positive budget amount." });
            return;
        }

        if (!projectId || !jitToken) {
            setUpdateStatus({ type: 'error', message: "Missing project context or authentication token." });
            return;
        }

        setIsUpdating(true);
        setUpdateStatus(null);

        try {
            const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
            const response = await fetch(`${backendUrl}/api/v1/billing/budget`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jitToken}`
                },
                body: JSON.stringify({
                    project_id: projectId,
                    amount: Number(newBudgetAmount),
                    jit_token: jitToken
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || "Failed to update budget");
            }

            setUpdateStatus({ type: 'success', message: "Budget updated successfully! Alerts will be sent to project administrators." });
            setNewBudgetAmount('');
        } catch (e: any) {
            setUpdateStatus({ type: 'error', message: e.message });
        } finally {
            setIsUpdating(false);
        }
    };

    // Filter risks specific to billing
    const billingRisks = risks.filter(r => r.category === 'billing' || r.category === 'waste' || r.category === 'governance');

    const formatCurrency = (amount: number | null) => {
        if (amount === null) return 'N/A';
        return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header / KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Card 1: Current Spend */}
                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wider">Current Month Spend</p>
                    <div className="mt-2 flex items-baseline gap-3">
                        <span className="text-3xl font-extrabold text-gray-900">
                            {formatCurrency(data.current_month_spend)}
                        </span>
                        {data.spend_trend === 'increasing' && (
                            <span className="text-sm font-medium text-red-600 bg-red-100 px-2 py-0.5 rounded-full">
                                ↗ Increasing
                            </span>
                        )}
                        {data.spend_trend === 'decreasing' && (
                            <span className="text-sm font-medium text-green-600 bg-green-100 px-2 py-0.5 rounded-full">
                                ↘ Decreasing
                            </span>
                        )}
                    </div>
                    <p className="text-xs text-gray-500 mt-2">
                        vs {formatCurrency(data.prior_month_spend)} last month
                    </p>
                    <div className="mt-3 text-xs text-gray-400 border-t border-gray-100 pt-2">
                        * Requires BigQuery export for exact figures
                    </div>
                </div>

                {/* Card 2: Budget Status */}
                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 col-span-1 min-h-[160px]">
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-3">Active Budgets</p>

                    {data.budgets && data.budgets.length > 0 ? (
                        <div className="space-y-4 max-h-48 overflow-y-auto pr-1">
                            {data.budgets.map((budget, idx) => (
                                <div key={idx} className="pb-3 border-b border-gray-100 last:border-0 last:pb-0">
                                    <div className="flex justify-between items-start mb-1">
                                        <div>
                                            <p className="font-bold text-gray-900 text-sm truncate max-w-[140px]" title={budget.display_name}>
                                                {budget.display_name}
                                            </p>
                                            <p className="text-[10px] text-gray-400 truncate">
                                                {budget.projects && budget.projects.length > 0
                                                    ? 'Specific Project'
                                                    : 'All Projects'}
                                            </p>
                                        </div>
                                        <div className="text-right">
                                            <span className="font-mono text-sm font-bold text-gray-900">
                                                {formatCurrency(budget.amount)}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Mini Progress Bar for this budget */}
                                    {data.current_month_spend !== null && (
                                        <div className="w-full bg-gray-100 rounded-full h-1.5 mt-1">
                                            <div
                                                className={`h-1.5 rounded-full ${((data.current_month_spend) / budget.amount) > 0.9 ? 'bg-red-500' : 'bg-blue-500'}`}
                                                style={{ width: `${Math.min(100, (data.current_month_spend / budget.amount) * 100)}%` }}
                                            ></div>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="flex flex-col h-24 justify-center items-center text-center">
                            <span className="text-2xl mb-1">⚠️</span>
                            <span className="text-sm font-medium text-gray-600">No Budgets Found</span>
                            <p className="text-xs text-gray-400 mt-1">Set one below to protect this project.</p>
                        </div>
                    )}
                </div>

                {/* Card 3: Account Info */}
                <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wider">Billing Account</p>
                    <div className="mt-2">
                        {data.billing_account_id ? (
                            <>
                                <h4 className={`text-lg font-bold truncate ${data.billing_account_name && data.billing_account_name.includes('Access Denied') ? 'text-red-500 text-sm' : 'text-gray-900'}`} title={data.billing_account_name || data.billing_account_id}>
                                    {data.billing_account_name && !data.billing_account_name.includes('Access Denied')
                                        ? data.billing_account_name
                                        : '⚠ Limited Access'}
                                </h4>
                                <p className="text-xs font-mono text-gray-600 mt-1 font-semibold">
                                    ID: {data.billing_account_id}
                                </p>
                                <p className="text-xs mt-1">
                                    <span className={`inline-flex items-center gap-1 font-medium ${data.has_project_billing ? 'text-green-600' : 'text-red-500'}`}>
                                        {data.has_project_billing ? '✓ billingEnabled: true' : '✗ billingEnabled: false'}
                                    </span>
                                </p>
                                {(!data.billing_account_name || data.billing_account_name.includes('Access Denied')) && (
                                    <p className="text-[10px] text-red-400 mt-1 leading-tight">
                                        SA needs <code>roles/billing.viewer</code> on this Billing Account to read budget details.
                                    </p>
                                )}
                            </>
                        ) : (
                            <h4 className="text-base font-semibold text-gray-500">No Billing Account Linked</h4>
                        )}

                        <div className="mt-4 flex gap-2">
                            {data.has_org_billing ? (
                                <span className="px-2 py-1 bg-purple-100 text-purple-700 text-xs rounded font-medium">Organization Billing</span>
                            ) : (
                                <span className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded font-medium">Project Billing</span>
                            )}
                        </div>
                    </div>
                </div>

            </div>

            {/* Config: Set New Budget */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 flex items-center justify-between">
                <div>
                    <h3 className="text-lg font-bold text-gray-900">Set New Project Budget</h3>
                    <p className="text-sm text-gray-500">Automatically create a budget with 50%, 90%, and 100% email alerts.</p>
                </div>
                <div className="flex items-center gap-3">
                    <div className="relative">
                        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">$</span>
                        <input
                            type="number"
                            placeholder="Amount"
                            value={newBudgetAmount}
                            onChange={(e) => setNewBudgetAmount(e.target.value)}
                            className="pl-7 pr-4 py-2 border border-gray-300 rounded-lg w-32 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all"
                        />
                    </div>
                    <button
                        onClick={handleSetBudget}
                        disabled={isUpdating}
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
                    >
                        {isUpdating ? 'Updating...' : 'Set Budget'}
                    </button>
                </div>
            </div>
            {updateStatus && (
                <div className={`p-4 rounded-lg flex items-center gap-2 ${updateStatus.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                    <span>{updateStatus.type === 'success' ? '✓' : '⚠️'}</span>
                    <span>{updateStatus.message}</span>
                </div>
            )}

            {/* Recommendations / Risks Area */}
            {billingRisks.length > 0 && (
                <div className="space-y-4">
                    <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                        <span className="text-xl">🚨</span> Critical Findings
                    </h3>
                    <div className="grid grid-cols-1 gap-4">
                        {billingRisks.map((risk, idx) => (
                            <div key={`${risk.id}-${idx}`} className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg">
                                <div className="flex justify-between items-start">
                                    <div>
                                        <h4 className="font-bold text-red-900">{risk.title}</h4>
                                        <p className="text-sm text-red-800 mt-1">{risk.description}</p>
                                    </div>
                                    <span className="bg-red-200 text-red-800 text-xs px-2 py-1 rounded font-bold uppercase">
                                        {risk.risk_level}
                                    </span>
                                </div>
                                <div className="mt-3 pt-3 border-t border-red-200">
                                    <p className="text-xs font-bold text-red-900 uppercase">Recommendation:</p>
                                    <p className="text-sm text-red-800 mt-0.5">{risk.recommendation}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Governance: IAM Users Table */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100 bg-gray-50 flex justify-between items-center">
                    <div>
                        <h3 className="font-bold text-gray-900">Billing Governance</h3>
                        <p className="text-sm text-gray-500">Users with direct billing access (Role-Based Access Control)</p>
                    </div>
                    {iamUsers.length > 0 ? (
                        <span className="bg-red-100 text-red-700 text-xs px-2 py-1 rounded-full font-medium">
                            {iamUsers.length} Direct Users Found
                        </span>
                    ) : (
                        <span className="bg-green-100 text-green-700 text-xs px-2 py-1 rounded-full font-medium">
                            Clean Access Control
                        </span>
                    )}
                </div>

                {iamUsers.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User / Principal</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Roles Assigned</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {iamUsers.map((user, idx) => (
                                    <tr key={idx} className="hover:bg-gray-50">
                                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                            {user.user}
                                        </td>
                                        <td className="px-6 py-4 text-sm text-gray-500">
                                            <div className="flex flex-wrap gap-1">
                                                {user.roles.map((role, ridx) => (
                                                    <span key={ridx} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                                                        {role}
                                                    </span>
                                                ))}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-red-600 font-medium">
                                            High (Direct Access)
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="p-8 text-center text-gray-500">
                        <div className="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-3">
                            <svg className="w-6 h-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                        </div>
                        <p>No individual users have direct access. Good job using groups!</p>
                    </div>
                )}
            </div>

            {/* Actions Footer */}
            <div className="bg-gray-900 rounded-xl p-6 text-white flex justify-between items-center">
                <div>
                    <h4 className="font-bold text-lg">Detailed Cost Analysis</h4>
                    <p className="text-gray-400 text-sm">Download the full CSV report for breakdown by SKU and Project.</p>
                </div>
                <button className="px-4 py-2 bg-white text-gray-900 rounded font-medium hover:bg-gray-100 transition-colors">
                    Download Report
                </button>
            </div>


        </div>
    );
}
