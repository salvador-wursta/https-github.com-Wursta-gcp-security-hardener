/**
 * Scan Results Component - CONDENSED VERSION
 * Compact, efficient display of security scan findings
 */
'use client';

import { useState, useEffect } from 'react';
import { ScanResponse, RiskCard } from '@/lib/api';
import {
  AlertTriangle, Shield, CheckCircle, Info, AlertCircle, RotateCcw,
  DollarSign, CreditCard, ChevronDown, ChevronUp, Sparkles, Cpu, Server, CheckCircle2,
  Lock, Users, Cloud, Network, ShieldCheck, LayoutTemplate
} from 'lucide-react';
import GeminiChat from './GeminiChat';
import ClaudeChat from './ClaudeChat';
import ArchitecturalReviewModule from './modules/ArchitecturalReviewModule';

interface ScanResultsProps {
  results: ScanResponse;
  onSecureClick: (selectedRiskIds: string[], orgMonitoringEnabled: boolean, vpcHardeningEnabled: boolean) => void;
  onBackoutClick?: () => void;
  showBackout?: boolean;
  budgetCap?: number;
  onBudgetChange?: (budget: number) => void;
}

export default function ScanResults({ results, onSecureClick, onBackoutClick, showBackout = false, budgetCap = 500, onBudgetChange }: ScanResultsProps) {
  const [selectedRisks, setSelectedRisks] = useState<Set<string>>(new Set());
  const [localBudgetCap, setLocalBudgetCap] = useState<number>(budgetCap);
  const [aiProvider, setAiProvider] = useState<'gemini' | 'claude'>('gemini');

  // Section visibility states
  const [showArchitecture, setShowArchitecture] = useState(false);
  const [showBilling, setShowBilling] = useState(false);
  const [showGpuQuota, setShowGpuQuota] = useState(false);
  const [showComputeInstances, setShowComputeInstances] = useState(false);
  const [showFirewall, setShowFirewall] = useState(false);
  const [showSecurityServices, setShowSecurityServices] = useState(false);
  const [showIamAudit, setShowIamAudit] = useState(false);
  const [showApis, setShowApis] = useState(false);
  const [showAiChat, setShowAiChat] = useState(false);

  const [orgMonitoringEnabled, setOrgMonitoringEnabled] = useState(true); // Default ON
  const [vpcHardeningEnabled, setVpcHardeningEnabled] = useState(true); // Default ON

  // Extract specific risks for dedicated sections
  const firewallRisk = results.risks.find(r => r.id.startsWith('firewall_config_'));
  const securityServicesRisk = results.risks.find(r => r.id === 'missing_advanced_security' || r.id === 'advanced_security_verified');
  const iamAuditRisk = results.risks.find(r => r.id === 'iam_org_admin_direct_access' || r.id === 'iam_org_admin_verified');

  // IDs to exclude from general list (because they have dedicated sections)
  const specializedRiskIds = new Set([
    'direct_billing_iam_users',
    'missing_advanced_security',
    'advanced_security_verified',
    'iam_org_admin_direct_access',
    'iam_org_admin_verified',
    ...(firewallRisk ? [firewallRisk.id] : [])
  ]);

  // Select all risks by default
  useEffect(() => {
    const fixableRiskIds = new Set(results.risks.filter(r => r.is_fixable !== false).map(r => r.id));
    setSelectedRisks(fixableRiskIds);
  }, [results.risks]);

  const toggleRisk = (riskId: string) => {
    setSelectedRisks(prev => {
      const next = new Set(prev);
      if (next.has(riskId)) {
        next.delete(riskId);
      } else {
        next.add(riskId);
      }
      return next;
    });
  };

  const selectAll = () => {
    const fixableRiskIds = new Set(results.risks.filter(r => r.is_fixable !== false).map(r => r.id));
    setSelectedRisks(fixableRiskIds);
  };

  const deselectAll = () => {
    setSelectedRisks(new Set());
  };

  const handleSecureClick = () => {
    onSecureClick(Array.from(selectedRisks), orgMonitoringEnabled, vpcHardeningEnabled);
  };

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'critical':
        return <AlertTriangle className="w-4 h-4 text-red-600" />;
      case 'high':
        return <AlertCircle className="w-4 h-4 text-orange-600" />;
      case 'medium':
        return <Info className="w-4 h-4 text-yellow-600" />;
      case 'low':
        return <Info className="w-4 h-4 text-blue-600" />;
      default:
        return <Info className="w-4 h-4 text-gray-600" />;
    }
  };

  const getRiskBadgeColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  return (
    <div className="space-y-4">
      {/* Compact Header with Summary */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xl font-bold text-gray-900">Security Scan Results</h2>

          {/* Helper variables for combined counts */}
          {(() => {
            const archFindings = results.architecture_info?.findings || [];
            const archCritical = archFindings.filter((f: any) => f.severity === 'CRITICAL').length;
            const archHigh = archFindings.filter((f: any) => f.severity === 'HIGH').length;
            const archMedium = archFindings.filter((f: any) => f.severity === 'MEDIUM').length;
            const archLow = archFindings.filter((f: any) => f.severity === 'LOW').length;

            const totalCritical = results.summary.critical + archCritical;
            const totalHigh = results.summary.high + archHigh;
            const totalMedium = results.summary.medium + archMedium;
            const totalLow = results.summary.low + archLow;
            const totalAll = results.summary.total + archFindings.length; // assuming summary.total is risk-only

            if (totalAll === 0) {
              return (
                <div className="flex items-center gap-2 text-green-600">
                  <CheckCircle className="w-5 h-5" />
                  <span className="font-semibold">All Clear!</span>
                </div>
              );
            }

            return (
              <div className="flex items-center gap-3">
                {totalCritical > 0 && (
                  <div className="flex items-center gap-1 px-2 py-1 bg-red-50 border border-red-200 rounded text-sm">
                    <span className="font-bold text-red-600">{totalCritical}</span>
                    <span className="text-red-700 text-xs">Critical</span>
                  </div>
                )}
                {totalHigh > 0 && (
                  <div className="flex items-center gap-1 px-2 py-1 bg-orange-50 border border-orange-200 rounded text-sm">
                    <span className="font-bold text-orange-600">{totalHigh}</span>
                    <span className="text-orange-700 text-xs">High</span>
                  </div>
                )}
                {totalMedium > 0 && (
                  <div className="flex items-center gap-1 px-2 py-1 bg-yellow-50 border border-yellow-200 rounded text-sm">
                    <span className="font-bold text-yellow-600">{totalMedium}</span>
                    <span className="text-yellow-700 text-xs">Medium</span>
                  </div>
                )}
                {totalLow > 0 && (
                  <div className="flex items-center gap-1 px-2 py-1 bg-blue-50 border border-blue-200 rounded text-sm">
                    <span className="font-bold text-blue-600">{totalLow}</span>
                    <span className="text-blue-700 text-xs">Low</span>
                  </div>
                )}
                <div className="flex items-center gap-1 px-2 py-1 bg-gray-100 border border-gray-300 rounded text-sm font-semibold text-gray-700">
                  {totalAll} Total
                </div>
              </div>
            );
          })()}
        </div>

        {/* Action Bar */}
        {results.summary.total > 0 && (
          <div className="flex items-center justify-between pt-3 border-t">
            <div className="text-sm text-gray-600">
              {selectedRisks.size} of {results.risks.length} issues selected
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={selectAll}
                className="px-3 py-1 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
              >
                Select All
              </button>
              <button
                onClick={deselectAll}
                className="px-3 py-1 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
              >
                Clear
              </button>

              {/* Organization Monitoring Checkbox - Default ON */}
              <label className="flex items-center gap-2 px-3 py-1.5 bg-green-50 border border-green-200 rounded cursor-pointer hover:bg-green-100">
                <input
                  type="checkbox"
                  checked={orgMonitoringEnabled}
                  onChange={(e) => setOrgMonitoringEnabled(e.target.checked)}
                  className="w-4 h-4 text-green-600 border-gray-300 rounded focus:ring-green-500"
                />
                <span className="text-xs text-green-800 font-medium">Org Monitoring</span>
              </label>

              {/* VPC Hardening Checkbox - Default ON */}
              <label className="flex items-center gap-2 px-3 py-1.5 bg-blue-50 border border-blue-200 rounded cursor-pointer hover:bg-blue-100">
                <input
                  type="checkbox"
                  checked={vpcHardeningEnabled}
                  onChange={(e) => setVpcHardeningEnabled(e.target.checked)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <span className="text-xs text-blue-800 font-medium">VPC Hardening</span>
              </label>

              <button
                onClick={handleSecureClick}
                disabled={selectedRisks.size === 0}
                className="px-4 py-1.5 bg-primary-600 text-white text-sm rounded font-medium hover:bg-primary-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-1.5"
              >
                <Shield className="w-4 h-4" />
                Fix Selected
              </button>
              {showBackout && onBackoutClick && (
                <button
                  onClick={onBackoutClick}
                  className="px-4 py-1.5 bg-orange-600 text-white text-sm rounded font-medium hover:bg-orange-700 flex items-center gap-1.5"
                >
                  <RotateCcw className="w-4 h-4" />
                  Rollback
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Collapsible Architecture Info */}
      {results.architecture_info && results.architecture_info.findings && results.architecture_info.findings.length > 0 && (
        <div className="bg-white rounded-lg shadow">
          <button
            onClick={() => setShowArchitecture(!showArchitecture)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center gap-2">
              <LayoutTemplate className="w-5 h-5 text-indigo-600" />
              <span className="font-semibold text-gray-900">Architectural Foundations</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-800">
                {results.architecture_info.findings.length} Findings
              </span>
            </div>
            {showArchitecture ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          {showArchitecture && (
            <div className="px-4 pb-4 border-t pt-2">
              <ArchitecturalReviewModule data={results.architecture_info} />
            </div>
          )}
        </div>
      )}

      {/* Collapsible Billing Info */}
      {results.billing_info && (
        <div className="bg-white rounded-lg shadow">
          <button
            onClick={() => setShowBilling(!showBilling)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center gap-2">
              <DollarSign className="w-5 h-5 text-blue-600" />
              <span className="font-semibold text-gray-900">Billing & Budget Info</span>
              {results.billing_info.billing_account_id && (
                <span className="text-xs text-gray-500">
                  ({results.billing_info.budgets?.length || 0} budgets)
                </span>
              )}
            </div>
            {showBilling ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          {showBilling && (
            <div className="px-4 pb-4 space-y-3 border-t">
              {results.billing_info.billing_account_id ? (
                <>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600">Account:</span>
                    <span className="font-mono text-gray-900">{results.billing_info.billing_account_id}</span>
                  </div>
                  {results.billing_info.billing_account_name && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-600">Name:</span>
                      <span className="text-gray-900">{results.billing_info.billing_account_name}</span>
                    </div>
                  )}

                  {/* Monthly Spending */}
                  <div className="mt-4 pt-3 border-t border-gray-200">
                    <div className="text-xs font-semibold text-gray-700 mb-2">📊 Monthly Spending:</div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-600">Prior Month:</span>
                      <span className="font-semibold text-gray-900">
                        ${(results.billing_info.prior_month_spend || 0).toFixed(2)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-sm mt-1">
                      <span className="text-gray-600">Current Month:</span>
                      <span className="font-semibold text-gray-900">
                        ${(results.billing_info.current_month_spend || 0).toFixed(2)}
                      </span>
                    </div>
                    {results.billing_info.spend_trend && results.billing_info.spend_trend !== 'unknown' && (
                      <div className="flex items-center justify-between text-sm mt-1">
                        <span className="text-gray-600">Trend:</span>
                        <span className={`font-semibold ${results.billing_info.spend_trend === 'increasing' ? 'text-red-600' :
                          results.billing_info.spend_trend === 'decreasing' ? 'text-green-600' :
                            'text-gray-600'
                          }`}>
                          {results.billing_info.spend_trend === 'increasing' && '↑ Increasing'}
                          {results.billing_info.spend_trend === 'decreasing' && '↓ Decreasing'}
                          {results.billing_info.spend_trend === 'stable' && '→ Stable'}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Current Budget - Display After Monthly Spending */}
                  <div className="mt-4 pt-3 border-t border-gray-200">
                    <div className="text-xs font-semibold text-gray-700 mb-2">💰 Current Budget Status:</div>
                    {results.billing_info.current_budget_limit !== null && results.billing_info.current_budget_limit !== undefined ? (
                      <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-green-600" />
                            <span className="text-sm font-semibold text-green-900">Current Budget Limit:</span>
                          </div>
                          <span className="text-lg font-bold text-green-700">
                            ${results.billing_info.current_budget_limit.toLocaleString()}
                          </span>
                        </div>
                        <div className="mt-1 text-xs text-green-700">
                          This is the highest budget limit currently set for this project
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 bg-orange-50 border border-orange-200 rounded-lg">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-orange-600" />
                          <span className="text-sm font-semibold text-orange-900">No Budget Set</span>
                        </div>
                        <div className="mt-1 text-xs text-orange-700">
                          No budget limit is currently configured for this project. Consider setting one below.
                        </div>
                      </div>
                    )}

                    {/* List configured budgets if multiple */}
                    {results.billing_info.budgets && results.billing_info.budgets.length > 0 && (
                      <div className="mt-3 space-y-2">
                        <div className="text-xs font-semibold text-gray-700">
                          📋 Configured Budgets ({results.billing_info.budgets.length}):
                        </div>
                        {results.billing_info.budgets.map((budget, idx) => (
                          <div key={idx} className="text-xs text-gray-600 pl-3 py-2 border-l-2 border-gray-300 bg-gray-50 rounded-r">
                            <div className="font-medium text-gray-900">{budget.display_name}</div>
                            {budget.amount !== null && budget.amount !== undefined ? (
                              <div className="text-gray-700 mt-1">Amount: ${budget.amount.toLocaleString()}</div>
                            ) : (
                              <div className="text-gray-500 mt-1">Amount: Not specified</div>
                            )}
                            {budget.projects && budget.projects.length > 0 ? (
                              <div className="text-gray-500 mt-1">Projects: {budget.projects.join(', ')}</div>
                            ) : (
                              <div className="text-blue-600 mt-1">✓ Applies to all projects in billing account</div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Direct Billing Access Table */}
                    {results.billing_info.iam_users && results.billing_info.iam_users.length > 0 && (
                      <div className="mt-6 border-t pt-4">
                        <div className="flex items-center justify-between mb-3">
                          <label className="text-sm font-bold text-gray-900 flex items-center gap-2">
                            <Shield className="w-4 h-4 text-red-600" />
                            Direct Individual Billing Access
                          </label>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-bold text-red-600 uppercase bg-red-50 px-2 py-0.5 rounded border border-red-200">High Risk</span>
                            <input
                              type="checkbox"
                              checked={selectedRisks.has('direct_billing_iam_users')}
                              onChange={() => toggleRisk('direct_billing_iam_users')}
                              className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500 cursor-pointer"
                            />
                          </div>
                        </div>

                        <div className="overflow-hidden border rounded-lg bg-white shadow-sm mb-4">
                          <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                              <tr>
                                <th className="px-4 py-2 text-left text-[10px] font-bold text-gray-500 uppercase tracking-wider">User Identity</th>
                                <th className="px-4 py-2 text-left text-[10px] font-bold text-gray-500 uppercase tracking-wider">Assigned Roles</th>
                              </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                              {results.billing_info.iam_users.map((user, idx) => (
                                <tr key={idx} className="hover:bg-slate-50">
                                  <td className="px-4 py-2 whitespace-nowrap text-xs font-medium text-gray-900">{user.user}</td>
                                  <td className="px-4 py-2 text-xs text-gray-600">
                                    <div className="flex flex-wrap gap-1">
                                      {user.roles.map((role, ridx) => (
                                        <span key={ridx} className="px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded text-[10px] border border-blue-100 italic">
                                          {role}
                                        </span>
                                      ))}
                                    </div>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>

                        <div className="bg-red-50 border border-red-100 rounded-lg p-3 space-y-2">
                          <div>
                            <span className="text-xs font-bold text-red-800">Risk Statement:</span>
                            <p className="text-[11px] text-red-700 leading-relaxed mt-0.5">
                              Finding {results.billing_info.iam_users.length} unique individuals with direct billing access.
                              Individual users are security silos; if an account is compromised or a user leaves,
                              tracking and revoking these financial privileges becomes a critical failure point.
                            </p>
                          </div>
                          <div>
                            <span className="text-xs font-bold text-indigo-800">Recommendation:</span>
                            <p className="text-[11px] text-indigo-700 leading-relaxed mt-0.5 italic">
                              Migrate these users to managed groups (e.g., gcp-billing-admins@yourorg.com) and enforce
                              Organization-level IAM policies to prevent future direct assignments.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Budget Cap Input */}
                  <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                    <label className="block text-sm font-semibold text-gray-900 mb-2">
                      💰 Set Monthly Budget Quota
                    </label>
                    <p className="text-xs text-gray-600 mb-3">
                      Based on your spending history, set a budget cap. If spending exceeds this amount,
                      we'll automatically shut down resources to prevent crypto-mining attacks.
                    </p>

                    {/* Suggested budget */}
                    {results.billing_info.prior_month_spend && results.billing_info.prior_month_spend > 0 && (
                      <div className="mb-3 text-xs text-blue-700 bg-blue-100 p-2 rounded">
                        💡 <strong>Suggested:</strong> ${Math.ceil((results.billing_info.prior_month_spend * 1.5) / 50) * 50}
                        <span className="text-blue-600"> (150% of prior month)</span>
                      </div>
                    )}

                    <div className="flex items-center gap-3">
                      <span className="text-lg font-bold text-gray-700">$</span>
                      <input
                        type="number"
                        value={localBudgetCap || ''}
                        onChange={(e) => {
                          const value = parseFloat(e.target.value) || 0;
                          setLocalBudgetCap(value);
                          onBudgetChange?.(value);
                        }}
                        min="0"
                        step="50"
                        placeholder="500"
                        className="flex-1 p-2 border-2 border-gray-300 rounded-lg text-base font-semibold focus:border-blue-500 focus:outline-none"
                      />
                      <span className="text-sm text-gray-600">per month</span>
                    </div>

                    <div className="mt-3 p-2 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-800">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                        <div>
                          <strong>Budget Quota:</strong> When this spending limit is reached, an email notification will be sent to alert you of the pending overage on this project. This does not automatically stop spending.
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-sm text-orange-700">No billing account linked</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Collapsible GPU Quota Info */}
      {results.gpu_quota && (
        <div className="bg-white rounded-lg shadow">
          <button
            onClick={() => setShowGpuQuota(!showGpuQuota)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-purple-600" />
              <span className="font-semibold text-gray-900">GPU Quota</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${results.gpu_quota.risk_level === 'safe'
                ? 'bg-green-100 text-green-800'
                : results.gpu_quota.risk_level === 'warning'
                  ? 'bg-yellow-100 text-yellow-800'
                  : 'bg-red-100 text-red-800'
                }`}>
                {results.gpu_quota.total_quota === 0 ? '✓ Zero' : `${results.gpu_quota.total_quota} GPUs`}
              </span>
            </div>
            {showGpuQuota ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          {showGpuQuota && (
            <div className="px-4 pb-4 space-y-3 border-t">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">Total GPU Quota:</span>
                <span className={`font-semibold ${results.gpu_quota.total_quota === 0
                  ? 'text-green-700'
                  : 'text-red-700'
                  }`}>
                  {results.gpu_quota.total_quota}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">Regions with GPUs:</span>
                <span className="text-gray-900">{results.gpu_quota.regions_with_quota}</span>
              </div>
              {results.gpu_quota.summary && (
                <div className="text-xs text-gray-600 p-2 bg-gray-50 rounded">
                  {results.gpu_quota.summary}
                </div>
              )}
              {results.gpu_quota.recommendation && (
                <div className={`text-sm p-2 rounded ${results.gpu_quota.risk_level === 'safe'
                  ? 'bg-green-50 text-green-800'
                  : results.gpu_quota.risk_level === 'warning'
                    ? 'bg-yellow-50 text-yellow-800'
                    : 'bg-red-50 text-red-800'
                  }`}>
                  {results.gpu_quota.recommendation}
                </div>
              )}
              {results.gpu_quota.quota_by_region && results.gpu_quota.quota_by_region.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-gray-700">GPU Quota by Region:</div>
                  <div className="max-h-48 overflow-y-auto space-y-1">
                    {results.gpu_quota.quota_by_region.map((region, idx) => (
                      <div key={idx} className="text-xs text-gray-600 flex justify-between items-center p-1.5 hover:bg-gray-50 rounded">
                        <span className="font-mono">{region.region}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-gray-500">{region.metric}</span>
                          <span className={`font-semibold ${region.limit > 0 ? 'text-red-600' : 'text-green-600'}`}>
                            {region.limit}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Collapsible N2/C2 Compute Instances Info */}
      {results.compute_instances && (
        <div className="bg-white rounded-lg shadow">
          <button
            onClick={() => setShowComputeInstances(!showComputeInstances)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5 text-indigo-600" />
              <span className="font-semibold text-gray-900">High-Cost Compute (N2/C2)</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${results.compute_instances.risk_level === 'safe'
                ? 'bg-green-100 text-green-800'
                : results.compute_instances.risk_level === 'warning'
                  ? 'bg-yellow-100 text-yellow-800'
                  : results.compute_instances.risk_level === 'high'
                    ? 'bg-red-100 text-red-800'
                    : 'bg-gray-100 text-gray-800'
                }`}>
                {results.compute_instances.total_restricted_instances === 0
                  ? '✓ None'
                  : `${results.compute_instances.total_restricted_instances} instances`}
              </span>
            </div>
            {showComputeInstances ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          {showComputeInstances && (
            <div className="px-4 pb-4 space-y-3 border-t">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">N2 Instances:</span>
                <span className={`font-semibold ${results.compute_instances.n2_instances === 0
                  ? 'text-green-700'
                  : 'text-orange-700'
                  }`}>
                  {results.compute_instances.n2_instances}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">C2 Instances:</span>
                <span className={`font-semibold ${results.compute_instances.c2_instances === 0
                  ? 'text-green-700'
                  : 'text-red-700'
                  }`}>
                  {results.compute_instances.c2_instances}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">Total High-Cost:</span>
                <span className="font-semibold text-gray-900">
                  {results.compute_instances.total_restricted_instances}
                </span>
              </div>
              {results.compute_instances.recommendation && (
                <div className={`text-sm p-3 rounded ${results.compute_instances.risk_level === 'safe'
                  ? 'bg-green-50 text-green-800'
                  : results.compute_instances.risk_level === 'warning'
                    ? 'bg-yellow-50 text-yellow-800'
                    : results.compute_instances.risk_level === 'high'
                      ? 'bg-red-50 text-red-800'
                      : 'bg-blue-50 text-blue-800'
                  }`}>
                  {results.compute_instances.recommendation}
                </div>
              )}
              {results.compute_instances.instances_by_zone && results.compute_instances.instances_by_zone.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-gray-700">Active Instances:</div>
                  <div className="max-h-48 overflow-y-auto space-y-1">
                    {results.compute_instances.instances_by_zone.map((instance, idx) => (
                      <div key={idx} className="text-xs p-2 bg-gray-50 rounded hover:bg-gray-100">
                        <div className="flex justify-between items-center mb-1">
                          <span className="font-mono font-semibold text-gray-900">{instance.name}</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${instance.machine_family === 'N2'
                            ? 'bg-orange-100 text-orange-800'
                            : 'bg-red-100 text-red-800'
                            }`}>
                            {instance.machine_family}
                          </span>
                        </div>
                        <div className="flex justify-between text-gray-600">
                          <span>{instance.zone}</span>
                          <span>{instance.machine_type}</span>
                        </div>
                        <div className="text-gray-500">
                          Status: {instance.status}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              <div className="text-xs text-gray-500 p-2 bg-blue-50 rounded border border-blue-200">
                <strong>ℹ️ For Small Businesses:</strong> Most workloads run well on E2 (cost-optimized) or N1 (general purpose) instances.
                N2 and C2 are expensive, high-performance instances rarely needed by SMBs. If you're not actively using them,
                consider restricting these instance types to prevent expensive abuse if your account is compromised.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Collapsible Firewall Info */}
      {firewallRisk && (
        <div className="bg-white rounded-lg shadow">
          <button
            onClick={() => setShowFirewall(!showFirewall)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-blue-600" />
              <span className="font-semibold text-gray-900">VPC Firewall Configuration</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${firewallRisk.risk_level === 'info'
                ? 'bg-green-100 text-green-800'
                : firewallRisk.risk_level === 'medium'
                  ? 'bg-yellow-100 text-yellow-800'
                  : 'bg-red-100 text-red-800'
                }`}>
                {firewallRisk.current_state?.firewall_status || 'Unknown'}
              </span>
            </div>
            {showFirewall ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          {showFirewall && (
            <div className="px-4 pb-4 space-y-3 border-t">
              <div className="mt-3">
                <div className="text-sm text-gray-700 mb-2">{firewallRisk.description}</div>
                <div className={`text-sm p-3 rounded ${firewallRisk.risk_level === 'info'
                  ? 'bg-green-50 text-green-800'
                  : 'bg-yellow-50 text-yellow-800'
                  }`}>
                  <strong>Recommendation:</strong> {firewallRisk.recommendation}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Collapsible Security Services Info */}
      {securityServicesRisk && (
        <div className="bg-white rounded-lg shadow">
          <button
            onClick={() => setShowSecurityServices(!showSecurityServices)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-indigo-600" />
              <span className="font-semibold text-gray-900">Advanced Network Defense</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${securityServicesRisk.risk_level === 'info'
                ? 'bg-green-100 text-green-800'
                : 'bg-red-100 text-red-800'
                }`}>
                {securityServicesRisk.risk_level === 'info' ? '✓ Verified' : 'Missing Protections'}
              </span>
            </div>
            {showSecurityServices ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          {showSecurityServices && (
            <div className="px-4 pb-4 space-y-3 border-t">
              <div className="mt-3">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="text-gray-600">External IPs Detected:</span>
                  <span className={`font-semibold ${securityServicesRisk.risk_level === 'info' ? 'text-green-700' : 'text-red-700'}`}>
                    {securityServicesRisk.current_state?.external_ip_count || 0}
                  </span>
                </div>
                <div className="text-sm text-gray-700 mb-2">{securityServicesRisk.description}</div>
                {securityServicesRisk.affected_resources && (
                  <div className="text-xs text-gray-600 p-2 bg-gray-50 rounded mb-2">
                    <strong>Exposed Resources:</strong> {securityServicesRisk.affected_resources.join(', ')}
                  </div>
                )}
                <div className="whitespace-pre-line mt-1">{securityServicesRisk.recommendation}</div>
              </div>
            </div>
          )}
        </div>
      )}


      {/* Collapsible IAM Audit Info */}
      {
        iamAuditRisk && (
          <div className="bg-white rounded-lg shadow">
            <button
              onClick={() => setShowIamAudit(!showIamAudit)}
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
            >
              <div className="flex items-center gap-2">
                <Users className="w-5 h-5 text-purple-600" />
                <span className="font-semibold text-gray-900">IAM Org Admin Segmentation</span>
                <span className={`text-xs px-2 py-0.5 rounded-full ${iamAuditRisk.risk_level === 'info'
                  ? 'bg-green-100 text-green-800'
                  : 'bg-red-100 text-red-800'
                  }`}>
                  {iamAuditRisk.risk_level === 'info'
                    ? '✓ Verified'
                    : `${iamAuditRisk.current_state?.offender_count} Violations`}
                </span>
              </div>
              {showIamAudit ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
            </button>
            {showIamAudit && (
              <div className="px-4 pb-4 space-y-3 border-t">
                <div className="mt-3">
                  <div className="text-sm text-gray-700 mb-2">{iamAuditRisk.description}</div>
                  {iamAuditRisk.affected_resources && (
                    <div className="mb-3">
                      <div className="text-xs font-semibold text-gray-700 mb-1">Directly Assigned Org Admins:</div>
                      <div className="max-h-32 overflow-y-auto bg-gray-50 rounded border p-2">
                        {iamAuditRisk.affected_resources.map((offender, idx) => (
                          <div key={idx} className="text-xs text-red-700 font-mono py-0.5">
                            {offender}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="whitespace-pre-line mt-1">{iamAuditRisk.recommendation}</div>
                </div>
              </div>
            )}
          </div>
        )}

      {/* Compact Risk List */}
      {
        results.risks.length > 0 && (
          <div className="bg-white rounded-lg shadow">
            <div className="px-4 py-3 border-b">
              <h3 className="font-semibold text-gray-900">Other Security Issues</h3>
            </div>
            <div className="divide-y">
              {results.risks
                .filter(risk => !specializedRiskIds.has(risk.id))
                .map((risk) => (
                  <CompactRiskCard
                    key={risk.id}
                    risk={risk}
                    getRiskIcon={getRiskIcon}
                    getRiskBadgeColor={getRiskBadgeColor}
                    isSelected={selectedRisks.has(risk.id)}
                    onToggle={() => toggleRisk(risk.id)}
                  />
                ))
              }
            </div>
          </div>
        )
      }

      {/* Collapsible Enabled APIs */}
      {
        results.enabled_apis.length > 0 && (
          <div className="bg-white rounded-lg shadow">
            <button
              onClick={() => setShowApis(!showApis)}
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50"
            >
              <div className="flex items-center gap-2">
                <Info className="w-5 h-5 text-gray-600" />
                <span className="font-semibold text-gray-900">Enabled APIs</span>
                <span className="text-xs text-gray-500">({results.enabled_apis.length})</span>
              </div>
              {showApis ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
            </button>
            {showApis && (
              <div className="px-4 pb-4 border-t">
                <div className="flex flex-wrap gap-1.5 mt-3">
                  {results.enabled_apis.map((api) => (
                    <span
                      key={api}
                      className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs"
                    >
                      {api}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )
      }

      {/* Errors */}
      {
        results.errors.length > 0 && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3">
            <div className="font-semibold text-red-900 text-sm mb-2">Scan Errors:</div>
            <ul className="list-disc list-inside text-xs text-red-700 space-y-1">
              {results.errors.map((error, index) => (
                <li key={index}>{error}</li>
              ))}
            </ul>
          </div>
        )
      }

      {/* Collapsible AI Assistant */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-4 py-3 flex items-center justify-between hover:bg-gray-50">
          <div className="flex items-center gap-3 flex-1">
            <button
              onClick={() => setShowAiChat(!showAiChat)}
              className="flex items-center gap-2 flex-1 text-left"
            >
              <Sparkles className="w-5 h-5 text-purple-600" />
              <span className="font-semibold text-gray-900">AI Security Assistant</span>
            </button>
            <div className="flex gap-1">
              <button
                onClick={() => setAiProvider('gemini')}
                className={`px-2 py-0.5 rounded text-xs font-medium ${aiProvider === 'gemini'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 text-gray-700'
                  }`}
              >
                Gemini
              </button>
              <button
                onClick={() => setAiProvider('claude')}
                className={`px-2 py-0.5 rounded text-xs font-medium ${aiProvider === 'claude'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-200 text-gray-700'
                  }`}
              >
                Claude
              </button>
            </div>
          </div>
          <button
            onClick={() => setShowAiChat(!showAiChat)}
            className="ml-2"
          >
            {showAiChat ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
        </div>
        {showAiChat && (
          <div className="px-4 pb-4 border-t">
            <p className="text-xs text-gray-600 mb-3 mt-3">
              Ask questions about your scan results, security risks, or GCP best practices.
            </p>
            {aiProvider === 'gemini' ? (
              <GeminiChat scanResults={results} context="scan_results" />
            ) : (
              <ClaudeChat scanResults={results} context="scan_results" />
            )}
          </div>
        )}
      </div>
    </div >
  );
}

function CompactRiskCard({
  risk,
  getRiskIcon,
  getRiskBadgeColor,
  isSelected,
  onToggle,
}: {
  risk: RiskCard;
  getRiskIcon: (level: string) => JSX.Element;
  getRiskBadgeColor: (level: string) => string;
  isSelected: boolean;
  onToggle: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`px-4 py-3 hover:bg-gray-50 ${isSelected ? 'bg-primary-50' : ''}`}>
      <div className="flex items-start gap-3">
        {/* Checkbox - only show if fixable */}
        {risk.is_fixable !== false ? (
          <input
            type="checkbox"
            checked={isSelected}
            onChange={onToggle}
            className="mt-1 w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500 cursor-pointer"
          />
        ) : (
          <div className="w-4 flex-shrink-0" /> // Placeholder to maintain alignment
        )}

        {/* Icon */}
        <div className="flex-shrink-0 mt-0.5">{getRiskIcon(risk.risk_level)}</div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2 mb-1">
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-left flex-1"
            >
              <h4 className="font-semibold text-gray-900 text-sm">{risk.title}</h4>
            </button>
            <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase border ${getRiskBadgeColor(risk.risk_level)}`}>
              {risk.risk_level}
            </span>
          </div>

          {!expanded && (
            <p className="text-xs text-gray-600 line-clamp-1">{risk.description}</p>
          )}

          {expanded && (
            <div className="mt-2 space-y-2">
              <p className="text-xs text-gray-700">{risk.description}</p>
              <div className="bg-blue-50 border border-blue-200 rounded p-2">
                <div className="text-xs font-semibold text-blue-900 mb-1">Recommendation:</div>
                <div className="text-xs text-blue-800 whitespace-pre-wrap">{risk.recommendation}</div>
              </div>
              {risk.affected_resources && risk.affected_resources.length > 0 && (
                <div className="text-xs text-gray-600">
                  <span className="font-semibold">Affected:</span> {risk.affected_resources.join(', ')}
                </div>
              )}
            </div>
          )}

          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-primary-600 hover:text-primary-700 mt-1"
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
        </div>
      </div>
    </div>
  );
}
