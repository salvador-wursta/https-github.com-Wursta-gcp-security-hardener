'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import DefaultLayout from '@/components/coreui/DefaultLayout';
import OnboardingModal from '@/components/OnboardingModal';
import ActionBtn from '@/components/ActionBtn';
import StandardHeader from '@/components/StandardHeader';
import { useClient } from '@/context/ClientContext';


import BillingModule from '@/components/modules/BillingModule';
import NetworkModule from '@/components/modules/NetworkModule';
import ApiSecurityModule from '@/components/modules/ApiSecurityModule';
import IamSecurityModule from '@/components/modules/IamSecurityModule';
import MonitoringModule from '@/components/modules/MonitoringModule';
import ArchitecturalReviewModule from '@/components/modules/ArchitecturalReviewModule';
import LockdownInterface from '@/components/LockdownInterface';
import ChangeControlAuditModule from '@/components/modules/ChangeControlAuditModule';
import ReportingInterface from '@/components/ReportingInterface';
import FullScanReport from '@/components/FullScanReport';
import { Shield, Server, CreditCard, Lock, Activity, Eye, FileText, Info, Download } from 'lucide-react';

export interface ScanResponse {
  billing_info?: any;
  api_analysis?: any;
  iam_analysis?: any;
  risks: any[];
  scan_status: string;
  project_id: string; // Ensure we track which project this is for
  change_control_info?: any;
  scc_info?: any;
  architecture_info?: any;
  inventory_summary?: {
    total_assets: number;
    resource_counts: Record<string, number>;
    public_ip_count: number;
    storage_buckets: number;
    sql_instances: number;
    firewall_rules: number;
  };
}

interface ProjectInfo {
  project_id: string;
  name: string;
  project_number: string;
  lifecycle_state: string;

  labels: Record<string, string>;
  organization_id?: string;
}

type WorkflowStage = 'initial' | 'project_discovery' | 'project_selection' | 'scan_configuration' | 'scanning' | 'results';

export default function Home() {
  const router = useRouter(); // Initialize router
  const { clientData, updateClientData, saveClient, saveScanResult } = useClient();

  // Auth State
  const [jitToken, setJitToken] = useState<string | null>(null);
  const [isJitActive, setIsJitActive] = useState(false);
  const [showJitModal, setShowJitModal] = useState(false);

  // Workflow State
  const [workflowStage, setWorkflowStage] = useState<WorkflowStage>('initial');
  const [error, setError] = useState<string | null>(null);

  // Discovery State
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [selectedProjects, setSelectedProjects] = useState<Set<string>>(new Set());

  const [loadingProjects, setLoadingProjects] = useState(false);
  const [detectedOrgId, setDetectedOrgId] = useState<string | null>(null);

  // DEBUG LOGGING
  useEffect(() => {
    console.log("Current Workflow Stage:", workflowStage);
    console.log("Projects Count:", projects.length);
    console.log("Selected Projects:", selectedProjects.size);
  }, [workflowStage, projects, selectedProjects]);

  // Scan Config State
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set()); // Default to none
  const [detailsModalModuleId, setDetailsModalModuleId] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Results State
  const [scanResults, setScanResults] = useState<ScanResponse[]>([]); // Array for multi-project results
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());
  const [expandedSubSections, setExpandedSubSections] = useState<Set<string>>(new Set()); // Format: "projId-modId"
  const [showReport, setShowReport] = useState(false);
  const [showFullReport, setShowFullReport] = useState(false);
  const [isDestroyingIdentity, setIsDestroyingIdentity] = useState(false);

  // Sorting State
  const [sortOption, setSortOption] = useState<'issues' | 'name' | 'billing'>('issues');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Scan Mode State
  const [scanMode, setScanMode] = useState<'product' | 'solution'>('product');
  const [activeScannerEmail, setActiveScannerEmail] = useState<string | null>(null);

  const solutionScans = [
    {
      id: 'finops',
      name: 'FinOps Protection',
      icon: '💰',
      desc: 'Billing Security, Budget Auditing & Cost Controls',
      details: {
        risk: 'Unchecked spending, billing account hijacking, and lack of separation of duties.',
        collected: 'Budgets, Quotas, Billing Account Access, Policy Constraints, and Alert configurations.'
      }
    },
    {
      id: 'ai_security',
      name: 'AI Security',
      icon: '🧠',
      desc: 'Model Protection & Training Data Safety',
      details: {
        risk: 'Model theft, poisoning attacks, and unauthorized access to training data.',
        collected: 'Vertex AI configurations, storage permissions for training data, and API access controls.'
      }
    },
    {
      id: 'data_discovery',
      name: 'Data Discovery',
      icon: '🔍',
      desc: 'Sensitive Data Classification & Exposure',
      details: {
        risk: 'PII/PHI exposure, public buckets, and unencrypted critical data.',
        collected: 'Storage bucket analysis, DLP scan results (if enabled), and IAM permission analysis for data resources.'
      }
    }
  ];

  const modules = [
    {
      id: 'billing',
      name: 'Billing & Cost',
      icon: '💰',
      desc: 'Budgets, Kill Switch, Waste Analysis',
      details: {
        risk: 'Runaway costs, cryptojacking, and untracked spending can rapidly deplete budgets.',
        collected: 'Current month spend, active budget thresholds, breakdown by service, and high-cost SKU detection.'
      }
    },
    {
      id: 'iam',
      name: 'IAM & Access',
      icon: '🔑',
      desc: 'Key Rotation, Separation of Duties',
      details: {
        risk: 'Overprivileged users and service accounts increase the blast radius of any compromise.',
        collected: 'Primitive role usage (Owner/Editor), Service Account key age, separation of duties checks, and default service account analysis.'
      }
    },
    {
      id: 'api',
      name: 'API Security',
      icon: '🔌',
      desc: 'High-risk APIs, GPU Quotas',
      details: {
        risk: 'Unrestricted high-risk APIs (e.g., Admin SDKs) and high quotas enable massive abuse if credentials are leaked.',
        collected: 'List of enabled APIs, checks for sensitive APIs (e.g., Cloud Build, Deployment Manager), and GPU quota usage.'
      }
    },
    {
      id: 'scc',
      name: 'Operational & SCC',
      icon: '🚨',
      desc: 'Threat Findings & Vulnerabilities',
      details: {
        risk: 'Ignored vulnerabilities and active threats detected by Google can lead to immediate breaches.',
        collected: 'Aggregation of active findings from Security Command Center (SCC), suppression state, and severity breakdown.'
      }
    },
    {
      id: 'network',
      name: 'Network Security',
      icon: '🛡️',
      desc: 'Firewalls, VPC Flow Logs, IDS',
      details: {
        risk: 'Open firewalls (0.0.0.0/0) and unrestricted internal traffic allow attackers to move laterally.',
        collected: 'Firewall rule analysis, open ports (22, 3389), VPC Flow Log status, and default network usage.'
      }
    },
    {
      id: 'monitoring',
      name: 'Logging & Monitoring',
      icon: '📊',
      desc: 'Alerts, Audit Logs',
      details: {
        risk: 'Lack of visibility prevents detection of incidents and forensic analysis after a breach.',
        collected: 'Cloud Logging API status, CIS 2.0 benchmark metrics (e.g., alerts for IAM changes), and log sink configuration.'
      }
    },
    {
      id: 'change_control',
      name: 'Change Control',
      icon: '📝',
      desc: 'Approval Workflows, Terraform State',
      details: {
        risk: 'Manual "ClickOps" changes lead to configuration drift and lack of audit trails.',
        collected: 'Audit of manual vs. automated changes, Terraform usage signals, and CI/CD pipeline detection.'
      }
    },
    {
      id: 'architectural_foundations',
      name: 'Architectural Foundations',
      icon: '🏛️',
      desc: 'AI CAI Analysis & NIST Compliance',
      details: {
        risk: 'Fundamental design flaws in resource hierarchy and boundaries weaken the entire security posture.',
        collected: 'AI-driven review against Google Cloud Architecture Framework & NIST 800-53, utilizing Cloud Asset Inventory.'
      }
    },
  ];

  // Only treat an email as a valid scanner SA if it looks like one.
  // This prevents personal ADC emails from ever appearing in the identity field.
  const isScannerSA = (email: string | null | undefined): boolean =>
    !!email && email.endsWith('.iam.gserviceaccount.com');

  // On page load, restore the scanner SA email.
  // Priority: 1) backend active session  2) localStorage (set by OnboardingModal)
  useEffect(() => {
    const syncIdentity = async () => {
      let resolvedEmail = null;
      try {
        const res = await fetch('/api/session/identity');
        if (res.ok) {
          const data = await res.json();
          if (data.active && isScannerSA(data.sa_email)) {
            setActiveScannerEmail(data.sa_email);
            setIsJitActive(true);
            resolvedEmail = data.sa_email;
          }
        }
      } catch { /* backend offline */ }

      // Fallback: use the last scanner SA the user configured in the modal.
      if (!resolvedEmail) {
        const cachedSa = localStorage.getItem('scanner_sa_email');
        if (isScannerSA(cachedSa)) {
          setActiveScannerEmail(cachedSa!);
          resolvedEmail = cachedSa;
        }
      }

      // Automatically fetch projects if we restored an identity
      if (resolvedEmail) {
        const targetId = localStorage.getItem('scanner_target_id');
        const orgId = localStorage.getItem('scanner_org_id');
        // Let's assume scope is project if targetId is set, else org.
        fetchProjects('', orgId || undefined, resolvedEmail, targetId || undefined);
      }
    };
    syncIdentity();
  }, []);



  const handleVerified = (resourceId: string, scope: 'project' | 'organization', saEmail: string) => {
    console.log(`SaaS Onboarding verified for ${scope}:`, resourceId);
    setActiveScannerEmail(saEmail);
    setIsJitActive(true);
    setShowJitModal(false);

    // Save target ID so refresh buttons work correctly
    if (scope === 'project') {
      localStorage.setItem('scanner_target_id', resourceId);
      localStorage.removeItem('scanner_org_id');
    } else {
      localStorage.removeItem('scanner_target_id');
      localStorage.setItem('scanner_org_id', resourceId);
    }

    // Pass saEmail explicitly here — clientData.sessionSaEmail is async and stale at this moment
    fetchProjects('', scope === 'organization' ? resourceId : undefined, saEmail, scope === 'project' ? resourceId : undefined);
  };

  const handleJitSessionStarted = (token: string) => {
    // Keep for legacy support if needed, but primary is handleVerified
    console.log("JIT Session Started with token:", token);
    setJitToken(token);
    setIsJitActive(true);
    setShowJitModal(false);

    const targetId = typeof window !== 'undefined' ? localStorage.getItem('scanner_target_id') : null;
    fetchProjects(token, targetId ? undefined : clientData.orgId, undefined, targetId || undefined);
  };

  const fetchProjects = async (token: string, organizationId?: string, impersonateEmail?: string, targetId?: string) => {
    setLoadingProjects(true);
    setWorkflowStage('project_discovery');
    setError(null);

    // RESET ALL STATE
    setProjects([]);
    setScanResults([]);
    setSelectedProjects(new Set());

    try {
      // Use explicitly-passed impersonateEmail first (fresh from modal), else fall back to state
      const resolvedSaEmail = impersonateEmail || clientData.sessionSaEmail || '';

      // Target explicitly verified project ID, otherwise fallback to cache
      const resolvedTargetId = targetId || (typeof window !== 'undefined' ? localStorage.getItem('scanner_target_id') : null);

      console.log(`Fetching projects as SA: ${resolvedSaEmail || 'ADC'} for Target: ${resolvedTargetId || 'all'} (Org ${organizationId || 'none'})...`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

      // If a specific Target Project ID is given, we MUST nuke the organization_id.
      // Otherwise, the backend will prioritize the org_id and attempt an org-wide list API call,
      // which will instantly fail with 403 because the SA only has roles/browser on the specific project.
      const finalOrgId = resolvedTargetId ? null : (organizationId || null);

      // Hit the Next.js proxy instead of the backend directly
      const response = await fetch('/api/v1/projects/list', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jit_token: token || null,
          access_token: "",
          organization_id: finalOrgId,
          impersonate_email: resolvedSaEmail,
          target_id: resolvedTargetId || null
        }),
        signal: controller.signal
      }).finally(() => clearTimeout(timeoutId));

      console.log("Project fetch response status:", response.status);

      if (!response.ok) {
        let errorDetail = "Failed to list projects";
        try {
          const err = await response.json();
          errorDetail = err.detail || errorDetail;
        } catch (e) {
          // ignore
        }
        throw new Error(errorDetail);
      }

      const data = await response.json();
      console.log("Projects fetched successfully:", data);

      const projectList = data.projects || [];
      setProjects(projectList);

      // Detect Organization ID from first project that has it
      const orgProject = projectList.find((p: ProjectInfo) => p.organization_id);
      if (orgProject) {
        setDetectedOrgId(orgProject.organization_id);
        console.log("Detected Organization ID:", orgProject.organization_id);
      } else {
        setDetectedOrgId(null);
      }

      if (projectList.length === 0) {
        // Fallback: Try to get project from session status
        try {
          console.log("No projects listed. Attempting to fetch session project...");
          const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
          const statusResp = await fetch(`${backendUrl}/api/v1/session/status`, {
            headers: { 'X-JIT-Token': token }
          });
          if (statusResp.ok) {
            const statusData = await statusResp.json();
            if (statusData.project_id) {
              console.log("Fallback successful. Found project:", statusData.project_id);
              const fallbackProject: ProjectInfo = {
                project_id: statusData.project_id,
                name: 'Current Project',
                project_number: '',
                lifecycle_state: 'ACTIVE',
                labels: {}
              };
              setProjects([fallbackProject]);
              // Important: update local variable for the logic below
              projectList.push(fallbackProject);
            } else {
              setError("No projects found and no session project identification available.");
            }
          }
        } catch (fbErr) {
          console.error("Fallback failed:", fbErr);
          setError("No projects found. Check service account permissions.");
        }
      }

    } catch (err: any) {
      console.error("Project discovery error:", err);
      // Even on error, try fallback? No, usually list error is distinct.
      // Actually, let's try fallback on error too!
      try {
        console.log("Discovery failed. Attempting to fetch session project...");
        const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
        const statusResp = await fetch(`${backendUrl}/api/v1/session/status`, {
          headers: { 'X-JIT-Token': token }
        });
        if (statusResp.ok) {
          const statusData = await statusResp.json();
          if (statusData.project_id) {
            console.log("Fallback successful. Found project:", statusData.project_id);
            const fallbackProject: ProjectInfo = {
              project_id: statusData.project_id,
              name: 'Current Project',
              project_number: '',
              lifecycle_state: 'ACTIVE',
              labels: {}
            };
            setProjects([fallbackProject]);
            setError(null); // Clear error since we recovered
          }
        }
      } catch (fbErr) {
        if (err.name === 'AbortError') {
          setError("Connection timed out. Backend warming up?");
        } else {
          setError(err.message || "Failed to list projects.");
        }
      }
    } finally {
      setLoadingProjects(false);

      // Auto-Advance Logic
      // We need to check state.projects, but state updates aren't immediate.
      // However, we populated 'projectList' variable earlier if success.
      // If we fell back, we can't easily see it here without refactoring.
      // Let's rely on a timeout hack or just check the length of what we think we have.
      // Actually, simpler: just wait for the effect? No.

      // Safest approach: Let the user see the selection screen if we can't guarantee state.
      // But we WANT auto-advance. 
      // Let's assume if we didn't error, and we have projects...
      // Instead of relying on 'projects' state, let's use a flag.

      // Use a timeout to allow state to settle, then decide? No, that causes flicker.

      // BETTER: We can't see the new 'projects' state here yet.
      // BUT, we can check the logic we just ran.

      // I will implement a `useEffect` to handle the auto-advance instead of doing it here.
      // That is cleaner React pattern.
      // Remove the force transition here.
    }
  };

  // Add Effect for Auto-Advance
  useEffect(() => {
    if (workflowStage === 'project_discovery' && !loadingProjects && !error) {
      // logic was here to auto-advance if length === 1
      // Removing auto-advance to ensure user always sees the selection screen
      // and can verify if projects are missing.
      if (projects.length > 0) {
        setWorkflowStage('project_selection');
      } else {
        // If 0 projects, we stay here. The UI will show "No projects found" or similar if we handled it?
        // Actually the UI shows spinner "Discovering..." if no error. 
        // We should force transition to selection even if empty, so they can use "Manual Entry" (if we had it)
        // or at least see the empty state.
        setWorkflowStage('project_selection');
      }
    }
  }, [projects, loadingProjects, workflowStage, error]);


  const handleProjectToggle = (projectId: string) => {
    const next = new Set(selectedProjects);
    if (next.has(projectId)) {
      next.delete(projectId);
    } else {
      next.add(projectId);
    }
    setSelectedProjects(next);
  };

  const handleModuleToggle = (moduleId: string) => {
    const next = new Set(selectedModules);
    if (next.has(moduleId)) {
      next.delete(moduleId);
    } else {
      next.add(moduleId);
    }
    setSelectedModules(next);
  };

  // New Progress State
  const [scanProgress, setScanProgress] = useState<{ current: number, total: number, message: string } | null>(null);

  const handleRunScans = async () => {
    if (!jitToken) {
      // ADC-mode: no JIT token needed — the backend uses its own credentials.
      // Only block if we somehow have no projects selected.
      console.log("ADC mode: proceeding without JIT token");
    }

    if (selectedProjects.size === 0) {
      setError("No projects selected.");
      return;
    }

    setWorkflowStage('scanning');
    setError(null);
    setScanResults([]);
    setIsScanning(true);
    setScanProgress({ current: 0, total: selectedProjects.size, message: 'Initializing...' });

    try {
      // Check if architectural scan is selected, which requires careful visual progress
      const isArchScan = selectedModules.has('architectural_foundations');
      const projectIds = Array.from(selectedProjects);

      let allResults: ScanResponse[] = [];

      // Parallel Scan with Incremental Feedback
      setScanProgress({
        current: 0,
        total: projectIds.length,
        message: `Starting parallel scan for ${projectIds.length} projects...`
      });

      let completedCount = 0;

      // Define scan worker
      // Define scan worker
      const scanProject = async (pid: string) => {
        // Use /multi endpoint for individual requests as it handles the schema reliably
        const payload = {
          project_ids: [pid],
          jit_token: jitToken,
          scan_modules: Array.from(selectedModules),
          organization_id: detectedOrgId,
          impersonate_email: activeScannerEmail || clientData.sessionSaEmail
        };

        try {
          const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
          const response = await fetch(`${backendUrl}/api/v1/scan/multi`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${jitToken}`
            },
            body: JSON.stringify(payload)
          });

          if (!response.ok) {
            if (response.status === 401) {
              throw new Error("JIT_EXPIRED");
            }
            console.error(`Scan failed for ${pid}: ${response.statusText}`);
          } else {
            const data = await response.json();
            // Multi-scan returns { scans: [...] }
            if (data.scans && data.scans.length > 0) {
              const result = data.scans[0];
              setScanResults(prev => [...prev, result]);
              allResults.push(result);

              // Automatically extract scanner identity if not already set.
              // ONLY accept emails that look like a service account to prevent
              // personal ADC emails (e.g. user@domain.com) from showing here.
              if (!activeScannerEmail) {
                const cachedSa = localStorage.getItem('scanner_sa_email');
                const identityToShow = isScannerSA(cachedSa) ? cachedSa
                  : isScannerSA(result.scanner_email) ? result.scanner_email
                    : null;
                if (identityToShow) setActiveScannerEmail(identityToShow);
              }
            }
          }
        } catch (err: any) {
          if (err.message === "JIT_EXPIRED") throw err;
          console.error(`Scan error for ${pid}:`, err);
        } finally {
          completedCount++;
          setScanProgress({
            current: completedCount,
            total: projectIds.length,
            message: `Scanned ${pid} (${completedCount}/${projectIds.length})...`
          });
        }
      };

      try {
        // Execute all requests in parallel
        // Browser will manage connection limits (usually 6-10 concurrent)
        // Rate limit on backend increased to 100/min to accommodate this
        await Promise.all(projectIds.map(pid => scanProject(pid)));
      } catch (err: any) {
        if (err.message === "JIT_EXPIRED") {
          setError("JIT Session Expired. Please click 'Lock Session' and re-authenticate.");
          setIsScanning(false);
          return;
        }
      }

      console.log("All Scan Results Received:", allResults);
      setScanResults(allResults);

      // --- Post Processing (same as before) ---
      const results = allResults;

      // Auto-populate Org Details from Scan Context
      const firstResult = results.length > 0 ? results[0] : null;

      // Prefer explicit scan result fields (added in backend)
      const finalOrgId = (firstResult as any)?.organization_id || detectedOrgId || firstResult?.scc_info?.organization_id;
      const foundOrgName = (firstResult as any)?.organization_name;

      console.log(`Scan Analysis for Populating Org Details: ID=${finalOrgId}, Name=${foundOrgName}`);

      if (finalOrgId && (!clientData.orgId || clientData.orgId !== finalOrgId)) {
        console.log("Auto-populating Org ID:", finalOrgId);
        // If ID changed, we must update ID.
        // We also check Name: if found, use it. If NOT found, clear the old name to avoid mismatch.
        updateClientData({
          orgId: finalOrgId,
          orgName: foundOrgName || '' // Clear name if we switched orgs but can't resolve the new name
        });
      } else if (foundOrgName && (!clientData.orgName || clientData.orgName !== foundOrgName)) {
        // ID didn't change (or wasn't found), but we found a new Name (e.g. permission fixed)
        console.log("Auto-populating Org Name:", foundOrgName);
        updateClientData({ orgName: foundOrgName });
      }

      // Save to Client History if client is selected
      if (clientData.id) {
        const scanSummary = {
          ran_by: clientData.scannerName,
          ran_by_email: clientData.scannerEmail,
          modules: Array.from(selectedModules),
          project_count: results.length
        };
        // We save the array of project results
        saveScanResult(scanSummary, { scans: results });
      }

      // Auto-expand the first project
      if (results.length > 0) {
        const firstProj = results[0].project_id;
        setExpandedResults(new Set([firstProj]));
      }

      setWorkflowStage('results');

    } catch (err: any) {
      console.error("Scan error:", err);
      setError(err.message);
      setWorkflowStage('scan_configuration'); // Go back
    } finally {
      setIsScanning(false);
      setScanProgress(null);
    }
  };

  const renderModuleResult = (result: ScanResponse, activeModule: string) => {
    switch (activeModule) {
      case 'billing':
        return (
          <BillingModule
            data={result.billing_info}
            risks={result.risks || []}
            loading={false}
            projectId={result.project_id}
            jitToken={jitToken!}
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
                              {/* If it's an error message disguised as a finding, show full text. Otherwise show resource ID */}
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

            {/* NEW: Audit Results */}
            <ChangeControlAuditModule data={result.change_control_info} />

            {/* LockdownInterface removed as requested - to be moved to API Remediation later */}
          </div>
        );
      case 'architectural_foundations':
        return (
          <ArchitecturalReviewModule data={result.architecture_info} />
        );
      default:
        // For other modules not yet implemented, check if we have risks
        const moduleRisks = (result.risks || []).filter(r =>
          // Heuristic mapping
          (activeModule === 'api' && r.category === 'api') ||
          (activeModule === 'iam' && r.category === 'iam') ||
          (activeModule === 'monitoring' && r.category === 'monitoring')
        );

        if (moduleRisks.length > 0) {
          return (
            <div className="space-y-4">
              <h3 className="font-bold text-gray-800">Findings for {activeModule.toUpperCase()}</h3>
              {moduleRisks.map((risk, idx) => (
                <div key={idx} className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
                  <div className="flex justify-between items-start">
                    <div className="flex gap-2 items-center">
                      <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${risk.risk_level === 'critical' ? 'bg-red-200 text-red-800' : 'bg-yellow-200 text-yellow-800'}`}>
                        {risk.risk_level}
                      </span>
                      <h4 className="font-bold text-gray-900">{risk.title}</h4>
                    </div>

                    {/* Download Script Button */}
                    {(risk as any).remediation_script_content && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          const element = document.createElement("a");
                          const file = new Blob([(risk as any).remediation_script_content], { type: 'text/plain' });
                          element.href = URL.createObjectURL(file);
                          element.download = (risk as any).remediation_script_filename || 'fix_script.sh';
                          document.body.appendChild(element);
                          element.click();
                          document.body.removeChild(element);
                        }}
                        className="flex items-center gap-1 text-xs bg-primary-50 text-primary-700 px-3 py-1.5 rounded border border-primary-200 hover:bg-primary-100 font-medium transition-colors"
                        title="Download automated fix script"
                      >
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                        Download Fix Script
                      </button>
                    )}
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

        return (
          <div className="text-center p-12 bg-gray-50 rounded-lg border border-gray-200">
            <p className="text-gray-500">No specific view implemented for module '{activeModule}' yet.</p>
            <p className="text-xs text-gray-400">But we found {(result.risks || []).length} total risks in this project.</p>
          </div>
        );
    }
  };

  return (
    <DefaultLayout
      jitActive={isJitActive}
      onUploadClick={() => setShowJitModal(true)}
    >
      <OnboardingModal
        isOpen={showJitModal}
        onClose={() => setShowJitModal(false)}
        onVerified={handleVerified}
        initialSaEmail={clientData.sessionSaEmail}
      />

      {workflowStage === 'initial' ? (
        <div className="py-10 text-center max-w-2xl mx-auto relative">

          <h1 className="text-4xl font-extrabold text-gray-900 tracking-tight sm:text-5xl mb-6 mt-12">
            Secure Your GCP Environment
          </h1>
          <p className="text-lg text-gray-600 mb-10">
            Modular security hardening for Google Cloud Platform.
            Upload your Just-In-Time (JIT) credentials to unlock the dashboard.
          </p>
          <ActionBtn onClick={() => setShowJitModal(true)} className="px-8 py-3 text-lg shadow-xl shadow-blue-500/20">
            Connect Environment
          </ActionBtn>

          {/* Skip button for users who already completed SA setup */}
          <div className="mt-4">
            <button
              onClick={() => {
                // Bypass the SA modal — use ADC credentials already on the backend
                setIsJitActive(true);
                setJitToken(null); // ADC mode: no JIT token

                const targetId = typeof window !== 'undefined' ? localStorage.getItem('scanner_target_id') : null;
                fetchProjects('', targetId ? undefined : clientData.orgId, undefined, targetId || undefined); // Discover projects via ADC
              }}
              className="text-sm text-gray-500 underline hover:text-gray-700 transition-colors"
            >
              ⚡ Skip — I already set up my environment, go to discovery
            </button>
          </div>
          {/* Feature Grid ... */}
          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6 text-left">
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
              <div className="text-blue-600 mb-3">⚡</div>
              <h3 className="font-semibold text-gray-900">Modular Scanning</h3>
              <p className="text-sm text-gray-500 mt-2">Scan specific domains like Network or IAM individually.</p>
            </div>
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
              <div className="text-purple-600 mb-3">🔐</div>
              <h3 className="font-semibold text-gray-900">JIT Access</h3>
              <p className="text-sm text-gray-500 mt-2">Zero-trust architecture. Credentials live in memory only.</p>
            </div>
            <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
              <div className="text-green-600 mb-3">📜</div>
              <h3 className="font-semibold text-gray-900">Audit Ready</h3>
              <p className="text-sm text-gray-500 mt-2">Generate executive reports and Terraform mitigation scripts.</p>
            </div>
          </div>
        </div>
      ) : (
        <>
          {/* Authenticated Dashboard Header */}



          <div className="max-w-6xl mx-auto space-y-8">
            <div className="flex justify-between items-end border-b border-gray-100 pb-4">
              <div>
                <h2 className="text-3xl font-bold text-gray-900">Security Dashboard</h2>
                <div className="flex items-center gap-2 mt-2 text-sm text-gray-500">
                  <button
                    onClick={() => {
                      if (workflowStage === 'scan_configuration' || workflowStage === 'results') {
                        setWorkflowStage('project_selection');
                      }
                    }}
                    disabled={['initial', 'project_discovery'].includes(workflowStage)}
                    className={`px-3 py-1 rounded-full font-medium transition-colors ${['project_discovery', 'project_selection'].includes(workflowStage)
                      ? 'bg-primary-100 text-primary-700 shadow-sm'
                      : 'bg-gray-100 hover:bg-gray-200 cursor-pointer text-gray-600'
                      } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    1. Discovery
                  </button>
                  <span className="text-gray-300">→</span>

                  <button
                    onClick={() => {
                      if (projects && projects.length > 0) {
                        setWorkflowStage('scan_configuration');
                      }
                    }}
                    disabled={!(projects && projects.length > 0)}
                    className={`px-3 py-1 rounded-full font-medium transition-colors ${workflowStage === 'scan_configuration'
                      ? 'bg-primary-100 text-primary-700 shadow-sm'
                      : 'bg-gray-100 hover:bg-gray-200 cursor-pointer text-gray-600'
                      } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    2. Configuration
                  </button>
                  <span className="text-gray-300">→</span>

                  <button
                    onClick={() => {
                      if (scanResults && scanResults.length > 0) {
                        setWorkflowStage('results');
                      }
                    }}
                    disabled={!(scanResults && scanResults.length > 0)}
                    className={`px-3 py-1 rounded-full font-medium transition-colors ${workflowStage === 'results'
                      ? 'bg-primary-100 text-primary-700 shadow-sm'
                      : 'bg-gray-100 hover:bg-gray-200 cursor-pointer text-gray-600'
                      } disabled:opacity-50 disabled:cursor-not-allowed`}
                  >
                    3. Results
                  </button>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm font-medium text-green-600 flex items-center justify-end gap-2">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  JIT Session Active
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <button
                    onClick={() => {
                      setWorkflowStage('initial');
                      setJitToken(null);
                      setProjects([]);
                      setError(null);
                    }}
                    className="text-xs text-red-500 hover:underline"
                  >
                    Lock Session
                  </button>
                </div>
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-lg flex justify-between items-center shadow-sm max-w-4xl mx-auto my-4">
                <div className="flex items-center gap-2">
                  <span className="text-xl">⚠️</span>
                  <span>{error}</span>
                </div>
                <button onClick={() => setError(null)} className="text-red-500 hover:text-red-700 font-bold px-2">✕</button>
              </div>
            )}

            {/* STAGE: PROJECT DISCOVERY (LOADING or ERROR) */}
            {workflowStage === 'project_discovery' && (
              <div className="text-center py-20 bg-white rounded-xl shadow-sm border border-gray-100">
                {error ? (
                  <div className="space-y-4">
                    <h3 className="text-lg font-medium text-red-600">Discovery Failed</h3>
                    <p className="text-gray-500 max-w-md mx-auto">
                      We couldn't list your projects. Please check that your Service Account has the
                      <code className="bg-gray-100 px-1 rounded mx-1">resourcemanager.projects.list</code> permission.
                    </p>
                    <div className="flex justify-center gap-4">
                      <button
                        onClick={() => fetchProjects(jitToken!)}
                        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                      >
                        Retry Discovery
                      </button>
                      <button
                        onClick={() => setWorkflowStage('project_selection')}
                        className="px-4 py-2 bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
                      >
                        Continue Anyway
                      </button>
                    </div>
                    <p className="text-xs text-gray-400 mt-4">
                      Check console logs for details: {error}
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="inline-block animate-spin rounded-full h-10 w-10 border-4 border-blue-600 border-r-transparent mb-4"></div>
                    <h3 className="text-lg font-medium text-gray-900">Discovering Tenant Projects...</h3>
                    <div className="mt-4">
                      <p className="text-gray-500 text-sm">This may take a moment depending on your permissions.</p>
                      {/* Emergency Hatch */}
                      <button
                        onClick={() => setWorkflowStage('project_selection')}
                        className="mt-8 text-xs text-gray-400 underline hover:text-gray-600"
                      >
                        Stuck? Click here to skip discovery
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* STAGE: PROJECT SELECTION */}
            {workflowStage === 'project_selection' && (
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <StandardHeader
                  title="Select Projects to Scan"
                  subtitle={`Found ${projects.length} accessible projects in tenant.`}
                  actions={
                    <>
                      <div className="space-x-3">
                        <button
                          onClick={() => setSelectedProjects(new Set(projects.map(p => p.project_id)))}
                          className="text-sm text-blue-600 hover:text-blue-800"
                        >
                          Select All
                        </button>
                        <span className="text-gray-300">|</span>
                        <button
                          onClick={() => setSelectedProjects(new Set())}
                          className="text-sm text-gray-500 hover:text-gray-700"
                        >
                          Clear
                        </button>
                      </div>

                      {/* Scan Mode Toggle */}
                      <div className="flex bg-gray-100 p-1 rounded-lg border border-gray-200 mx-2">
                        <button
                          onClick={() => {
                            setScanMode('product');
                            setSelectedModules(new Set());
                          }}
                          className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all ${scanMode === 'product'
                            ? 'bg-white text-blue-600 shadow-sm'
                            : 'text-gray-500 hover:text-gray-700'
                            }`}
                        >
                          Product Scans
                        </button>
                        <button
                          onClick={() => {
                            setScanMode('solution');
                            setSelectedModules(new Set());
                          }}
                          className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all ${scanMode === 'solution'
                            ? 'bg-white text-blue-600 shadow-sm'
                            : 'text-gray-500 hover:text-gray-700'
                            }`}
                        >
                          Solution Scans
                        </button>
                      </div>

                      <ActionBtn
                        disabled={selectedProjects.size === 0}
                        onClick={() => setWorkflowStage('scan_configuration')}
                        className="px-6 py-2"
                      >
                        Configure Scans →
                      </ActionBtn>
                    </>
                  }
                />

                {projects.length === 0 ? (
                  <div className="p-10 text-center text-gray-500">
                    <p>No projects found. Check service account permissions.</p>
                    <button
                      onClick={() => {
                        const targetId = localStorage.getItem('scanner_target_id');
                        // If there is a explicit project targetId saved, we must NOT pass an orgId, otherwise the backend overrides the direct lookup
                        fetchProjects(jitToken!, targetId ? undefined : clientData.orgId, undefined, targetId || undefined);
                      }}
                      className="mt-4 text-sm text-blue-600 hover:underline"
                    >
                      Refresh
                    </button>
                  </div>
                ) : (

                  <div className="max-h-[60vh] overflow-y-auto border border-gray-200 rounded-lg mx-4 mb-4 custom-scrollbar">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50 sticky top-0 z-10 shadow-sm">
                        <tr>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-10 bg-gray-50">
                            Select
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">
                            Project Name
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">
                            Project ID
                          </th>
                          <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">
                            Status
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {projects.map((project) => (
                          <tr
                            key={project.project_id}
                            className={`hover:bg-gray-50 cursor-pointer ${selectedProjects.has(project.project_id) ? 'bg-blue-50/30' : ''}`}
                            onClick={() => handleProjectToggle(project.project_id)}
                          >
                            <td className="px-6 py-4 whitespace-nowrap">
                              <input
                                type="checkbox"
                                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                checked={selectedProjects.has(project.project_id)}
                                onChange={() => handleProjectToggle(project.project_id)}
                                onClick={(e) => e.stopPropagation()}
                              />
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                              {project.name}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                              {project.project_id}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${project.lifecycle_state === 'ACTIVE' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                                }`}>
                                {project.lifecycle_state}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div >
                )
                }


              </div >
            )}

            {/* STAGE: SCAN CONFIGURATION */}
            {
              workflowStage === 'scan_configuration' && (
                <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden text-left">
                  <StandardHeader
                    title={scanMode === 'product' ? "Product Scan Options" : "Solution Scan Options"}
                    subtitle={`Select security modules to run on ${selectedProjects.size} projects.`}
                    onBack={() => setWorkflowStage('project_selection')}
                    backLabel="Back to Projects"
                    actions={
                      <>
                        <div className="space-x-3">
                          <button
                            onClick={() => setSelectedModules(new Set(
                              scanMode === 'product'
                                ? modules.map(m => m.id)
                                : solutionScans.map(m => m.id)
                            ))}
                            className="text-sm text-blue-600 hover:text-blue-800"
                          >
                            Select All
                          </button>
                          <span className="text-gray-300">|</span>
                          <button
                            onClick={() => setSelectedModules(new Set())}
                            className="text-sm text-gray-500 hover:text-gray-700"
                          >
                            Clear
                          </button>
                        </div>
                        <ActionBtn
                          onClick={handleRunScans}
                          disabled={selectedModules.size === 0}
                          className="px-6 py-2 whitespace-nowrap"
                        >
                          Run Scans →
                        </ActionBtn>
                      </>
                    }
                  />

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-4 bg-gray-50/50 max-h-[60vh] overflow-y-auto custom-scrollbar border border-gray-200 rounded-lg m-4">
                    {scanMode === 'product' && modules.map((mod) => (
                      <div
                        key={mod.id}
                        onClick={() => handleModuleToggle(mod.id)}
                        className={`group relative p-3 rounded-xl border transition-all cursor-pointer shadow-sm hover:shadow-md flex flex-col gap-1.5 h-full ${selectedModules.has(mod.id)
                          ? 'bg-white border-blue-600 ring-1 ring-blue-600'
                          : 'bg-white border-gray-200 hover:border-blue-400'
                          }`}
                      >
                        <div className="flex justify-between items-start mb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-2xl p-1.5 bg-gray-50 rounded-lg group-hover:scale-105 transition-transform">{mod.icon}</span>
                            <h4 className={`font-bold text-base ${selectedModules.has(mod.id) ? 'text-blue-900' : 'text-gray-900'}`}>
                              {mod.name}
                            </h4>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setDetailsModalModuleId(mod.id);
                              }}
                              className="mt-0.5 text-gray-400 hover:text-blue-600 transition-colors p-1 rounded-full hover:bg-blue-50"
                              title="View details"
                            >
                              <Info className="w-3.5 h-3.5" />
                            </button>
                          </div>
                          <div className="relative flex items-center justify-center p-0.5">
                            <input
                              type="checkbox"
                              className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500 border-gray-300 pointer-events-none"
                              checked={selectedModules.has(mod.id)}
                              readOnly
                            />
                          </div>
                        </div>

                        <p className="text-xs text-gray-600 leading-relaxed pl-1">
                          {mod.desc}
                        </p>
                      </div>
                    ))}

                    {/* Render Solution Scans if selected */}
                    {scanMode === 'solution' && modules.length === 0 /* This hack ensures we don't duplicate if we used same array, but we have separate arrays */ ? null : null}

                    {scanMode === 'solution' && solutionScans.map((mod) => (
                      <div
                        key={mod.id}
                        onClick={() => handleModuleToggle(mod.id)}
                        className={`group relative p-3 rounded-xl border transition-all cursor-pointer shadow-sm hover:shadow-md flex flex-col gap-1.5 h-full ${selectedModules.has(mod.id)
                          ? 'bg-white border-blue-600 ring-1 ring-blue-600'
                          : 'bg-white border-gray-200 hover:border-blue-400'
                          }`}
                      >
                        <div className="flex justify-between items-start mb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-2xl p-1.5 bg-gray-50 rounded-lg group-hover:scale-105 transition-transform">{mod.icon}</span>
                            <h4 className={`font-bold text-base ${selectedModules.has(mod.id) ? 'text-blue-900' : 'text-gray-900'}`}>
                              {mod.name}
                            </h4>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setDetailsModalModuleId(mod.id); // Re-use details modal logic, need to ensure lookup works
                              }}
                              className="mt-0.5 text-gray-400 hover:text-blue-600 transition-colors p-1 rounded-full hover:bg-blue-50"
                              title="View details"
                            >
                              <Info className="w-3.5 h-3.5" />
                            </button>
                          </div>
                          <div className="relative flex items-center justify-center p-0.5">
                            <input
                              type="checkbox"
                              className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500 border-gray-300 pointer-events-none"
                              checked={selectedModules.has(mod.id)}
                              readOnly
                            />
                          </div>
                        </div>

                        <p className="text-xs text-gray-600 leading-relaxed pl-1">
                          {mod.desc}
                        </p>
                      </div>
                    ))}
                  </div>

                  {/* Module Details Modal */}
                  {detailsModalModuleId && (
                    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 animate-in fade-in duration-200">
                      <div className="bg-white rounded-xl shadow-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
                        <div className="p-6">
                          {(() => {
                            const mod = scanMode === 'product'
                              ? modules.find(m => m.id === detailsModalModuleId)
                              : solutionScans.find(m => m.id === detailsModalModuleId);
                            if (!mod) return null;
                            return (
                              <>
                                <div className="flex items-center gap-3 mb-4">
                                  <span className="text-3xl p-2 bg-gray-50 rounded-lg">{mod.icon}</span>
                                  <h3 className="text-xl font-bold text-gray-900">{mod.name}</h3>
                                </div>

                                <div className="space-y-4">
                                  <div>
                                    <h4 className="text-sm font-bold text-gray-900 uppercase tracking-wider mb-1 flex items-center gap-2">
                                      <Shield className="w-4 h-4 text-orange-500" /> Risk
                                    </h4>
                                    <p className="text-sm text-gray-600 leading-relaxed bg-orange-50 p-3 rounded-lg border border-orange-100">
                                      {mod.details?.risk}
                                    </p>
                                  </div>

                                  <div>
                                    <h4 className="text-sm font-bold text-gray-900 uppercase tracking-wider mb-1 flex items-center gap-2">
                                      <FileText className="w-4 h-4 text-blue-500" /> Data Collected
                                    </h4>
                                    <p className="text-sm text-gray-600 leading-relaxed bg-blue-50 p-3 rounded-lg border border-blue-100">
                                      {mod.details?.collected}
                                    </p>
                                  </div>
                                </div>

                                <div className="mt-8 flex justify-end">
                                  <button
                                    onClick={() => setDetailsModalModuleId(null)}
                                    className="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-800 rounded-lg font-medium transition-colors"
                                  >
                                    Close
                                  </button>
                                </div>
                              </>
                            );
                          })()}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )
            }



            {/* STAGE: SCANNING */}
            {
              workflowStage === 'scanning' && (
                <div className="text-center py-24 bg-white rounded-xl shadow-sm border border-gray-100">
                  <div className="inline-block relative mb-6">
                    {/* Pulse Effect */}
                    <span className="absolute inline-flex h-full w-full rounded-full bg-blue-100 opacity-75 animate-ping"></span>
                    <div className="relative bg-white rounded-full p-4 border-2 border-blue-100">
                      <Shield className="w-12 h-12 text-blue-600 animate-pulse" />
                    </div>
                  </div>

                  <h3 className="text-xl font-bold text-gray-900 mb-2">Security Scan in Progress</h3>

                  {scanProgress ? (
                    <div className="max-w-md mx-auto mt-4 px-4">
                      <p className="text-gray-600 mb-2 font-medium">{scanProgress.message}</p>
                      <div className="w-full bg-gray-200 rounded-full h-2.5 mb-1">
                        <div
                          className="bg-blue-600 h-2.5 rounded-full transition-all duration-500 ease-out"
                          style={{ width: `${(scanProgress.current / scanProgress.total) * 100}%` }}
                        ></div>
                      </div>
                      <p className="text-xs text-gray-400 text-right">
                        Project {scanProgress.current} of {scanProgress.total}
                      </p>
                    </div>
                  ) : (
                    <p className="text-gray-500 max-w-sm mx-auto">
                      Running selected security modules ({selectedModules.size}) on {selectedProjects.size} project{selectedProjects.size > 1 ? 's' : ''}...
                    </p>
                  )}

                  <p className="text-xs text-gray-400 mt-8 animate-pulse">
                    This may take 30-60 seconds depending on API quotas...
                  </p>
                </div>
              )
            }

            {/* STAGE: RESULTS */}
            {
              workflowStage === 'results' && (
                scanResults.length > 0 ? (
                  <div className="space-y-6">
                    {/* Organization Details Inputs */}
                    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
                      <h3 className="text-sm font-bold text-gray-900 mb-4 uppercase tracking-wider border-b border-gray-100 pb-2">Target Organization Details</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">

                        {/* Org Name */}
                        <div>
                          <label className="block text-xs font-bold text-gray-500 mb-1 uppercase">Organization Name</label>
                          <input
                            type="text"
                            value={clientData.orgName || ''}
                            readOnly
                            className="w-full px-3 py-2 border border-gray-200 bg-gray-50 text-gray-600 rounded-md text-sm cursor-not-allowed"
                            placeholder="Detected from Scan"
                          />
                        </div>

                        {/* Org ID */}
                        <div>
                          <label className="block text-xs font-bold text-gray-500 mb-1 uppercase">Organization ID</label>
                          <input
                            type="text"
                            value={clientData.orgId || ''}
                            readOnly
                            className="w-full px-3 py-2 border border-gray-200 bg-gray-50 text-gray-600 rounded-md text-sm font-mono cursor-not-allowed"
                            placeholder="Detected from Scan"
                          />
                          <p className="text-[10px] text-gray-400 mt-1">Unique identifier retrieved from Google Cloud.</p>
                        </div>

                        {/* Active Scanner SA */}
                        <div>
                          <label className="block text-xs font-bold text-gray-500 mb-1 uppercase">Active Scanner Identity</label>
                          <input
                            type="text"
                            value={activeScannerEmail || 'Unknown Scanner Identity'}
                            readOnly
                            className="w-full px-3 py-2 border border-blue-200 bg-blue-50 text-blue-700 font-bold rounded-md text-sm cursor-not-allowed"
                            title={activeScannerEmail || 'Unknown'}
                          />
                          <p className="text-[10px] text-gray-400 mt-1">Identity utilized to execute the security scan.</p>
                        </div>

                      </div>
                    </div>

                    {/* Global SCC Status Banner */}
                    {scanResults.length > 0 && scanResults[0].scc_info && (
                      <div className="bg-white rounded-xl shadow-sm border border-l-4 border-gray-200 border-l-blue-600 p-6 flex justify-between items-center">
                        <div>
                          <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                            <Shield className="w-5 h-5 text-blue-600" />
                            Security Command Center Status
                          </h2>
                          <p className="text-sm text-gray-500 mt-1">Global Organization Security Posture</p>
                        </div>
                        <div className="flex items-center gap-4">
                          {/* Download Artifacts Button */}
                          <button
                            onClick={async () => {
                              try {
                                const response = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:8001"}/api/v1/report/download-artifacts`, {
                                  method: 'POST',
                                  headers: {
                                    'Content-Type': 'application/json',
                                    'X-JIT-Token': jitToken || '' // Use correct JIT header
                                  },
                                  body: JSON.stringify(scanResults) // Send full results to generate kit
                                });

                                if (!response.ok) throw new Error("Download failed");

                                const blob = await response.blob();
                                const url = window.URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `remediation_kit_${new Date().toISOString().split('T')[0]}.zip`;
                                document.body.appendChild(a);
                                a.click();
                                window.URL.revokeObjectURL(url);
                              } catch (e) {
                                console.error("Download error:", e);
                                alert("Failed to download remediation kit.");
                              }
                            }}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-semibold shadow-sm"
                          >
                            <Download className="w-4 h-4" />
                            Download Remediation Kit
                          </button>

                          <div className="text-center pl-4 border-l border-gray-200">
                            <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Status</p>
                            <span className={`mt-1 px-3 py-1 inline-flex text-sm leading-5 font-bold rounded-full ${scanResults[0].scc_info.status === 'ACTIVE' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                              }`}>
                              {scanResults[0].scc_info.status}
                            </span>
                          </div>
                          <div className="text-center pl-4 border-l border-gray-200">
                            <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Tier</p>
                            <span className="mt-1 block text-lg font-mono text-gray-900">
                              {scanResults[0].scc_info.tier}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="flex flex-col sm:flex-row justify-between items-center mb-4 gap-4">
                      <div className="flex items-center gap-3">
                        <h2 className="text-xl font-bold text-gray-900 border-l-4 border-blue-600 pl-3">Scan Results</h2>
                        <span className="bg-gray-100 text-gray-600 text-xs px-2 py-1 rounded-full font-medium">
                          {scanResults.length} Projects Scanned
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {/* Sorting Controls */}
                        <div className="flex items-center gap-2 mr-2 bg-gray-50 p-1 rounded-lg border border-gray-200 shadow-sm">
                          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider pl-2">Sort:</span>
                          <div className="relative">
                            <select
                              value={sortOption}
                              onChange={(e) => setSortOption(e.target.value as any)}
                              className="appearance-none bg-transparent border-none text-xs font-semibold text-gray-700 focus:ring-0 cursor-pointer py-1 pl-1 pr-6"
                            >
                              <option value="issues"># Issues</option>
                              <option value="name">Project Name</option>
                              <option value="billing">Billing ID</option>
                            </select>
                          </div>
                          <button
                            onClick={() => setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc')}
                            className="p-1 hover:bg-white rounded shadow-sm transition-all text-gray-600 w-6 h-6 flex items-center justify-center font-bold text-xs bg-white/50"
                            title={sortOrder === 'asc' ? "Ascending" : "Descending"}
                          >
                            {sortOrder === 'asc' ? '↑' : '↓'}
                          </button>
                        </div>

                        <div className="w-px h-6 bg-gray-200 mx-1"></div>

                        <button
                          onClick={() => {
                            // Expand all projects
                            setExpandedResults(new Set(scanResults.map(r => r.project_id)));
                          }}
                          className="px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-100 rounded border border-gray-200"
                        >
                          Expand All
                        </button>
                        <button
                          onClick={() => {
                            // Collapse all
                            setExpandedResults(new Set());
                          }}
                          className="px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-100 rounded border border-gray-200"
                        >
                          Collapse All
                        </button>
                        <div className="w-px h-6 bg-gray-200 mx-1"></div>
                        <button
                          onClick={() => setWorkflowStage('scan_configuration')}
                          className="px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-100 rounded-lg flex items-center gap-2 transition-colors"
                        >
                          <span>↺</span> New Scan
                        </button>

                        <button
                          onClick={() => setShowReport(true)}
                          className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg flex items-center gap-2 transition-colors shadow-sm"
                        >
                          <FileText className="w-4 h-4" /> Generate Report
                        </button>
                        <button
                          onClick={() => setShowFullReport(true)}
                          className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50 rounded-lg flex items-center gap-2 transition-colors shadow-sm"
                        >
                          <Download className="w-4 h-4" /> Export Data
                        </button>
                        <button
                          disabled={isDestroyingIdentity}
                          onClick={async () => {
                            if (!window.confirm("Are you sure you want to permanently delete this Scanner Identity? This will revoke all its access immediately.")) return;
                            setIsDestroyingIdentity(true);
                            try {
                              const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:8001';
                              await fetch(`${backendUrl}/api/session/stop`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                  domain: "cleanup",
                                  sa_email: activeScannerEmail,
                                  target_project_id: Array.from(selectedProjects)[0] || null
                                })
                              });
                              localStorage.removeItem('scanner_sa_email');
                              setScanResults([]);
                              setProjects([]);
                              setWorkflowStage('project_discovery');
                            } catch (e) {
                              console.error("Cleanup failed", e);
                              alert("Failed to destroy scanner identity.");
                            } finally {
                              setIsDestroyingIdentity(false);
                            }
                          }}
                          className={`px-4 py-2 text-sm font-medium text-red-600 bg-red-50 border border-red-200 hover:bg-red-100 rounded-lg flex items-center gap-2 transition-colors shadow-sm ${isDestroyingIdentity ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                          <Shield className="w-4 h-4" /> {isDestroyingIdentity ? 'Destroying...' : 'Destroy Identity'}
                        </button>
                      </div>
                    </div>

                    {/* PDF Report Modals */}
                    {showReport && (
                      <ReportingInterface
                        scanResults={scanResults}
                        jitToken={jitToken!}
                        onClose={() => setShowReport(false)}
                      />
                    )}

                    {showFullReport && (
                      <FullScanReport
                        scanResults={scanResults}
                        selectedModules={selectedModules}
                        onClose={() => setShowFullReport(false)}
                        modulesDef={scanMode === 'product' ? modules : solutionScans}
                        jitToken={jitToken!}
                      />
                    )}

                    <div className="space-y-4">
                      {[...scanResults]
                        .sort((a, b) => {
                          if (sortOption === 'issues') {
                            // Sort by total issues
                            const countA = (a.risks || []).length;
                            const countB = (b.risks || []).length;
                            if (countA !== countB) {
                              return sortOrder === 'asc' ? countA - countB : countB - countA;
                            }
                            // If issues count is same, fallback to name
                            return a.project_id.localeCompare(b.project_id);
                          } else if (sortOption === 'billing') {
                            // Sort by Billing Account ID
                            const idA = a.billing_info?.billing_account_id || '';
                            const idB = b.billing_info?.billing_account_id || '';

                            if (idA !== idB) {
                              return sortOrder === 'asc' ? idA.localeCompare(idB) : idB.localeCompare(idA);
                            }
                            return a.project_id.localeCompare(b.project_id);
                          } else {
                            // Sort by Name
                            const nameA = a.project_id.toLowerCase();
                            const nameB = b.project_id.toLowerCase();
                            if (nameA < nameB) return sortOrder === 'asc' ? -1 : 1;
                            if (nameA > nameB) return sortOrder === 'asc' ? 1 : -1;
                            return 0;
                          }
                        })
                        .map(res => {
                          const isProjectExpanded = expandedResults.has(res.project_id);

                          return (
                            <div key={res.project_id} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden transition-all duration-200 hover:shadow-md">
                              {/* Project Header */}
                              <div
                                className="p-5 flex items-center justify-between cursor-pointer hover:bg-gray-50 transition-colors select-none"
                                onClick={() => {
                                  const newSet = new Set(expandedResults);
                                  if (isProjectExpanded) newSet.delete(res.project_id);
                                  else newSet.add(res.project_id);
                                  setExpandedResults(newSet);
                                }}
                              >
                                <div className="flex items-center gap-5">
                                  <div className={`w-10 h-10 rounded-full flex items-center justify-center text-xl shrink-0 ${(res.risks || []).length > 0 ? 'bg-red-50 text-red-500' : 'bg-green-50 text-green-500'}`}>
                                    {(res.risks || []).length > 0 ? '⚠️' : '✓'}
                                  </div>
                                  <div>
                                    <h3 className="font-bold text-lg text-gray-900 leading-tight">{res.project_id}</h3>
                                    <div className="flex items-center gap-2 mt-1 flex-wrap">
                                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${(res.risks || []).length > 0 ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                                        {(res.risks || []).length} Issues Found
                                      </span>

                                      {res.billing_info?.billing_account_id ? (
                                        <span className="text-xs font-mono bg-gray-100 text-gray-600 px-2 py-0.5 rounded border border-gray-200 flex items-center gap-1" title="Billing Account ID">
                                          <span className="text-gray-400">$</span> {res.billing_info.billing_account_id}
                                        </span>
                                      ) : (
                                        <span className="text-xs font-medium text-gray-400 bg-gray-50 px-2 py-0.5 rounded border border-dashed border-gray-200" title="No Billing ID Associated with this Account">
                                          No Billing ID
                                        </span>
                                      )}

                                      <span className="text-xs text-gray-400 ml-1">
                                        Scanning {selectedModules.size} modules
                                      </span>
                                    </div>
                                  </div>
                                </div>
                                <div className={`text-gray-400 transform transition-transform duration-300 ${isProjectExpanded ? 'rotate-180' : ''}`}>
                                  ▼
                                </div>
                              </div>

                              {isProjectExpanded && (
                                <div className="border-t border-gray-100 bg-gray-50/50 p-4 space-y-3">

                                  {/* Inventory Summary (Phase 2 Data) */}
                                  {res.inventory_summary && (
                                    <div className="bg-white border border-blue-100 rounded-lg p-4 shadow-sm relative overflow-hidden">
                                      <div className="absolute top-0 right-0 p-2 opacity-5">
                                        <Server className="w-24 h-24" />
                                      </div>
                                      <h4 className="font-bold text-gray-900 mb-3 flex items-center gap-2 text-sm uppercase tracking-wide">
                                        <Server className="w-4 h-4 text-blue-600" /> Resource Inventory Snapshot
                                      </h4>
                                      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm relative z-10">
                                        <div className="bg-gray-50 p-2 rounded border border-gray-100">
                                          <span className="block text-gray-500 text-[10px] uppercase font-bold tracking-wider">Total Assets</span>
                                          <span className="font-mono text-lg font-bold text-gray-900">{res.inventory_summary.total_assets}</span>
                                        </div>
                                        <div className="bg-gray-50 p-2 rounded border border-gray-100">
                                          <span className="block text-gray-500 text-[10px] uppercase font-bold tracking-wider">Public IPs</span>
                                          <span className={`font-mono text-lg font-bold ${res.inventory_summary.public_ip_count > 0 ? 'text-orange-600' : 'text-green-600'}`}>
                                            {res.inventory_summary.public_ip_count}
                                          </span>
                                        </div>
                                        <div className="bg-gray-50 p-2 rounded border border-gray-100">
                                          <span className="block text-gray-500 text-[10px] uppercase font-bold tracking-wider">Storage Buckets</span>
                                          <span className="font-mono text-lg font-bold text-gray-900">{res.inventory_summary.storage_buckets}</span>
                                        </div>
                                        <div className="bg-gray-50 p-2 rounded border border-gray-100">
                                          <span className="block text-gray-500 text-[10px] uppercase font-bold tracking-wider">SQL Instances</span>
                                          <span className="font-mono text-lg font-bold text-gray-900">{res.inventory_summary.sql_instances}</span>
                                        </div>
                                        <div className="bg-gray-50 p-2 rounded border border-gray-100">
                                          <span className="block text-gray-500 text-[10px] uppercase font-bold tracking-wider">Firewall Rules</span>
                                          <span className="font-mono text-lg font-bold text-gray-900">{res.inventory_summary.firewall_rules}</span>
                                        </div>
                                      </div>
                                    </div>
                                  )}

                                  {(scanMode === 'product' ? modules : solutionScans).filter(m => selectedModules.has(m.id)).map(mod => {
                                    const subSectionId = `${res.project_id}-${mod.id}`;
                                    const isModuleExpanded = expandedSubSections.has(subSectionId);

                                    // Calculate risk count for this module (heuristic)
                                    const moduleRiskCount = (res.risks || []).filter(r => {
                                      if (mod.id === 'billing') return r.category === 'billing' || r.category === 'waste';
                                      return r.category === mod.id;
                                    }).length;

                                    return (
                                      <div key={mod.id} className="bg-white rounded-lg border border-gray-200 overflow-hidden">
                                        {/* Module Header */}
                                        <div
                                          className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-gray-50 transition-colors select-none"
                                          onClick={() => {
                                            const newSet = new Set(expandedSubSections);
                                            if (isModuleExpanded) newSet.delete(subSectionId);
                                            else newSet.add(subSectionId);
                                            setExpandedSubSections(newSet);
                                          }}
                                        >
                                          <div className="flex items-center gap-3">
                                            <span className="text-xl">{mod.icon}</span>
                                            <span className="font-medium text-gray-800">{mod.name}</span>
                                            {moduleRiskCount > 0 && (
                                              <span className="bg-red-100 text-red-700 text-xs px-2 py-0.5 rounded-full font-medium">
                                                {moduleRiskCount} Issues
                                              </span>
                                            )}
                                          </div>
                                          <div className={`text-gray-400 transform transition-transform duration-300 ${isModuleExpanded ? 'rotate-180' : ''}`}>
                                            ▼
                                          </div>
                                        </div>

                                        {/* Module Body */}
                                        {isModuleExpanded && (
                                          <div className="p-4 border-t border-gray-100">
                                            {renderModuleResult(res, mod.id)}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          );
                        })}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-24 bg-white rounded-xl shadow-sm border border-gray-100">
                    <div className="inline-block mb-4 p-4 bg-red-50 rounded-full">
                      <Shield className="w-12 h-12 text-red-500" />
                    </div>
                    <h3 className="text-xl font-bold text-gray-900 mb-2">Scan Failed or No Results</h3>
                    <p className="text-gray-500 max-w-md mx-auto mb-6">
                      The scan completed but did not return any data. This usually indicates that the backend encountered an error or the scanner service account lacked required permissions to access the target projects.
                    </p>
                    <ActionBtn onClick={() => setWorkflowStage('scan_configuration')} className="px-6 py-2">
                      Back to Configuration
                    </ActionBtn>
                  </div>
                )
              )}
          </div>
        </>
      )}
    </DefaultLayout>
  );
}
