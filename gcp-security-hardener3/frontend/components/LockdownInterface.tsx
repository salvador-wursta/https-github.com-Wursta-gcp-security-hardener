/**
 * Lockdown Interface Component
 * Allows user to select security profile and apply lockdown
 */
'use client';

import { useState, useEffect } from 'react';
import { SecurityProfile, LockdownRequest, LockdownResponse, MultiProjectLockdownRequest, MultiProjectLockdownResponse } from '@/lib/api';
import { getSecurityProfiles, applyLockdown, applyMultiProjectLockdown, downloadLockdownScript, downloadMultiProjectLockdownScript, uploadCredentials, planLockdown } from '@/lib/api';
import { Shield, Loader2, CheckCircle, AlertCircle, Download } from 'lucide-react';

interface LockdownInterfaceProps {
  projectId?: string; // Optional for single project
  projectIds?: string[]; // Optional for multiple projects
  accessToken: string;
  serviceAccountCredentials: any; // Service account key JSON
  wizardData: {
    region: string;
    budgetLimit: number;
    alertEmails: string[];
  };
  selectedRiskIds?: string[]; // List of risk IDs to fix
  credentialToken: string; // Secure token from credential upload
  budgetCap?: number; // Budget cap from scan results billing section
  onComplete: (response: LockdownResponse | MultiProjectLockdownResponse) => void;
  onError: (error: string) => void;
}

export default function LockdownInterface({
  projectId,
  projectIds,
  accessToken,
  serviceAccountCredentials,
  wizardData,
  selectedRiskIds = [],
  credentialToken,
  budgetCap,
  onComplete,
  onError,
}: LockdownInterfaceProps) {
  const isMultiProject = projectIds && projectIds.length > 0;
  const effectiveProjectId = projectId || (projectIds && projectIds.length === 1 ? projectIds[0] : '');
  const [profiles, setProfiles] = useState<SecurityProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>('');

  // Phase 7: Change Control States
  const [viewMode, setViewMode] = useState<'selection' | 'planning'>('selection');
  const [plannedSteps, setPlannedSteps] = useState<any[]>([]);
  const [selectedStepIds, setSelectedStepIds] = useState<string[]>([]);
  const [isAuthorized, setIsAuthorized] = useState(false);

  const [loading, setLoading] = useState(false);
  const [loadingProfiles, setLoadingProfiles] = useState(true);

  useEffect(() => {
    loadProfiles();
  }, []);

  const loadProfiles = async () => {
    try {
      const data = await getSecurityProfiles();

      if (!data || !Array.isArray(data)) {
        console.error("Invalid profiles data:", data);
        throw new Error("Received invalid profile data from server");
      }

      setProfiles(data);
      if (data.length > 0) {
        // Auto-select based on wizard data
        const usageProfile = wizardData.region; // This would come from wizard
        setSelectedProfile(data[0].id); // Default to first
      }
      setLoadingProfiles(false);
    } catch (error: any) {
      onError(error.message || 'Failed to load security profiles');
      setLoadingProfiles(false);
    }
  };

  const buildLockdownRequest = async (): Promise<LockdownRequest> => {
    if (!effectiveProjectId) {
      throw new Error('Project ID is required');
    }

    // Upload credentials and get secure token (if not already provided)
    let finalCredentialToken = credentialToken;

    if (!finalCredentialToken && serviceAccountCredentials) {
      console.log('[LockdownInterface] Uploading credentials to get secure token...');
      const response = await uploadCredentials(serviceAccountCredentials);
      finalCredentialToken = response.credential_token;
    } else if (!finalCredentialToken) {
      // No token and no credentials - this might be an issue unless we are using access_token for everything?
      // But the backend expects credential_token for most privileged ops.
      console.warn('[LockdownInterface] No credential token or service account credentials available.');
    }

    // Build request, converting empty strings to undefined
    const request: any = {
      project_id: effectiveProjectId,
      access_token: accessToken || '', // No Firebase token needed - using service account only
      security_profile: selectedProfile as any,
      credential_token: finalCredentialToken, // Use secure token instead of raw credentials
      selected_risk_ids: selectedRiskIds, // Only fix selected risks
      selected_step_ids: selectedStepIds.length > 0 ? selectedStepIds : undefined
    };

    // Only add optional fields if they have values
    if (wizardData?.region && wizardData.region.trim()) {
      request.region = wizardData.region;
    }
    // Use budgetCap from scan results if available, otherwise fall back to wizardData
    const effectiveBudget = budgetCap || wizardData?.budgetLimit;
    if (effectiveBudget && effectiveBudget > 0) {
      request.budget_limit = effectiveBudget;
    }
    if (wizardData?.alertEmails && wizardData.alertEmails.length > 0) {
      request.alert_emails = wizardData.alertEmails;
    }

    console.log('[LockdownInterface] Built request:', {
      ...request,
      credential_token: '***REDACTED***'
    });

    return request;
  };

  // Phase 7: Generate Plan
  const handleGeneratePlan = async () => {
    if (!selectedProfile) {
      onError('Please select a security profile');
      return;
    }

    setLoading(true);
    try {
      if (isMultiProject) {
        // For multi-project, we skip detailed planning per project for now 
        // and just show the standard list or warn user.
        // Or we could implement planMultiLockdown later.
        onError("Detailed planning is currently single-project only. Proceeding to direct application.");
        return;
      }

      // Single Project Plan
      // planLockdown imported at top
      const request = await buildLockdownRequest();

      // Clear step selection for initial plan generation to get default
      request.selected_step_ids = undefined;

      const plan = await planLockdown(request);
      setPlannedSteps(plan.steps);
      // Default all to selected
      setSelectedStepIds(plan.steps.map(s => s.step_id));
      setViewMode('planning');

    } catch (error: any) {
      onError(error.message || 'Failed to generate plan');
    } finally {
      setLoading(false);
    }
  };

  const toggleStep = (stepId: string) => {
    if (selectedStepIds.includes(stepId)) {
      setSelectedStepIds(selectedStepIds.filter(id => id !== stepId));
    } else {
      setSelectedStepIds([...selectedStepIds, stepId]);
    }
  };

  const handleDownloadScript = async () => {
    if (!selectedProfile) {
      onError('Please select a security profile first');
      return;
    }

    try {
      // Upload credentials and get secure token (if not already provided)
      let finalCredentialToken = credentialToken;

      if (!finalCredentialToken && serviceAccountCredentials) {
        console.log('[LockdownInterface] Uploading credentials for script download...');
        const response = await uploadCredentials(serviceAccountCredentials);
        finalCredentialToken = response.credential_token;
      }

      if (isMultiProject && projectIds) {
        // Multi-project script
        const request: any = {
          project_ids: projectIds,
          access_token: accessToken,
          security_profile: selectedProfile as any,
          credential_token: finalCredentialToken, // Use secure token
          selected_risk_ids: selectedRiskIds,
        };

        // Only add optional fields if they have values
        if (wizardData.region && wizardData.region.trim()) {
          request.region = wizardData.region;
        }
        // Use budgetCap from scan results if available, otherwise fall back to wizardData
        const effectiveBudget = budgetCap || wizardData.budgetLimit;
        if (effectiveBudget && effectiveBudget > 0) {
          request.budget_limit = effectiveBudget;
        }
        if (wizardData.alertEmails && wizardData.alertEmails.length > 0) {
          request.alert_emails = wizardData.alertEmails;
        }

        await downloadMultiProjectLockdownScript(request);
      } else if (effectiveProjectId) {
        // Single project script
        const request = await buildLockdownRequest();
        await downloadLockdownScript(request);
      } else {
        onError('No project ID(s) specified');
      }
    } catch (error: any) {
      onError(error.message || 'Failed to download script');
    }
  };

  const handleApplyLockdown = async () => {
    if (!selectedProfile) {
      onError('Please select a security profile');
      return;
    }

    // Phase 7: Enforcement check
    if (viewMode === 'planning' && !isAuthorized) {
      onError("You must confirm authorization before proceeding.");
      return;
    }

    setLoading(true);

    try {
      // Upload credentials and get secure token (if not already provided)
      let finalCredentialToken = credentialToken;

      if (!finalCredentialToken && serviceAccountCredentials) {
        console.log('[LockdownInterface] Uploading credentials for lockdown...');
        const response = await uploadCredentials(serviceAccountCredentials);
        finalCredentialToken = response.credential_token;
      }

      if (isMultiProject && projectIds) {
        // Multi-project lockdown
        const request: any = {
          project_ids: projectIds,
          access_token: accessToken,
          security_profile: selectedProfile as any,
          credential_token: finalCredentialToken, // Use secure token
          selected_risk_ids: selectedRiskIds,
        };

        // Only add optional fields if they have values
        if (wizardData.region && wizardData.region.trim()) {
          request.region = wizardData.region;
        }
        // Use budgetCap from scan results if available, otherwise fall back to wizardData
        const effectiveBudget = budgetCap || wizardData.budgetLimit;
        if (effectiveBudget && effectiveBudget > 0) {
          request.budget_limit = effectiveBudget;
        }
        if (wizardData.alertEmails && wizardData.alertEmails.length > 0) {
          request.alert_emails = wizardData.alertEmails;
        }

        console.log('[LockdownInterface] Multi-project request:', {
          ...request,
          credential_token: '***REDACTED***'
        });

        const response = await applyMultiProjectLockdown(request);
        onComplete(response);
      } else if (effectiveProjectId) {
        // Single project lockdown
        const request = await buildLockdownRequest();
        // Make sure selected steps are passed
        if (selectedStepIds.length > 0) {
          request.selected_step_ids = selectedStepIds;
        }

        const response = await applyLockdown(request);
        onComplete(response);
      } else {
        onError('No project ID(s) specified');
      }
    } catch (error: any) {
      onError(error.message || 'Failed to apply lockdown');
    } finally {
      setLoading(false);
    }
  };

  if (loadingProfiles) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="w-6 h-6 animate-spin text-primary-600" />
        <span className="ml-2 text-gray-600">Loading security profiles...</span>
      </div>
    );
  }

  // RENDER: Selecting Profile
  if (viewMode === 'selection') {
    return (
      <div className="space-y-6">
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">
            Choose Your Security Profile
          </h2>
          {isMultiProject && projectIds && (
            <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
              <p className="text-sm text-blue-800 font-semibold">
                Applying to {projectIds.length} project{projectIds.length !== 1 ? 's' : ''}: {projectIds.join(', ')}
              </p>
            </div>
          )}
          <p className="text-gray-600 mb-6">
            Select the security profile that best matches how you use Google Cloud.
            We'll customize the protections based on your choice.
          </p>

          <div className="space-y-4">
            {profiles.map((profile) => (
              <label
                key={profile.id}
                className={`block p-4 border-2 rounded-lg cursor-pointer transition-all ${selectedProfile === profile.id
                  ? 'border-primary-600 bg-primary-50'
                  : 'border-gray-200 hover:border-gray-300'
                  }`}
              >
                <input
                  type="radio"
                  name="securityProfile"
                  value={profile.id}
                  checked={selectedProfile === profile.id}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="sr-only"
                />
                <div className="font-semibold text-gray-900 mb-1">{profile.name}</div>
                <div className="text-sm text-gray-600 mb-3">{profile.description}</div>
                <div className="text-xs text-gray-500">
                  <div>Allows: {profile.allowed_apis.slice(0, 3).join(', ')}...</div>
                  <div>Blocks: {profile.denied_apis.slice(0, 2).join(', ')}...</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={handleDownloadScript}
            disabled={!selectedProfile || loading}
            className="flex-1 px-6 py-3 bg-gray-600 text-white rounded-lg font-medium hover:bg-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <Download className="w-5 h-5" />
            Download Script
          </button>
          <button
            onClick={isMultiProject ? handleApplyLockdown : handleGeneratePlan}
            disabled={!selectedProfile || loading}
            className="flex-1 px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Working...
              </>
            ) : (
              <>
                {isMultiProject ? (
                  <>
                    <Shield className="w-5 h-5" />Apply Security Settings
                  </>
                ) : (
                  <>Review Remediation Plan &rarr;</>
                )}
              </>
            )}
          </button>
        </div>
      </div>
    );
  }

  // RENDER: Change Control Plan
  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-gray-900">
            Change Control Plan
          </h2>
          <button
            onClick={() => setViewMode('selection')}
            className="text-gray-500 hover:text-gray-700 text-sm underline"
          >
            &larr; Back to Profiles
          </button>
        </div>

        <p className="text-gray-600 mb-6">
          Review the specific actions that will be performed. Uncheck any actions you wish to skip (not recommended).
        </p>

        <div className="space-y-3 mb-8">
          {plannedSteps.map((step) => (
            <div
              key={step.step_id}
              className={`p-4 border rounded-lg flex items-start gap-4 transition-colors ${selectedStepIds.includes(step.step_id) ? 'bg-white border-gray-300' : 'bg-gray-50 border-gray-200 opacity-75'
                }`}
            >
              <input
                type="checkbox"
                checked={selectedStepIds.includes(step.step_id)}
                onChange={() => toggleStep(step.step_id)}
                className="mt-1 w-5 h-5 text-primary-600 rounded border-gray-300 focus:ring-primary-500"
              />
              <div className="flex-1">
                <h3 className="font-semibold text-gray-900">{step.name}</h3>
                <p className="text-gray-600 text-sm mt-1">{step.description}</p>
                <div className="mt-2 text-xs text-blue-700 bg-blue-50 inline-block px-2 py-1 rounded">
                  <strong>Why:</strong> {step.security_benefit}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={isAuthorized}
              onChange={(e) => setIsAuthorized(e.target.checked)}
              className="mt-1 w-5 h-5 text-yellow-600 rounded border-yellow-300 focus:ring-yellow-500"
            />
            <div className="text-sm text-yellow-800">
              <strong>Authorization Required:</strong> I confirm that I am authorized to apply these security controls to project <code>{effectiveProjectId}</code>. I understand these changes may affect service availability if not properly configured.
            </div>
          </label>
        </div>

        <button
          onClick={handleApplyLockdown}
          disabled={!isAuthorized || loading || selectedStepIds.length === 0}
          className="w-full px-6 py-4 bg-primary-600 text-white rounded-lg font-bold text-lg hover:bg-primary-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg"
        >
          {loading ? (
            <>
              <Loader2 className="w-6 h-6 animate-spin" />
              Applying Approved Changes...
            </>
          ) : (
            <>
              <Shield className="w-6 h-6" />
              Execute Application
            </>
          )}
        </button>

      </div>
    </div>
  );
}

