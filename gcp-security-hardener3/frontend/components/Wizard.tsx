/**
 * Needs Assessment Wizard - Phase 2, Step 1
 * Multi-step wizard to gather security policy variables
 * "Explain Like I'm 5" - all text is user-friendly
 */
'use client';

import { useState } from 'react';
import { ChevronRight, ChevronLeft, Shield, AlertTriangle } from 'lucide-react';

export interface WizardData {
  organizationId: string;
  region: string;
  alertEmails: string[];
  finOpsConcern: boolean;
}

interface WizardProps {
  onComplete: (data: WizardData) => void;
}

export default function Wizard({ onComplete }: WizardProps) {
  const [currentStep, setCurrentStep] = useState(1);
  const [data, setData] = useState<WizardData>({
    organizationId: '',
    region: 'us-central1',
    alertEmails: [],
    finOpsConcern: false,
  });

  const totalSteps = 3;

  const handleNext = () => {
    if (currentStep < totalSteps) {
      setCurrentStep(currentStep + 1);
    } else {
      onComplete(data);
    }
  };

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const updateData = (field: keyof WizardData, value: any) => {
    setData({ ...data, [field]: value });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg p-8 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-primary-600" />
            <h1 className="text-3xl font-bold text-gray-900">
              Let's Secure Your Cloud
            </h1>
          </div>
          <p className="text-lg text-gray-600">
            We'll ask you a few simple questions to customize your security settings.
            This will only take a minute!
          </p>
        </div>

        {/* Progress Bar */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm font-medium text-gray-700">
              Step {currentStep} of {totalSteps}
            </span>
            <span className="text-sm text-gray-500">
              {Math.round((currentStep / totalSteps) * 100)}% Complete
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className="bg-primary-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${(currentStep / totalSteps) * 100}%` }}
            />
          </div>
        </div>

        {/* Step Content */}
        <div className="bg-white rounded-lg shadow-lg p-8 h-[350px] flex flex-col">
          <div className="flex-1 overflow-auto">
            {currentStep === 1 && (
              <Step1
                value={data.alertEmails}
                onChange={(value) => updateData('alertEmails', value)}
              />
            )}
            {currentStep === 2 && (
              <Step2
                value={data.region}
                onChange={(value) => updateData('region', value)}
              />
            )}
            {currentStep === 3 && (
              <Step3
                value={data.finOpsConcern}
                onChange={(value) => updateData('finOpsConcern', value)}
              />
            )}
          </div>

          {/* Navigation Buttons */}
          <div className="flex justify-end gap-3 mt-6 pt-6 border-t border-gray-200">
            {currentStep > 1 && (
              <button
                onClick={handleBack}
                className="flex items-center gap-2 px-6 py-3 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
              >
                <ChevronLeft className="w-5 h-5" />
                Back
              </button>
            )}
            <button
              onClick={handleNext}
              className="flex items-center gap-2 px-8 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors min-w-[200px] justify-center"
            >
              {currentStep === totalSteps ? 'Complete' : 'Next'}
              {currentStep < totalSteps && <ChevronRight className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Step 0: Organization ID (for org-level monitoring)
function Step0({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-4">
        What's your Google Cloud Organization ID?
      </h2>
      <p className="text-gray-600 mb-4">
        Enter your GCP Organization ID to enable organization-wide security monitoring.
        This allows us to monitor ALL projects in your organization from one central location.
      </p>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="123456789012"
        className="w-full p-4 border-2 border-gray-200 rounded-lg text-gray-900 focus:border-primary-600 focus:outline-none font-mono"
      />
      <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
        <p className="text-sm text-blue-800">
          <strong>How to find your Organization ID:</strong>
        </p>
        <p className="text-sm text-blue-700 mt-1">
          Run: <code className="bg-blue-100 px-1 rounded">gcloud organizations list</code>
        </p>
        <p className="text-xs text-blue-600 mt-2">
          Leave blank if you only want project-level monitoring.
        </p>
      </div>
    </div>
  );
}

// Step 1: Alert Emails
function Step1({ value, onChange }: { value: string[]; onChange: (value: string[]) => void }) {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // Split by comma, validation happens later or in backend
    const emails = e.target.value.split(',').map(s => s.trim());
    onChange(emails);
  };

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-4">
        Who should we alert if something goes wrong?
      </h2>
      <p className="text-gray-600 mb-6">
        Enter email addresses separated by commas (e.g., admin@company.com, security@company.com).
        We'll verify these emails before sending alerts.
      </p>
      <input
        type="text"
        value={value.join(', ')}
        onChange={handleChange}
        placeholder="admin@yourcompany.com, security@yourcompany.com"
        className="w-full p-4 border-2 border-gray-200 rounded-lg text-gray-900 focus:border-primary-600 focus:outline-none"
      />
      <p className="mt-2 text-sm text-gray-500">
        These contacts will receive high-priority security notifications.
      </p>
    </div>
  );
}

// Step 2: Region (moved from old Step 2)
function Step2({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const regions = [
    { id: 'us-central1', name: 'United States (Iowa)' },
    { id: 'us-east1', name: 'United States (South Carolina)' },
    { id: 'us-west1', name: 'United States (Oregon)' },
    { id: 'europe-west1', name: 'Europe (Belgium)' },
    { id: 'europe-west4', name: 'Europe (Netherlands)' },
    { id: 'asia-east1', name: 'Asia (Taiwan)' },
    { id: 'asia-southeast1', name: 'Asia (Singapore)' },
  ];

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-4">
        Where is your business located?
      </h2>
      <p className="text-gray-600 mb-6">
        We'll lock down your cloud to only allow resources in this region. This helps with security and compliance.
      </p>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full p-4 border-2 border-gray-200 rounded-lg text-gray-900 focus:border-primary-600 focus:outline-none"
      >
        {regions.map((region) => (
          <option key={region.id} value={region.id}>
            {region.name}
          </option>
        ))}
      </select>
    </div>
  );
}

// Step 3: FinOps Concern (moved from old Step 5)
function Step3({
  value,
  onChange,
}: {
  value: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-3">
        Are you worried about unexpected costs?
      </h2>
      <p className="text-gray-600 mb-4">
        If you're seeing unexpected charges or want help understanding your cloud costs, we can connect you with our team.
      </p>
      <div className="grid grid-cols-2 gap-3">
        <label className="flex items-center gap-3 p-3 border-2 border-gray-200 rounded-lg cursor-pointer hover:border-gray-300 transition-all">
          <input
            type="radio"
            name="finOpsConcern"
            checked={!value}
            onChange={() => onChange(false)}
            className="w-4 h-4 text-primary-600"
          />
          <div>
            <div className="font-semibold text-gray-900">No, we're good</div>
            <div className="text-sm text-gray-600">Our costs are under control.</div>
          </div>
        </label>
        <label className="flex items-center gap-3 p-3 border-2 border-gray-200 rounded-lg cursor-pointer hover:border-gray-300 transition-all">
          <input
            type="radio"
            name="finOpsConcern"
            checked={value}
            onChange={() => onChange(true)}
            className="w-4 h-4 text-primary-600"
          />
          <div>
            <div className="font-semibold text-gray-900">Yes, help me control spending</div>
          </div>
        </label>
      </div>
    </div>
  );
}

