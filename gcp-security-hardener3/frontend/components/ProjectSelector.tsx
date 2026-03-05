/**
 * Project Selector Component
 * Allows users to select which projects to apply security changes to
 */
'use client';

import { useState, useEffect } from 'react';
import { ScanResponse } from '@/lib/api';
import { CheckCircle, XCircle, AlertTriangle, Shield } from 'lucide-react';

interface ProjectSelectorProps {
  scanResults: ScanResponse[];
  onProjectsSelected: (selectedProjectIds: string[]) => void;
  onCancel?: () => void;
}

export default function ProjectSelector({ 
  scanResults, 
  onProjectsSelected,
  onCancel 
}: ProjectSelectorProps) {
  const [selectedProjects, setSelectedProjects] = useState<Set<string>>(new Set());
  
  // Select all projects by default
  useEffect(() => {
    const allProjectIds = new Set(scanResults.map(r => r.project_id));
    setSelectedProjects(allProjectIds);
  }, [scanResults]);
  
  const toggleProject = (projectId: string) => {
    setSelectedProjects(prev => {
      const next = new Set(prev);
      if (next.has(projectId)) {
        next.delete(projectId);
      } else {
        next.add(projectId);
      }
      return next;
    });
  };
  
  const selectAll = () => {
    const allProjectIds = new Set(scanResults.map(r => r.project_id));
    setSelectedProjects(allProjectIds);
  };
  
  const deselectAll = () => {
    setSelectedProjects(new Set());
  };
  
  const handleContinue = () => {
    if (selectedProjects.size === 0) {
      alert('Please select at least one project to apply security changes.');
      return;
    }
    onProjectsSelected(Array.from(selectedProjects));
  };
  
  const getTotalRisks = (projectId: string) => {
    const result = scanResults.find(r => r.project_id === projectId);
    return result?.summary.total || 0;
  };
  
  const getRiskLevel = (projectId: string) => {
    const result = scanResults.find(r => r.project_id === projectId);
    if (!result) return 'none';
    if (result.summary.critical > 0) return 'critical';
    if (result.summary.high > 0) return 'high';
    if (result.summary.medium > 0) return 'medium';
    return 'low';
  };
  
  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'bg-red-50 border-red-200';
      case 'high':
        return 'bg-orange-50 border-orange-200';
      case 'medium':
        return 'bg-yellow-50 border-yellow-200';
      case 'low':
        return 'bg-blue-50 border-blue-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };
  
  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">Select Projects to Secure</h2>
        <p className="text-gray-600 mb-6">
          Choose which projects you want to apply security changes to. Only selected projects will be included in the lockdown and backout scripts.
        </p>
        
        <div className="flex items-center justify-between mb-4">
          <div className="text-sm text-gray-600">
            {selectedProjects.size} of {scanResults.length} projects selected
          </div>
          <div className="flex gap-2">
            <button
              onClick={selectAll}
              className="px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors"
            >
              Select All
            </button>
            <button
              onClick={deselectAll}
              className="px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors"
            >
              Deselect All
            </button>
          </div>
        </div>
        
        <div className="space-y-3">
          {scanResults.map((result) => {
            const isSelected = selectedProjects.has(result.project_id);
            const riskLevel = getRiskLevel(result.project_id);
            const totalRisks = getTotalRisks(result.project_id);
            
            return (
              <div
                key={result.project_id}
                className={`border-2 rounded-lg p-4 cursor-pointer transition-all ${
                  isSelected 
                    ? `${getRiskColor(riskLevel)} ring-2 ring-primary-500` 
                    : 'border-gray-200 hover:border-gray-300'
                }`}
                onClick={() => toggleProject(result.project_id)}
              >
                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 pt-1">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleProject(result.project_id)}
                      onClick={(e) => e.stopPropagation()}
                      className="w-5 h-5 text-primary-600 border-gray-300 rounded focus:ring-primary-500 cursor-pointer"
                    />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-lg font-bold text-gray-900">{result.project_id}</h3>
                      {totalRisks > 0 && (
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          riskLevel === 'critical' ? 'bg-red-100 text-red-800' :
                          riskLevel === 'high' ? 'bg-orange-100 text-orange-800' :
                          riskLevel === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-blue-100 text-blue-800'
                        }`}>
                          {totalRisks} {totalRisks === 1 ? 'risk' : 'risks'}
                        </span>
                      )}
                      {totalRisks === 0 && (
                        <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-semibold">
                          <CheckCircle className="w-3 h-3 inline mr-1" />
                          No risks
                        </span>
                      )}
                    </div>
                    <div className="grid grid-cols-4 gap-2 text-xs">
                      {result.summary.critical > 0 && (
                        <div className="text-red-700">
                          <AlertTriangle className="w-3 h-3 inline mr-1" />
                          {result.summary.critical} Critical
                        </div>
                      )}
                      {result.summary.high > 0 && (
                        <div className="text-orange-700">
                          {result.summary.high} High
                        </div>
                      )}
                      {result.summary.medium > 0 && (
                        <div className="text-yellow-700">
                          {result.summary.medium} Medium
                        </div>
                      )}
                      {result.summary.low > 0 && (
                        <div className="text-blue-700">
                          {result.summary.low} Low
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
      
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">Ready to Apply Security Changes?</h3>
            <p className="text-gray-600 mb-2">
              Security changes will be applied to {selectedProjects.size} selected project{selectedProjects.size !== 1 ? 's' : ''}.
            </p>
            {selectedProjects.size === 0 && (
              <p className="text-sm text-orange-600 font-medium">
                ⚠️ Please select at least one project to continue.
              </p>
            )}
          </div>
          <div className="flex gap-3">
            {onCancel && (
              <button
                onClick={onCancel}
                className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
              >
                Cancel
              </button>
            )}
            <button
              onClick={handleContinue}
              disabled={selectedProjects.size === 0}
              className="px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors flex items-center gap-2 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              <Shield className="w-5 h-5" />
              Continue with {selectedProjects.size} Project{selectedProjects.size !== 1 ? 's' : ''}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
