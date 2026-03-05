/**
 * Debug Panel Component
 * Shows debugging information in development
 */
'use client';

import { useState } from 'react';
import { Bug, X, ChevronDown, ChevronUp } from 'lucide-react';

interface DebugPanelProps {
  projectId?: string;
  hasToken?: boolean;
  currentStep?: string;
  error?: string;
}

export default function DebugPanel({ projectId, hasToken, currentStep, error }: DebugPanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);

  // Only show in development
  if (process.env.NODE_ENV === 'production') {
    return null;
  }

  // Capture console logs
  if (typeof window !== 'undefined') {
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;

    console.log = (...args) => {
      originalLog(...args);
      setLogs(prev => [...prev.slice(-49), `[LOG] ${args.join(' ')}`]);
    };

    console.error = (...args) => {
      originalError(...args);
      setLogs(prev => [...prev.slice(-49), `[ERROR] ${args.join(' ')}`]);
    };

    console.warn = (...args) => {
      originalWarn(...args);
      setLogs(prev => [...prev.slice(-49), `[WARN] ${args.join(' ')}`]);
    };
  }

  return (
    <div className="fixed bottom-4 right-4 z-50">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="bg-gray-800 text-white px-4 py-2 rounded-lg shadow-lg flex items-center gap-2 hover:bg-gray-700"
      >
        <Bug className="w-4 h-4" />
        Debug
        {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
      </button>

      {isOpen && (
        <div className="absolute bottom-12 right-0 w-96 bg-white border border-gray-200 rounded-lg shadow-xl max-h-96 overflow-auto">
          <div className="p-4 border-b border-gray-200 flex items-center justify-between">
            <h3 className="font-semibold text-gray-900">Debug Information</h3>
            <button
              onClick={() => setIsOpen(false)}
              className="text-gray-500 hover:text-gray-700"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-4 space-y-2">
            <div>
              <strong>Current Step:</strong> {currentStep || 'unknown'}
            </div>
            <div>
              <strong>Project ID:</strong> {projectId || 'Not set'}
            </div>
            <div>
              <strong>Token:</strong> {hasToken ? '✅ Present' : '❌ Missing'}
            </div>
            {error && (
              <div className="text-red-600">
                <strong>Error:</strong> {error}
              </div>
            )}
          </div>

          <div className="p-4 border-t border-gray-200">
            <div className="text-xs font-semibold text-gray-700 mb-2">Recent Logs:</div>
            <div className="space-y-1 text-xs font-mono bg-gray-50 p-2 rounded max-h-48 overflow-auto">
              {logs.length === 0 ? (
                <div className="text-gray-500">No logs yet...</div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className={log.includes('[ERROR]') ? 'text-red-600' : log.includes('[WARN]') ? 'text-yellow-600' : 'text-gray-700'}>
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="p-4 border-t border-gray-200">
            <button
              onClick={() => {
                console.clear();
                setLogs([]);
              }}
              className="text-xs text-gray-600 hover:text-gray-800"
            >
              Clear Logs
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

