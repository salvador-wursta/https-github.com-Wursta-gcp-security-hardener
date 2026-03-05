/**
 * OAuth Flow Component
 * Handles Google Cloud Platform OAuth authentication
 * Uses incremental auth - starts with read-only, escalates to write when needed
 */
'use client';

import { useState, useEffect } from 'react';
import { requestOAuthToken, requestEscalatedPermissions } from '@/lib/oauth';
import { Loader2, Shield, AlertCircle, CheckCircle2 } from 'lucide-react';

interface OAuthFlowProps {
  clientId: string;
  onTokenReceived: (token: string, scope: string) => void;
  onError: (error: string) => void;
  requireWriteAccess?: boolean;
}

export default function OAuthFlow({
  clientId,
  onTokenReceived,
  onError,
  requireWriteAccess = false,
}: OAuthFlowProps) {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [scope, setScope] = useState<string>('read-only');

  useEffect(() => {
    // Load Google Identity Services script
    if (typeof window !== 'undefined' && !window.google) {
      const script = document.createElement('script');
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      script.onload = () => {
        console.log('Google Identity Services loaded');
      };
      document.head.appendChild(script);
    }
  }, []);

  const handleAuth = async () => {
    // Validate Client ID first
    if (!clientId || clientId === '' || clientId.includes('your_google_oauth_client_id')) {
      setStatus('error');
      const message = 'OAuth Client ID not configured. Please set NEXT_PUBLIC_GOOGLE_CLIENT_ID in .env.local';
      setErrorMessage(message);
      onError(message);
      return;
    }

    // Validate Client ID format
    if (!clientId.includes('.apps.googleusercontent.com')) {
      setStatus('error');
      const message = 'Invalid Client ID format. Should end with .apps.googleusercontent.com';
      setErrorMessage(message);
      onError(message);
      return;
    }

    setStatus('loading');
    setErrorMessage('');

    // Wait for Google Identity Services to load
    if (!window.google?.accounts) {
      await new Promise((resolve) => {
        const checkGoogle = setInterval(() => {
          if (window.google?.accounts) {
            clearInterval(checkGoogle);
            resolve(true);
          }
        }, 100);
        // Timeout after 5 seconds
        setTimeout(() => {
          clearInterval(checkGoogle);
          resolve(false);
        }, 5000);
      });
    }

    if (!window.google?.accounts) {
      setStatus('error');
      const message = 'Failed to load Google Identity Services. Please check your internet connection.';
      setErrorMessage(message);
      onError(message);
      return;
    }

    try {
      let token: string;
      let tokenScope: string;

      if (requireWriteAccess) {
        // Request full cloud-platform access
        token = await requestEscalatedPermissions(clientId);
        tokenScope = 'full';
      } else {
        // Start with read-only access
        token = await requestOAuthToken(clientId);
        tokenScope = 'read-only';
      }

      setScope(tokenScope);
      setStatus('success');
      onTokenReceived(token, tokenScope);
    } catch (error: any) {
      setStatus('error');
      let message = error.message || 'Authentication failed';
      
      // Provide helpful error messages
      if (message.includes('invalid_client') || message.includes('401')) {
        message = 'Invalid OAuth Client ID. Please check:\n' +
                  '1. Client ID is correct in .env.local\n' +
                  '2. Client ID is for "Web application" type\n' +
                  '3. http://localhost:3000 is in authorized origins\n' +
                  '4. OAuth consent screen is configured';
      } else if (message.includes('access_denied')) {
        message = 'Access denied. Please check:\n' +
                  '1. OAuth consent screen is configured\n' +
                  '2. Your email is in test users (if app is in testing mode)';
      } else if (message.includes('redirect_uri_mismatch')) {
        message = 'Redirect URI mismatch. Please add http://localhost:3000 to authorized redirect URIs in Google Cloud Console';
      }
      
      setErrorMessage(message);
      onError(message);
    }
  };

  const handleEscalate = async () => {
    setStatus('loading');
    setErrorMessage('');

    try {
      const token = await requestEscalatedPermissions(clientId);
      setScope('full');
      setStatus('success');
      onTokenReceived(token, 'full');
    } catch (error: any) {
      setStatus('error');
      const message = error.message || 'Failed to escalate permissions';
      setErrorMessage(message);
      onError(message);
    }
  };

  if (status === 'success') {
    return (
      <div className="p-6 bg-green-50 border border-green-200 rounded-lg">
        <div className="flex items-center gap-3">
          <CheckCircle2 className="w-6 h-6 text-green-600" />
          <div>
            <div className="font-semibold text-green-900">
              Connected to Google Cloud
            </div>
            <div className="text-sm text-green-700">
              Access level: {scope === 'read-only' ? 'Read-only (for scanning)' : 'Full access (for securing)'}
            </div>
          </div>
        </div>
        {scope === 'read-only' && requireWriteAccess && (
          <button
            onClick={handleEscalate}
            className="mt-4 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
          >
            Grant Full Access (Required for Securing)
          </button>
        )}
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="p-6 bg-red-50 border border-red-200 rounded-lg">
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="w-6 h-6 text-red-600" />
          <div className="font-semibold text-red-900">Authentication Failed</div>
        </div>
        <p className="text-sm text-red-700 mb-4">{errorMessage}</p>
        <button
          onClick={handleAuth}
          className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="p-6 bg-white border border-gray-200 rounded-lg">
      <div className="flex items-center gap-3 mb-4">
        <Shield className="w-6 h-6 text-primary-600" />
        <div>
          <div className="font-semibold text-gray-900">
            Connect Your Google Cloud Account
          </div>
          <div className="text-sm text-gray-600">
            We need permission to scan your cloud for security risks.
            {requireWriteAccess && ' Full access required to apply security settings.'}
          </div>
        </div>
      </div>

      {status === 'loading' ? (
        <div className="flex items-center gap-3 text-gray-600">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Connecting to Google Cloud...</span>
        </div>
      ) : (
        <button
          onClick={handleAuth}
          className="w-full px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors"
        >
          Connect Google Cloud Account
        </button>
      )}

      <p className="mt-4 text-xs text-gray-500">
        We'll only access what we need to secure your cloud. You can revoke access at any time.
      </p>
    </div>
  );
}

