/**
 * Firebase Authentication Component
 * Uses Firebase Auth (Google sign-in) - no OAuth Client ID needed!
 * This is much easier for users.
 */
'use client';

import { useState, useEffect } from 'react';
import { signInWithGoogle, signOut, getCurrentUser, getFirebaseIdToken, onAuthStateChange } from '@/lib/firebase-auth';
import { getGCPAccessToken } from '@/lib/gcp-oauth-browser';
import { Loader2, Shield, AlertCircle, CheckCircle2, LogOut } from 'lucide-react';

interface FirebaseAuthProps {
  onTokenReceived: (token: string) => void;
  onError: (error: string) => void;
}

export default function FirebaseAuth({ onTokenReceived, onError }: FirebaseAuthProps) {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    let hasCalledTokenReceived = false; // Prevent multiple calls
    
    // Listen to auth state changes
    const unsubscribe = onAuthStateChange(async (currentUser) => {
      setUser(currentUser);
      if (currentUser && !hasCalledTokenReceived) {
        hasCalledTokenReceived = true;
        console.log('[FirebaseAuth] User authenticated, getting tokens...');
        try {
          // Get both Firebase token (for verification) and GCP token (for API calls)
          const [firebaseToken, gcpToken] = await Promise.all([
            getFirebaseIdToken(),
            getGCPAccessToken().catch(() => ''), // GCP token is optional, will fallback to default creds
          ]);
          
          // Send both tokens - backend will use Firebase for verification and GCP for API calls
          // Format: "firebase_token|gcp_token" or just "firebase_token" if GCP token unavailable
          const combinedToken = gcpToken ? `${firebaseToken}|${gcpToken}` : firebaseToken;
          console.log('[FirebaseAuth] Tokens received, calling onTokenReceived...');
          onTokenReceived(combinedToken);
        } catch (err: any) {
          console.error('[FirebaseAuth] Error getting tokens:', err);
          onError(err.message);
        }
      } else if (!currentUser) {
        hasCalledTokenReceived = false; // Reset when user signs out
      }
    });

    return () => unsubscribe();
  }, [onTokenReceived, onError]);

  const handleSignIn = async () => {
    setLoading(true);
    setError('');

    try {
      await signInWithGoogle();
      // Auth state change will trigger token retrieval
    } catch (err: any) {
      const message = err.message || 'Sign in failed';
      setError(message);
      onError(message);
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut();
      setUser(null);
    } catch (err: any) {
      setError(err.message || 'Sign out failed');
    }
  };

  if (user) {
    return (
      <div className="p-6 bg-green-50 border border-green-200 rounded-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-6 h-6 text-green-600" />
            <div>
              <div className="font-semibold text-green-900">
                Signed in as {user.email}
              </div>
              <div className="text-sm text-green-700">
                Authenticated. Next, provide service account credentials to continue.
              </div>
            </div>
          </div>
          <button
            onClick={handleSignOut}
            className="flex items-center gap-2 px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 bg-red-50 border border-red-200 rounded-lg">
        <div className="flex items-center gap-3 mb-4">
          <AlertCircle className="w-6 h-6 text-red-600" />
          <div className="font-semibold text-red-900">Sign In Failed</div>
        </div>
        <p className="text-sm text-red-700 mb-4">{error}</p>
        <button
          onClick={handleSignIn}
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
            Sign in with Google
          </div>
          <div className="text-sm text-gray-600">
            Sign in to authenticate. You'll need to provide service account credentials next.
          </div>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-gray-600">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Signing in...</span>
        </div>
      ) : (
        <button
          onClick={handleSignIn}
          className="w-full px-6 py-3 bg-primary-600 text-white rounded-lg font-medium hover:bg-primary-700 transition-colors flex items-center justify-center gap-2"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24">
            <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Sign in with Google
        </button>
      )}

      <p className="mt-4 text-xs text-gray-500">
        Sign in to authenticate your identity. After signing in, you'll be asked to provide service account credentials with the required GCP roles to perform security scans and lockdown operations.
      </p>
    </div>
  );
}

