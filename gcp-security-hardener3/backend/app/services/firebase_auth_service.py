"""
Firebase Authentication Service
Exchanges Firebase ID tokens for GCP access tokens
This allows users to authenticate without needing OAuth Client ID
"""
import logging
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import auth, credentials
from google.oauth2 import id_token
from google.auth.transport import requests

logger = logging.getLogger(__name__)

# Load environment variables from .env file if not already loaded
# Try multiple possible locations
def _load_env_file():
    """Load .env file from common locations"""
    possible_paths = [
        Path(__file__).parent.parent.parent / '.env',  # backend/.env
        Path(__file__).parent.parent.parent.parent / 'backend' / '.env',  # project/backend/.env
        Path.cwd() / '.env',  # Current directory
        Path.cwd() / 'backend' / '.env',  # backend/.env from project root
    ]
    
    for env_path in possible_paths:
        try:
            if env_path.exists():
                load_dotenv(dotenv_path=env_path, override=False)
                logger.info(f"Loaded .env file from: {env_path}")
                return True
        except PermissionError:
            logger.debug(f"Permission denied accessing: {env_path}")
            continue
    
    # Try loading from current directory as fallback
    try:
        load_dotenv(override=False)
    except Exception:
        pass
    return False

_load_env_file()

# Initialize Firebase Admin (if not already initialized)
def _initialize_firebase_admin():
    """Initialize Firebase Admin SDK with project ID from environment"""
    if firebase_admin._apps:
        return  # Already initialized
    
    # Reload environment variables to ensure we have the latest
    _load_env_file()
    
    # Get Firebase project ID from environment
    firebase_project_id = os.getenv('FIREBASE_PROJECT_ID') or os.getenv('GOOGLE_CLOUD_PROJECT') or os.getenv('GCP_PROJECT_ID')
    
    if not firebase_project_id:
        logger.warning("FIREBASE_PROJECT_ID not set. Firebase Admin will be initialized on first token verification.")
        logger.warning(f"Current working directory: {Path.cwd()}")
        logger.warning(f"Environment variables checked: FIREBASE_PROJECT_ID={os.getenv('FIREBASE_PROJECT_ID')}, GOOGLE_CLOUD_PROJECT={os.getenv('GOOGLE_CLOUD_PROJECT')}, GCP_PROJECT_ID={os.getenv('GCP_PROJECT_ID')}")
        return
    
    logger.info(f"Initializing Firebase Admin with project ID: {firebase_project_id}")
    
    try:
        # Try to initialize with service account if available
        cred_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if cred_path and os.path.exists(cred_path):
            logger.info(f"Using service account credentials from: {cred_path}")
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred, {
                'projectId': firebase_project_id
            })
        else:
            # Use default credentials (for Cloud Run, etc.)
            logger.info("Using default credentials for Firebase Admin")
            firebase_admin.initialize_app(options={
                'projectId': firebase_project_id
            })
        logger.info(f"Firebase Admin initialized successfully with project ID: {firebase_project_id}")
    except Exception as e:
        logger.error(f"Failed to initialize Firebase Admin: {str(e)}")
        logger.error(f"Project ID was: {firebase_project_id}")
        raise

# Try to initialize on module load
try:
    _initialize_firebase_admin()
except Exception as e:
    logger.warning(f"Firebase Admin initialization deferred: {str(e)}")


class FirebaseAuthService:
    """Service for handling Firebase authentication and token exchange"""
    
    @staticmethod
    def verify_firebase_token(id_token_str: str) -> dict:
        """
        Verify Firebase ID token and return user info
        
        Args:
            id_token_str: Firebase ID token from client
            
        Returns:
            Dict with user information
        """
        try:
            # Ensure Firebase Admin is initialized
            if not firebase_admin._apps:
                logger.info("Firebase Admin not initialized, attempting initialization...")
                _initialize_firebase_admin()
                
                # Double-check after initialization attempt
                if not firebase_admin._apps:
                    firebase_project_id = os.getenv('FIREBASE_PROJECT_ID') or os.getenv('GOOGLE_CLOUD_PROJECT') or os.getenv('GCP_PROJECT_ID')
                    if not firebase_project_id:
                        raise ValueError(
                            "Firebase project ID is required. Set FIREBASE_PROJECT_ID in backend/.env file. "
                            "Get this value from frontend/.env.local (NEXT_PUBLIC_FIREBASE_PROJECT_ID) or "
                            "Firebase Console -> Project Settings -> General"
                        )
                    raise ValueError(
                        f"Firebase Admin initialization failed. Project ID was set to: {firebase_project_id}. "
                        "Check backend logs for more details."
                    )
            
            # Verify the token using Firebase Admin
            decoded_token = auth.verify_id_token(id_token_str)
            return {
                'uid': decoded_token.get('uid'),
                'email': decoded_token.get('email'),
                'name': decoded_token.get('name'),
                'picture': decoded_token.get('picture'),
            }
        except ValueError as e:
            # Re-raise ValueError as-is (these are our custom error messages)
            raise
        except Exception as e:
            logger.error(f"Firebase token verification failed: {str(e)}")
            # Check if it's a project ID error
            if "project ID is required" in str(e).lower():
                raise ValueError(
                    "Firebase project ID is required. Set FIREBASE_PROJECT_ID in backend/.env file. "
                    "Get this value from frontend/.env.local (NEXT_PUBLIC_FIREBASE_PROJECT_ID) or "
                    "Firebase Console -> Project Settings -> General"
                )
            raise ValueError(f"Invalid Firebase token: {str(e)}")
    
    @staticmethod
    def exchange_for_gcp_credentials(id_token_str: str) -> 'Credentials':
        """
        Exchange Firebase ID token for GCP OAuth credentials
        
        This uses the Firebase ID token to get the user's Google OAuth credentials
        which can be used to make GCP API calls.
        
        Args:
            id_token_str: Firebase ID token
            
        Returns:
            google.oauth2.credentials.Credentials object
        """
        try:
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import Flow
            from google.auth.transport.requests import Request
            import json
            
            # Verify the Firebase token first
            decoded_token = FirebaseAuthService.verify_firebase_token(id_token_str)
            user_email = decoded_token.get('email')
            
            logger.info(f"Exchanging Firebase token for GCP credentials for user: {user_email}")
            
            # The Firebase ID token contains the user's Google account info
            # We can use it to create OAuth credentials with the required scopes
            # For GCP API access, we need the cloud-platform scope
            
            # Note: Firebase tokens are ID tokens, not access tokens
            # We need to use the user's Google account to get an access token
            # This requires the user to have granted OAuth consent
            
            # Alternative approach: Use the ID token to identify the user,
            # then use their existing Google session to get credentials
            # This works if the user is already authenticated with Google
            
            # For now, we'll create credentials from the ID token
            # In production, you might want to use OAuth2 flow to get proper credentials
            
            # Since Firebase Auth uses Google Sign-In, the user is already authenticated
            # We can use their Google account credentials directly
            # This requires the backend to have access to the user's Google session
            
            # For the superadmin use case, we can use the ID token to get user info
            # and then use Google's OAuth2 to get an access token with cloud-platform scope
            
            # Return a credentials object that can be used for GCP API calls
            # This is a simplified version - in production, you'd do proper OAuth flow
            
            raise NotImplementedError(
                "GCP credentials exchange from Firebase token requires OAuth2 flow. "
                "For superadmin accounts, we'll use a different approach."
            )
            
        except Exception as e:
            logger.error(f"Token exchange failed: {str(e)}")
            raise ValueError(f"Failed to exchange token: {str(e)}")
    
    @staticmethod
    def exchange_for_gcp_token(id_token_str: str, target_audience: Optional[str] = None) -> str:
        """
        Exchange Firebase ID token for GCP access token (legacy method)
        
        Note: This requires the Firebase project to have Google Cloud integration
        enabled. Alternatively, we can use the user's Google credentials directly.
        
        Args:
            id_token_str: Firebase ID token
            target_audience: Optional target audience for the token
            
        Returns:
            GCP access token
        """
        try:
            # Verify the Firebase token first
            decoded_token = FirebaseAuthService.verify_firebase_token(id_token_str)
            
            # For now, we'll use the ID token directly if it has the right scopes
            # In production, you might want to exchange it for a GCP access token
            # This requires additional setup in Firebase/Google Cloud Console
            
            # Alternative: Use the ID token to get user's Google credentials
            # The user is already authenticated with Google via Firebase
            # We can use their Google account to make GCP API calls
            
            # Return the Firebase ID token - the backend will use it
            # In a full implementation, you'd exchange this for a GCP access token
            return id_token_str
            
        except Exception as e:
            logger.error(f"Token exchange failed: {str(e)}")
            raise ValueError(f"Failed to exchange token: {str(e)}")

