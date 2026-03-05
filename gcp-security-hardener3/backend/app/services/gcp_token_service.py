"""
GCP Token Service
Handles getting GCP access tokens from Firebase Auth or user credentials
"""
import logging
from typing import Optional
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import os

logger = logging.getLogger(__name__)


class GCPTokenService:
    """Service for obtaining GCP access tokens"""
    
    @staticmethod
    def get_token_from_firebase_user(firebase_id_token: str, project_id: str) -> str:
        """
        Get GCP access token from Firebase-authenticated user
        
        Note: This requires the user to have granted GCP access.
        We'll use a service account approach or direct OAuth flow.
        
        For now, we'll use the Firebase token to identify the user,
        then request GCP OAuth token using their Google account.
        """
        # In production, you would:
        # 1. Verify Firebase token
        # 2. Extract user's Google account
        # 3. Use that account to request GCP OAuth token
        # 4. Return GCP access token
        
        # For MVP, we can use a service account approach:
        # The backend has a service account that makes calls on behalf of users
        # Users just need to grant the service account access to their projects
        
        # Alternative: Use Application Default Credentials if available
        # This works if the backend is running in GCP with proper IAM
        
        return firebase_id_token  # Placeholder - will be replaced with actual GCP token
    
    @staticmethod
    def use_service_account_approach() -> bool:
        """
        Check if we should use service account approach
        
        This is better for clients who don't want to set up OAuth.
        The backend uses a service account to make GCP API calls.
        """
        service_account_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        return service_account_path is not None and os.path.exists(service_account_path)

