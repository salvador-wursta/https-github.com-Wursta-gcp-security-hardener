"""
API endpoints for initial setup and service account creation
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from pathlib import Path
from app.services.firebase_auth_service import FirebaseAuthService
from app.services.service_account_service import ServiceAccountService
from app.services.user_privilege_service import UserPrivilegeService
from google.oauth2.credentials import Credentials
from google.auth import default as default_credentials
import logging
import os
import json
import traceback

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/setup", tags=["setup"])


class SetupRequest(BaseModel):
    """Request to set up bootstrap service account"""
    project_id: str = Field(..., description="GCP Project ID")
    access_token: str = Field(..., description="Firebase ID token (for verification) or GCP OAuth token")
    organization_id: Optional[str] = Field(None, description="GCP Organization ID (optional)")


class SetupResponse(BaseModel):
    """Response from setup operation"""
    success: bool
    service_account_email: str
    service_account_key: dict
    message: str
    instructions: str


@router.post("/bootstrap", response_model=SetupResponse)
async def setup_bootstrap_service_account(request: SetupRequest):
    """
    Automatically create bootstrap service account using user's credentials
    
    This endpoint:
    1. Verifies the user is authenticated
    2. Uses user's credentials to create a bootstrap service account
    3. Grants necessary roles
    4. Creates and returns the service account key
    """
    try:
        # Parse access token - may contain both Firebase and GCP tokens
        access_token_parts = request.access_token.split('|', 1)
        firebase_token = access_token_parts[0]
        gcp_token = access_token_parts[1] if len(access_token_parts) > 1 else None
        
        # Verify Firebase token
        logger.info("Verifying user authentication...")
        try:
            user_info = FirebaseAuthService.verify_firebase_token(firebase_token)
            user_email = user_info.get('email', 'unknown')
            logger.info(f"User verified: {user_email}")
        except Exception as auth_error:
            logger.error(f"Authentication failed: {str(auth_error)}")
            raise HTTPException(
                status_code=401,
                detail=f"Authentication failed: {str(auth_error)}"
            )
        
        # Get user credentials for creating service account
        user_credentials = None
        
        # Try GCP OAuth token first
        if gcp_token:
            logger.info("Using GCP OAuth token from browser")
            try:
                user_credentials = Credentials(token=gcp_token)
                from google.auth.transport.requests import Request
                user_credentials.refresh(Request())
                logger.info("Successfully created credentials from GCP OAuth token")
            except Exception as token_error:
                logger.warning(f"Could not use GCP OAuth token: {str(token_error)}")
        
        # Fallback to default credentials
        if not user_credentials:
            logger.info("Trying default credentials (from gcloud auth application-default login)")
            try:
                user_credentials, detected_project = default_credentials()
                logger.info(f"Successfully loaded default credentials")
                logger.info(f"Detected project: {detected_project}")
                
                # Verify credentials work by getting user info
                try:
                    from googleapiclient.discovery import build
                    oauth2 = build('oauth2', 'v2', credentials=user_credentials)
                    user_info_gcp = oauth2.userinfo().get().execute()
                    logger.info(f"Credentials verified for user: {user_info_gcp.get('email')}")
                except Exception as verify_error:
                    logger.warning(f"Could not verify credentials: {str(verify_error)}")
                    # Continue anyway - credentials might still work
                    
            except Exception as default_error:
                logger.error(f"Could not load default credentials: {str(default_error)}")
                logger.error(f"Error type: {type(default_error).__name__}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                
                # Check if credentials file exists
                creds_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
                creds_exist = os.path.exists(creds_path)
                logger.info(f"Credentials file exists: {creds_exist} at {creds_path}")
                
                # Provide more helpful error message
                error_detail = (
                    f"Could not load default credentials. Error: {str(default_error)}\n\n"
                    f"Credentials file exists: {creds_exist}\n"
                    f"Expected location: {creds_path}\n\n"
                    "⚠️ IMPORTANT: After running 'gcloud auth application-default login', you MUST restart your backend server!\n\n"
                    "Troubleshooting:\n"
                    "1. Verify gcloud auth worked: gcloud auth application-default print-access-token\n"
                    "2. Check credentials file exists: ls -la ~/.config/gcloud/application_default_credentials.json\n"
                    "3. ⚠️ RESTART BACKEND: Stop and restart your backend server\n"
                    "4. Try: gcloud auth application-default login --no-launch-browser\n\n"
                    f"Full error: {str(default_error)}"
                )
                raise HTTPException(
                    status_code=400,
                    detail=error_detail
                )
        
        # Grant temporary privileges to user account
        logger.info("Granting temporary privileges to create service account...")
        privilege_service = None
        try:
            privilege_service = UserPrivilegeService(
                project_id=request.project_id,
                user_credentials=user_credentials
            )
            privilege_info = privilege_service.grant_privileges()
            logger.info(f"Granted privileges: {privilege_info['granted_roles']}")
        except Exception as grant_error:
            logger.warning(f"Could not grant privileges: {str(grant_error)}")
            logger.warning(f"Error type: {type(grant_error).__name__}")
            logger.warning(f"Traceback: {traceback.format_exc()}")
            
            # Check if user already has permissions
            logger.info("User may already have the necessary permissions, continuing...")
            # Continue - user might already have the necessary permissions
        
        # Create bootstrap service account
        logger.info("Creating bootstrap service account...")
        logger.info(f"Using project ID: {request.project_id}")
        logger.info(f"User email: {user_email}")
        
        try:
            sa_service = ServiceAccountService(
                project_id=request.project_id,
                credentials=user_credentials
            )
            
            logger.info("ServiceAccountService initialized, creating service account...")
            
            # Create the bootstrap service account
            sa_info = sa_service.create_temp_service_account(
                user_email=f"bootstrap-{user_email}"
            )
            
            logger.info(f"Bootstrap service account created successfully: {sa_info['email']}")
            
            # Automatically save the key file
            backend_dir = Path(__file__).parent.parent.parent
            key_file_path = backend_dir / 'bootstrap-service-account.json'
            
            try:
                # Save the key file
                with open(key_file_path, 'w') as f:
                    json.dump(sa_info['key'], f, indent=2)
                
                # Set secure permissions (read/write for owner only)
                os.chmod(key_file_path, 0o600)
                
                logger.info(f"Service account key saved to: {key_file_path}")
                
                # Update .env file automatically
                env_file_path = backend_dir / '.env'
                env_updated = False
                
                if env_file_path.exists():
                    # Read existing .env file
                    with open(env_file_path, 'r') as f:
                        env_lines = f.readlines()
                    
                    # Check if GOOGLE_APPLICATION_CREDENTIALS already exists
                    creds_line_index = None
                    for i, line in enumerate(env_lines):
                        if line.strip().startswith('GOOGLE_APPLICATION_CREDENTIALS='):
                            creds_line_index = i
                            break
                    
                    # Update or add the line
                    creds_line = f"GOOGLE_APPLICATION_CREDENTIALS={key_file_path}\n"
                    
                    if creds_line_index is not None:
                        # Update existing line
                        env_lines[creds_line_index] = creds_line
                    else:
                        # Add new line (add after Firebase config if it exists, otherwise at the top)
                        firebase_index = None
                        for i, line in enumerate(env_lines):
                            if 'FIREBASE_PROJECT_ID' in line:
                                firebase_index = i
                                break
                        
                        if firebase_index is not None:
                            env_lines.insert(firebase_index + 1, creds_line)
                        else:
                            env_lines.insert(0, creds_line)
                    
                    # Write back to .env file
                    with open(env_file_path, 'w') as f:
                        f.writelines(env_lines)
                    
                    env_updated = True
                    logger.info(f"Updated .env file with GOOGLE_APPLICATION_CREDENTIALS")
                else:
                    # Create .env file if it doesn't exist
                    with open(env_file_path, 'w') as f:
                        f.write(f"# Bootstrap Service Account Credentials\n")
                        f.write(f"GOOGLE_APPLICATION_CREDENTIALS={key_file_path}\n")
                        f.write(f"\n# Firebase Configuration\n")
                        f.write(f"FIREBASE_PROJECT_ID={os.getenv('FIREBASE_PROJECT_ID', 'your_firebase_project_id')}\n")
                        f.write(f"\n# GCP Project Configuration\n")
                        f.write(f"GCP_PROJECT_ID={request.project_id}\n")
                    
                    env_updated = True
                    logger.info(f"Created .env file with GOOGLE_APPLICATION_CREDENTIALS")
                
            except Exception as save_error:
                logger.error(f"Failed to save key file or update .env: {str(save_error)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                # Continue - user can still download the key manually
            
            # Revoke temporary privileges
            if privilege_service:
                logger.info("Revoking temporary privileges...")
                try:
                    privilege_service.revoke_privileges()
                except Exception as revoke_error:
                    logger.warning(f"Failed to revoke privileges: {str(revoke_error)}")
            
            # Generate instructions
            if env_updated:
                instructions = f"""Setup Complete! ✅

The bootstrap service account has been created and configured automatically:

1. ✅ Service account created: {sa_info['email']}
2. ✅ Key file saved: {key_file_path}
3. ✅ .env file updated with GOOGLE_APPLICATION_CREDENTIALS
4. ✅ File permissions set to secure (600)

**Next Step:** Restart your backend server to apply the changes.

The bootstrap service account is ready to use!"""
            else:
                instructions = f"""Setup Complete! ✅

The bootstrap service account has been created:

1. ✅ Service account created: {sa_info['email']}
2. ✅ Key file saved: {key_file_path}

**Manual Step Required:**
Update backend/.env with:
GOOGLE_APPLICATION_CREDENTIALS={key_file_path}

Then restart your backend server."""
            
            return SetupResponse(
                success=True,
                service_account_email=sa_info['email'],
                service_account_key=sa_info['key'],
                message="Bootstrap service account created and configured automatically!",
                instructions=instructions
            )
            
        except Exception as sa_error:
            logger.error(f"Failed to create service account: {str(sa_error)}")
            logger.error(f"Error type: {type(sa_error).__name__}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            
            # Revoke privileges if we granted them
            if privilege_service:
                try:
                    privilege_service.revoke_privileges()
                except Exception as revoke_err:
                    logger.warning(f"Failed to revoke privileges during cleanup: {str(revoke_err)}")
            
            # Provide detailed error message
            error_detail = (
                f"Failed to create service account: {str(sa_error)}\n\n"
                f"Error type: {type(sa_error).__name__}\n\n"
                "Common causes:\n"
                "1. Insufficient permissions - ensure you have:\n"
                "   - roles/iam.serviceAccountAdmin\n"
                "   - roles/iam.serviceAccountKeyAdmin\n"
                "   - roles/resourcemanager.projectIamAdmin\n"
                "2. Wrong project ID - verify the project ID is correct\n"
                "3. Service account quota exceeded\n"
                "4. Organization policies preventing service account creation\n\n"
                "Check backend logs for full error details."
            )
            
            raise HTTPException(
                status_code=500,
                detail=error_detail
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Setup failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Setup failed: {str(e)}"
        )


@router.get("/check")
async def check_setup_status():
    """
    Check if bootstrap service account is configured
    """
    cred_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
    has_credentials = cred_path and os.path.exists(cred_path)
    
    return {
        "configured": has_credentials,
        "credentials_path": cred_path if has_credentials else None,
        "message": "Bootstrap service account is configured" if has_credentials else "Bootstrap service account not configured"
    }


@router.get("/test-credentials")
async def test_credentials():
    """
    Test if default credentials are available and working
    """
    try:
        user_credentials, detected_project = default_credentials()
        
        # Try to get user info
        try:
            from googleapiclient.discovery import build
            oauth2 = build('oauth2', 'v2', credentials=user_credentials)
            user_info = oauth2.userinfo().get().execute()
            user_email = user_info.get('email', 'unknown')
        except:
            user_email = 'unknown (could not fetch)'
        
        # Check credentials file
        creds_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
        creds_exist = os.path.exists(creds_path)
        
        return {
            "success": True,
            "message": "Default credentials are available and working",
            "detected_project": detected_project,
            "user_email": user_email,
            "credentials_file_exists": creds_exist,
            "credentials_file_path": creds_path
        }
    except Exception as e:
        creds_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
        creds_exist = os.path.exists(creds_path)
        
        return {
            "success": False,
            "message": f"Default credentials not available: {str(e)}",
            "error_type": type(e).__name__,
            "credentials_file_exists": creds_exist,
            "credentials_file_path": creds_path,
            "troubleshooting": "After running 'gcloud auth application-default login', restart your backend server"
        }


@router.get("/health")
async def setup_health():
    """Health check for setup service"""
    return {"status": "healthy", "service": "setup"}
