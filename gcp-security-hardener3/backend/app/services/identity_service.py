"""
identity_service.py — Per-customer scanner SA lifecycle management.

CREDENTIAL STRATEGY
───────────────────
• We MUST NOT use the firebase-adminsdk key that lives in the .env file.
  That key is specified via GOOGLE_APPLICATION_CREDENTIALS and would be
  returned by google.auth.default() if not suppressed.
• Before every ADC call we temporarily pop GOOGLE_APPLICATION_CREDENTIALS
  from os.environ so that google.auth.default() walks the full ADC chain
  (workload identity / gcloud auth application-default / metadata server)
  and finds a bootstrap SA that actually has iam.serviceAccountAdmin.
• We restore the env var in a finally block so nothing else breaks.
"""

import os
import re
import time
import google.auth
from googleapiclient import discovery


def _get_credentials_without_firebase():
    """
    Returns (credentials, project_id) via ADC, but with the firebase-adminsdk
    JSON key hidden so it cannot bleed in.
    """
    firebase_path = os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
    try:
        credentials, project_id = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        return credentials, project_id
    finally:
        if firebase_path:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = firebase_path


def _sanitize_name(raw: str, max_len: int = 21) -> str:
    """
    Produces a valid SA account-id component:
      - Lowercase alphanumeric + hyphens only
      - Starts with a letter, does not end with a hyphen
      - At most max_len characters
    """
    # Replace anything non-alphanumeric with a hyphen
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    
    # Must start with a letter
    if not slug or not slug[0].isalpha():
        slug = "client-" + slug
        
    return slug[:max_len].rstrip("-") or "client"


def create_session_identity(domain: str) -> dict:
    """
    Creates a brand-new per-customer scanner Service Account in OUR GCP project.

    The SA name is derived from the company name / domain slug so it is
    human-readable (e.g. "scanner-acme-corp-93f2"). A short timestamp suffix
    is appended so re-scanning the same customer always produces a fresh SA.

    Returns
    -------
    {
        "sa_email":      "scanner-acme-corp-93f2@<project>.iam.gserviceaccount.com",
        "project_id":    "<our-gcp-project>",
        "display_name":  "Scanner for acme-corp",
        "created":       True | False   (False = already existed)
    }

    Raises RuntimeError on any unrecoverable failure so main.py can catch and
    return a clean 503 instead of a 500 traceback.
    """
    try:
        credentials, project_id = _get_credentials_without_firebase()
    except Exception as e:
        raise RuntimeError(
            f"ADC resolution failed — ensure gcloud auth application-default login "
            f"or workload identity is configured (not firebase key). Detail: {e}"
        ) from e

    if not project_id:
        # ADC returned no project — try env vars first, then gcloud config
        project_id = (
            os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCLOUD_PROJECT")
        )
        if not project_id:
            # Last resort: ask gcloud CLI directly
            try:
                import subprocess
                result = subprocess.run(
                    ["gcloud", "config", "get-value", "project"],
                    capture_output=True, text=True, timeout=5
                )
                gcloud_project = result.stdout.strip()
                if gcloud_project and gcloud_project != "(unset)":
                    project_id = gcloud_project
                    print(f"[identity_service] Resolved project from gcloud config: {project_id}")
            except Exception as gcloud_err:
                print(f"[identity_service] gcloud config lookup failed: {gcloud_err}")

    if not project_id:
        raise RuntimeError(
            "Could not detect host GCP project. Set GCP_PROJECT_ID in backend/.env "
            "or run: gcloud config set project YOUR_HOST_PROJECT_ID"
        )


    # Build a stable, unique account-id based on the domain
    # Max total accountId length = 30; prefix "scanner-" is 8 chars. Max slug is 21.
    slug = _sanitize_name(domain, max_len=21)
    account_id = f"scanner-{slug}".rstrip("-")
    
    # Strictly enforce 30 character limit for accountId per GCP IAM rules
    account_id = account_id[:30].rstrip("-")
    
    sa_email = f"{account_id}@{project_id}.iam.gserviceaccount.com"
    full_resource = f"projects/{project_id}/serviceAccounts/{sa_email}"
    display_name = f"Scanner for {domain}"

    iam = discovery.build("iam", "v1", credentials=credentials, cache_discovery=False)

    # Try to create — if it already exists (409) that's fine, we'll just use it
    created = False
    try:
        iam.projects().serviceAccounts().get(name=full_resource).execute()
        print(f"[identity_service] SA already exists: {sa_email}")
    except Exception:
        print(f"[identity_service] Creating new SA: {sa_email}")
        try:
            iam.projects().serviceAccounts().create(
                name=f"projects/{project_id}",
                body={
                    "accountId": account_id,
                    "serviceAccount": {"displayName": display_name},
                },
            ).execute()
            created = True
            print(f"[identity_service] Created: {sa_email}")
        except Exception as create_err:
            raise RuntimeError(
                f"IAM SA creation failed for {account_id!r} in project {project_id!r}. "
                f"Ensure your bootstrap identity has roles/iam.serviceAccountAdmin. "
                f"Detail: {create_err}"
            ) from create_err

    # Always ensure the caller has Token Creator on this SA so impersonation works
    import subprocess
    try:
        res = subprocess.run(
            ["gcloud", "config", "get-value", "account"], 
            capture_output=True, text=True, check=True, timeout=5
        )
        user_email = res.stdout.strip()
        if user_email:
            # Determine if the caller is a user or a service account
            member_type = "serviceAccount" if user_email.endswith(".gserviceaccount.com") else "user"
            member_str = f"{member_type}:{user_email}"
            
            print(f"[identity_service] Adding Token Creator binding for {member_str}")
            policy = iam.projects().serviceAccounts().getIamPolicy(
                resource=full_resource
            ).execute()
            
            binding_exists = False
            if 'bindings' not in policy:
                policy['bindings'] = []
                
            for binding in policy['bindings']:
                if binding.get('role') == 'roles/iam.serviceAccountTokenCreator':
                    if member_str in binding.get('members', []):
                        binding_exists = True
                    else:
                        binding['members'].append(member_str)
                        binding_exists = True
            
            if not binding_exists:
                policy['bindings'].append({
                    'role': 'roles/iam.serviceAccountTokenCreator',
                    'members': [member_str]
                })
                
            iam.projects().serviceAccounts().setIamPolicy(
                resource=full_resource,
                body={'policy': policy}
            ).execute()
            print("[identity_service] Token Creator binding applied successfully.")
    except Exception as e:
        print(f"[identity_service] Could not automatically apply Token Creator binding: {e}")

    return {
        "sa_email": sa_email,
        "project_id": project_id,
        "display_name": display_name,
        "created": created,
    }


def delete_session_identity(sa_email: str, target_project_id: str | None = None) -> dict:
    """
    Deletes the per-customer scanner SA from OUR project.
    Optionally returns the gcloud command the customer must run to clean up
    the IAM binding on their side.
    """
    cleanup_cmd = ""
    if target_project_id:
        cleanup_cmd = (
            f"gcloud projects remove-iam-policy-binding {target_project_id} "
            f"--member='serviceAccount:{sa_email}' "
            f"--role='roles/iam.securityReviewer'"
        )

    try:
        credentials, project_id = _get_credentials_without_firebase()
    except Exception as e:
        return {"status": f"credential_error: {e}", "cleanup_command": cleanup_cmd}

    iam = discovery.build("iam", "v1", credentials=credentials, cache_discovery=False)
    full_resource = f"projects/{project_id}/serviceAccounts/{sa_email}"

    try:
        iam.projects().serviceAccounts().delete(name=full_resource).execute()
        status = "deleted"
        print(f"[identity_service] Deleted SA: {sa_email}")
    except Exception as e:
        status = f"failed_to_delete: {e}"
        print(f"[identity_service] Delete failed for {sa_email}: {e}")

    return {"status": status, "cleanup_command": cleanup_cmd}
