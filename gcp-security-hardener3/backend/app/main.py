"""
GCP Security Hardener - Backend API
Crash-proof, CORS-permissive main entry point.
"""
import os
import pathlib
from fastapi import HTTPException

# Load .env from the backend directory so GCP_PROJECT_ID etc. are available
_env_path = pathlib.Path(__file__).parent.parent / ".env"
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=_env_path, override=False)  # override=False: real env vars win
    print(f"[startup] Loaded .env from {_env_path}")
except ImportError:
    # python-dotenv not installed — env vars must be set externally
    print("[startup] python-dotenv not available; relying on shell env vars")


# ─────────────────────────────────────────────────────────────
# IDENTITY RESOLUTION ORDER (evaluated at module load + per-request)
#
# 1. GOOGLE_IMPERSONATE_SERVICE_ACCOUNT  → explicit override set in terminal
# 2. google.auth.default() with GOOGLE_APPLICATION_CREDENTIALS cleared
#    (prevents .env firebase-adminsdk from bleeding into identity)
# ─────────────────────────────────────────────────────────────

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="GCP Security Hardener API", version="1.0.0")

# In-memory store for the active scan identity (set via Connect Env flow)
_active_session = {
    "sa_email": None,
    "target_id": None,
    "scope": None
}

# ──────────────────────────────────────────────────────────────
# 1. CORS — Allow everything. No network blocks on localhost.

# ──────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.scan import router as scan_router
from app.api.projects import router as projects_router
from app.api.reporting import router as reporting_router

app.include_router(scan_router)
app.include_router(projects_router)
app.include_router(reporting_router, prefix="/api/v1/report", tags=["reporting"])


@app.get("/api/session/identity")
def get_session_identity():
    """
    Returns the active scanner SA email set by /api/session/activate.
    To enforce strict browser session isolation (e.g., Incognito Mode), we NO LONGER return global state here.
    The frontend MUST rely on its own isolated localStorage.
    """
    return {
        "sa_email": None,
        "target_id": None,
        "active": False,
    }


# ──────────────────────────────────────────────────────────────
# 2. /api/system-config — Crash-proof identity detection
# ──────────────────────────────────────────────────────────────
@app.get("/api/system-config")
def get_system_config():
    """
    Returns the identity the scanner is running as.

    Priority A — Explicit terminal override (GOOGLE_IMPERSONATE_SERVICE_ACCOUNT)
    Priority B — google.auth.default() with the firebase-adminsdk key SUPPRESSED
                 so .env's GOOGLE_APPLICATION_CREDENTIALS cannot bleed in.
    """
    try:
        # ── Priority A: Explicit impersonation override set in terminal ──
        manual_sa = os.environ.get("GOOGLE_IMPERSONATE_SERVICE_ACCOUNT")
        if manual_sa:
            print(f"[identity] Using explicit override: {manual_sa}")
            return {
                "service_account_email": manual_sa, 
                "source": "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
                "host_customer_id": "C029pik90" # Host Google Workspace ID
            }

        # ── Priority B: Discover from ADC, but hide firebase-adminsdk key ──
        # Temporarily shadow GOOGLE_APPLICATION_CREDENTIALS so the firebase
        # service-account JSON from .env cannot bleed into this call.
        original_creds_path = os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
        try:
            import google.auth
            credentials, project_id = google.auth.default()
            email = (
                getattr(credentials, "service_account_email", None)
                or getattr(credentials, "signer_email", None)
            )
            if email and email != "default":
                return {
                    "service_account_email": email, 
                    "source": "google.auth.default", 
                    "project": project_id,
                    "host_customer_id": "C029pik90"
                }
            # ADC resolved but no SA email (e.g. user credentials)
            service_account = getattr(credentials, "_service_account_email", None)
            if not service_account:
                try:
                    import requests
                    import google.auth.transport.requests
                    
                    # Refresh if needed to get a valid token
                    if getattr(credentials, "token", None) is None:
                        credentials.refresh(google.auth.transport.requests.Request())
                        
                    res = requests.get(f'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={credentials.token}')
                    if res.status_code == 200:
                        service_account = res.json().get('email', "user-credentials-detected")
                    else:
                        print(f"[identity] Tokeninfo failed: {res.text}")
                        service_account = "user-credentials-detected"
                except Exception as eval_err:
                    print(f"[identity] Error extracting oauth email: {eval_err}")
                    service_account = "user-credentials-detected"

            return {
                "service_account_email": service_account,
                "source": "google.auth.default",
                "project": project_id,
                "host_customer_id": "C029pik90"
            }
        finally:
            # Restore the env var so other parts of the app still see it if needed
            if original_creds_path:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = original_creds_path

    except Exception as exc:
        print(f"[identity] ERROR detecting identity: {exc}")
        return {
            "service_account_email": "error-detecting-identity", 
            "source": "error", 
            "detail": str(exc),
            "host_customer_id": "C029pik90"
        }


# ──────────────────────────────────────────────────────────────
# 3. /api/session/start — Creates a real per-customer scanner SA
# ──────────────────────────────────────────────────────────────
class SessionStartRequest(BaseModel):
    domain: str


@app.post("/api/session/start")
def start_session(req: SessionStartRequest):
    """
    Creates a new per-customer scanner Service Account in OUR GCP project.
    The SA email is what gets shown in the OnboardingModal gcloud command.

    Returns: { status, sa_email, project_id, display_name, created }
    On failure: HTTP 503 with detail — never a raw 500 traceback.
    """
    from app.services.identity_service import create_session_identity
    try:
        result = create_session_identity(req.domain)
        print(f"[session] start → {result['sa_email']} (created={result['created']})")
        return {
            "status": "ok",
            **result,
        }
    except RuntimeError as e:
        # Known, expected failures (bad creds, missing role, etc.)
        print(f"[session] start FAILED for {req.domain!r}: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        print(f"[session] start UNEXPECTED ERROR for {req.domain!r}: {e}")
        raise HTTPException(status_code=503, detail=f"Unexpected error creating scanner identity: {e}")


# ──────────────────────────────────────────────────────────────
# 4. /api/session/stop — Deletes the per-customer scanner SA
# ──────────────────────────────────────────────────────────────
class SessionStopRequest(BaseModel):
    domain: str
    sa_email: str | None = None          # If provided, deletes this specific SA
    target_project_id: str | None = None # Customer project to generate cleanup cmd


@app.post("/api/session/stop")
def stop_session(req: SessionStopRequest):
    """
    Deletes the scanner SA created for this customer session.
    If sa_email is omitted, returns success without deleting (safe no-op).
    """
    if not req.sa_email:
        print(f"[session] stop → no sa_email provided, no-op")
        return {"status": "ok", "message": "No SA to delete."}

    from app.services.identity_service import delete_session_identity
    try:
        result = delete_session_identity(req.sa_email, req.target_project_id)
        print(f"[session] stop → {result['status']} for {req.sa_email}")
        return {"status": "ok", **result}
    except Exception as e:
        print(f"[session] stop error for {req.sa_email}: {e}")
        return {"status": "error", "detail": str(e)}


# ──────────────────────────────────────────────────────────────
# 5. /api/session/activate — Switches backend to use scanner SA
# ──────────────────────────────────────────────────────────────
class SessionActivateRequest(BaseModel):
    sa_email: str
    target_id: str
    scope: str

@app.post("/api/session/activate")
def activate_session(req: SessionActivateRequest):
    """
    Stores the scanner SA email in the shared session dict so all subsequent
    scans use it via impersonation.

    IMPORTANT: We call ensure_token_creator() here (best-effort) so that BOTH
    new SAs and pre-existing SAs always have the backend ADC granted
    roles/iam.serviceAccountTokenCreator before the first scan runs.
    Without this, existing SAs fail with getAccessToken 403 because
    identity_service.create_session_identity() is NOT called for them.
    """
    # Best-effort: grant TokenCreator to the backend ADC on the scanner SA.
    # Never blocks activation even if it fails.
    try:
        from app.services.identity_service import ensure_token_creator
        ensure_token_creator(req.sa_email)
    except Exception as e:
        print(f"[session] TokenCreator grant failed (non-fatal) for {req.sa_email}: {e}")

    _active_session["sa_email"] = req.sa_email
    _active_session["target_id"] = req.target_id
    _active_session["scope"] = req.scope
    print(f"[session] activate → set scanner SA to {req.sa_email} for target {req.target_id}")
    return {"status": "ok"}




# ──────────────────────────────────────────────────────────────
# 6. /api/validate-permissions — Checks if SA has required roles
# ──────────────────────────────────────────────────────────────
@app.get("/api/validate-permissions")
def validate_permissions(sa_email: str, target_id: str, scope: str = "project"):
    """
    Validates that the scanner SA has the required roles by impersonating it and
    calling testIamPermissions AS the SA. This avoids needing getIamPolicy on the 
    backend ADC and accurately reports what the SA itself can do.

    Required: The backend ADC must have roles/iam.serviceAccountTokenCreator on the SA.
    This is automatically set during SA creation in identity_service.py.
    """
    import requests as _req
    from app.services.identity_service import _get_credentials_without_firebase
    import google.auth.transport.requests

    # Permissions we test — one per required role
    permission_to_role = {
        "resourcemanager.projects.getIamPolicy": "roles/iam.securityReviewer",
        "iam.serviceAccounts.list":              "roles/iam.serviceAccountViewer",
        "securitycenter.assets.list":            "roles/securitycenter.adminViewer",
        "resourcemanager.projects.get":          "roles/browser",
    }
    results = {role: False for role in permission_to_role.values()}
    results["roles/billing.viewer"] = True  # billing.viewer is at billing-account level, treated as optional

    try:
        # Step 1: Get backend ADC credentials to generate an impersonation token for the scanner SA
        source_creds, _ = _get_credentials_without_firebase()
        source_creds.refresh(google.auth.transport.requests.Request())

        # Step 2: Get a short-lived access token for the scanner SA via generateAccessToken
        iam_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken"
        token_resp = _req.post(
            iam_url,
            headers={"Authorization": f"Bearer {source_creds.token}"},
            json={"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "300s"},
            timeout=10,
        )

        if token_resp.status_code != 200:
            detail = token_resp.text
            print(f"[validation] Failed to impersonate {sa_email}: {detail}")
            # If impersonation fails (Token Creator not set), fall back to a heuristic:
            # try a direct GCP API call with backend creds to see if the target project exists,
            # and return an informative error.
            return {
                "status": "impersonation_error",
                "detail": f"Cannot impersonate scanner SA. Ensure the SA exists and your backend account has roles/iam.serviceAccountTokenCreator on it. Raw: {detail[:200]}",
                "all_granted": False,
                "roles": results,
            }

        sa_token = token_resp.json()["accessToken"]

        # Step 3: Call testIamPermissions AS the scanner SA
        resource = f"projects/{target_id}"
        if scope == "organization":
            resource = f"organizations/{target_id}"

        test_url = f"https://cloudresourcemanager.googleapis.com/v1/{resource}:testIamPermissions"
        test_resp = _req.post(
            test_url,
            headers={"Authorization": f"Bearer {sa_token}"},
            json={"permissions": list(permission_to_role.keys())},
            timeout=10,
        )

        if test_resp.status_code != 200:
            print(f"[validation] testIamPermissions failed: {test_resp.text}")
            return {
                "status": "error",
                "detail": f"testIamPermissions call failed: {test_resp.status_code} {test_resp.text[:200]}",
                "all_granted": False,
                "roles": results,
            }

        granted_permissions = set(test_resp.json().get("permissions", []))
        print(f"[validation] SA {sa_email} has permissions on {target_id}: {granted_permissions}")

        for perm, role in permission_to_role.items():
            results[role] = perm in granted_permissions

        all_granted = all(results.values())
        return {"status": "ok", "all_granted": all_granted, "roles": results}

    except Exception as e:
        import traceback
        print(f"[validation] Unexpected error: {e}")
        traceback.print_exc()
        return {"status": "error", "detail": str(e), "all_granted": False, "roles": results}

# ──────────────────────────────────────────────────────────────
# 7. /api/verify-access/{resource_id} — Dev bypass

# ──────────────────────────────────────────────────────────────
@app.get("/api/verify-access/{resource_id}")
def verify_access(resource_id: str, scope: str = "project"):
    return {
        "status": "success",
        "message": "Development mode — verification skipped.",
        "resource_id": resource_id,
        "scope": scope,
    }


# ──────────────────────────────────────────────────────────────
# 6. Health check
# ──────────────────────────────────────────────────────────────
@app.get("/healthz")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("BACKEND_PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)
