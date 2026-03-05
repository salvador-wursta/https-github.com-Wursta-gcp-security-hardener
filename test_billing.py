import os
import google.auth
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

def main():
    # Use ADC
    credentials, project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    
    # We want to impersonate scanner-domain222@sam-quota-project.iam.gserviceaccount.com
    from google.auth import impersonated_credentials
    target_sa = "scanner-domain222@sam-quota-project.iam.gserviceaccount.com"
    target_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    
    icreds = impersonated_credentials.Credentials(
        source_credentials=credentials,
        target_principal=target_sa,
        target_scopes=target_scopes
    )
    
    service = build('cloudbilling', 'v1', credentials=icreds)
    project_id = "sam-quota-project"
    
    print(f"Testing getBillingInfo for {project_id}...")
    try:
        res = service.projects().getBillingInfo(name=f"projects/{project_id}").execute()
        print("Success!", res)
    except Exception as e:
        print("Error!", e)

if __name__ == "__main__":
    main()
