import os
import sys

sys.path.insert(0, os.path.abspath('.'))

from app.services.identity_service import create_session_identity, _get_credentials_without_firebase

if __name__ == "__main__":
    creds, _ = _get_credentials_without_firebase()
    if not creds:
        print("Could not get credentials")
        sys.exit(1)
        
    project_id = "demot-test"
    domain = "wursta"
    
    # We purposefully delete it to cause a soft-delete 409
    from googleapiclient import discovery
    iam = discovery.build("iam", "v1", credentials=creds, cache_discovery=False)
    account_id = f"scanner-{domain}"
    sa_email = f"{account_id}@{project_id}.iam.gserviceaccount.com"
    
    try:
        iam.projects().serviceAccounts().delete(name=f"projects/{project_id}/serviceAccounts/{sa_email}").execute()
        print(f"Deleted {sa_email} to trigger soft-delete conflict.")
    except Exception as e:
        print(f"SA not deleted (might not exist yet): {e}")
        
    print("\nCreating session identity...")
    try:
        new_sa_payload = create_session_identity(domain)
        print(f"\nResulting SA Payload: {new_sa_payload}")
    except Exception as e:
        print(f"\nFAILED: {e}")
