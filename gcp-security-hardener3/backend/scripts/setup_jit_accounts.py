#!/usr/bin/env python3
"""
GCP Security Hardener - JIT Service Account Setup (Python Version)
Cross-platform compatible (Windows, Mac, Linux)
"""
import subprocess
import sys
import json
import time
import os
from pathlib import Path

def run_command(command, check=True, capture_output=True):
    """Run a shell command and return key details."""
    try:
        result = subprocess.run(
            command,
            check=check,
            shell=True,
            text=True,
            capture_output=capture_output
        )
        return result
    except subprocess.CalledProcessError as e:
        if check:
            print(f"❌ Command failed: {command}")
            print(f"Error: {e.stderr}")
            sys.exit(1)
        return e

def print_step(step, total, message):
    print(f"\n[{step}/{total}] {message}")

def get_project_id():
    print("Checking active GCP project...")
    res = run_command("gcloud config get-value project", check=False)
    project_id = res.stdout.strip()
    
    if not project_id:
        print("❌ Error: No project selected")
        print("\nPlease run this first:")
        print("  gcloud config set project YOUR_PROJECT_ID")
        sys.exit(1)
        
    print(f"✓ Project: {project_id}")
    return project_id

def create_service_account(name, display_name, description, project_id):
    email = f"{name}@{project_id}.iam.gserviceaccount.com"
    
    # Check if exists
    res = run_command(
        f"gcloud iam service-accounts describe {email} --project={project_id}", 
        check=False
    )
    
    if res.returncode == 0:
        print(f"   (Service account '{name}' already exists, skipping creation)")
    else:
        run_command(
            f"gcloud iam service-accounts create {name} "
            f"--display-name=\"{display_name}\" "
            f"--description=\"{description}\" "
            f"--project={project_id}"
        )
        print(f"   ✓ Created {name}")
        
    return email

def add_binding(project_id, email, role):
    cmd = (
        f"gcloud projects add-iam-policy-binding {project_id} "
        f"--member=\"serviceAccount:{email}\" "
        f"--role=\"{role}\" "
        f"--condition=None "
        f"--quiet"
    )
    res = run_command(cmd, check=False)
    if res.returncode != 0:
        print(f"   ⚠️  Failed to grant {role}: {res.stderr.strip()}")

def add_org_binding(org_id, email, role):
    cmd = (
        f"gcloud organizations add-iam-policy-binding {org_id} "
        f"--member=\"serviceAccount:{email}\" "
        f"--role=\"{role}\" "
        f"--condition=None "
        f"--quiet"
    )
    res = run_command(cmd, check=False)
    if res.returncode != 0:
        print(f"   ⚠️  Could not grant {role} at Org level")

def main():
    print("==================================================")
    print("GCP Security Hardener - JIT Setup (Python)")
    print("==================================================")
    
    # Check dependencies
    if subprocess.run("gcloud --version", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        print("❌ Error: 'gcloud' CLI is not installed or not in PATH.")
        sys.exit(1)
        
    project_id = get_project_id()
    
    # 1. Create Scanner SA
    print_step(1, 7, "Creating scanner service account...")
    scanner_email = create_service_account(
        "gcp-hardener-scanner",
        "GCP Security Hardener - Scanner",
        "Read-only access for scanning GCP resources",
        project_id
    )
    print(f"   ✓ Scanner: {scanner_email}")
    
    # 2. Create Admin SA
    print_step(2, 7, "Creating admin service account...")
    admin_email = create_service_account(
        "gcp-hardener-admin",
        "GCP Security Hardener - Admin",
        "Administrative access for applying security hardening",
        project_id
    )
    print(f"   ✓ Admin: {admin_email}")
    
    # 3. Assign Scanner roles
    print_step(3, 7, "Assigning scanner permissions (read-only)...")
    scanner_roles = [
        "roles/cloudasset.viewer",
        "roles/viewer",
        "roles/iam.securityReviewer",
        "roles/securitycenter.findingsViewer",
        "roles/serviceusage.serviceUsageConsumer",
        "roles/serviceusage.apiKeysViewer",
        "roles/browser"
    ]
    for role in scanner_roles:
        add_binding(project_id, scanner_email, role)
    print("   ✓ Scanner roles assigned")
    
    # 4. Assign Admin roles
    print_step(4, 7, "Assigning admin permissions (full access)...")
    admin_roles = [
        "roles/editor",
        "roles/iam.securityAdmin", 
        "roles/serviceusage.serviceUsageAdmin",
        "roles/serviceusage.apiKeysAdmin",
        "roles/logging.configWriter",
        "roles/monitoring.admin",
        "roles/compute.securityAdmin",
        "roles/monitoring.editor",
        "roles/cloudasset.owner"
    ]
    for role in admin_roles:
        add_binding(project_id, admin_email, role)
    print("   ✓ Admin roles assigned")
    
    # 4.5 Check Org
    print("\n[4.5/7] Checking for Organization Level permissions...")
    
    # Check parent info
    res_type = run_command(f"gcloud projects describe {project_id} --format=\"value(parent.type)\"", check=False)
    parent_type = res_type.stdout.strip()
    
    res_id = run_command(f"gcloud projects describe {project_id} --format=\"value(parent.id)\"", check=False)
    sys_parent_id = res_id.stdout.strip()
    
    org_id = None
    if parent_type == 'organization':
        org_id = sys_parent_id
        
    # Fallback: If project is in a Folder or Standalone, find the Root Org via list
    if not org_id:
        print(f"   (Project parent is '{parent_type}', searching for Root Organization...)")
        # Try to find the Organization this project belongs to (ancestors)
        # Or just the first accessible Org
        res_org_list = run_command("gcloud organizations list --format=\"value(ID)\" --limit=1", check=False)
        org_id = res_org_list.stdout.strip()

    if org_id:
        print(f"   Detected Organization ID: {org_id}")
        
        # Org Scanner Roles
        org_scanner_roles = [
            "roles/resourcemanager.organizationViewer",
            "roles/resourcemanager.folderViewer",
            "roles/browser",
            "roles/serviceusage.serviceUsageViewer",
            "roles/serviceusage.apiKeysViewer",
            "roles/iam.securityReviewer",
            "roles/securitycenter.findingsViewer",
            "roles/iam.securityReviewer",
            "roles/compute.viewer",
            "roles/cloudasset.viewer",
            "roles/billing.viewer"
        ]
        for role in org_scanner_roles:
            add_org_binding(org_id, scanner_email, role)
            
        # Org Admin Roles
        org_admin_roles = [
            "roles/browser",
            "roles/orgpolicy.policyAdmin",
            "roles/serviceusage.serviceUsageAdmin",
            "roles/serviceusage.apiKeysAdmin",
            "roles/compute.networkAdmin",
            "roles/iam.securityAdmin",
            "roles/logging.configWriter",
            "roles/cloudasset.owner"
        ]
        for role in org_admin_roles:
            add_org_binding(org_id, admin_email, role)
            
    else:
        print("   ⚠️  No Organization ID found (Project might be standalone)")
        
    # 4.8 Billing Account Permissions (Project-Based Discovery)
    print("\n[4.8/7] Checking Billing Account permissions (Project-Based Discovery)...")
    try:
        # 1. List Projects
        print("   Scan: Listing projects to find billing associations (limit 50)...")
        res_projects = run_command("gcloud projects list --format=\"value(projectId)\" --limit=50 --quiet", check=False)
        
        if res_projects.returncode == 0:
            projects = res_projects.stdout.strip().split('\n')
            unique_accounts = set()
            print(f"   (Checking {len(projects)} projects for billing links...)")
            
            for pid in projects:
                if not pid: continue
                # Get billing info for each project
                # This is slower but bypasses the need for global list permissions
                res_bill = run_command(f"gcloud beta billing projects describe {pid} --format=\"value(billingAccountName)\" --quiet", check=False)
                if res_bill.returncode == 0:
                    acct = res_bill.stdout.strip()
                    if acct and acct.startswith("billingAccounts/"):
                         unique_accounts.add(acct.split('/')[-1])
            
            if not unique_accounts:
                 print("   (No billing accounts linked to scanned projects)")
            
            print(f"   ✓ Found {len(unique_accounts)} unique billing accounts.")
            
            for acct_id in unique_accounts:
                print(f"   Account {acct_id}: Granting billing.viewer...")
                
                # Grant Scanner Viewer
                cmd = (
                    f"gcloud beta billing accounts add-iam-policy-binding {acct_id} "
                    f"--member=\"serviceAccount:{scanner_email}\" "
                    f"--role=\"roles/billing.viewer\" "
                    f"--quiet"
                )
                res = run_command(cmd, check=False)
                if res.returncode != 0:
                     print(f"     ⚠️ Failed (You lack Admin rights on this Billing Account)")
                else:
                     print(f"     ✓ Granted")

                # Grant Admin Admin
                cmd_admin = (
                    f"gcloud beta billing accounts add-iam-policy-binding {acct_id} "
                    f"--member=\"serviceAccount:{admin_email}\" "
                    f"--role=\"roles/billing.admin\" "
                    f"--quiet"
                )
                run_command(cmd_admin, check=False)
        else:
             print(f"   ⚠️  Failed to list projects: {res_projects.stderr}")
             
    except Exception as e:
        print(f"   ⚠️  Failed to enumerate/update billing accounts: {e}")
        
    # 5. Disable key creation restrictions
    print_step(5, 7, "Ensuring key creation is allowed...")
    run_command(
        f"gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyCreation --project={project_id} --quiet",
        check=False
    )
    
    # 6. Create Keys
    print_step(6, 7, "Creating credential keys...")
    
    # Scanner Key
    if os.path.exists("scanner-key.json"):
        os.remove("scanner-key.json")
    print("   Creating scanner-key.json (waiting 10s for propagation)...")
    time.sleep(10)
    
    run_command(
        f"gcloud iam service-accounts keys create scanner-key.json --iam-account={scanner_email} --project={project_id}"
    )
    if os.path.exists("scanner-key.json"):
         print("   ✓ scanner-key.json created")
    else:
         print("   ❌ Error creating scanner-key.json")
         
    # Admin Key
    if os.path.exists("admin-key.json"):
        os.remove("admin-key.json")
    print("   Creating admin-key.json...")
    time.sleep(5)
    
    run_command(
        f"gcloud iam service-accounts keys create admin-key.json --iam-account={admin_email} --project={project_id}"
    )
    if os.path.exists("admin-key.json"):
         print("   ✓ admin-key.json created")
    else:
         print("   ❌ Error creating admin-key.json")
         
    # 7. Enable APIs
    print_step(7, 7, "Enabling required APIs...")
    apis = [
        "serviceusage.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "iam.googleapis.com",
        "cloudbilling.googleapis.com",
        "billingbudgets.googleapis.com", 
        "recommender.googleapis.com",
        "orgpolicy.googleapis.com",
        "compute.googleapis.com",
        "logging.googleapis.com",
        "monitoring.googleapis.com",
        "pubsub.googleapis.com",
        "cloudasset.googleapis.com",
        "apikeys.googleapis.com",
        "securitycenter.googleapis.com",
        "ids.googleapis.com"
    ]
    
    for api in apis:
        print(f"   Enabling {api}...")
        try:
            run_command(f"gcloud services enable {api} --project={project_id}", check=True, capture_output=True)
        except Exception as e:
            print(f"   ⚠️  Failed to enable {api}. You may need to enable it manually.")
            print(f"      Error details: {str(e)}")
        
    print("\n==================================================")
    print("✅ Setup Complete!")
    print("==================================================")
    print("Generated files:")
    print("  📄 scanner-key.json")
    print("  📄 admin-key.json")
    print("\nUpload these references to the GCP Security Hardener app.")

if __name__ == "__main__":
    main()
