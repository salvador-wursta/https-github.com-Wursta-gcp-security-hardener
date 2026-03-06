# GCP Security Guardian & Hardener

Welcome to the **GCP Security Guardian & Hardener** project repository! 
This project serves as a security "Guardian" that safeguards Google Workspace and Google Cloud Platform (GCP) environments from emerging cloud threats, such as privilege escalation attacks and runaway crypto-mining botnets.

## 📖 What is this Project?

Many small and medium-sized businesses (SMBs) run critical tools on Google Workspace or Google Cloud. When an administrative account gets hijacked, attackers can misuse those accounts to spin up incredibly expensive servers to mine cryptocurrency, potentially costing businesses thousands of dollars overnight. 

**This application solves that problem.** It actively scans your Google Cloud environments, discovers hidden risks, uncovers accounts with too much access, checks your billing controls, and securely "hardens" (locks down) your environment by automatically applying safe limits and kill switches.

## ⭐ Key Features for Your Business
1. **Automated Threat Detection:** Scans your entire organization or specific projects to find misconfigurations, missing alerts, and overly-powerful user accounts.
2. **Billing and Cost Protection:** Ensures you have strict budgets set so you never wake up to an unexpected massive cloud bill.
3. **Automated PDF Reports:** Generates professional, executive-friendly PDF reports detailing the security health of your cloud infrastructure.
4. **Least Privilege Enforcement:** Relies on temporary, restricted "Scanner" and "Admin" accounts to do its job, meaning the tool itself is highly secure.

## 🤝 For Non-Technical Stakeholders and Users

### How the App Works
This system consists of two main pieces:
1. **The Dashboard (Frontend):** A sleek, easy-to-use web interface where you can initiate security scans, review risks identified in plain English, and download reports.
2. **The Engine (Backend):** The powerhouse that talks directly to Google Cloud on your behalf to inspect security rules, billing configurations, and technical vulnerabilities safely.

### How to Trigger an Update (Deployment)
This repository is configured with **GitHub Actions (CI/CD)**. This means the deployment is fully automated! 
**Any time a change (like saving this README) is pushed to this repository's `main` branch, it automatically kicks off a secure process to build and deploy the application straight into the Google Cloud environment.**

**Zero manual configuration is required in the backend once deployed.**

## 🛠️ Technical Details (For the IT Team)

If you are an engineer or IT administrator managing this solution, here is a quick overview of our technology stack:

- **Frontend Application:** Built with Next.js 14, React, and styled with Tailwind CSS for a modern, responsive user experience.
- **Backend Application:** Powered by Python (FastAPI), delivering high-speed, parallel security checks using Google Cloud APIs.
- **Infrastructure as Code (IaC):** Everything is provisioned automatically with Terraform. This ensures all servers, load balancers, and security rules are identical and perfectly configured every time.
- **Hosting & Networking:** 
  - The application runs on **Google Cloud Run** behind an elite **Application Load Balancer**.
  - All access is protected behind **Identity-Aware Proxy (IAP)**, meaning only approved corporate users can access the dashboard.
- **Workload Identity Federation (WIF):** When GitHub Actions deploys the app, it uses temporary, passwordless authentication to Google Cloud, preventing the risk of stolen service keys.

## 🚀 How to Re-Deploy the Infrastructure

Whenever you need to rebuild the servers and ensure your app is running the latest code, the process is simple:

1. Make your changes to the application code, Terraform modules, or documentation.
2. Commit your changes.
3. Push to the `main` branch. 
4. Head to the **Actions** tab above. You will see the `Deploy Infrastructure` workflow running. It automatically plans and applies the infrastructure and deploys the newest version of the app to your Cloud Run services!

---

*Thank you for using the GCP Security Guardian! Together, we keep your cloud safe, secure, and cost-effective.*
