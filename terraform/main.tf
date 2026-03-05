terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}
data "google_project" "project" {}

# ==============================================================================
# 1. Identity & Access Management (WIF & Service Accounts)
# ==============================================================================

# Runtime Service Account for Cloud Run
resource "google_service_account" "runtime_sa" {
  account_id   = "app-runtime-sa"
  display_name = "Cloud Run Application Runtime Service Account"
  description  = "Dedicated service account for the frontend and backend Cloud Run services."
}

# Give runtime SA token creator role so it can impersonate other SAs
resource "google_project_iam_member" "runtime_sa_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# Deployment Service Account for GitHub Actions
resource "google_service_account" "deployment_sa" {
  account_id   = "github-deploy-sa"
  display_name = "GitHub Actions Deployment Service Account"
}

# Grant deployment SA the necessary roles to deploy infra
resource "google_project_iam_member" "deployment_sa_roles" {
  for_each = toset([
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/compute.admin",
    "roles/run.admin",
    "roles/vpcaccess.admin",
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.deployment_sa.email}"
}

# Workload Identity Pool
resource "google_iam_workload_identity_pool" "github_pool" {
  workload_identity_pool_id = "github-actions-pool"
  display_name              = "GitHub Actions Pool"
  description               = "Identity pool for GitHub Actions deployments"
}

# Workload Identity Provider
resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-repo-provider"
  display_name                       = "GitHub Repo Provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository == '${var.github_repo}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Allow GitHub Actions to impersonate the deployment Service Account
resource "google_service_account_iam_member" "github_sa_impersonation" {
  service_account_id = google_service_account.deployment_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_repo}"
}


# ==============================================================================
# 2. Network Configuration (Custom VPC & Serverless VPC Access)
# ==============================================================================

# Custom VPC Network
resource "google_compute_network" "custom_vpc" {
  name                    = "app-custom-vpc"
  auto_create_subnetworks = false
}

# Subnet for general resources
resource "google_compute_subnetwork" "app_subnet" {
  name          = "app-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.custom_vpc.id
}

# Subnet for Serverless VPC Access Connector
resource "google_compute_subnetwork" "connector_subnet" {
  name          = "vpc-connector-subnet"
  ip_cidr_range = "10.8.0.0/28"
  region        = var.region
  network       = google_compute_network.custom_vpc.id
}

# Serverless VPC Access Connector
resource "google_vpc_access_connector" "connector" {
  name   = "app-vpc-connector"
  region = var.region
  subnet {
    name = google_compute_subnetwork.connector_subnet.name
  }
  machine_type  = "e2-micro"
  min_instances = 2
  max_instances = 3
}

# Cloud Router and NAT for outbound internet access from the VPC
resource "google_compute_router" "router" {
  name    = "app-router"
  region  = var.region
  network = google_compute_network.custom_vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "app-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}


# ==============================================================================
# 3. Compute (Cloud Run Services)
# ==============================================================================

# FastAPI Backend Service
resource "google_cloud_run_v2_service" "backend" {
  name     = "fastapi-backend"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.runtime_sa.email

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      image = var.backend_image
      ports {
        container_port = 8000
      }
    }
  }
}

# Next.js Frontend Service
resource "google_cloud_run_v2_service" "frontend" {
  name     = "nextjs-frontend"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.runtime_sa.email

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      image = var.frontend_image
      ports {
        container_port = 3000
      }
      env {
        name  = "NEXT_PUBLIC_BACKEND_URL"
        value = "https://${var.iap_domain}/api"
      }
    }
  }
}

# Allow external invocation. Because ingress is restricted to INTERNAL_LOAD_BALANCER,
# only requests coming through the Load Balancer (and passing IAP auth) will reach the service.
resource "google_cloud_run_service_iam_member" "backend_invoker" {
  location = google_cloud_run_v2_service.backend.location
  service  = google_cloud_run_v2_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_service_iam_member" "frontend_invoker" {
  location = google_cloud_run_v2_service.frontend.location
  service  = google_cloud_run_v2_service.frontend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ==============================================================================
# 4. Network Security (Application Load Balancer & IAP)
# ==============================================================================

# Static IP for the Load Balancer
resource "google_compute_global_address" "default" {
  name = "app-lb-ip"
}

# Serverless Network Endpoint Group (NEG) for Backend
resource "google_compute_region_network_endpoint_group" "backend_neg" {
  name                  = "backend-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_v2_service.backend.name
  }
}

# Serverless Network Endpoint Group (NEG) for Frontend
resource "google_compute_region_network_endpoint_group" "frontend_neg" {
  name                  = "frontend-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_v2_service.frontend.name
  }
}

# Load Balancer Backend Service for Frontend
resource "google_compute_backend_service" "frontend_bs" {
  name                  = "frontend-backend-service"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  backend {
    group = google_compute_region_network_endpoint_group.frontend_neg.id
  }

  iap {
    oauth2_client_id     = var.iap_client_id
    oauth2_client_secret = var.iap_client_secret
  }
}

# Load Balancer Backend Service for Backend
resource "google_compute_backend_service" "backend_bs" {
  name                  = "api-backend-service"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"

  backend {
    group = google_compute_region_network_endpoint_group.backend_neg.id
  }

  iap {
    oauth2_client_id     = var.iap_client_id
    oauth2_client_secret = var.iap_client_secret
  }
}

# Allow Workspace domain to bypass IAP for the Backend Service
resource "google_iap_web_backend_service_iam_member" "frontend_iap_access" {
  project             = var.project_id
  web_backend_service = google_compute_backend_service.frontend_bs.name
  role                = "roles/iap.httpsResourceAccessor"
  member              = "domain:${var.authorized_domain}"
}

resource "google_iap_web_backend_service_iam_member" "backend_iap_access" {
  project             = var.project_id
  web_backend_service = google_compute_backend_service.backend_bs.name
  role                = "roles/iap.httpsResourceAccessor"
  member              = "domain:${var.authorized_domain}"
}

# URL Map (Routing rules)
resource "google_compute_url_map" "default" {
  name            = "app-url-map"
  default_service = google_compute_backend_service.frontend_bs.id

  host_rule {
    hosts        = [var.iap_domain]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.frontend_bs.id

    path_rule {
      paths   = ["/api", "/api/*", "/docs", "/openapi.json"]
      service = google_compute_backend_service.backend_bs.id
    }
  }
}

# Google-managed SSL Certificate
resource "google_compute_managed_ssl_certificate" "default" {
  name = "app-cert"
  managed {
    domains = [var.iap_domain]
  }
}

# HTTPS Target Proxy
resource "google_compute_target_https_proxy" "default" {
  name             = "app-https-proxy"
  url_map          = google_compute_url_map.default.id
  ssl_certificates = [google_compute_managed_ssl_certificate.default.id]
}

# HTTP to HTTPS redirect proxy
resource "google_compute_url_map" "https_redirect" {
  name = "app-https-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "http_proxy" {
  name    = "app-http-proxy"
  url_map = google_compute_url_map.https_redirect.id
}

# Global Forwarding Rule (HTTPS)
resource "google_compute_global_forwarding_rule" "https" {
  name                  = "app-https-rule"
  target                = google_compute_target_https_proxy.default.id
  port_range            = "443"
  ip_address            = google_compute_global_address.default.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

# Global Forwarding Rule (HTTP)
resource "google_compute_global_forwarding_rule" "http" {
  name                  = "app-http-rule"
  target                = google_compute_target_http_proxy.http_proxy.id
  port_range            = "80"
  ip_address            = google_compute_global_address.default.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
