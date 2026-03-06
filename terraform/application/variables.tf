variable "project_id" {
  description = "The GCP Project ID"
  type        = string
  default     = "demot-test"
}

variable "region" {
  description = "The GCP region to deploy resources (e.g., us-central1)"
  type        = string
  default     = "us-central1"
}

variable "frontend_image" {
  description = "The Docker image URL for the Next.js frontend"
  type        = string
}

variable "backend_image" {
  description = "The Docker image URL for the FastAPI backend"
  type        = string
}

variable "iap_domain" {
  description = "The domain name for the Load Balancer (e.g., demo.wursta.com)"
  type        = string
  default     = "136.110.224.227.nip.io"
}

variable "authorized_domain" {
  description = "The Google Workspace domain authorized to access the app via IAP (e.g., wursta.com)"
  type        = string
  default     = "demo.wursta.com"
}

variable "iap_client_id" {
  description = "The OAuth Client ID for Identity-Aware Proxy. Must be created manually in GCP console."
  type        = string
}

variable "iap_client_secret" {
  description = "The OAuth Client Secret for Identity-Aware Proxy. Must be created manually in GCP console."
  type        = string
  sensitive   = true
}
