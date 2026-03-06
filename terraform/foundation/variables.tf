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

variable "github_repo" {
  description = "The GitHub repository in format OWNER/REPO (e.g., octocat/Hello-World)"
  type        = string
  default     = "salvador-wursta/https-github.com-Wursta-gcp-security-hardener"
}
