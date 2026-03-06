output "wif_provider_name" {
  description = "The Workload Identity Provider Name to use in GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "deployment_sa_email" {
  description = "The Service Account Email for GitHub Actions deployment"
  value       = google_service_account.deployment_sa.email
}
