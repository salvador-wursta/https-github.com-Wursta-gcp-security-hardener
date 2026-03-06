output "load_balancer_ip" {
  description = "The static IP address of the External Application Load Balancer"
  value       = google_compute_global_address.default.address
}

output "iap_client_id" {
  description = "The OAuth Client ID used for IAP"
  value       = var.iap_client_id
}

output "frontend_url" {
  description = "The URL of the frontend Cloud Run service (internal only)"
  value       = google_cloud_run_v2_service.frontend.uri
}
