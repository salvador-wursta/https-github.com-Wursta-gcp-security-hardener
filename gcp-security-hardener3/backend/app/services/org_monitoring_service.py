
import logging
from typing import List, Optional
from google.cloud import logging_v2
from google.cloud import billing
from google.cloud.billing import budgets_v1
from google.cloud import monitoring_v3
from google.api_core import exceptions
import json
from googleapiclient.discovery import build as google_build

logger = logging.getLogger(__name__)

class OrgMonitoringService:
    def __init__(self, credentials=None):
        self.credentials = credentials
        self.logging_client = logging_v2.Client(credentials=credentials)
        self.config_client = logging_v2.ConfigServiceV2Client(credentials=credentials)
        self.metrics_client = logging_v2.MetricsServiceV2Client(credentials=credentials)
        self.budget_client = budgets_v1.BudgetServiceClient(credentials=credentials)
        self.alert_client = monitoring_v3.AlertPolicyServiceClient(credentials=credentials)
        self.channel_client = monitoring_v3.NotificationChannelServiceClient(credentials=credentials)

    def setup_aggregated_sink(self, org_id: str, destination_project_id: str, destination_bucket_name: str, location: str = "us-central1") -> dict:
        """
        Creates or updates an Aggregated Log Sink at the Organization level.
        """
        sink_name = "security-hardener-org-sink"
        parent = f"organizations/{org_id}"
        destination = f"logging.googleapis.com/projects/{destination_project_id}/locations/{location}/buckets/{destination_bucket_name}"

        # Strict filter for 6 categories
        # 1. API Enablement
        # 2. Org Policy Changes
        # 3. Billing Budget Changes
        # 4. Firewall Rule Changes
        # 5. Inbound RDP Enabled (subset of firewall)
        # 6. Project Creation
        
        filter_conditions = [
            'protoPayload.methodName=~"EnableService"', # API Enablement
            'protoPayload.methodName=~"SetPolicy" OR protoPayload.methodName=~"SetOrgPolicy" OR protoPayload.methodName=~"UpdatePolicy" OR protoPayload.methodName=~"DeletePolicy"', # Org Policy
            'protoPayload.serviceName="billingbudgets.googleapis.com" OR protoPayload.methodName=~"UpdateQuota" OR protoPayload.serviceName="cloudbilling.googleapis.com"', # Billing & Quota
            'resource.type="gce_firewall_rule" OR protoPayload.methodName=~"compute.firewalls"', # Firewall Changes
            'protoPayload.methodName=~"CreateProject"' # Project Creation
        ]
        
        # Combine with OR, and simplify filter to ensure organization-wide capture
        combined_filter = (
            'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" AND ('
            + ' OR '.join(filter_conditions) + 
            ')'
        )

        sink = logging_v2.types.LogSink(
            name=sink_name,
            destination=destination,
            filter=combined_filter,
            include_children=True  # CRITICAL: Aggregated Sink
        )

        try:
            logger.info(f"Creating/Updating Aggregated Sink '{sink_name}' in {parent}...")
            created_sink = self.config_client.update_sink(
                request={
                    "sink_name": f"{parent}/sinks/{sink_name}",
                    "sink": sink,
                    "update_mask": {"paths": ["destination", "filter", "include_children"]}
                }
            )
            logger.info(f"Sink created/updated successfully. Writer Identity: {created_sink.writer_identity}")
            return {
                "success": True,
                "sink_name": created_sink.name,
                "writer_identity": created_sink.writer_identity
            }
        except exceptions.NotFound:
            # Create if not exists
            created_sink = self.config_client.create_sink(
                request={
                    "parent": parent,
                    "sink": sink
                }
            )
            logger.info(f"Sink created successfully. Writer Identity: {created_sink.writer_identity}")
            return {
                "success": True,
                "sink_name": created_sink.name,
                "writer_identity": created_sink.writer_identity
            }
        except Exception as e:
            logger.error(f"Failed to setup aggregated sink: {e}")
            raise

    def ensure_log_bucket(self, project_id: str, bucket_name: str, location: str = "us-central1", writer_identity: str = None) -> dict:
        """
        Ensures the central log bucket exists and grants permission to the sink.
        """
        bucket_path = f"projects/{project_id}/locations/{location}/buckets/{bucket_name}"
        
        # 1. Create Bucket if not exists
        try:
            self.config_client.get_bucket(request={"name": bucket_path})
            logger.info(f"Log Bucket {bucket_path} exists.")
        except exceptions.NotFound:
            logger.info(f"Creating Log Bucket {bucket_path}...")
            try:
                self.config_client.create_bucket(
                    request={
                        "parent": f"projects/{project_id}/locations/{location}",
                        "bucket_id": bucket_name,
                        "bucket": logging_v2.types.LogBucket(
                            retention_days=30 # Free tier friendly
                        )
                    }
                )
            except Exception as e:
                logger.error(f"Failed to create log bucket: {e}")
                raise

        if writer_identity:
            try:
                logger.info(f"Granting roles/logging.bucketWriter to {writer_identity} on project {project_id}...")
                crm = google_build('cloudresourcemanager', 'v1', credentials=self.credentials)
                
                # Get current IAM policy
                policy = crm.projects().getIamPolicy(
                    resource=project_id,
                    body={},
                ).execute()
                
                # Append member to role
                binding_found = False
                for binding in policy.get('bindings', []):
                    if binding.get('role') == 'roles/logging.bucketWriter':
                        if writer_identity not in binding.get('members', []):
                            binding['members'].append(writer_identity)
                        binding_found = True
                        break
                
                if not binding_found:
                    policy.setdefault('bindings', []).append({
                        'role': 'roles/logging.bucketWriter',
                        'members': [writer_identity]
                    })
                
                # Update policy
                crm.projects().setIamPolicy(
                    resource=project_id,
                    body={'policy': policy},
                ).execute()
                logger.info(f"Successfully granted bucketWriter role.")
            except Exception as e:
                logger.warning(f"Could not auto-grant bucketWriter role: {e}")
                # We don't raise here to allow the rest of the monitoring to set up

        return {
            "success": True,
            "bucket_path": bucket_path,
            "retention_days": 30
        }

    def create_logging_budget(self, billing_account_id: str, project_id: str, email_address: str) -> dict:
        """
        Creates a Billing Budget for Cloud Logging costs ($0.10 threshold).
        """
        try:
            budget_name = f"billingAccounts/{billing_account_id}/budgets/logging-safety-{project_id}"
            
            # Define budget
            budget = budgets_v1.Budget(
                display_name=f"Logging Cost Safety - {project_id}",
                amount=budgets_v1.BudgetAmount(
                    specified_amount=budgets_v1.types.Money(
                        currency_code="USD",
                        units=0,
                        nanos=100000000 # $0.10
                    )
                ),
                budget_filter=budgets_v1.Filter(
                    projects=[f"projects/{project_id}"],
                    services=["services/C10F-DB16-6401"] # Cloud Logging Service ID (Known stable ID)
                    # Alternatively, use text filter if Service ID lookup is complex in this scope, 
                    # but API usually requires Resource Name. 
                    # Fallback: Monitor ALL services for the project if Service ID is tricky.
                    # For safety, let's monitor the WHOLE project's cost at $0.10 if strictly dedicated to logging,
                    # or try to lookup service.
                ),
                threshold_rules=[
                    budgets_v1.ThresholdRule(threshold_percent=0.5), # 50% ($0.05)
                    budgets_v1.ThresholdRule(threshold_percent=1.0)  # 100% ($0.10)
                ],
                notifications_rule=budgets_v1.NotificationsRule(
                    monitoring_notification_channels=[] # Would link to Email Channel ID here
                )
            )

            # This part is complex because finding the correct Channel ID programmatically requires Monitoring API.
            # We will assume the Channel is created elsewhere and passed in, OR we skip the NotificationRule
            # and rely on the default Billing Admin emails.
            
            # Create the budget
            try:
                # Note: Budget creation requires Billing Account Admin permissions
                parent = f"billingAccounts/{billing_account_id}"
                created_budget = self.budget_client.create_budget(
                    request={"parent": parent, "budget": budget}
                )
                logger.info(f"Created Logging Budget: {created_budget.name}")
                return {"success": True, "budget_name": created_budget.name}
            except exceptions.AlreadyExists:
                logger.info(f"Budget for project {project_id} already exists.")
                return {"success": True, "status": "already_exists"}
            
        except Exception as e:
            logger.error(f"Failed to create budget: {e}")
            return {"success": False, "error": str(e)}

    def create_log_metrics(self, project_id: str) -> dict:
        """
        Creates the 6 Log-Based Metrics in the central project.
        """
        metrics = [
            {
                "name": "api_enablement_count",
                "filter": 'protoPayload.serviceName="serviceusage.googleapis.com" AND protoPayload.methodName=~"EnableService"',
                "description": "API enablement events"
            },
            {
                "name": "org_policy_change_count",
                "filter": 'protoPayload.methodName=~"SetPolicy" OR protoPayload.methodName=~"SetOrgPolicy" OR protoPayload.methodName=~"UpdatePolicy"',
                "description": "Organization policy changes"
            },
            {
                "name": "billing_budget_change_count",
                "filter": 'protoPayload.serviceName="billingbudgets.googleapis.com" OR protoPayload.methodName=~"UpdateQuota" OR protoPayload.serviceName="cloudbilling.googleapis.com"',
                "description": "Billing and Quota changes"
            },
            {
                "name": "firewall_rule_change_count",
                "filter": 'protoPayload.serviceName="compute.googleapis.com" AND (protoPayload.methodName=~"compute.firewalls" OR resource.type="gce_firewall_rule")',
                "description": "Firewall rule changes"
            },
            {
                "name": "inbound_rdp_count",
                "filter": 'resource.type="gce_firewall_rule" AND protoPayload.methodName=~"insert" AND protoPayload.request.allowed.ports:"3389"',
                "description": "Inbound RDP rules enabled"
            },
            {
                "name": "project_creation_count",
                "filter": 'protoPayload.methodName=~"CreateProject"',
                "description": "Project creation events"
            }
        ]

        parent = f"projects/{project_id}"
        bucket_full_path = f"projects/{project_id}/locations/us-central1/buckets/security-org-logs"
        results = []

        # Build logging service via googleapiclient for bucketName support
        logging_service = google_build('logging', 'v2', credentials=self.credentials)

        for m in metrics:
            metric_name = m["name"]
            metric_filter = m["filter"] 
            
            metric_body = {
                "name": metric_name,
                "filter": metric_filter,
                "description": m["description"],
                "bucketName": bucket_full_path,
                "metricDescriptor": {
                    "metricKind": "DELTA",
                    "valueType": "INT64",
                    "labels": [
                        { "key": "service_name", "valueType": "STRING", "description": "Service name" },
                        { "key": "method_name", "valueType": "STRING", "description": "Method name" },
                        { "key": "project_id", "valueType": "STRING", "description": "Impacted Project ID" },
                        { "key": "principal", "valueType": "STRING", "description": "Performing user" }
                    ]
                },
                "labelExtractors": {
                    "service_name": "EXTRACT(protoPayload.serviceName)",
                    "method_name": "EXTRACT(protoPayload.methodName)",
                    "project_id": "EXTRACT(resource.labels.project_id)",
                    "principal": "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
                }
            }

            try:
                logging_service.projects().metrics().create(
                    parent=parent,
                    body=metric_body
                ).execute()
                logger.info(f"Created bucket-scoped metric: {metric_name}")
                results.append({"name": metric_name, "status": "created"})
            except Exception as e:
                if "409" in str(e) or "AlreadyExists" in str(e):
                    try:
                        metric_full_name = f"{parent}/metrics/{metric_name}"
                        logging_service.projects().metrics().update(
                            metricName=metric_full_name,
                            body=metric_body
                        ).execute()
                        logger.info(f"Updated existing bucket-scoped metric: {metric_name}")
                        results.append({"name": metric_name, "status": "updated"})
                    except Exception as patch_e:
                        logger.error(f"Failed to update metric {metric_name}: {patch_e}")
                        results.append({"name": metric_name, "status": "failed", "error": str(patch_e)})
                else:
                    logger.error(f"Failed to create metric {metric_name}: {e}")
                    results.append({"name": metric_name, "status": "failed", "error": str(e)})

        return {"success": True, "results": results}

    def create_metric_alerts(self, project_id: str, alert_emails: List[str]) -> dict:
        """
        Creates Alert Policies based on the Log-Based Metrics.
        """
        # 1. Ensure Notification Channels exist
        channel_ids = []
        for email in alert_emails:
            # Check/Create logic simplified for brevity - in prod assume duplicates handled
            channel = monitoring_v3.NotificationChannel(
                type_="email",
                display_name=f"Security Alert - {email}",
                labels={"email_address": email}
            )
            try:
                created_channel = self.channel_client.create_notification_channel(
                    request={"name": f"projects/{project_id}", "notification_channel": channel}
                )
                channel_ids.append(created_channel.name)
            except Exception as e:
                logger.error(f"Failed to create channel for {email}: {e}")

        if not channel_ids:
            logger.warning("No notification channels created. Alerts will trigger silently.")

        # 2. Create Alert Policies
        metrics = [
            "api_enablement_count", "org_policy_change_count", "billing_budget_change_count",
            "firewall_rule_change_count", "inbound_rdp_count", "project_creation_count"
        ]
        
        results = []
        for metric_name in metrics:
            display_name = f"Security Alert: {metric_name.replace('_count', '').replace('_', ' ').title()}"
            
            # Condition: Value > 0 for 1 minute
            # Use resource.type="logging_bucket" for bucket-scoped metrics
            condition = monitoring_v3.AlertPolicy.Condition(
                display_name=f"{display_name} Condition",
                condition_threshold=monitoring_v3.AlertPolicy.Condition.MetricThreshold(
                    filter=f'metric.type="logging.googleapis.com/user/{metric_name}" AND resource.type="logging_bucket"',
                    comparison=monitoring_v3.ComparisonType.COMPARISON_GT,
                    threshold_value=0,
                    duration={"seconds": 0}, # Instant trigger
                    aggregations=[
                        monitoring_v3.Aggregation(
                            alignment_period={"seconds": 60},
                            per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM
                        )
                    ]
                )
            )

            policy = monitoring_v3.AlertPolicy(
                display_name=display_name,
                conditions=[condition],
                severity=monitoring_v3.AlertPolicy.Severity.WARNING,
                combiner=monitoring_v3.AlertPolicy.ConditionCombinerType.OR,
                notification_channels=channel_ids,
                documentation=monitoring_v3.AlertPolicy.Documentation(
                   content=f"## {display_name}\n\n"
                           f"**Description:** Aggregated security event matching `{metric_name}` has been detected.\n\n"
                           f"**Source:** Aggregated Logs in `security-org-logs` bucket.\n"
                           f"**Impacted Project:** `${{metric.label.project_id}}`\n"
                           f"**Action Taken:** `${{metric.label.method_name}}` on `${{metric.label.service_name}}`\n"
                           f"**User:** `${{metric.label.principal}}`\n\n"
                           f"**Monitoring Project:** {project_id}\n\n"
                           f"### Next Steps\n"
                           f"1. Open [Cloud Logging Explorer](https://console.cloud.google.com/logs/query;query=resource.type%3D%22logging_bucket%22%20logName:%22projects/{project_id}/locations/us-central1/buckets/security-org-logs%22;project={project_id}) to review the event details.\n"
                           f"2. Verify if this change was authorized.\n"
                           f"3. Revert the change if it violates security policy.",
                   mime_type='text/markdown'
                )
            )

            try:
                self.alert_client.create_alert_policy(
                    request={"name": f"projects/{project_id}", "alert_policy": policy}
                )
                results.append({"policy": display_name, "status": "created"})
            except Exception as e:
                if "409" in str(e) or "AlreadyExists" in str(e):
                    try:
                        # Find existing policy
                        policies = self.alert_client.list_alert_policies(
                            request={"name": f"projects/{project_id}", "filter": f'display_name="{display_name}"'}
                        )
                        for p in policies:
                            # Update existing policy
                            p.severity = policy.severity
                            p.documentation = policy.documentation
                            # For the gRPC client, update_alert_policy takes the policy and a field mask
                            from google.protobuf import field_mask_pb2
                            update_mask = field_mask_pb2.FieldMask(paths=["severity", "documentation"])
                            self.alert_client.update_alert_policy(
                                request={"alert_policy": p, "update_mask": update_mask}
                            )
                            logger.info(f"Updated existing alert policy severity/documentation: {display_name}")
                            break
                        results.append({"policy": display_name, "status": "updated"})
                    except Exception as patch_e:
                        logger.error(f"Failed to update policy {display_name}: {patch_e}")
                        results.append({"policy": display_name, "status": "failed", "error": str(patch_e)})
                else:
                    logger.error(f"Failed to create policy {display_name}: {e}")
                    results.append({"policy": display_name, "status": "failed", "error": str(e)})

        return {"success": True, "results": results}

    def check_monitoring_exists(self, org_id: str, project_id: str) -> dict:
        """
        Check if organization monitoring is already configured.
        Returns status of sink, metrics, and alerts.
        """
        result = {
            "sink_exists": False,
            "metrics_exist": False,
            "alerts_exist": False,
            "existing_emails": [],
            "sink_name": None,
            "metric_count": 0,
            "alert_count": 0
        }
        
        try:
            # Check for existing sink at organization level
            sink_name = f"organizations/{org_id}/sinks/security-hardener-org-sink"
            try:
                sink = self.config_client.get_sink(request={"sink_name": sink_name})
                result["sink_exists"] = True
                result["sink_name"] = sink.name
                logger.info(f"Found existing sink: {sink.name}")
            except exceptions.NotFound:
                logger.info(f"No existing sink found at org level")
            except Exception as e:
                logger.warning(f"Error checking sink: {e}")
        
            # Check for existing log-based metrics
            parent = f"projects/{project_id}"
            try:
                metrics = list(self.metrics_client.list_log_metrics(request={"parent": parent}))
                security_metrics = [m for m in metrics if m.name.startswith("api_enablement") or 
                                   "org_policy" in m.name or "firewall" in m.name or 
                                   "billing" in m.name or "rdp" in m.name or "project_creation" in m.name]
                if security_metrics:
                    result["metrics_exist"] = True
                    result["metric_count"] = len(security_metrics)
                    logger.info(f"Found {len(security_metrics)} existing security metrics")
            except Exception as e:
                logger.warning(f"Error checking metrics: {e}")
        
            # Check for existing alert policies
            try:
                policies = list(self.alert_client.list_alert_policies(request={"name": parent}))
                security_policies = [p for p in policies if p.display_name.startswith("Security Alert:")]
                if security_policies:
                    result["alerts_exist"] = True
                    result["alert_count"] = len(security_policies)
                    
                    # Extract existing email addresses from notification channels
                    for policy in security_policies:
                        for channel_name in policy.notification_channels:
                            try:
                                channel = self.channel_client.get_notification_channel(name=channel_name)
                                if channel.type_ == "email":
                                    email = channel.labels.get("email_address")
                                    if email and email not in result["existing_emails"]:
                                        result["existing_emails"].append(email)
                            except Exception:
                                pass
                    
                    logger.info(f"Found {len(security_policies)} existing alert policies with emails: {result['existing_emails']}")
            except Exception as e:
                logger.warning(f"Error checking alert policies: {e}")
                
        except Exception as e:
            logger.error(f"Error in check_monitoring_exists: {e}")
        
        return result

    def update_alert_emails(self, project_id: str, new_emails: List[str]) -> dict:
        """
        Update email addresses on existing security alert policies.
        Creates new notification channels if needed and updates all security alerts.
        """
        try:
            parent = f"projects/{project_id}"
            
            # 1. Create notification channels for new emails
            new_channel_ids = []
            for email in new_emails:
                try:
                    channel = monitoring_v3.NotificationChannel(
                        type_="email",
                        display_name=f"Security Alert - {email}",
                        labels={"email_address": email}
                    )
                    created = self.channel_client.create_notification_channel(
                        name=parent,
                        notification_channel=channel
                    )
                    new_channel_ids.append(created.name)
                    logger.info(f"Created notification channel for {email}")
                except exceptions.AlreadyExists:
                    # Find existing channel
                    channels = list(self.channel_client.list_notification_channels(name=parent))
                    for ch in channels:
                        if ch.type_ == "email" and ch.labels.get("email_address") == email:
                            new_channel_ids.append(ch.name)
                            break
                except Exception as e:
                    logger.error(f"Failed to create channel for {email}: {e}")
            
            if not new_channel_ids:
                return {"success": False, "error": "No notification channels created"}
            
            # 2. Update all security alert policies with new channels
            policies = list(self.alert_client.list_alert_policies(request={"name": parent}))
            security_policies = [p for p in policies if p.display_name.startswith("Security Alert:")]
            
            updated_count = 0
            for policy in security_policies:
                try:
                    policy.notification_channels = new_channel_ids
                    self.alert_client.update_alert_policy(alert_policy=policy)
                    updated_count += 1
                except Exception as e:
                    logger.error(f"Failed to update policy {policy.display_name}: {e}")
            
            return {
                "success": True,
                "channels_created": len(new_channel_ids),
                "policies_updated": updated_count
            }
            
        except Exception as e:
            logger.error(f"Failed to update alert emails: {e}")
            return {"success": False, "error": str(e)}

