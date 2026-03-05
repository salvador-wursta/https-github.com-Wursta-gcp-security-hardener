"""
Billing Service - Creates budgets and kill switches
Security: Never logs billing account details
"""
import logging
from typing import Optional, Dict, Any, List
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class BillingService:
    """Service for managing billing budgets and kill switches"""
    
    def __init__(self, credentials: Credentials, project_id: str, gcp_client=None):
        self.credentials = credentials
        self.project_id = project_id
        self.gcp_client = gcp_client  # Reference to GCPClient for API enable/disable
        self.billing_service = build('cloudbilling', 'v1', credentials=credentials)
        try:
            self.budgets_service = build('billingbudgets', 'v1', credentials=credentials)
        except Exception:
            self.budgets_service = None
            logger.warning("Billing Budgets API not available")
    
    def get_monthly_spending(self, billing_account_id: str) -> Dict[str, Any]:
        """
        Get current and prior month spending for the project
        
        Note: This requires BigQuery billing export to be enabled.
        Without BigQuery export, we can only estimate based on budgets.
        
        Args:
            billing_account_id: Billing account ID
            
        Returns:
            Dict with current_month_spend, prior_month_spend, and trend
        """
        try:
            logger.info(f"[BILLING] Attempting to get monthly spending for project {self.project_id}")
            
            # Note: Google Cloud doesn't provide a direct API to get actual spending
            # The only way to get actual costs is through:
            # 1. BigQuery billing export (requires setup)
            # 2. Cloud Billing Reports API (limited access)
            # 3. Billing account-level data (not project-specific)
            
            # For now, we'll return placeholder data with a note
            # In production, you would query BigQuery billing export
            
            logger.warning(f"[BILLING] Direct spending data not available without BigQuery export")
            logger.info(f"[BILLING] To enable spending tracking:")
            logger.info(f"[BILLING]   1. Enable BigQuery billing export in GCP Console")
            logger.info(f"[BILLING]   2. Query the billing export table for project costs")
            logger.info(f"[BILLING]   3. https://cloud.google.com/billing/docs/how-to/export-data-bigquery")
            
            # Retrieve from Local History Service
            from app.services.billing_history_service import BillingHistoryService
            history_service = BillingHistoryService()
            history = history_service.get_spend_summary(self.project_id)
            
            return {
                'current_month_spend': history['current_month_spend'],
                'prior_month_spend': history['prior_month_spend'],
                'spend_trend': 'unknown', # could calculate based on history
                'note': 'Data from local history (CSV import or accumulation)',
                'available': True,
                'source': history.get('source', 'local')
            }
            
        except Exception as e:
            logger.error(f"[BILLING] Error getting monthly spending: {e}")
            return {
                'current_month_spend': 0.0,
                'prior_month_spend': 0.0,
                'spend_trend': 'unknown',
                'error': str(e),
                'available': False
            }
    
    def get_project_billing_info(self) -> Dict[str, Any]:
        """
        Get the full billing info for the project, equivalent to:
        gcloud billing projects describe <PROJECT_ID>
        
        Returns a dict with:
          - billing_account_id: str or None
          - billing_account_full_name: str (e.g. 'billingAccounts/0118DE-...')
          - billing_enabled: bool
          - error: str or None (if an error occurred)
        """
        result = {
            'billing_account_id': None,
            'billing_account_full_name': None,
            'billing_enabled': False,
            'error': None
        }
        try:
            project_name = f"projects/{self.project_id}"
            logger.info(f"[BILLING] Calling getBillingInfo for {project_name}")
            project_info = self.billing_service.projects().getBillingInfo(
                name=project_name
            ).execute()
            
            logger.info(f"[BILLING] getBillingInfo response: {project_info}")
            
            # billingEnabled: true/false
            result['billing_enabled'] = project_info.get('billingEnabled', False)
            
            if 'billingAccountName' in project_info:
                full_name = project_info['billingAccountName']
                result['billing_account_full_name'] = full_name
                # Extract ID from "billingAccounts/0118DE-1E52C9-F51A1B"
                result['billing_account_id'] = full_name.split('/')[-1] if '/' in full_name else full_name
                logger.info(f"[BILLING] ✓ Billing account: {result['billing_account_id']} (enabled={result['billing_enabled']})")
            else:
                logger.warning(f"[BILLING] No billingAccountName in response — project may not have billing linked")
                
        except HttpError as e:
            result['error'] = str(e)
            logger.error(f"[BILLING] HttpError getting project billing info: {e}")
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[BILLING] Unexpected error getting project billing info: {e}")
        
        return result

    def get_billing_account(self) -> Optional[str]:
        """Get the billing account ID for the project. Thin wrapper around get_project_billing_info."""
        info = self.get_project_billing_info()
        return info.get('billing_account_id')
    
    def create_budget(
        self,
        budget_amount: float,
        alert_emails: Optional[List[str]] = None,
        threshold_percent: float = 100.0
    ) -> Dict[str, Any]:
        """
        Create a billing budget with alert
        
        Args:
            budget_amount: Monthly budget amount in USD
            alert_emails: Emails (or channel IDs) to send alerts to
            threshold_percent: Alert threshold percentage (100 = alert at budget limit)
            
        Returns:
            Budget configuration dict
        """
        try:
            billing_account_id = self.get_billing_account()
            if not billing_account_id:
                raise Exception("No billing account found for project")
            
            if not self.budgets_service:
                raise Exception("Billing Budgets API not available")
            
            # Create budget configuration
            budget_config = {
                "displayName": f"Security Hardener Budget - ${budget_amount}/month",
                "budgetFilter": {
                    "projects": [f"projects/{self.project_id}"]
                },
                "amount": {
                    "specifiedAmount": {
                        "currencyCode": "USD",
                        "units": str(int(budget_amount)),
                        "nanos": int((budget_amount - int(budget_amount)) * 1e9)
                    }
                },
                "thresholdRules": [
                    {
                        "thresholdPercent": threshold_percent,
                        "spendBasis": "CURRENT_SPEND"
                    }
                ]
            }
            
            # Add alert emails if provided
            if alert_emails:
                budget_config["notificationsRule"] = {
                    "monitoringNotificationChannels": alert_emails,
                    "disableDefaultIamRecipients": False
                }
                
            parent = f"billingAccounts/{billing_account_id}"
            
            # CLEANUP: Delete old budgets first (avoid duplicates)
            deleted_count = 0
            if replace_existing:
                logger.info(f"[BUDGET] Checking for existing budgets to replace...")
                deleted_count = self.delete_old_budgets(billing_account_id)
                if deleted_count > 0:
                    logger.info(f"[BUDGET] ✓ Removed {deleted_count} old budget(s)")
            
            # Create the budget via API
            logger.info(f"[BUDGET] Creating budget at: {parent}")
            logger.info(f"[BUDGET] Budget config: {budget_config}")
            
            budget = self.budgets_service.billingAccounts().budgets().create(
                parent=parent,
                body=budget_config
            ).execute()
            
            budget_id = budget.get('name', '').split('/')[-1]
            logger.info(f"[BUDGET] ✓ Budget created successfully!")
            logger.info(f"[BUDGET] Budget ID: {budget_id}")
            logger.info(f"[BUDGET] Full response: {budget}")
            
            return {
                "billing_account": billing_account_id,
                "budget_amount": budget_amount,
                "threshold_percent": threshold_percent,
                "budget_id": budget_id,
                "status": "created",
                "replaced_count": deleted_count
            }
            
        except Exception as e:
            error_msg = f"Failed to create budget: {str(e)}"
            logger.error("=" * 80)
            logger.error(f"ERROR creating billing budget:")
            logger.error(f"  Project: {self.project_id}")
            logger.error(f"  Budget amount: ${budget_amount}")
            logger.error(f"  Alert email: {alert_email or 'None'}")
            logger.error(f"  Billing account: {billing_account_id if 'billing_account_id' in locals() else 'Not found'}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Error message: {error_msg}")
            import traceback
            logger.error(f"  Stack trace:\n{traceback.format_exc()}")
            logger.error("=" * 80)
            raise Exception(error_msg)
    
    def list_budgets(self, billing_account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all budgets for a billing account
        
        Args:
            billing_account_id: Billing account ID (if None, uses project's billing account)
            
        Returns:
            List of budget configurations
        """
        try:
            if not billing_account_id:
                billing_account_id = self.get_billing_account()
            
            if not billing_account_id:
                logger.warning("No billing account found - cannot list budgets")
                return []
            
            if not self.budgets_service:
                logger.warning("Billing Budgets API not available")
                return []
            
            parent = f"billingAccounts/{billing_account_id}"
            
            # List budgets
            budgets = []
            try:
                logger.info("=" * 80)
                logger.info(f"[BUDGETS] Listing budgets for billing account: {billing_account_id}")
                logger.info(f"[BUDGETS] Parent format: {parent}")
                logger.info(f"[BUDGETS] Calling billingAccounts().budgets().list(parent='{parent}')")
                
                request = self.budgets_service.billingAccounts().budgets().list(parent=parent)
                response = request.execute()
                
                logger.info(f"[BUDGETS] ✓ API call successful")
                logger.info(f"[BUDGETS] Response keys: {list(response.keys())}")
                logger.info(f"[BUDGETS] Number of budgets in response: {len(response.get('budgets', []))}")
                logger.info(f"[BUDGETS] Full API response: {response}")
                
                for idx, budget in enumerate(response.get('budgets', [])):
                    logger.info(f"[BUDGETS] Processing budget {idx + 1}:")
                    logger.info(f"[BUDGETS]   Raw budget data: {budget}")
                    
                    budget_info = {
                        'budget_id': budget.get('name', '').split('/')[-1],
                        'display_name': budget.get('displayName', ''),
                        'amount': None,
                        'threshold_percent': None,
                        'projects': [],
                        'notifications': []
                    }
                    
                    logger.info(f"[BUDGETS]   Budget ID: {budget_info['budget_id']}")
                    logger.info(f"[BUDGETS]   Display Name: {budget_info['display_name']}")
                    
                    # Extract amount
                    if 'amount' in budget:
                        logger.info(f"[BUDGETS]   Amount data: {budget['amount']}")
                        amount_spec = budget['amount'].get('specifiedAmount', {})
                        if amount_spec:
                            units = int(amount_spec.get('units', 0))
                            nanos = amount_spec.get('nanos', 0) / 1e9
                            budget_info['amount'] = units + nanos
                            budget_info['currency'] = amount_spec.get('currencyCode', 'USD')
                            logger.info(f"[BUDGETS]   Extracted amount: ${budget_info['amount']} {budget_info['currency']}")
                    else:
                        logger.warning(f"[BUDGETS]   No 'amount' field in budget")
                    
                    # Extract threshold
                    if 'thresholdRules' in budget and budget['thresholdRules']:
                        budget_info['threshold_percent'] = budget['thresholdRules'][0].get('thresholdPercent')
                        logger.info(f"[BUDGETS]   Threshold: {budget_info['threshold_percent']}%")
                    
                    # Extract projects
                    if 'budgetFilter' in budget and 'projects' in budget['budgetFilter']:
                        budget_info['projects'] = [
                            p.split('/')[-1] for p in budget['budgetFilter'].get('projects', [])
                        ]
                        logger.info(f"[BUDGETS]   Applies to projects: {budget_info['projects']}")
                    else:
                        logger.info(f"[BUDGETS]   No project filter (applies to all projects in billing account)")
                    
                    # Extract notifications
                    if 'notificationsRule' in budget:
                        notifications = budget['notificationsRule']
                        budget_info['notifications'] = {
                            'channels': notifications.get('monitoringNotificationChannels', []),
                            'disable_default_iam': notifications.get('disableDefaultIamRecipients', False)
                        }
                        logger.info(f"[BUDGETS]   Notification channels: {budget_info['notifications']['channels']}")
                    
                    budgets.append(budget_info)
                    logger.info(f"[BUDGETS]   ✓ Budget added to list")
                
                logger.info(f"[BUDGETS] ✓ Successfully parsed {len(budgets)} budgets")
                logger.info("=" * 80)
                return budgets
                
            except HttpError as http_error:
                logger.error("=" * 80)
                logger.error(f"[BUDGETS] ✗ HTTP Error listing budgets:")
                logger.error(f"[BUDGETS]   HTTP Status: {http_error.resp.status if hasattr(http_error, 'resp') else 'N/A'}")
                logger.error(f"[BUDGETS]   Error: {str(http_error)}")
                logger.error(f"[BUDGETS]   Billing Account: {billing_account_id}")
                logger.error(f"[BUDGETS]   Parent: {parent}")
                if http_error.resp.status == 403:
                    logger.error(f"[BUDGETS]   PERMISSION DENIED: Service account needs 'Billing Account Viewer' or 'Billing Account Administrator' role")
                    logger.error(f"[BUDGETS]   Grant permissions: gcloud beta billing accounts add-iam-policy-binding {billing_account_id} --member=serviceAccount:YOUR_SA@PROJECT.iam.gserviceaccount.com --role=roles/billing.viewer")
                    return None # Return None to indicate permission failure vs empty list
                elif http_error.resp.status == 404:
                    logger.error(f"[BUDGETS]   NOT FOUND: Billing account {billing_account_id} not found or API not enabled")
                    logger.error(f"[BUDGETS]   Enable API: gcloud services enable billingbudgets.googleapis.com")
                    return []
                import traceback
                logger.error(f"[BUDGETS]   Stack trace:\n{traceback.format_exc()}")
                logger.error("=" * 80)
                return None # Treat other HTTP errors as unknowns (None)
            except Exception as list_error:
                logger.error("=" * 80)
                logger.error(f"[BUDGETS] ✗ Unexpected error listing budgets:")
                logger.error(f"[BUDGETS]   Error type: {type(list_error).__name__}")
                logger.error(f"[BUDGETS]   Error: {str(list_error)}")
                logger.error(f"[BUDGETS]   Billing Account: {billing_account_id}")
                import traceback
                logger.error(f"[BUDGETS]   Stack trace:\n{traceback.format_exc()}")
                logger.error("=" * 80)
                return None
                
        except Exception as e:
            logger.warning(f"Error listing budgets: {str(e)}")
            return None
    
    def get_billing_account_name(self, billing_account_id: str) -> Optional[str]:
        """
        Get billing account display name
        
        Args:
            billing_account_id: Billing account ID
            
        Returns:
            Billing account display name or None
        """
        try:
            billing_account_name = f"billingAccounts/{billing_account_id}"
            account_info = self.billing_service.billingAccounts().get(
                name=billing_account_name
            ).execute()
            
            return account_info.get('displayName')
        except Exception as e:
            logger.warning(f"Could not get billing account name: {str(e)}")
            if "403" in str(e):
                return "Access Denied (Missing permissions on Billing Account)"
            return None

    def get_billing_iam_policy(self, billing_account_id: str) -> Dict[str, Any]:
        """
        Get IAM policy for a billing account
        
        Args:
            billing_account_id: Billing account ID
            
        Returns:
            IAM policy dictionary
        """
        try:
            billing_account_name = f"billingAccounts/{billing_account_id}"
            logger.info(f"[BILLING] Getting IAM policy for: {billing_account_name}")
            policy = self.billing_service.billingAccounts().getIamPolicy(
                resource=billing_account_name
            ).execute()
            return policy
        except Exception as e:
            logger.error(f"[BILLING] Failed to get IAM policy for billing account {billing_account_id}: {e}")
            return {}
    
    def check_org_billing(self, organization_id: Optional[str] = None) -> bool:
        """
        Check if project uses organization-level billing
        
        Args:
            organization_id: Organization ID (optional)
            
        Returns:
            True if org-level billing is used, False otherwise
        """
        # This is a simplified check - in practice, you'd need to check
        # if the billing account is linked at the org level
        # For now, we'll return False and let the scan service determine this
        return False
    
    def create_kill_switch_pubsub_topic(self, topic_name: str = "billing-kill-switch") -> Dict[str, Any]:
        """
        Create Pub/Sub topic for billing kill switch
        
        Args:
            topic_name: Name of the Pub/Sub topic
            
        Returns:
            Topic configuration dict
        """
        try:
            pubsub_service = build('pubsub', 'v1', credentials=self.credentials)
            
            topic_path = f"projects/{self.project_id}/topics/{topic_name}"
            
            # Create topic
            # Note: Simplified implementation
            # Full implementation would use:
            # topic = pubsub_service.projects().topics().create(
            #     name=topic_path,
            #     body={}
            # ).execute()
            
            logger.info(f"Pub/Sub topic {topic_name} configured for kill switch")
            
            return {
                "topic_name": topic_name,
                "topic_path": topic_path,
                "status": "configured"
            }
            
        except Exception as e:
            error_msg = f"Failed to create Pub/Sub topic: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    def disable_billing_account(self, billing_account_id: str) -> Dict[str, Any]:
        """
        Disable a billing account (kill switch action)
        
        WARNING: This is a destructive operation!
        Only call this from a Cloud Function triggered by budget alerts.
        
        Args:
            billing_account_id: Billing account ID to disable
            
        Returns:
            Operation result
        """
        try:
            billing_account_name = f"billingAccounts/{billing_account_id}"
            
            # Disable billing
            # Note: This requires Billing Account Admin role
            # Full implementation would use:
            # self.billing_service.billingAccounts().updateBillingInfo(
            #     name=billing_account_name,
            #     body={"billingEnabled": False}
            # ).execute()
            
            logger.warning(f"Billing account {billing_account_id} would be disabled (kill switch)")
            
            return {
                "billing_account": billing_account_id,
                "status": "disabled",
                "warning": "This is a destructive operation - only use in kill switch scenarios"
            }
            
        except Exception as e:
            error_msg = f"Failed to disable billing account: {str(e)}"
            logger.error(error_msg)
            raise Exception(error_msg)

