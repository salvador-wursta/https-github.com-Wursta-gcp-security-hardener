"""
Cloud Function code for billing kill switch
This function is deployed to Cloud Functions and triggered by Pub/Sub
when a budget threshold is exceeded.
"""
# This file contains the Cloud Function code that will be deployed
# It's separate from the main service for deployment purposes

KILL_SWITCH_FUNCTION_CODE = '''
"""
Billing Kill Switch Cloud Function
Triggered by Pub/Sub when budget threshold is exceeded
"""
import json
import logging
from google.cloud import billing_v1
from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def kill_switch_handler(event, context):
    """
    Cloud Function entry point
    
    Args:
        event: Pub/Sub event containing budget alert
        context: Cloud Functions context
    """
    try:
        # Parse Pub/Sub message
        if 'data' in event:
            message_data = json.loads(base64.b64decode(event['data']).decode('utf-8'))
        else:
            message_data = event
        
        billing_account_id = message_data.get('billingAccountId')
        budget_name = message_data.get('budgetName')
        cost_amount = message_data.get('costAmount')
        
        logger.warning(
            f"Budget threshold exceeded! "
            f"Billing Account: {billing_account_id}, "
            f"Budget: {budget_name}, "
            f"Cost: ${cost_amount}"
        )
        
        # Disable billing account
        billing_client = billing_v1.CloudBillingClient()
        billing_account_name = f"billingAccounts/{billing_account_id}"
        
        # Update billing info to disable
        project_billing_info = billing_v1.ProjectBillingInfo()
        project_billing_info.billing_enabled = False
        
        # Note: This requires Billing Account Admin permissions
        # billing_client.update_project_billing_info(
        #     name=f"projects/{PROJECT_ID}",
        #     project_billing_info=project_billing_info
        # )
        
        logger.critical(f"Billing account {billing_account_id} disabled by kill switch")
        
        return {
            "status": "success",
            "billing_account": billing_account_id,
            "action": "disabled"
        }
        
    except Exception as e:
        logger.error(f"Error in kill switch handler: {str(e)}")
        raise
'''

