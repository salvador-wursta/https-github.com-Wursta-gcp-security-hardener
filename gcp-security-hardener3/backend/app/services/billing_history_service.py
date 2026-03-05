"""
Billing History Service
Manage local storage of billing data retrieved via Pub/Sub or manual input.
Proposed solution for "Local Database" tracking without BigQuery.
"""
import json
import os
import logging
from datetime import datetime, date
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)

class BillingHistoryService:
    DB_FILE = "data/billing_history.json"
    
    def __init__(self):
        self._ensure_db_exists()
        
    def _ensure_db_exists(self):
        """Initialize the local JSON database"""
        Path("data").mkdir(exist_ok=True)
        if not os.path.exists(self.DB_FILE):
             with open(self.DB_FILE, 'w') as f:
                 json.dump({
                     "projects": {},
                     "meta": {
                         "created_at": datetime.utcnow().isoformat(),
                         "note": "Local billing storage for Security Hardener"
                     }
                 }, f, indent=2)

    def _load_db(self) -> Dict[str, Any]:
        try:
            with open(self.DB_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load billing history: {e}")
            return {"projects": {}}

    def _save_db(self, db: Dict[str, Any]):
        try:
            with open(self.DB_FILE, 'w') as f:
                json.dump(db, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save billing history: {e}")

    def update_spend(self, project_id: str, amount: float, period_start: str, period_end: str, currency: str = "USD"):
        """
        Update spend record for a specific period.
        Logic: Always keep the HIGHEST amount seen for a given period (since spend accumulates).
        """
        db = self._load_db()
        
        if project_id not in db["projects"]:
            db["projects"][project_id] = {"periods": []}
            
        periods = db["projects"][project_id]["periods"]
        
        # Check if period exists
        found = False
        for p in periods:
            # Match strictly by dates? Or just "Month"?
            # Since budgets are usually monthly, let's look for matching start/end
            if p["period_start"] == period_start and p["period_end"] == period_end:
                 # Update if new amount is stored (or if identical, just update timestamp)
                 # We assume spend only goes UP during the month.
                 if amount > p["amount"]:
                     p["amount"] = amount
                     p["last_updated"] = datetime.utcnow().isoformat()
                 found = True
                 break
        
        if not found:
            periods.append({
                "period_start": period_start,
                "period_end": period_end,
                "amount": amount,
                "currency": currency,
                "last_updated": datetime.utcnow().isoformat()
            })
            
        # Sort periods by date
        periods.sort(key=lambda x: x["period_start"], reverse=True)
        
        db["projects"][project_id]["periods"] = periods
        self._save_db(db)
        logger.info(f"Updated local billing history for {project_id}: ${amount} ({period_start} to {period_end})")

    def get_spend_summary(self, project_id: str) -> Dict[str, Any]:
        """
        Get current and prior month spend from local history.
        """
        db = self._load_db()
        if project_id not in db["projects"]:
            # Fallback for new projects
            return {
                "current_month_spend": 0.0,
                "prior_month_spend": 0.0,
                "source": "empty_local_db"
            }
            
        periods = db["projects"][project_id]["periods"]
        if not periods:
            return {
                "current_month_spend": 0.0,
                "prior_month_spend": 0.0,
                "source": "empty_periods"
            }

        # Determine "Current" and "Prior" based on today's date
        today = date.today()
        # Simple heuristic: Current is period containing Today. Prior is period before that.
        
        current_spend = 0.0
        prior_spend = 0.0
        
        # Assuming periods are sorted desc (newest first)
        for p in periods:
            # In a real app, parse ISO dates. For prototype, we'll blindly take:
            # Index 0 as current (if recent), Index 1 as prior.
            pass
            
        # Better: Filter by current YYYY-MM
        current_month_str = today.strftime("%Y-%m")
        # Calc prior month
        if today.month == 1:
            prior_month_str = f"{today.year-1}-12"
        else:
            prior_month_str = f"{today.year}-{today.month-1:02d}"
            
        # Find matches
        # Note: Budget dates are usually full dates "2026-01-01", but let's assume we store them standardly
        for p in periods:
            if p["period_start"].startswith(current_month_str):
                current_spend = max(current_spend, p["amount"])
            elif p["period_start"].startswith(prior_month_str):
                prior_spend = max(prior_spend, p["amount"])
                
        return {
            "current_month_spend": current_spend,
            "prior_month_spend": prior_spend,
            "source": "local_db"
        }

    def process_pubsub_message(self, message_data: Dict[str, Any]):
        """
        Ingest a Pub/Sub Budget Notification message.
        """
        # Format: { "budgetDisplayName": "...", "costAmount": 10.5, "costIntervalStart": "...", ... }
        try:
            # We need to link Budget -> Project. The message contains 'budgetDisplayName' but not ProjectID explicitly usually?
            # Actually, standard Cloud Billing Budget Notifications payload:
            # {
            #   "budgetDisplayName": "My Budget",
            #   "alertThresholdExceeded": 1.0,
            #   "costAmount": 100.00,
            #   "costIntervalStart": "2023-01-01T00:00:00Z",
            #   "budgetAmount": 100.00,
            #   "budgetAmountType": "SPECIFIED_AMOUNT",
            #   "currencyCode": "USD"
            # }
            # It DOES NOT provide Project ID natively if the budget is for multiple projects.
            # WORKAROUND: We assume the Budget Display Name contains the Project ID if we created it.
            # e.g. "Security Hardener Budget - my-project-id - $100"
            
            display_name = message_data.get("budgetDisplayName", "")
            cost = message_data.get("costAmount", 0.0)
            start = message_data.get("costIntervalStart", "")
            # End is not provided, usually implies 'Now' or 'End of Month'?
            
            # Extract Project ID from name (Weak link, but necessary without BQ)
            # We'll need to enforce naming convention.
            project_id = None
            if " - " in display_name:
                 # Try to parse our format
                 parts = display_name.split(" - ")
                 # Look for something that looks like a project id
                 # This is heuristic.
                 pass
            
            if not project_id:
                logger.warning(f"Could not derive Project ID from budget name: {display_name}")
                return

            self.update_spend(project_id, cost, start, "End of Month")
            
        except Exception as e:
            logger.error(f"Error processing Pub/Sub message: {e}")

