
import csv
import io
import logging
from typing import Dict, Any, List
from app.services.billing_history_service import BillingHistoryService

logger = logging.getLogger(__name__)

class BillingCsvParser:
    """
    Parses GCP Billing Cost Table CSV exports.
    Supports the standard format downloaded from:
    Billing > Cost Management > Cost Table > Download CSV
    """
    
    def __init__(self, history_service: BillingHistoryService):
        self.history_service = history_service
        
    def parse_and_store(self, csv_content: str) -> Dict[str, Any]:
        """
        Parse CSV content and update local history.
        Expected columns: "Project ID", "Total cost", "Currency", or similar variations.
        """
        try:
            # GCP CSVs can have inconsistent headers depending on view settings.
            # We look for key columns.
            reader = csv.DictReader(io.StringIO(csv_content))
            
            # Normalize headers (lowercase, strip)
            normalized_rows = []
            field_map = {}
            
            if not reader.fieldnames:
                return {"status": "error", "message": "Empty CSV"}
                
            for field in reader.fieldnames:
                lower = field.lower().strip()
                if "project id" in lower:
                    field_map["project_id"] = field
                elif "cost" in lower and "total" in lower:
                    field_map["cost"] = field
                elif "cost" in lower and "amount" in lower: # usage report
                    field_map["cost"] = field
                elif "currency" in lower:
                    field_map["currency"] = field
                elif "month" in lower: # usage report
                     field_map["month"] = field

            logger.info(f"CSV Headers mapped: {field_map}")
            
            if "project_id" not in field_map or "cost" not in field_map:
                return {
                    "status": "error", 
                    "message": "Could not identify 'Project ID' or 'Total cost' columns. Please export the 'Cost Table' CSV from GCP Billing."
                }
            
            updates = 0
            
            for row in reader:
                project_id = row.get(field_map["project_id"])
                
                # Clean cost string (remove currency symbols, commas)
                cost_str = row.get(field_map["cost"], "0")
                # Handle "$1,234.56" -> 1234.56
                import re
                cost_clean = re.sub(r'[^\d.-]', '', cost_str)
                
                try:
                    cost = float(cost_clean)
                except ValueError:
                    continue
                    
                if project_id and cost > 0:
                    # Determine period
                    # If CSV has "Month" column (e.g. 2023-01), use it.
                    # Else, assume valid for extraction time (Cost Table usually represents the viewed period)
                    period_start = "Unknown"
                    period_end = "Unknown"
                    
                    if "month" in field_map:
                         month_val = row.get(field_map["month"]) # e.g. "2023-01"
                         period_start = f"{month_val}-01"
                         period_end = "End of Month"
                    
                    # Update local DB
                    # Note: We append/overwrite based on the CSV data
                    self.history_service.update_spend(
                        project_id=project_id,
                        amount=cost,
                        period_start=period_start,
                        period_end=period_end
                    )
                    updates += 1
            
            return {
                "status": "success",
                "updates_processed": updates,
                "message": f"Successfully processed {updates} billing records."
            }
            
        except Exception as e:
            logger.error(f"Failed to parse CSV: {e}")
            return {"status": "error", "message": f"Parse error: {str(e)}"}
