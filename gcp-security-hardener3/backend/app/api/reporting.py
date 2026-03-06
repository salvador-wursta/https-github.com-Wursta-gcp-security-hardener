"""
Reporting API — PDF Generation (Single-Step Streaming)

Architecture:
  POST /generate-pdf → directly generates and streams the PDF back to the client.
  This avoids all Cloud Run multi-instance file-not-found issues that occur
  when saving to /tmp across Load Balancers.
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any, Optional
from app.services.reporting_service import ReportingService
import logging
import io

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/generate-pdf")
async def generate_pdf(
    scan_results: List[Dict[str, Any]],
    org_name: Optional[str] = Query(default=""),
    analyst_name: Optional[str] = Query(default=""),
):
    """
    Generate the PDF and synchronously stream it back to the client.
    No JIT session required — scan data comes in the request body.
    """
    if not scan_results:
        raise HTTPException(status_code=400, detail="No scan results provided.")
    try:
        service = ReportingService()
        pdf_bytes = service.generate_pdf_report(
            scan_results, 
            org_name=org_name or "", 
            analyst_name=analyst_name or ""
        )
        
        from datetime import datetime
        filename = f"gcp_security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        logger.info(f"[reporting] PDF streamed to client: {filename} ({len(pdf_bytes)} bytes)")
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        import traceback
        logger.error(f"[reporting] PDF generation/stream failed: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate")
async def generate_report(scan_results: List[Dict[str, Any]], project_id: str = None):
    """Generates a JSON executive report (not PDF)."""
    try:
        service = ReportingService()
        report = service.generate_report(scan_results)
        return report
    except Exception as e:
        import traceback
        logger.error(f"Report generation failed: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/download-artifacts")
async def download_artifacts(scan_results: List[Dict[str, Any]] = None, project_id: str = None):
    """Generates and downloads a ZIP file containing the report and remediation scripts."""
    try:
        if not scan_results:
            raise HTTPException(status_code=400, detail="No scan results provided or found.")
        service = ReportingService()
        zip_bytes = service.generate_remediation_kit_zip(scan_results)
        return StreamingResponse(
            io.BytesIO(zip_bytes),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=remediation_kit_{project_id or 'scan'}.zip"},
        )
    except Exception as e:
        logger.error(f"Artifact generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
