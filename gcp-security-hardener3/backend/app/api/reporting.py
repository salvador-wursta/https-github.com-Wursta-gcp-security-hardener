"""
Reporting API — PDF Generation (Two-Step Server-Side Download)

Architecture:
  Step 1: POST /generate-pdf  → generates PDF, saves to /tmp/<uuid>.pdf, returns {"download_id": "<uuid>"}
  Step 2: GET  /download/<download_id> → browser navigates here directly → native file download

This eliminates all browser-side blob/URL.createObjectURL/header issues that caused
the "weird file" problem. Browser native download is always reliable.
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse, FileResponse
from typing import List, Dict, Any, Optional
from app.services.reporting_service import ReportingService
import logging
import io
import os
import uuid
import tempfile

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Temp file registry: download_id → file path ──────────────────────────────
# Simple in-memory map; files are cleaned up after one download or after 10 min.
_pending_downloads: Dict[str, str] = {}


@router.post("/generate-pdf")
async def generate_pdf(
    scan_results: List[Dict[str, Any]],
    org_name: Optional[str] = Query(default=""),
    analyst_name: Optional[str] = Query(default=""),
):
    """
    Step 1: Generate the PDF and save it to a temp file.
    Returns a JSON object with a download_id the frontend uses
    to trigger the actual file download via a GET request.

    No JIT session required — scan data comes in the request body.
    """
    if not scan_results:
        raise HTTPException(status_code=400, detail="No scan results provided.")

    try:
        service = ReportingService()
        pdf_bytes = service.generate_pdf_report(
            scan_results,
            org_name=org_name or "",
            analyst_name=analyst_name or "",
        )

        from datetime import datetime
        date_str = datetime.utcnow().strftime('%Y%m%d')
        filename = f"gcp_security_report_{date_str}.pdf"

        # Save to a uniquely-named temp file
        download_id = str(uuid.uuid4())
        tmp_path = os.path.join(tempfile.gettempdir(), f"gcp_report_{download_id}.pdf")
        with open(tmp_path, "wb") as f:
            f.write(pdf_bytes)

        _pending_downloads[download_id] = (tmp_path, filename)
        logger.info(f"[reporting] PDF ready: {filename} ({len(pdf_bytes)} bytes) | id={download_id}")

        return {"download_id": download_id, "filename": filename, "size": len(pdf_bytes)}

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"[reporting] PDF generation failed: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@router.get("/download/{download_id}")
async def download_pdf(download_id: str):
    """
    Step 2: Serve the pre-generated PDF using the browser's native file download.
    The frontend navigates to this URL (window.open or anchor href) — no fetch(), no blob.
    """
    entry = _pending_downloads.get(download_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Download not found or already downloaded.")

    tmp_path, filename = entry

    if not os.path.exists(tmp_path):
        _pending_downloads.pop(download_id, None)
        raise HTTPException(status_code=404, detail="PDF file no longer exists on server.")

    # Remove from registry so it can't be downloaded twice (clean up after use)
    _pending_downloads.pop(download_id, None)

    logger.info(f"[reporting] Serving download: {filename} from {tmp_path}")

    return FileResponse(
        path=tmp_path,
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Legacy streaming endpoint (kept for backward compatibility) ───────────────
@router.post("/generate-pdf-stream")
async def generate_pdf_stream(
    scan_results: List[Dict[str, Any]],
    org_name: Optional[str] = Query(default=""),
    analyst_name: Optional[str] = Query(default=""),
):
    """Kept for compatibility. Prefer /generate-pdf + /download/<id>."""
    if not scan_results:
        raise HTTPException(status_code=400, detail="No scan results provided.")
    try:
        service = ReportingService()
        pdf_bytes = service.generate_pdf_report(scan_results, org_name=org_name or "", analyst_name=analyst_name or "")
        from datetime import datetime
        filename = f"gcp_security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
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
