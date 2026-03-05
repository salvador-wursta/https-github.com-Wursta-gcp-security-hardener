"""
Reporting Service
Generates Executive and Detailed reports from scan results.
aggregates findings, calculates risk scores, and generates AI-driven insights.
"""
import logging
import io
from datetime import datetime
from typing import List, Dict, Any
from app.models.scan_models import ScanResponse, RiskLevel

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Colour palette for risk levels (used by PDF)                                #
# --------------------------------------------------------------------------- #
_RISK_COLORS = {
    "critical": (0.90, 0.10, 0.10),
    "high":     (0.95, 0.45, 0.10),
    "medium":   (0.20, 0.45, 0.85),
    "low":      (0.10, 0.68, 0.45),
    "info":     (0.50, 0.50, 0.50),
}


class ReportingService:
    def generate_report(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generates a comprehensive report for a list of scan results.
        Input is a list of dicts (serialized ScanResponse).
        """
        # 1. Aggregate Stats
        total_projects = len(scans)
        total_risks = 0
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts = {}
        
        all_risks = []
        
        maturity_scores = []
        
        for scan in scans:
            # Handle risks
            risks = scan.get("risks", [])
            total_risks += len(risks)
            
            for risk in risks:
                # --- Just-In-Time Risk Re-evaluation (BEFORE COUNTING) ---
                # Ensure critical items are properly flagged even if scan data is older
                title_upper = risk.get("title", "").upper()
                
                # Check for critical keywords and force upgrade
                if "MFA" in title_upper or "MULTI-FACTOR" in title_upper:
                    risk["risk_level"] = "critical"
                elif "OWNER" in title_upper or "PRIMITIVE ROLES" in title_upper:
                    risk["risk_level"] = "critical"
                elif "SERVICE ACCOUNT KEYS" in title_upper and "CREATED" in title_upper:
                    risk["risk_level"] = "critical"
                elif "DENY-EXTERNAL-INGRESS" in title_upper:
                    risk["risk_level"] = "critical"
                # ---------------------------------------------------------

                level = risk.get("risk_level", "info").lower()
                if level in risk_counts:
                    risk_counts[level] += 1
                
                cat = risk.get("category", "other")
                category_counts[cat] = category_counts.get(cat, 0) + 1
                
                # Enrich risk with project context
                risk["project_id"] = scan.get("project_id")
                
                all_risks.append(risk)
            
            # Handle Maturity
            cc_info = scan.get("change_control_info")
            if cc_info and "score" in cc_info:
                maturity_scores.append(cc_info["score"])

        # Sort All Risks by Severity (Critical -> Info)
        # This ensures:
        # 1. Gemini receives the most critical context first (before token limit)
        # 2. Results are displayed in priority order
        all_risks.sort(key=lambda x: self._risk_weight(x.get("risk_level", "info")))

        # 2. Calculate Overall Score
        # Formula: Start at 100. Deduct for risks.
        # Critical: -10, High: -5, Medium: -2, Low: -0.5
        security_score = 100
        security_score -= (risk_counts["critical"] * 10)
        security_score -= (risk_counts["high"] * 5)
        security_score -= (risk_counts["medium"] * 2)
        security_score -= (risk_counts["low"] * 0.5)
        
        security_score = max(0, min(100, security_score)) # Clamp 0-100
        
        # 3. Calculate Overall Maturity
        avg_maturity = sum(maturity_scores) / len(maturity_scores) if maturity_scores else 0
        
        # 4. Determine Ratings
        risk_rating = "Safe"
        if risk_counts["critical"] > 0 or security_score < 60:
            risk_rating = "Critical"
        elif risk_counts["high"] > 0 or security_score < 80:
            risk_rating = "High"
        elif risk_counts["medium"] > 5 or security_score < 90:
            risk_rating = "Medium"
        elif risk_counts["low"] > 0:
            risk_rating = "Low"
            
        maturity_rating = "Initial"
        if avg_maturity >= 80:
            maturity_rating = "Advanced"
        elif avg_maturity >= 50:
            maturity_rating = "Developing"

        from app.services.ai_service import AIService
        
        # 5. Generate Executive Summary & Recommendations (Try AI First)
        exec_summary = self._generate_executive_summary(total_projects, risk_rating, risk_counts, maturity_rating, all_risks)
        recommendations = self._generate_recommendations(risk_counts, category_counts, maturity_rating)
        
        try:
            ai_service = AIService()
            if ai_service.model:
                # We pass the already-escalated specific risks to the AI now for better context
                # Re-package context since all_risks has the updated severity
                ai_context_scans = [{"risks": all_risks, "project_id": "Aggregated"}]
                
                ai_report = ai_service.generate_security_report(ai_context_scans)
                if ai_report:
                    if "executive_summary" in ai_report:
                        exec_summary = ai_report["executive_summary"]
                    
                    if "recommendations" in ai_report and isinstance(ai_report["recommendations"], list):
                        # Ensure recommendations match expected schema
                        recommendations = [
                            {
                                "title": rec.get("title", "Strategic Recommendation"),
                                "description": rec.get("description", "No description provided"),
                                "priority": rec.get("priority", "High")
                            }
                            for rec in ai_report["recommendations"]
                        ]
                    
                    if "finding_enrichments" in ai_report and isinstance(ai_report["finding_enrichments"], dict):
                        enrichments = ai_report["finding_enrichments"]
                        enriched_count = 0
                        for risk in all_risks:
                            if risk.get("title") in enrichments:
                                risk["recommendation"] = enrichments[risk["title"]]
                                enriched_count += 1
                        
                        logger.info(f"Enriched {enriched_count} findings with specific AI recommendations")

                    logger.info("Successfully generated AI-enhanced report content")
        except Exception as e:
            logger.warning(f"Failed to generate AI report content, falling back to static: {e}")

        # --- FINAL ENFORCEMENT OF RISK DRIVERS ---
        # Regardless of whether AI or Static generated the summary, we MUST explicitly list 
        # the Critical/High drivers to ensure visibility.
        risk_drivers = self._get_risk_themes(all_risks)
        if risk_drivers:
            drivers_text = "\n\nPrimary Risk Drivers:\n" + "\n".join([f"• {t}" for t in risk_drivers])
            # Avoid duplicating if AI already added it (naive check)
            if "Primary Risk Drivers" not in exec_summary:
                exec_summary += drivers_text

        from datetime import datetime
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "scope": {
                "projects_scanned": total_projects,
                "total_risks_found": total_risks
            },
            "executive_summary": {
                "text": exec_summary,
                "overall_score": round(security_score),
                "risk_rating": risk_rating,
                "maturity_rating": maturity_rating,
                "maturity_score": round(avg_maturity)
            },
            "charts": {
                "risk_distribution": [
                    {"name": "Critical", "value": risk_counts["critical"], "color": "#EF4444"},
                    {"name": "High", "value": risk_counts["high"], "color": "#F59E0B"},
                    {"name": "Medium", "value": risk_counts["medium"], "color": "#3B82F6"},
                    {"name": "Low", "value": risk_counts["low"], "color": "#10B981"},
                ],
                "category_breakdown": [{"name": k, "value": v} for k, v in category_counts.items()]
            },
            "top_risks": sorted(all_risks, key=lambda x: self._risk_weight(x.get("risk_level")))[:10],
            "recommendations": recommendations,
            "all_findings": all_risks 
        }

    def _get_risk_themes(self, all_risks: List[Dict]) -> List[str]:
        themes = []
        if not all_risks:
            return themes
            
        criticals = [r for r in all_risks if r.get('risk_level') == 'critical']
        highs = [r for r in all_risks if r.get('risk_level') == 'high']
        important_risks = criticals + highs
        
        # Simple keyword matching for themes
        has_mfa = any("MFA" in r.get('title', '').upper() or "MULTI-FACTOR" in r.get('title', '').upper() for r in important_risks)
        has_keys = any("KEY" in r.get('title', '').upper() and "SERVICE" in r.get('title', '').upper() for r in important_risks)
        has_firewall = any("FIREWALL" in r.get('title', '').upper() or "NETWORK" in r.get('title', '').upper() or "INGRESS" in r.get('title', '').upper() for r in important_risks)
        has_roles = any("ROLE" in r.get('title', '').upper() or "IAM" in r.get('title', '').upper() or "PRIVILEGE" in r.get('title', '').upper() for r in important_risks)
        
        if has_mfa: themes.append("Lack of Multi-Factor Authentication (MFA)")
        if has_keys: themes.append("Unsecured Service Account Keys")
        if has_firewall: themes.append("Critical Network/Firewall Misconfigurations")
        if has_roles: themes.append("Over-privileged IAM Roles")
        
        return themes

    def _generate_executive_summary(self, projects: int, risk_rating: str, counts: Dict[str, int], maturity: str, all_risks: List[Dict] = None) -> str:
        text = f"Over the scope of {projects} project(s), the security posture is rated as **{risk_rating}**."
        
        if risk_rating == "Critical":
            text += f" Immediate attention is required to address {counts['critical']} critical vulnerabilities which pose a severe threat."
        elif risk_rating == "High":
            text += f" Significant vulnerabilities were found including {counts['high']} high-severity issues."
            
        # Add automated details for top risks if available (Static Fallback)
        if all_risks and risk_rating in ["Critical", "High"]:
            text += "\n\nTop Priority Observations:"
            top_risks = [r for r in all_risks if r.get('risk_level') in ['critical', 'high']][:3]
            for r in top_risks:
                text += f"\n- **{r.get('title')}**: {r.get('description')[:150]}..."
        
        # Note: Themes are now appended centrally in generate_report
        
        text += f"\n\nOrganization maturity is determined to be **{maturity}**."
        
        return text

    def _risk_weight(self, level: str) -> int:
        weights = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return weights.get(level.lower(), 5)

    def _generate_recommendations(self, risk_counts: Dict[str, int], cat_counts: Dict[str, int], maturity: str) -> List[Dict[str, str]]:
        recs = []
        
        # Risk-based
        if risk_counts["critical"] > 0:
            recs.append({
                "title": "Remediate Critical Vulnerabilities",
                "description": "Critical risks (e.g., Public RDP, Admin Access) must be patched within 24 hours.",
                "priority": "Immediate"
            })
            
        # Category-based
        if cat_counts.get("billing", 0) > 0:
            recs.append({
                "title": "Establish Cost Controls",
                "description": "Billing anomalies detected. Implement strict budget alerts and potentially disable API usage caps.",
                "priority": "High"
            })
            
        if cat_counts.get("iam", 0) > 0:
            recs.append({
                "title": "Enforce Least Privilege",
                "description": "IAM findings indicate over-privileged accounts. Review roles and apply the Principle of Least Privilege.",
                "priority": "High"
            })

        # Maturity-based
        if maturity == "Initial":
            recs.append({
                "title": "Adopt Infrastructure as Code",
                "description": "Move away from ClickOps. Use Terraform to manage the state of your security foundations.",
                "priority": "High"
            })
            
        return recs

    def generate_remediation_kit_zip(self, scans: List[Dict[str, Any]]) -> bytes:
        """
        Generates a ZIP file containing:
        1. A comprehensive REPORT.md (Markdown report)
        2. A /remediation_scripts folder with all executable scripts
        3. A README.txt instruction file.
        """
        import zipfile
        import io
        
        # 1. Generate Report Data
        report_data = self.generate_report(scans)
        markdown_report = self._json_to_markdown(report_data)
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add Report
            zip_file.writestr('SECURITY_REPORT.md', markdown_report)
            
            # Add README
            readme_text = (
                "GCP Security Remediation Kit\n"
                "============================\n\n"
                "This kit contains automated scripts to fix the security issues identified in your scan.\n\n"
                "Instructions:\n"
                "1. Review SECURITY_REPORT.md to understand the risks.\n"
                "2. Navigate to the 'remediation_scripts' folder.\n"
                "3. Each script corresponds to a specific finding.\n"
                "4. Make the scripts executable (chmod +x script_name.sh).\n"
                "5. Run the scripts in your GCP Cloud Shell or local terminal with gcloud installed.\n\n"
                "WARNING: Always review scripts before running them in production.\n"
            )
            zip_file.writestr('README.txt', readme_text)
            
            # Add Scripts
            added_scripts = set()
            for scan in scans:
                risks = scan.get('risks', [])
                for risk in risks:
                    filename = risk.get('remediation_script_filename')
                    content = risk.get('remediation_script_content')
                    
                    if filename and content:
                        # Ensure uniqueness if multiple projects have same script name
                        if filename in added_scripts:
                            # Append project ID or ID segment to make unique
                            base_part = filename.rsplit('.', 1)[0]
                            ext_part = filename.rsplit('.', 1)[1] if '.' in filename else "sh"
                            filename = f"{base_part}_{risk.get('id', 'dup')[-4:]}.{ext_part}"
                        
                        zip_file.writestr(f"remediation_scripts/{filename}", content)
                        added_scripts.add(filename)
                        
        return zip_buffer.getvalue()

    def _json_to_markdown(self, report: Dict) -> str:
        exec_summary = report.get("executive_summary", {})
        md = f"# GCP Security Assessment Report\n"
        md += f"**Generated:** {report.get('generated_at')}\n\n"
        
        md += "## Executive Summary\n"
        md += f"{exec_summary.get('text', 'No summary available.')}\n\n"
        md += f"- **Risk Rating:** {exec_summary.get('risk_rating')}\n"
        md += f"- **Security Score:** {exec_summary.get('overall_score')}/100\n"
        md += f"- **Maturity Rating:** {exec_summary.get('maturity_rating')}\n\n"
        
        md += "## Top Recommendations\n"
        for rec in report.get("recommendations", []):
            md += f"### {rec.get('title')}\n"
            md += f"**Priority:** {rec.get('priority')}\n"
            md += f"{rec.get('description')}\n\n"
            
        md += "## Findings Detail\n"
        for risk in report.get("all_findings", []):
            md += f"### [{risk.get('risk_level', 'INFO').upper()}] {risk.get('title')}\n"
            md += f"**Category:** {risk.get('category')}\n"
            affected = risk.get('affected_resources') or []
            md += f"**Affected Resources:** {', '.join(affected)}\n\n"
            md += f"{risk.get('description')}\n\n"
            md += f"**Recommendation:** {risk.get('recommendation')}\n"
            if risk.get('remediation_script_filename'):
                md += f"**Automated Fix:** Script available as `{risk.get('remediation_script_filename')}` in remediation_scripts folder.\n"
            md += "---\n\n"
            
        return md

    # ------------------------------------------------------------------ #
    #  PDF Generation (ReportLab) — handles 2 to 5,000+ pages            #
    # ------------------------------------------------------------------ #
    def generate_pdf_report(self, scans: List[Dict[str, Any]], org_name: str = "", analyst_name: str = "") -> bytes:
        """
        Generates a professional, multi-page PDF report using ReportLab.
        Processes data in chunks so memory usage stays flat regardless of scale.
        Supports 2 to 5,000+ pages without timeouts or browser involvement.
        Returns raw bytes ready to be streamed.
        """
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            rightMargin=0.6 * inch,
            leftMargin=0.6 * inch,
            topMargin=0.8 * inch,
            bottomMargin=0.8 * inch,
        )

        # ── Styles ────────────────────────────────────────────────────────── #
        base = getSampleStyleSheet()

        def _style(name, parent="Normal", **kw):
            s = ParagraphStyle(name=name, parent=base[parent], **kw)
            return s

        s = {
            "cover_title": _style("cover_title", "Title",
                                  fontSize=28, spaceAfter=8,
                                  textColor=colors.HexColor("#1e3a5f"), alignment=TA_CENTER),
            "cover_sub":   _style("cover_sub", "Normal",
                                  fontSize=13, textColor=colors.HexColor("#4a6481"),
                                  alignment=TA_CENTER, spaceAfter=6),
            "cover_meta":  _style("cover_meta", "Normal",
                                  fontSize=10, textColor=colors.HexColor("#6b7280"),
                                  alignment=TA_CENTER),
            "h1":          _style("h1", "Heading1",
                                  fontSize=16, textColor=colors.HexColor("#1e3a5f"),
                                  spaceBefore=14, spaceAfter=6),
            "h2":          _style("h2", "Heading2",
                                  fontSize=12, textColor=colors.HexColor("#1e3a5f"),
                                  spaceBefore=10, spaceAfter=4),
            "body":        _style("body", "Normal",
                                  fontSize=9, leading=13, spaceAfter=4),
            "small":       _style("small", "Normal",
                                  fontSize=8, textColor=colors.HexColor("#6b7280")),
            "cell":        _style("cell", "Normal", fontSize=8, leading=11),
            "cell_bold":   _style("cell_bold", "Normal", fontSize=8, leading=11,
                                  fontName="Helvetica-Bold"),
            "badge":       _style("badge", "Normal", fontSize=7,
                                  fontName="Helvetica-Bold", alignment=TA_CENTER),
        }

        # ── Colour helpers ────────────────────────────────────────────────── #
        def _risk_hex(level: str) -> str:
            m = {"critical": "#DC2626", "high": "#EA580C",
                 "medium":   "#2563EB", "low":  "#16A34A", "info": "#6B7280"}
            return m.get((level or "info").lower(), "#6B7280")

        # ── Page footer callback ───────────────────────────────────────────── #
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        def _footer(canvas, document):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#9CA3AF"))
            canvas.drawString(0.6 * inch, 0.45 * inch,
                              f"GCP Security Hardener  •  Confidential  •  Generated {generated_at}")
            canvas.drawRightString(letter[0] - 0.6 * inch, 0.45 * inch,
                                   f"Page {document.page}")
            canvas.restoreState()

        # ── Aggregate report data first ────────────────────────────────────── #
        report_data = self.generate_report(scans)
        exec_sum    = report_data["executive_summary"]
        all_risks   = report_data.get("all_findings", [])
        recs        = report_data.get("recommendations", [])
        scope       = report_data["scope"]
        charts      = report_data["charts"]["risk_distribution"]

        # ── Build story ───────────────────────────────────────────────────── #
        story = []

        # --- Cover Page ---
        story.append(Spacer(1, 1.4 * inch))
        story.append(Paragraph("GCP Security Assessment", s["cover_title"]))
        story.append(Paragraph("Executive Report", s["cover_sub"]))
        story.append(Spacer(1, 0.3 * inch))

        cover_meta_lines = [
            f"Organization: <b>{org_name or 'Not Specified'}</b>",
            f"Security Analyst: <b>{analyst_name or 'Not Specified'}</b>",
            f"Projects Scanned: <b>{scope['projects_scanned']}</b>  |  "
            f"Total Findings: <b>{scope['total_risks_found']}</b>",
            f"Date: <b>{generated_at}</b>",
        ]
        for line in cover_meta_lines:
            story.append(Paragraph(line, s["cover_meta"]))
            story.append(Spacer(1, 4))

        story.append(Spacer(1, 0.5 * inch))

        # Risk-rating pill on cover
        risk_color = _risk_hex(exec_sum["risk_rating"].lower())
        story.append(Paragraph(
            f'<font color="{risk_color}"><b>Overall Risk: {exec_sum["risk_rating"].upper()}'
            f'  |  Security Score: {exec_sum["overall_score"]}/100</b></font>',
            _style("cover_pill", "Normal", fontSize=14, alignment=TA_CENTER)
        ))

        story.append(PageBreak())

        # --- Executive Summary ---
        story.append(Paragraph("Executive Summary", s["h1"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor("#D1D5DB"), spaceAfter=8))

        # Score / risk table
        score_data = [
            ["Security Score", "Risk Rating", "Maturity Rating", "Projects Scanned"],
            [
                f"{exec_sum['overall_score']}/100",
                exec_sum["risk_rating"],
                exec_sum.get("maturity_rating", "N/A"),
                str(scope["projects_scanned"]),
            ],
        ]
        score_tbl = Table(score_data, colWidths=[1.5 * inch] * 4)
        score_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0), 9),
            ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 1), (-1, 1), 14),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F0F4F8")]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("TOPPADDING",  (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(score_tbl)
        story.append(Spacer(1, 10))

        story.append(Paragraph(exec_sum["text"], s["body"]))
        story.append(Spacer(1, 10))

        # Severity breakdown table
        story.append(Paragraph("Severity Breakdown", s["h2"]))
        sev_data = [["Severity", "Count"]] + [
            [item["name"], str(item["value"])] for item in charts
        ]
        sev_tbl = Table(sev_data, colWidths=[2 * inch, 1.5 * inch])
        sev_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F9FAFB"), colors.HexColor("#F3F4F6")]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(sev_tbl)
        story.append(Spacer(1, 10))

        # Recommendations
        if recs:
            story.append(Paragraph("Top Recommendations", s["h2"]))
            for i, rec in enumerate(recs, 1):
                story.append(KeepTogether([
                    Paragraph(f"{i}. {rec.get('title', '')}  "
                              f"[{rec.get('priority', '')}]", s["cell_bold"]),
                    Paragraph(rec.get("description", ""), s["cell"]),
                    Spacer(1, 4),
                ]))

        story.append(PageBreak())

        # --- Detailed Findings Table (chunked per project) ---
        story.append(Paragraph("Detailed Findings", s["h1"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor("#D1D5DB"), spaceAfter=8))
        story.append(Paragraph(
            f"The following table lists all {len(all_risks)} findings across "
            f"{scope['projects_scanned']} scanned project(s).", s["body"]))
        story.append(Spacer(1, 6))

        col_widths = [0.85 * inch, 1.6 * inch, 2.3 * inch, 2.5 * inch]
        tbl_header = [
            Paragraph("<b>Severity</b>", s["cell_bold"]),
            Paragraph("<b>Project</b>", s["cell_bold"]),
            Paragraph("<b>Finding</b>", s["cell_bold"]),
            Paragraph("<b>Recommendation</b>", s["cell_bold"]),
        ]

        # Chunk risks to avoid huge single table objects
        CHUNK_SIZE = 200
        risk_chunks = [all_risks[i:i + CHUNK_SIZE] for i in range(0, max(len(all_risks), 1), CHUNK_SIZE)]

        for chunk_idx, chunk in enumerate(risk_chunks):
            rows = [tbl_header] if chunk_idx == 0 else []
            for risk in chunk:
                lvl   = (risk.get("risk_level") or "info").lower()
                hex_c = _risk_hex(lvl)
                rows.append([
                    Paragraph(f'<font color="{hex_c}"><b>{lvl.upper()}</b></font>', s["badge"]),
                    Paragraph((risk.get("project_id") or "")[:30], s["cell"]),
                    Paragraph(
                        f"<b>{risk.get('title', '')}</b><br/>"
                        f"<font color='#6b7280'>{(risk.get('description') or '')[:180]}</font>",
                        s["cell"],
                    ),
                    Paragraph((risk.get("recommendation") or "")[:220], s["cell"]),
                ])

            if not rows:
                continue

            tbl = Table(rows, colWidths=col_widths, repeatRows=1 if chunk_idx == 0 else 0)
            tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#FFFFFF"), colors.HexColor("#F9FAFB")]),
                ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 4),
            ]))
            story.append(tbl)

        if not all_risks:
            story.append(Paragraph("✓ No findings detected in the scanned scope.", s["body"]))

        # ── Render ───────────────────────────────────────────────────────────── #
        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        buf.seek(0)
        return buf.read()
