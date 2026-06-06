"""
CyberGuard Pro - Consolidated PDF Report Compiler
=================================================
Compiles diagnostic outputs from all active security modules into a 
professional, standardized PDF document using fpdf2.
"""

import os
import datetime
import logging
from fpdf import FPDF

logger = logging.getLogger(__name__)

class CyberGuardPDF(FPDF):
    def header(self):
        # Top-left Branding
        self.set_font('helvetica', 'B', 15)
        self.set_text_color(41, 128, 185) # Corporate Blue
        self.cell(0, 10, 'CyberGuard Pro', border=0, align='L')
        
        # Top-right Subtitle
        self.set_font('helvetica', 'I', 10)
        self.set_text_color(128, 128, 128) # Gray
        self.cell(0, 10, 'Security Diagnostic Audit', border=0, align='R')
        
        self.ln(15)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')


def _flatten_to_text(data, indent=0) -> str:
    """
    Recursively converts nested dicts/lists into a readable plain-text block
    safe for fpdf multi_cell (no special control characters).
    """
    lines = []
    prefix = "  " * indent
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{prefix}{k}:")
                lines.append(_flatten_to_text(v, indent + 1))
            else:
                lines.append(f"{prefix}{k}: {v}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(_flatten_to_text(item, indent))
            else:
                lines.append(f"{prefix}- {item}")
    else:
        lines.append(f"{prefix}{data}")
    return "\n".join(lines)


def generate_report_route_data(session_data: dict) -> dict:
    """
    Reads both the JSON-string session keys (recon, network, etc.) AND the
    dict-object _results keys, converts all data to clean plain-text strings
    for the PDF generator.
    """
    import json
    formatted_data = {}

    # Map: short key used in session -> display label used in PDF
    target_modules = ['recon', 'network', 'threat', 'websec', 'forensics', 'phishing', 'passwords']

    for key in target_modules:
        # Prefer the dict form (_results key) for richer data
        results_key = f"{key}_results" if key != 'passwords' else 'password_results'
        raw_dict = session_data.get(results_key)

        if raw_dict and isinstance(raw_dict, dict):
            formatted_data[key] = _flatten_to_text(raw_dict)
            continue

        # Fall back to the JSON string key
        raw_str = session_data.get(key)
        if not raw_str:
            formatted_data[key] = None
            continue

        # Try parsing as JSON first, then flatten; otherwise use as-is
        try:
            parsed = json.loads(raw_str) if isinstance(raw_str, str) else raw_str
            if isinstance(parsed, (dict, list)):
                formatted_data[key] = _flatten_to_text(parsed)
            else:
                formatted_data[key] = str(raw_str).replace('\r', '').strip()
        except (json.JSONDecodeError, TypeError):
            formatted_data[key] = str(raw_str).replace('\r', '').strip()

    return formatted_data


def set_risk_color(pdf, risk_level):
    """Utility to dynamically set the PDF text color based on threat severity."""
    level = str(risk_level).upper()
    if level in ['CRITICAL', 'HIGH']:
        pdf.set_text_color(220, 53, 69) # Bootstrap Danger Red
    elif level == 'MEDIUM':
        pdf.set_text_color(253, 126, 20) # Bootstrap Warning Orange
    elif level in ['LOW', 'NONE', 'SAFE', 'CLEAN']:
        pdf.set_text_color(25, 135, 84) # Bootstrap Success Green
    else:
        pdf.set_text_color(80, 80, 80) # Default Dark Gray


def generate_pdf_report(scan_results: dict, output_path: str = None) -> dict:
    """
    Builds the premium PDF document using fpdf2.
    """
    try:
        pdf = CyberGuardPDF()
        # Enable total page tracking for the footer {nb} alias
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # --- 1. Cover Page ---
        pdf.ln(50)
        pdf.set_font('helvetica', 'B', 28)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 15, 'THREAT ASSESSMENT REPORT', align='C', ln=True)
        pdf.ln(5)
        
        pdf.set_font('helvetica', '', 14)
        pdf.set_text_color(100, 100, 100)
        date_str = datetime.datetime.now().strftime("%B %d, %Y - %H:%M UTC")
        pdf.cell(0, 10, f'Generated: {date_str}', align='C', ln=True)
        
        pdf.ln(10)
        pdf.set_font('helvetica', 'I', 12)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, 'Strictly Confidential & Proprietary', align='C', ln=True)
        
        # --- 2. Executive Summary ---
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 18)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 12, 'Executive Summary', ln=True)
        
        # Draw underline
        pdf.set_draw_color(200, 200, 200)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(8)
        
        pdf.set_font('helvetica', '', 11)
        pdf.set_text_color(60, 60, 60)
        
        # Filter active modules
        modules_run = [k for k, v in scan_results.items() if v is not None]
        
        summary_text = (
            f"This automated technical diagnostic report was generated by CyberGuard Pro. "
            f"A total of {len(modules_run)} security modules were successfully executed during the session timeline."
        )
        pdf.multi_cell(0, 7, summary_text)
        pdf.ln(8)
        
        # Deduce overall risk from scanning payloads
        overall_risk = "LOW"
        payload_blob = str(scan_results).upper()
        if "CRITICAL" in payload_blob:
            overall_risk = "CRITICAL"
        elif "HIGH" in payload_blob or "MALICIOUS" in payload_blob:
            overall_risk = "HIGH"
        elif "MEDIUM" in payload_blob or "SUSPICIOUS" in payload_blob:
            overall_risk = "MEDIUM"
            
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(40, 10, 'Aggregated Risk Level: ')
        set_risk_color(pdf, overall_risk)
        pdf.cell(0, 10, overall_risk, ln=True)
        pdf.ln(10)
        
        # --- 3. Module Sections ---
        for mod, data in scan_results.items():
            if data is None:
                continue
                
            pdf.add_page()
            
            # Module Header
            pdf.set_font('helvetica', 'B', 16)
            pdf.set_text_color(41, 128, 185)
            mod_title = str(mod).replace('_', ' ').title() + " Analysis"
            pdf.cell(0, 12, mod_title, ln=True)
            
            # Header underline
            pdf.set_draw_color(41, 128, 185)
            pdf.set_line_width(0.5)
            pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
            pdf.set_line_width(0.2)
            pdf.ln(8)
            
            # Formatted Output
            pdf.set_font('courier', '', 10)
            pdf.set_text_color(40, 40, 40)
            
            # Ensure data is a clean plain-text string safe for fpdf.
            # _flatten_to_text already handles this, but guard against edge cases.
            if isinstance(data, (dict, list)):
                safe_text = _flatten_to_text(data)
            else:
                safe_text = str(data).replace('\r', '')

            # fpdf multi_cell cannot handle non-latin characters; encode safely.
            safe_text = safe_text.encode('latin-1', errors='replace').decode('latin-1')
            pdf.multi_cell(0, 6, safe_text)
            
        # --- 4. Recommendations & Mitigation ---
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 18)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 12, 'Actionable Recommendations', ln=True)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
        pdf.ln(8)
        
        pdf.set_font('helvetica', '', 11)
        pdf.set_text_color(60, 60, 60)
        
        recommendations = [
            "IMMEDIATE ACTION: Address all vulnerabilities tagged as HIGH or CRITICAL.",
            "NETWORK: Patch identified CVE entries attached to exposed Shodan IP ports.",
            "WEB SECURITY: Enforce strict Content-Security-Policy (CSP) headers to mitigate XSS injections.",
            "CREDENTIALS: If HaveIBeenPwned API detected breaches, initiate organization-wide password rotations.",
            "PHISHING: If domain spoofing is unaligned, verify DNS TXT rules block unauthorized Return-Paths."
        ]
        
        for i, rec in enumerate(recommendations):
            pdf.set_font('helvetica', 'B', 11)
            pdf.cell(8, 8, f"{i+1}.")
            pdf.set_font('helvetica', '', 11)
            pdf.multi_cell(0, 8, rec)
            pdf.ln(2)
            
        # --- 5. File Output ---
        if not output_path:
            reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reports'))
            os.makedirs(reports_dir, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(reports_dir, f"CG_Audit_{timestamp}.pdf")
            
        pdf.output(output_path)
        logger.info(f"Premium PDF Report compiled successfully to: {output_path}")
        
        return {
            "success": True,
            "results": {
                "report_path": output_path,
                "overall_risk": overall_risk,
                "modules_executed": len(modules_run)
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to compile PDF document: {e}")
        return {
            "success": False,
            "error": str(e)
        }
