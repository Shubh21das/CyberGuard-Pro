"""
CyberGuard Pro - Main Flask Application Controller
==================================================
This script initializes the Flask application, loads secure environment configurations,
defines routing behaviors, validates secure targeting, and coordinates request flows
to the respective specialized tool modules under /modules/.

Modules integrated:
1. recon.py        - OSINT & Passive Reconnaissance
2. network.py      - Active network scanner (Nmap proxy)
3. threat_intel.py - VirusTotal & AbuseIPDB Threat Intel lookup
4. web_security.py - Security Headers, SSL validity, & basic injection test
5. forensics.py    - File Exif & forensic structure analyst
6. phishing.py     - Email Header analysis (SPF, DKIM, DMARC, hops)
7. passwords.py    - Password entropy & HIBP exposure validator
8. report.py       - Consolidated PDF report compiler
"""

import os
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, session
from flask_session import Session
from dotenv import load_dotenv
from datetime import datetime
from werkzeug.utils import secure_filename

# -------------------------------------------------------------
# 1. Environment & Path Initialization
# -------------------------------------------------------------
# Load environment configurations from secure local .env file
load_dotenv()

# Setup robust system logging for tracking security tool outputs and issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize the Flask instance
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cyberguard_secret_2026')

# Use server-side filesystem sessions to avoid the 4KB cookie size limit.
# Scan results (network maps, forensics data, etc.) easily exceed cookie limits,
# which causes Flask to silently drop session data. Filesystem sessions have no size cap.
SESSION_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'flask_sessions')
os.makedirs(SESSION_DIR, exist_ok=True)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = SESSION_DIR
app.config['SESSION_PERMANENT'] = False
# NOTE: SESSION_USE_SIGNER was removed in flask-session 0.8.0 — do NOT set it.
Session(app)

# Set up local directories inside workspace safely for file/report handling
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Standard 16MB upload ceiling

# Allowed image/document extensions for the forensics module
ALLOWED_FORENSIC_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx', 'zip'}

def allowed_file(filename):
    """Utility to verify if an uploaded file matches secure extensions."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_FORENSIC_EXTENSIONS

@app.template_filter('basename')
def basename_filter(path):
    """Jinja custom template filter to extract base file name from path."""
    if not path: return ""
    return str(path).replace('\\', '/').split('/')[-1]

# -------------------------------------------------------------
# 2. Importing Cybersecurity Modules
# -------------------------------------------------------------
try:
    from modules.recon import run_recon
    from modules.network import run_network_scan
    from modules.threat_intel import check_threat_intel
    from modules.web_security import scan_web_security
    from modules.forensics import analyze_file_forensics
    from modules.phishing import analyze_email_headers
    from modules.passwords import analyze_password
    from modules.report import generate_pdf_report, generate_report_route_data
    logger.info("Successfully imported all core modules from /modules/.")
except ImportError as e:
    logger.critical(f"CRITICAL IMPORT FAILURE: Could not import a core security module! Details: {e}")
    raise e

# -------------------------------------------------------------
# 3. Flask Route Definitions
# -------------------------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Home Dashboard Route.
    GET: Renders overall dashboard with overview statistics and modules state.
    POST: Processes quick scan summary triggers or manual actions.
    """
    results = None
    if request.method == 'POST':
        try:
            action = request.form.get('action')
            flash(f"Dashboard action '{action}' parsed successfully.", "success")
            results = {"status": "Active", "dashboard_action": action}
        except Exception as e:
            logger.error(f"Error handling dashboard POST: {e}")
            flash(f"Error handling dashboard request: {str(e)}", "danger")
            
    return render_template('index.html', results=results)


@app.route('/recon', methods=['GET', 'POST'])
def recon():
    """
    Reconnaissance Route (OSINT).
    GET: Renders passive target input interface.
    POST: Triggers active/passive intelligence collection against authorized target.
    """
    results = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if not target:
            flash("Target input is required for passive recon.", "warning")
        else:
            try:
                logger.info(f"Initiating OSINT Recon on target: {target}")
                response = run_recon(target)
                if response.get("success"):
                    results = response.get("results")
                    session['recon_results'] = results
                    session.modified = True
                    session['recon'] = json.dumps(results, indent=2)
                    flash(f"Passive recon completed successfully for target '{target}'!", "success")
                else:
                    flash(f"Recon failed: {response.get('error')}", "danger")
            except Exception as e:
                logger.error(f"Exception during recon execution: {e}")
                flash(f"An unexpected error occurred during recon: {str(e)}", "danger")
                
    return render_template('recon.html', results=results)


@app.route('/network', methods=['GET', 'POST'])
def network():
    """
    Network Scanning Route.
    GET: Renders network target & port scanning configuration panel.
    POST: Launches Nmap scanning protocol on verified authorized network nodes.
    """
    results = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        scan_type = request.form.get('scan_type', 'quick').strip()
        if not target:
            flash("Target host range or IP is required for scanning.", "warning")
        else:
            try:
                logger.info(f"Initiating network scan ({scan_type}) on target: {target}")
                response = run_network_scan(target, scan_type=scan_type)
                if response.get("success"):
                    results = response.get("results")
                    session['network_results'] = results
                    session.modified = True
                    session['network'] = json.dumps(results, indent=2)
                    flash(f"Network scan finished successfully on target '{target}'!", "success")
                else:
                    flash(f"Scan failed: {response.get('error')}", "danger")
            except Exception as e:
                logger.error(f"Exception during network scanning: {e}")
                flash(f"An unexpected error occurred during scanning: {str(e)}", "danger")

    return render_template('network.html', results=results)


@app.route('/threat', methods=['GET', 'POST'])
def threat():
    """
    Threat Intelligence Route.
    GET: Renders query portal for Domain, IP, or Hash lookups.
    POST: Queries external databases (AbuseIPDB & VirusTotal) for reputation records.
    """
    results = None
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if not query:
            flash("Query parameter (IP, Domain, or Hash) is required.", "warning")
        else:
            try:
                logger.info(f"Querying threat intelligence database for: {query}")
                response = check_threat_intel(query)
                if response.get("success"):
                    results = response.get("results")
                    session['threat_results'] = results
                    session.modified = True
                    session['threat'] = json.dumps(results, indent=2)
                    flash(f"Threat intelligence data retrieved successfully for '{query}'!", "success")
                else:
                    flash(f"Intel lookup failed: {response.get('error')}", "danger")
            except Exception as e:
                logger.error(f"Exception during threat lookup: {e}")
                flash(f"An unexpected error occurred during threat intel lookup: {str(e)}", "danger")

    return render_template('threat.html', results=results)


@app.route('/websec', methods=['GET', 'POST'])
def websec():
    """
    Web Security Auditor Route.
    GET: Renders target URL scanner interface for secure headers and certificate validations.
    POST: Triggers live secure headers lookup, SSL certificate analysis, and ethical SQLi analysis.
    """
    results = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash("Target web URL is required.", "warning")
        else:
            try:
                logger.info(f"Initiating web security audit for: {url}")
                response = scan_web_security(url)
                if response.get("success"):
                    results = response.get("results")
                    session['websec_results'] = results
                    session.modified = True
                    session['websec'] = json.dumps(results, indent=2)
                    flash(f"Web security scan completed successfully for target '{url}'!", "success")
                else:
                    flash(f"Web security scan failed: {response.get('error')}", "danger")
            except Exception as e:
                logger.error(f"Exception during web security audit: {e}")
                flash(f"An unexpected error occurred during web audit: {str(e)}", "danger")

    return render_template('websec.html', results=results)


@app.route('/forensics', methods=['GET', 'POST'])
def forensics():
    """
    File Forensics Route.
    GET: Renders file uploader interface.
    POST: Processes upload and runs automated Exif/forensics data extractions on target files.
    """
    results = None
    if request.method == 'POST':
        # Check if file part is present in request
        if 'file' not in request.files:
            flash("No file part in request form.", "warning")
        else:
            file = request.files['file']
            if file.filename == '':
                flash("No selected file to upload.", "warning")
            elif file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(saved_path)
                    
                    logger.info(f"File forensics audit initiated for secure file upload: {saved_path}")
                    response = analyze_file_forensics(saved_path)
                    
                    if response.get("success"):
                        results = response.get("results")
                        session['forensics_results'] = results
                        session.modified = True
                        session['forensics'] = json.dumps(results, indent=2)
                        flash(f"Forensic analysis completed successfully for file '{filename}'!", "success")
                    else:
                        flash(f"Forensic audit failed: {response.get('error')}", "danger")
                except Exception as e:
                    logger.error(f"Exception during forensics parsing: {e}")
                    flash(f"An unexpected error occurred during file forensic audit: {str(e)}", "danger")
            else:
                flash("Unsupported or dangerous file extension uploaded.", "danger")

    return render_template('forensics.html', results=results)


@app.route('/phishing', methods=['GET', 'POST'])
def phishing():
    """
    Phishing Header Analyzer Route.
    GET: Renders textarea input panel for email headers.
    POST: Processes raw headers for SPF alignment, DKIM validators, DMARC, and routing hops.
    """
    results = None
    if request.method == 'POST':
        headers_content = request.form.get('headers', '').strip()
        if not headers_content:
            flash("Raw email headers are required for analysis.", "warning")
        else:
            try:
                logger.info("Parsing raw email headers for phishing indicators...")
                response = analyze_email_headers(headers_content)
                if response.get("success"):
                    results = response.get("results")
                    session['phishing_results'] = results
                    session.modified = True
                    session['phishing'] = json.dumps(results, indent=2)
                    flash("Email headers analyzed successfully!", "success")
                else:
                    flash(f"Header analysis failed: {response.get('error')}", "danger")
            except Exception as e:
                logger.error(f"Exception during email header analysis: {e}")
                flash(f"An unexpected error occurred during phishing analysis: {str(e)}", "danger")

    return render_template('phishing.html', results=results)


@app.route('/passwords', methods=['GET', 'POST'])
def passwords():
    """
    Password Strength Route.
    GET: Renders password entropy evaluation form.
    POST: Calculates entropy score using zxcvbn and checks for pwned credentials.
    """
    results = None
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        if not password:
            flash("Please input a password for strength analysis.", "warning")
        else:
            try:
                logger.info("Evaluating password cryptographic strength...")
                response = analyze_password(password)
                if response.get("success"):
                    results = response.get("results")
                    session['password_results'] = results
                    session.modified = True
                    session['passwords'] = json.dumps(results, indent=2)
                    flash("Password audit complete!", "success")
                else:
                    flash(f"Password evaluation failed: {response.get('error')}", "danger")
            except Exception as e:
                logger.error(f"Exception during password auditing: {e}")
                flash(f"An unexpected error occurred during password audit: {str(e)}", "danger")

    return render_template('passwords.html', results=results)


@app.route('/report', methods=['GET', 'POST'])
def report():
    """
    PDF Report Compilation Route.
    GET: Renders manual report compilation preferences page.
    POST: Generates a premium PDF document summarising recent security checks.
    """
    results = None
    if request.method == 'POST':
        try:
            # Dynamically assemble available payload using the specialized report data parser
            scan_data = generate_report_route_data(session)
            
            logger.info("Compiling security findings into premium PDF report...")
            response = generate_pdf_report(scan_data)
            if response.get("success"):
                results = response.get("results")
                pdf_filename = os.path.basename(results.get("report_path"))
                flash(f"Consolidated PDF Report '{pdf_filename}' generated successfully!", "success")
            else:
                flash(f"Report compilation failed: {response.get('error')}", "danger")
        except Exception as e:
            logger.error(f"Exception during PDF generation: {e}")
            flash(f"An unexpected error occurred during report compiler boot: {str(e)}", "danger")

    report_data = {k: v for k, v in session.items() if k.endswith('_results')}
    has_data = len(report_data) > 0
    return render_template('report.html', results=results, report_data=report_data, has_data=has_data)


@app.route('/reports/<path:filename>')
def download_report(filename):
    """Safe endpoint to download compiled security assessments directly."""
    # Force clean filename (strip any stray pathing)
    clean_filename = filename.replace('\\', '/').split('/')[-1]
    if not clean_filename.endswith('.pdf'):
        clean_filename += '.pdf'
        
    pdf_path = os.path.join(app.config['REPORTS_FOLDER'], clean_filename)
    
    # Generate a unique timestamped filename for the user's download
    timestamp = datetime.now().strftime('%Y-%m-%d')
    report_name = f'CyberGuard_Report_{timestamp}.pdf'
    
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=report_name,
        mimetype='application/pdf'
    )

@app.route('/clear')
def clear_session():
    session.clear()
    session.modified = True
    return redirect(url_for('index'))

# -------------------------------------------------------------
# 4. Server Initiation block
# -------------------------------------------------------------
if __name__ == '__main__':
    # Boot server binding to all network interfaces for multi-host visibility and testing
    logger.info("Initializing CyberGuard Pro server on host 0.0.0.0, port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
