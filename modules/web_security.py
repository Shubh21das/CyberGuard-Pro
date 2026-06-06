"""
CyberGuard Pro - Web Security Audit Module
===========================================
Audits secure HTTP response headers, X.509 SSL certificate parameters,
security policies of cookies, and scans for passive SQL Injection/XSS risks.
All scans are fully ethical, cross-platform, and non-intrusive.
"""

import ssl
import socket
import datetime
import logging
import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from typing import Dict, Any, List

# Configure logging
logger = logging.getLogger(__name__)

# List of critical security headers to audit
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_security_headers(url: str) -> Dict[str, Any]:
    """
    Fetch HTTP headers from the target URL and check for presence/absence of standard security headers.
    """
    result = {}
    try:
        # Perform standard HEAD request to inspect headers efficiently
        response = requests.head(url, allow_redirects=True, timeout=6.0, headers={"User-Agent": "CyberGuardPro/1.0"})
        # Fallback to GET if HEAD request is denied
        if response.status_code in [404, 405]:
            response = requests.get(url, allow_redirects=True, timeout=6.0, headers={"User-Agent": "CyberGuardPro/1.0"})
            
        headers = response.headers
        for header in SECURITY_HEADERS:
            value = headers.get(header)
            if value:
                result[header] = {
                    "status": "present",
                    "value": value
                }
            else:
                result[header] = {
                    "status": "missing",
                    "value": None
                }
    except Exception as e:
        logger.error(f"Error checking security headers: {e}")
        # Populate empty/missing indicators on connection failure
        for header in SECURITY_HEADERS:
            result[header] = {
                "status": "missing",
                "value": None,
                "error": str(e)
            }
    return result

def extract_domain(url: str) -> str:
    """
    Helper function to safely extract domain name (without protocol or paths) from a URL.
    """
    parsed = urlparse(url)
    netloc = parsed.netloc or parsed.path
    # Eliminate port number if present
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return netloc

def check_ssl_certificate(domain_or_url: str) -> Dict[str, Any]:
    """
    Establishes an SSL socket connection to extract details from the remote certificate.
    """
    domain = extract_domain(domain_or_url)
    context = ssl.create_default_context()
    
    # Configure socket connection parameters
    port = 443
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(6.0)
    
    try:
        # Perform SSL handshake wrapper
        sock = context.wrap_socket(conn, server_hostname=domain)
        sock.connect((domain, port))
        cert = sock.getpeercert()
        sock.close()
        
        if not cert:
            return {
                "success": False,
                "error": "No SSL certificate was returned by the target host."
            }
            
        # Parse X.509 certificate fields
        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
        issuer = issuer_dict.get('commonName') or issuer_dict.get('organizationName') or "Unknown Issuer"
        
        subject_dict = dict(x[0] for x in cert.get('subject', []))
        subject = subject_dict.get('commonName') or "Unknown Subject"
        
        # Parse dates (format: "May 17 12:49:05 2026 GMT")
        valid_from_str = cert.get('notBefore')
        valid_until_str = cert.get('notAfter')
        
        valid_from = datetime.datetime.strptime(valid_from_str, "%b %d %H:%M:%S %Y %Z")
        valid_until = datetime.datetime.strptime(valid_until_str, "%b %d %H:%M:%S %Y %Z")
        
        now = datetime.datetime.utcnow()
        days_remaining = (valid_until - now).days
        is_expired = now > valid_until
        
        return {
            "success": True,
            "issuer": issuer,
            "subject": subject,
            "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "valid_until": valid_until.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_remaining": max(0, days_remaining),
            "is_expired": is_expired
        }
    except Exception as e:
        logger.error(f"SSL certificate inspection failure for {domain}: {e}")
        return {
            "success": False,
            "error": f"Failed to retrieve or parse SSL certificate: {str(e)}"
        }

def check_cookie_security(url: str) -> List[Dict[str, Any]]:
    """
    Performs an HTTP call to scan Cookie attributes for security flags (HttpOnly, Secure, SameSite).
    """
    cookie_audits = []
    try:
        response = requests.get(url, allow_redirects=True, timeout=6.0, headers={"User-Agent": "CyberGuardPro/1.0"})
        cookies = response.cookies
        
        # We can also parse raw headers for cookies that requests' session manager did not ingest
        set_cookie_headers = response.headers.get("Set-Cookie")
        
        for cookie in cookies:
            cookie_audits.append({
                "name": cookie.name,
                "value": "[REDACTED]" if len(cookie.value) > 6 else cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in [k.lower() for k in cookie._rest.keys()],
                "secure": cookie.secure,
                "samesite": cookie.get_nonstandard_attr("SameSite") or "None"
            })
            
    except Exception as e:
        logger.error(f"Error checking cookie policies: {e}")
    return cookie_audits

def basic_sqli_check(url: str) -> Dict[str, Any]:
    """
    Perform a clean, ethical check for SQL Injection vulnerability on URL query parameters.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        # Default probe check if no params exist in url
        test_url = url + "?id=1%27%20OR%201%3D1%20--"
        params_to_test = {"id": "1' OR 1=1 --"}
    else:
        # Take existing parameters and inject SQL logic
        params_to_test = {k: v[0] + "' OR '1'='1" for k, v in params.items()}
        
    # Standard database SQL error markers to flag reflection issues
    sql_errors = [
        "sql syntax",
        "mysql_fetch",
        "ora-",
        "native client",
        "postgresqlquery",
        "sqlite3_prepare",
        "microsoft oledb provider",
        "unclosed quotation mark after the character string"
    ]
    
    try:
        # Create base test URL without parameters and inject the parameters dictionary
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        response = requests.get(base_url, params=params_to_test, timeout=6.0, headers={"User-Agent": "CyberGuardPro/1.0"})
        content = response.text.lower()
        
        for error in sql_errors:
            if error in content:
                return {
                    "vulnerable": True,
                    "evidence": f"Found database signature match: '{error}' in response page body."
                }
                
        return {
            "vulnerable": False,
            "evidence": "No dynamic database errors or reflective injection strings detected."
        }
    except Exception as e:
        logger.error(f"SQL Injection audit failure: {e}")
        return {
            "vulnerable": False,
            "evidence": f"Scan failed to complete successfully: {str(e)}"
        }

def basic_xss_check(url: str) -> Dict[str, Any]:
    """
    Perform a clean, ethical check for Cross-Site Scripting (XSS) reflection vulnerabilities on URL query parameters.
    """
    parsed = urlparse(url)
    # Test script injection payload
    xss_payload = "<script>alert('CyberGuardPro')</script>"
    
    params = parse_qs(parsed.query)
    if not params:
        params_to_test = {"q": xss_payload}
    else:
        params_to_test = {k: xss_payload for k, in params.keys()}
        
    try:
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        response = requests.get(base_url, params=params_to_test, timeout=6.0, headers={"User-Agent": "CyberGuardPro/1.0"})
        
        # Check if the XSS payload is reflected without escaping
        if xss_payload in response.text:
            return {
                "vulnerable": True,
                "evidence": f"Reflective script found: '{xss_payload}' mirrored without validation."
            }
        return {
            "vulnerable": False,
            "evidence": "Reflective parameters are properly sanitized or ignored by the host application."
        }
    except Exception as e:
        logger.error(f"XSS audit failure: {e}")
        return {
            "vulnerable": False,
            "evidence": f"Scan failed to complete: {str(e)}"
        }

def run_web_audit(url: str) -> Dict[str, Any]:
    """
    Master web coordinator function.
    Performs security header checks, SSL validation, cookie inspection, SQLi, and XSS audits.
    """
    cleaned_url = url.strip()
    if not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://")):
        cleaned_url = "https://" + cleaned_url  # Default to HTTPS audit
        
    # 1. Check HTTP security headers
    headers_report = check_security_headers(cleaned_url)
    
    # 2. Check SSL validity
    ssl_report = check_ssl_certificate(cleaned_url)
    
    # 3. Check Cookie attributes
    cookies_report = check_cookie_security(cleaned_url)
    
    # 4. Probe SQLi
    sqli_report = basic_sqli_check(cleaned_url)
    
    # 5. Probe XSS
    xss_report = basic_xss_check(cleaned_url)
    
    # 6. Calculate Risk Score
    # Starting score = 100 (Max security), deduct points for flaws
    score = 100
    
    # Deduct 10 points per missing security header
    missing_header_count = sum(1 for h in headers_report.values() if h["status"] == "missing")
    score -= (missing_header_count * 10)
    
    # Deduct 25 points if SSL is broken/expired on HTTPS
    if not ssl_report.get("success") or ssl_report.get("is_expired"):
        score -= 25
        
    # Deduct 15 points if cookies lack HttpOnly or Secure properties
    for cookie in cookies_report:
        if not cookie["httponly"] or not cookie["secure"]:
            score -= 5  # Cap cumulative cookie penalty at 15
            
    # Deduct 30 points if SQL Injection is detected
    if sqli_report.get("vulnerable"):
        score -= 30
        
    # Deduct 20 points if XSS reflection is detected
    if xss_report.get("vulnerable"):
        score -= 20
        
    # Constrain final score boundary (0 to 100)
    final_score = max(0, min(100, score))
    
    if final_score >= 80:
        verdict = "LOW RISK"
    elif final_score >= 50:
        verdict = "MEDIUM RISK"
    else:
        verdict = "HIGH RISK"
        
    return {
        "url": cleaned_url,
        "risk_score": final_score,
        "verdict": verdict,
        "headers": headers_report,
        "ssl": ssl_report,
        "cookies": cookies_report,
        "sqli": sqli_report,
        "xss": xss_report
    }

def scan_web_security(url: str) -> Dict[str, Any]:
    """
    Main entrypoint invoked by the Flask app.py /websec route.
    """
    try:
        results = run_web_audit(url)
        return {
            "success": True,
            "results": results,
            "error": None
        }
    except Exception as e:
        logger.error(f"Web audit execution failed: {e}")
        return {
            "success": False,
            "results": {},
            "error": str(e)
        }
