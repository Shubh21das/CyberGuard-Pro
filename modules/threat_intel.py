"""
CyberGuard Pro - Threat Intelligence Module
===========================================
Integrates VirusTotal API v3 and AbuseIPDB API v2 to query threat indicators:
1. Validates and auto-detects target type (IP, Hash, or URL).
2. Performs direct reputation lookups against global cyber threat indexes.
3. Gracefully captures and bypasses API rate limits and connection issues.
"""

import re
import base64
import socket
import logging
import requests
from typing import Dict, Any

# Configure logging
logger = logging.getLogger(__name__)

def get_threat_verdict(score: int) -> str:
    """
    Helper function to classify risk thresholds:
    Returns 'CLEAN', 'SUSPICIOUS', or 'MALICIOUS' based on positive threat engines or score metrics.
    """
    if score == 0:
        return "CLEAN"
    elif score <= 3:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"

def check_url_virustotal(url: str, api_key: str) -> Dict[str, Any]:
    """
    Submit a URL or domain to the VirusTotal API v3 for scanning and caching.
    """
    cleaned_url = url.strip()
    # Add protocol if missing to satisfy VirusTotal v3 URL schema
    if not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://")):
        cleaned_url = "http://" + cleaned_url

    # Base64 encode URL without padding as required by VirusTotal v3 API
    url_id = base64.urlsafe_b64encode(cleaned_url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(vt_url, headers=headers, timeout=8.0)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            
            return {
                "success": True,
                "total_engines": total,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "verdict": get_threat_verdict(malicious),
                "reputation": attrs.get("reputation", 0),
                "last_analysis_results": attrs.get("last_analysis_results", {})
            }
        elif response.status_code == 404:
            # URL not yet in directory - attempt submission
            logger.info(f"URL not in directory. Submitting to VirusTotal: {cleaned_url}")
            submit_url = "https://www.virustotal.com/api/v3/urls"
            submit_res = requests.post(submit_url, headers=headers, data={"url": cleaned_url}, timeout=8.0)
            
            if submit_res.status_code == 200:
                return {
                    "success": True,
                    "total_engines": 0,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "harmless_count": 0,
                    "verdict": "CLEAN",
                    "message": "URL was not in VirusTotal records, but has been successfully submitted for scanning. Please re-run check in 1 minute."
                }
            else:
                return {
                    "success": False,
                    "error": f"Submission failed: {submit_res.status_code} - {submit_res.text}"
                }
        elif response.status_code == 401 or response.status_code == 403:
            return {
                "success": False,
                "error": "Authentication failed. The provided VirusTotal API Key is invalid or unauthorized."
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "error": "VirusTotal API Rate Limit reached (4 requests per minute limit for free accounts)."
            }
        else:
            return {
                "success": False,
                "error": f"VirusTotal returned error code: {response.status_code}"
            }
    except Exception as e:
        logger.error(f"VirusTotal URL scan exception: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def check_file_hash(hash_value: str, api_key: str) -> Dict[str, Any]:
    """
    Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal.
    """
    cleaned_hash = hash_value.strip().lower()
    vt_url = f"https://www.virustotal.com/api/v3/files/{cleaned_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(vt_url, headers=headers, timeout=8.0)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            
            file_name = attrs.get("meaningful_name") or (attrs.get("names", ["Unknown"])[0] if attrs.get("names") else "Unknown")
            detection_ratio = f"{malicious}/{total}" if total > 0 else "0/0"
            threat_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "None")
            
            return {
                "success": True,
                "file_name": file_name,
                "detection_ratio": detection_ratio,
                "threat_label": threat_label,
                "verdict": get_threat_verdict(malicious),
                "file_size": attrs.get("size", 0),
                "type_description": attrs.get("type_description", "Unknown Type"),
                "malicious_count": malicious,
                "total_engines": total
            }
        elif response.status_code == 404:
            return {
                "success": True,
                "file_name": "Unknown File",
                "detection_ratio": "0/0",
                "threat_label": "None",
                "verdict": "CLEAN",
                "message": "This file hash has not been encountered or indexed by VirusTotal."
            }
        elif response.status_code == 401 or response.status_code == 403:
            return {
                "success": False,
                "error": "Authentication failed. The provided VirusTotal API Key is invalid or unauthorized."
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "error": "VirusTotal API Rate Limit reached (4 requests per minute limit for free accounts)."
            }
        else:
            return {
                "success": False,
                "error": f"VirusTotal returned error code: {response.status_code}"
            }
    except Exception as e:
        logger.error(f"VirusTotal File Hash lookup exception: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def check_ip_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB API v2 for IP reputation score and abuse reports.
    """
    cleaned_ip = ip.strip()
    ab_url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": cleaned_ip,
        "maxAgeInDays": "90",
        "verbose": ""
    }
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    try:
        response = requests.get(ab_url, headers=headers, params=params, timeout=8.0)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            
            # Map score to standard verdict
            if score < 10:
                verdict = "CLEAN"
            elif score <= 30:
                verdict = "SUSPICIOUS"
            else:
                verdict = "MALICIOUS"
                
            return {
                "success": True,
                "abuse_confidence_score": score,
                "country": data.get("countryName") or data.get("countryCode") or "Unknown",
                "isp": data.get("isp") or "Unknown",
                "total_reports": data.get("totalReports", 0),
                "last_reported_date": data.get("lastReportedAt") or "Never",
                "verdict": verdict,
                "domain": data.get("domain", "Unknown"),
                "is_public": not data.get("isPrivate", False)
            }
        elif response.status_code == 401 or response.status_code == 403:
            return {
                "success": False,
                "error": "Authentication failed. The provided AbuseIPDB API Key is invalid or unauthorized."
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "error": "AbuseIPDB API Rate Limit exceeded."
            }
        else:
            return {
                "success": False,
                "error": f"AbuseIPDB returned error code: {response.status_code}"
            }
    except Exception as e:
        logger.error(f"AbuseIPDB reputation query exception: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def run_threat_check(target: str, target_type: str, vt_key: str, aipdb_key: str) -> Dict[str, Any]:
    """
    Master threat coordination function.
    Calls specific engine queries depending on target type ('url', 'hash', 'ip').
    """
    cleaned = target.strip()
    
    if target_type == 'ip':
        # Execute IP reputation scan against AbuseIPDB
        # We can also cross-query VT IP lookup if keys are active for additional coverage
        res = check_ip_abuseipdb(cleaned, aipdb_key)
        return res
        
    elif target_type == 'hash':
        # Execute File Hash check on VirusTotal
        res = check_file_hash(cleaned, vt_key)
        return res
        
    elif target_type == 'url':
        # Execute URL checking scan on VirusTotal
        res = check_url_virustotal(cleaned, vt_key)
        return res
        
    else:
        raise ValueError(f"Unsupported threat intelligence target type: {target_type}")

def detect_target_type(query: str) -> str:
    """
    Analyzes input query to detect target format structure.
    """
    cleaned = query.strip()
    
    # Test for standard IP syntax
    try:
        socket.inet_aton(cleaned)
        return 'ip'
    except socket.error:
        pass
        
    # Test for Cryptographic Hash signatures (MD5/SHA1/SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', cleaned) or re.match(r'^[a-fA-F0-9]{40}$', cleaned) or re.match(r'^[a-fA-F0-9]{64}$', cleaned):
        return 'hash'
        
    # Fallback to URL/Domain scanning
    return 'url'

def check_threat_intel(ip_or_domain: str) -> Dict[str, Any]:
    """
    Backward-compatible toolkit controller wrapper.
    Queries active .env keys and routes seamlessly to app.py threat view.
    """
    import os
    from dotenv import load_dotenv
    load_dotenv()
    
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    aipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
    
    if not vt_key or not aipdb_key:
        return {
            "success": False,
            "results": {},
            "error": "Missing VirusTotal or AbuseIPDB API Keys in your secure environment (.env) configuration."
        }
        
    target_type = detect_target_type(ip_or_domain)
    
    try:
        report = run_threat_check(ip_or_domain, target_type, vt_key, aipdb_key)
        if report.get("success"):
            # Enforce unified payload wrapper structure
            report["query"] = ip_or_domain
            report["target_type"] = target_type
            return {
                "success": True,
                "results": report,
                "error": None
            }
        else:
            return {
                "success": False,
                "results": {},
                "error": report.get("error", "An unknown error occurred during threat checking.")
            }
    except Exception as e:
        logger.error(f"Threat lookup execution failed: {e}")
        return {
            "success": False,
            "results": {},
            "error": str(e)
        }
