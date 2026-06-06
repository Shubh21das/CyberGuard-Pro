"""
CyberGuard Pro - Phishing Email Header Analyzer
================================================
Analyses raw email headers to identify spoofing indicators:
1. Parses From, To, Subject, Reply-To, Return-Path, Message-ID, and Received headers.
2. Evaluates sender-alignment checks (From vs. Return-Path vs. Reply-To base domains).
3. Queries live DNS records for SPF and DMARC text fields using dnspython.
4. Extracts embedded URLs from header payloads and scans them via VirusTotal v3.
5. Computes a centralized risk score and labels the email as LOW, MEDIUM, or HIGH risk.
"""

import os
import re
import base64
import logging
import email
from email.header import decode_header
import requests
from typing import Dict, Any, List, Tuple

# Import dnspython components safely
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Configure logger
logger = logging.getLogger(__name__)

def decode_mime_header(header_value: str) -> str:
    """
    Safely decodes RFC-2047 MIME encoded headers (e.g. =?utf-8?B?...?=).
    """
    if not header_value:
        return ""
    try:
        decoded_parts = decode_header(header_value)
        decoded_string = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_string += part
        return decoded_string.strip()
    except Exception as e:
        logger.warning(f"Failed to decode MIME header: {e}")
        return str(header_value).strip()

def extract_domain_from_email(email_str: str) -> str:
    """
    Extracts the lowercased domain part of an email address.
    Matches standard patterns like "John Doe <john.doe@sender.com>" or "john.doe@sender.com".
    """
    if not email_str:
        return ""
    # Extract match between < > first, or fall back to general email match
    match_brackets = re.search(r'<([^>]+)>', email_str)
    search_target = match_brackets.group(1) if match_brackets else email_str
    
    match = re.search(r'[\w\.-]+@([\w\.-]+\.[\w\.-]+)', search_target)
    if match:
        return match.group(1).lower().strip()
    return ""

def get_base_domain(domain: str) -> str:
    """
    Extracts the base organizational domain (e.g., sender.com from sub.sender.com).
    Covers most generic double-level domains simply (like .com.br or .co.uk can be expanded,
    but standard two-level splits are robust enough for standard diagnostics).
    """
    if not domain:
        return ""
    parts = domain.strip().split('.')
    if len(parts) >= 2:
        # Check for common dual-level domains (e.g. co.uk, com.br, net.au)
        if len(parts) >= 3 and parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu', 'ac'):
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return domain

def parse_email_headers(raw_headers: str) -> Dict[str, Any]:
    """
    Parses raw email header text into a structured dictionary.
    """
    if not raw_headers:
        return {}
    
    # Safely load the raw headers using Python's built-in email parser
    msg = email.message_from_string(raw_headers)
    
    # Get all Received headers - these are ordered from top (latest hop) to bottom (oldest hop)
    received_headers = msg.get_all('Received') or []
    cleaned_received = [str(r).replace('\n', ' ').replace('\r', '').strip() for r in received_headers]
    
    parsed = {
        "from": decode_mime_header(msg.get('From', '')),
        "to": decode_mime_header(msg.get('To', '')),
        "reply_to": decode_mime_header(msg.get('Reply-To', '')),
        "return_path": decode_mime_header(msg.get('Return-Path', '')),
        "subject": decode_mime_header(msg.get('Subject', '')),
        "date": decode_mime_header(msg.get('Date', '')),
        "message_id": decode_mime_header(msg.get('Message-ID', '')),
        "received": cleaned_received
    }
    return parsed

def detect_spoofing(parsed_headers: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Compares domain alignments across From, Return-Path, Reply-To and Received headers.
    Flag alignment failures as spoofing vectors.
    """
    is_suspicious = False
    reasons = []
    
    from_email = parsed_headers.get('from', '')
    from_domain = extract_domain_from_email(from_email)
    from_base = get_base_domain(from_domain)
    
    if not from_domain:
        return False, [] # No From domain to perform validation against
        
    # 1. From Domain vs. Return-Path Domain Alignment check
    return_path_email = parsed_headers.get('return_path', '')
    if return_path_email:
        rp_domain = extract_domain_from_email(return_path_email)
        rp_base = get_base_domain(rp_domain)
        if rp_base and from_base != rp_base:
            is_suspicious = True
            reasons.append(f"From domain ({from_domain}) is not aligned with Return-Path domain ({rp_domain})")
            
    # 2. From Domain vs. Reply-To Domain Alignment check
    reply_to_email = parsed_headers.get('reply_to', '')
    if reply_to_email:
        rt_domain = extract_domain_from_email(reply_to_email)
        rt_base = get_base_domain(rt_domain)
        if rt_base and from_base != rt_base:
            is_suspicious = True
            reasons.append(f"From domain ({from_domain}) is not aligned with Reply-To domain ({rt_domain})")
            
    # 3. Originating Hop Verification check
    received_list = parsed_headers.get('received', [])
    if received_list:
        # The oldest/originating hop is the bottommost element (index -1)
        originating_hop = received_list[-1].lower()
        
        # Check if the sender's base domain is mentioned anywhere in the originating hop string
        if from_base not in originating_hop:
            # Also check if it's in *any* received hop just in case it originated internally
            in_any_hop = any(from_base in hop.lower() for hop in received_list)
            if not in_any_hop:
                is_suspicious = True
                reasons.append(f"Sender's base domain ({from_base}) is entirely missing from all Received hop pathways")
                
    return is_suspicious, reasons

def check_spf_dmarc(domain: str) -> Tuple[bool, bool, str, str]:
    """
    Queries standard SPF and DMARC TXT records in live DNS directories using dnspython.
    """
    spf_exists = False
    dmarc_exists = False
    spf_record = "No SPF record found"
    dmarc_record = "No DMARC record found"
    
    if not domain or not DNS_AVAILABLE:
        return False, False, spf_record, dmarc_record
        
    # Configure short timeouts to maintain fast request cycles
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    # 1. SPF Check (Querying TXT records for the domain)
    try:
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_str = "".join([part.decode('utf-8') if isinstance(part, bytes) else part for part in rdata.strings])
            if txt_str.lower().startswith("v=spf1"):
                spf_record = txt_str
                spf_exists = True
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        logger.info(f"SPF resolution query complete (no record): {e}")
        spf_record = f"No SPF record detected (DNS status: {type(e).__name__})"
    except Exception as e:
        logger.warning(f"SPF query execution error: {e}")
        spf_record = f"Error querying SPF: {str(e)}"
        
    # 2. DMARC Check (Querying TXT records for _dmarc.{domain})
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt_str = "".join([part.decode('utf-8') if isinstance(part, bytes) else part for part in rdata.strings])
            if txt_str.upper().startswith("v=DMARC1"):
                dmarc_record = txt_str
                dmarc_exists = True
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
        logger.info(f"DMARC resolution query complete (no record): {e}")
        dmarc_record = f"No DMARC record detected (DNS status: {type(e).__name__})"
    except Exception as e:
        logger.warning(f"DMARC query execution error: {e}")
        dmarc_record = f"Error querying DMARC: {str(e)}"
        
    return spf_exists, dmarc_exists, spf_record, dmarc_record

def extract_urls_from_headers(raw_headers: str) -> List[str]:
    """
    Extracts all embedded URLs from raw header blocks using regular expressions.
    """
    if not raw_headers:
        return []
    # Match standard links starting with http://, https://
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, raw_headers)
    
    seen = set()
    unique_urls = []
    for url in urls:
        # Strip trailing punctuation marks (commas, periods, parentheses, quotes)
        cleaned_url = url.rstrip('.,;:)(">\'')
        if cleaned_url not in seen:
            seen.add(cleaned_url)
            unique_urls.append(cleaned_url)
            
    return unique_urls

def check_urls_virustotal(urls: List[str], api_key: str) -> List[Dict[str, Any]]:
    """
    Queries VirusTotal reputation metrics for the first 3 URLs found in the headers.
    """
    results = []
    target_urls = urls[:3]  # Enforce free tier ceiling limits (max 3 checks)
    
    if not api_key:
        # Return graceful fallbacks detailing missing API credentials
        for url in target_urls:
            results.append({
                "url": url,
                "verdict": "UNKNOWN (No VT API Key configured)",
                "malicious_count": 0,
                "total_engines": 0,
                "reputation": 0
            })
        return results
        
    headers = {"x-apikey": api_key}
    
    for url in target_urls:
        try:
            # Base64 encode URL without padding as required by VirusTotal v3 API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            response = requests.get(vt_url, headers=headers, timeout=5.0)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                
                # Classify verdict dynamically matching reputation counts
                if malicious > 0:
                    verdict = "MALICIOUS"
                elif suspicious > 0:
                    verdict = "SUSPICIOUS"
                else:
                    verdict = "CLEAN"
                    
                results.append({
                    "url": url,
                    "verdict": verdict,
                    "malicious_count": malicious,
                    "total_engines": total,
                    "reputation": attrs.get("reputation", 0)
                })
            elif response.status_code == 404:
                # URL is not currently cached by VirusTotal - submit for active scan
                submit_url = "https://www.virustotal.com/api/v3/urls"
                requests.post(submit_url, headers=headers, data={"url": url}, timeout=5.0)
                results.append({
                    "url": url,
                    "verdict": "SCAN_QUEUED (Submitted to VirusTotal for analysis)",
                    "malicious_count": 0,
                    "total_engines": 0,
                    "reputation": 0
                })
            elif response.status_code == 429:
                results.append({
                    "url": url,
                    "verdict": "RATE_LIMITED (VirusTotal API rate limits reached)",
                    "malicious_count": 0,
                    "total_engines": 0,
                    "reputation": 0
                })
            else:
                results.append({
                    "url": url,
                    "verdict": f"UNKNOWN (Status Code: {response.status_code})",
                    "malicious_count": 0,
                    "total_engines": 0,
                    "reputation": 0
                })
        except Exception as e:
            logger.error(f"Failed to fetch VirusTotal metrics for URL {url}: {e}")
            results.append({
                "url": url,
                "verdict": f"ERROR (Details: {type(e).__name__})",
                "malicious_count": 0,
                "total_engines": 0,
                "reputation": 0
            })
            
    return results

def run_phishing_analysis(raw_headers: str, api_key: str) -> Dict[str, Any]:
    """
    Master function combining parsing, spoof checks, SPF/DMARC DNS lookup, and URL scans.
    """
    if not raw_headers.strip():
        return {
            "success": False,
            "results": None,
            "error": "Empty header blocks provided"
        }
        
    try:
        # 1. Parse email headers
        parsed = parse_email_headers(raw_headers)
        
        # 2. Check domain spoofing indicators
        is_suspicious, spoofing_reasons = detect_spoofing(parsed)
        
        # 3. Perform live SPF/DMARC query for the sender domain
        from_domain = extract_domain_from_email(parsed.get('from', ''))
        if from_domain:
            spf_exists, dmarc_exists, spf_record, dmarc_record = check_spf_dmarc(from_domain)
        else:
            spf_exists = dmarc_exists = False
            spf_record = "Domain missing - SPF query skipped"
            dmarc_record = "Domain missing - DMARC query skipped"
            
        # 4. Extract URLs and query VirusTotal reputational counts
        urls_found = extract_urls_from_headers(raw_headers)
        checked_urls = check_urls_virustotal(urls_found, api_key)
        
        # 5. Centralized Risk Calculation scoring loop
        risk_score = 0
        
        # Spoofing triggers a substantial baseline risk increase
        if is_suspicious:
            risk_score += 3
            # Increment slightly for each verified alignment mismatch reason (up to 3 extra points)
            risk_score += min(len(spoofing_reasons), 3)
            
        # Add risk if authorization records are missing
        if not spf_exists:
            risk_score += 2
        if not dmarc_exists:
            risk_score += 2
            
        # Check VirusTotal verdicts to increment risk
        malicious_urls = 0
        suspicious_urls = 0
        for item in checked_urls:
            if item.get("verdict") == "MALICIOUS":
                malicious_urls += 1
                risk_score += 3
            elif item.get("verdict") == "SUSPICIOUS":
                suspicious_urls += 1
                risk_score += 1
                
        # Weak RFC structure check (missing vital fields)
        if not parsed.get("message_id"):
            risk_score += 1
        if not parsed.get("subject"):
            risk_score += 1
            
        # Compile score labels
        if risk_score <= 2:
            risk_rating = "LOW"
        elif risk_score <= 5:
            risk_rating = "MEDIUM"
        else:
            risk_rating = "HIGH"
            
        analysis_report = {
            "parsed_headers": parsed,
            "spoofing": {
                "is_suspicious": is_suspicious,
                "reasons": spoofing_reasons
            },
            "dns_security": {
                "spf_exists": spf_exists,
                "spf_record": spf_record,
                "dmarc_exists": dmarc_exists,
                "dmarc_record": dmarc_record,
                "domain": from_domain
            },
            "url_analysis": {
                "urls_found": urls_found,
                "checked_urls": checked_urls,
                "malicious_count": malicious_urls,
                "suspicious_count": suspicious_urls
            },
            "risk_score": risk_score,
            "risk_rating": risk_rating
        }
        
        return {
            "success": True,
            "results": analysis_report,
            "error": None
        }
        
    except Exception as e:
        logger.error(f"Error during phishing analysis execution: {e}")
        return {
            "success": False,
            "results": None,
            "error": f"Internal execution crash: {str(e)}"
        }

def analyze_email_headers(raw_headers: str) -> dict:
    """
    Standard entry wrapper mapped directly from the Flask controller.
    Uses VirusTotal API keys safely resolved from active environment keys.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    return run_phishing_analysis(raw_headers, api_key)
