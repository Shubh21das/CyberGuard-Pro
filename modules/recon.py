"""
CyberGuard Pro - OSINT Reconnaissance Module
============================================
This module executes passive target intelligence gathering and enumeration:
1. DNS Record Lookup (dnspython: A, MX, NS, TXT)
2. WHOIS Information Lookup (python-whois: Registrar, Creation, Expiry, Nameservers)
3. IP Geolocation tracking (ip-api.com: Country, City, ISP, Coordinates)
4. Shodan API Threat Scan (REST query: Ports, Services, known CVEs)

All operations are designed to be passive, ethical, and fully contained.
"""

import os
import re
import logging
import requests
import whois
import dns.resolver
import dns.reversename
import folium
import uuid

logger = logging.getLogger(__name__)

def clean_target(target: str) -> str:
    """
    Cleans target inputs (strips protocol prefixes, paths, queries, and spaces).
    Example: 'https://authorizedtarget.com/index.html' -> 'authorizedtarget.com'
    """
    target = target.strip()
    # Strip leading protocols
    target = re.sub(r'^https?://', '', target, flags=re.IGNORECASE)
    # Strip paths, parameters, or ports
    target = target.split('/')[0].split('?')[0].split(':')[0]
    return target

def is_ip_address(target: str) -> bool:
    """
    Checks if a target string matches an IPv4 pattern.
    """
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ipv4_pattern, target))

def format_whois_date(date_obj) -> str:
    """
    Safely converts datetime objects, lists of datetimes, or strings returned
    by WHOIS lookups into standard ISO YYYY-MM-DD HH:MM:SS format.
    """
    if not date_obj:
        return "N/A"
    if isinstance(date_obj, list):
        # Take the earliest or primary date listed
        return format_whois_date(date_obj[0])
    if hasattr(date_obj, 'strftime'):
        return date_obj.strftime('%Y-%m-%d %H:%M:%S')
    return str(date_obj)

def shodan_lookup(ip: str, api_key: str) -> dict:
    """
    Queries the Shodan REST API host lookup endpoint for the target IP.
    Gathers open ports, running services (banners), organization details, and associated CVE vulnerabilities.
    """
    if not api_key:
        logger.warning("Shodan API key is missing. Skipping active Shodan sweep.")
        return {
            "status": "Skipped",
            "message": "Shodan API Key not configured. Add SHODAN_API_KEY to your secure .env file to enable active vulnerability reports."
        }

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        logger.info(f"Querying Shodan REST API for host IP: {ip}")
        response = requests.get(url, timeout=7.0)
        
        if response.status_code == 200:
            data = response.json()
            
            # Format and gather running services and protocols
            services = []
            for item in data.get('data', []):
                services.append({
                    "port": item.get('port'),
                    "protocol": item.get('transport', 'tcp'),
                    "product": item.get('product', 'Unknown'),
                    "version": item.get('version', 'N/A'),
                    "banner": (item.get('data', '').strip()[:80] + '...') if item.get('data') else 'N/A'
                })

            return {
                "status": "Success",
                "organization": data.get('org', 'N/A'),
                "country": data.get('country_name', 'N/A'),
                "open_ports": data.get('ports', []),
                "services": services,
                "known_vulnerabilities": data.get('vulns', [])
            }
        elif response.status_code == 404:
            logger.info(f"No active Shodan logs found for IP: {ip}")
            return {
                "status": "No Data Found",
                "message": f"No active Shodan logs found for IP {ip} in public registers."
            }
        elif response.status_code == 401:
            logger.error("Shodan credential authentication failed.")
            return {
                "status": "Auth Error",
                "message": "Authentication failed. The provided Shodan API Key is invalid or expired."
            }
        elif response.status_code == 403:
            try:
                err_data = response.json()
                err_msg = err_data.get("error", "")
            except Exception:
                err_msg = ""
            
            if "membership" in err_msg.lower():
                logger.warning("Shodan API key does not have enough query privileges.")
                return {
                    "status": "Tier Restriction",
                    "message": "Authentication successful! However, your Shodan API Key is on a Free/OSS plan which requires a paid membership to query this specific target host."
                }
            else:
                logger.error("Shodan access forbidden.")
                return {
                    "status": "Auth Error",
                    "message": f"Shodan Access Forbidden: {err_msg or 'Unauthorized request'}"
                }
        else:
            logger.warning(f"Unexpected Shodan response code: {response.status_code}")
            return {
                "status": "Error",
                "message": f"Shodan API returned status code {response.status_code}."
            }
    except requests.exceptions.Timeout:
        logger.error(f"Shodan API connection timed out for IP: {ip}")
        return {
            "status": "Timeout",
            "message": "Shodan query connection timed out."
        }
    except Exception as e:
        logger.error(f"Error executing Shodan API query: {e}")
        return {
            "status": "Error",
            "message": f"Unhandled error querying Shodan: {str(e)}"
        }

def whois_lookup(domain_or_ip: str) -> dict:
    """
    Executes a standard WHOIS protocol query via python-whois.
    Resolves domain registrar, creation dates, expiration targets, and name servers.
    """
    try:
        logger.info(f"Querying WHOIS records for: {domain_or_ip}")
        w = whois.whois(domain_or_ip)
        
        # Format name servers list
        nservers = []
        if w.name_servers:
            if isinstance(w.name_servers, list):
                nservers = [ns.lower() for ns in w.name_servers if ns]
            else:
                nservers = [w.name_servers.lower()]

        return {
            "status": "Success",
            "registrar": w.registrar or "Unknown",
            "creation_date": format_whois_date(w.creation_date),
            "expiration_date": format_whois_date(w.expiration_date),
            "name_servers": nservers,
            "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
        }
    except Exception as e:
        logger.error(f"WHOIS lookup exception: {e}")
        return {
            "status": "Error",
            "message": f"Could not perform WHOIS query: {str(e)}"
        }

def dns_lookup(domain: str) -> dict:
    """
    Enumerates DNS records (A, MX, NS, TXT) using pure dnspython resolver sweeps.
    Encapsulates each lookup independently to preserve partial successes.
    """
    records = {
        "status": "Success",
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": []
    }
    
    # DNS queries parameters configuration
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. Resolve 'A' Records
    try:
        answers = resolver.resolve(domain, 'A')
        records["A"] = [r.to_text() for r in answers]
    except Exception as e:
        logger.info(f"Failed resolving DNS A records for {domain}: {e}")
        records["A"] = []

    # 2. Resolve 'MX' Records
    try:
        answers = resolver.resolve(domain, 'MX')
        records["MX"] = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
    except Exception as e:
        logger.info(f"Failed resolving DNS MX records for {domain}: {e}")
        records["MX"] = []

    # 3. Resolve 'NS' Records
    try:
        answers = resolver.resolve(domain, 'NS')
        records["NS"] = [r.target.to_text().rstrip('.') for r in answers]
    except Exception as e:
        logger.info(f"Failed resolving DNS NS records for {domain}: {e}")
        records["NS"] = []

    # 4. Resolve 'TXT' Records
    try:
        answers = resolver.resolve(domain, 'TXT')
        records["TXT"] = [b"".join(r.strings).decode('utf-8', errors='ignore') for r in answers]
    except Exception as e:
        logger.info(f"Failed resolving DNS TXT records for {domain}: {e}")
        records["TXT"] = []

    # Check if all returned lists are empty, denoting resolution failure
    if not any([records["A"], records["MX"], records["NS"], records["TXT"]]):
        records["status"] = "No Resolution"
        records["message"] = f"No active DNS resolutions found for target domain '{domain}'."

    return records

def ip_geolocation(ip: str) -> dict:
    """
    Fetches passive physical geolocation data targeting the free ip-api.com REST service.
    Requires no API keys.
    """
    url = f"http://ip-api.com/json/{ip}"
    try:
        logger.info(f"Fetching passive Geolocation coordinates for IP: {ip}")
        response = requests.get(url, timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    "status": "Success",
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "latitude": data.get('lat', 0.0),
                    "longitude": data.get('lon', 0.0)
                }
            else:
                return {
                    "status": "No Resolution",
                    "message": data.get('message', 'Failed geolocating target IP address.')
                }
        else:
            return {
                "status": "Error",
                "message": f"Geolocation lookup service returned status code {response.status_code}."
            }
    except Exception as e:
        logger.error(f"Exception during passive Geolocation lookups: {e}")
        return {
            "status": "Error",
            "message": f"Geolocation fetch connection failed: {str(e)}"
        }

def generate_map(lat, lon, target_info) -> str:
    """
    Generate Folium map centered on lat/lon, add a marker, and save as HTML.
    Returns the web-accessible path to the map.
    """
    map_dir = os.path.join("static", "maps")
    os.makedirs(map_dir, exist_ok=True)
    
    m = folium.Map(location=[lat, lon], zoom_start=12)
    
    popup_text = (
        f"<b>IP:</b> {target_info.get('ip', 'N/A')}<br>"
        f"<b>Country:</b> {target_info.get('country', 'N/A')}<br>"
        f"<b>City:</b> {target_info.get('city', 'N/A')}<br>"
        f"<b>ISP:</b> {target_info.get('isp', 'N/A')}"
    )
    
    folium.Marker(
        [lat, lon],
        popup=folium.Popup(popup_text, max_width=300),
        icon=folium.Icon(color="red", icon="info-sign")
    ).add_to(m)
    
    filename = f"map_{uuid.uuid4().hex[:8]}.html"
    filepath = os.path.join(map_dir, filename)
    m.save(filepath)
    
    return f"/static/maps/{filename}"

def run_recon(target: str, api_key: str = None) -> dict:
    """
    Core Entry Controller for OSINT passive audits.
    Adapts resolution based on input (IP address vs Domain name).
    - If Domain is provided: Queries domain DNS + WHOIS, resolves IP, then queries IP Geolocation + Shodan.
    - If IP is provided: Queries IP Geolocation + Shodan, queries IP WHOIS registries, and attempts reverse PTR DNS lookup.
    """
    try:
        # Fallback to local environment loaded variable if key is not passed directly
        if not api_key:
            api_key = os.getenv("SHODAN_API_KEY", "").strip() or None

        cleaned = clean_target(target)
        if not cleaned:
            return {
                "success": False,
                "results": {},
                "error": "Provided target host target string resolves to empty address space."
            }

        logger.info(f"OSINT Master Controller executing check on: {cleaned}")

        if is_ip_address(cleaned):
            # Target is an IP address
            geo_results = ip_geolocation(cleaned)
            if geo_results.get("status") == "Success":
                geo_results["map_path"] = generate_map(
                    geo_results["latitude"], 
                    geo_results["longitude"], 
                    {"ip": cleaned, "country": geo_results.get("country"), "city": geo_results.get("city"), "isp": geo_results.get("isp")}
                )
                
            shodan_results = shodan_lookup(cleaned, api_key)
            whois_results = whois_lookup(cleaned)
            
            # Reverse DNS lookup (PTR)
            reverse_domain = "N/A"
            try:
                rev_name = dns.reversename.from_address(cleaned)
                answers = dns.resolver.resolve(rev_name, 'PTR')
                if answers:
                    reverse_domain = answers[0].to_text().rstrip('.')
            except Exception as e:
                logger.info(f"No DNS PTR record mapped for IP address {cleaned}: {e}")

            return {
                "success": True,
                "results": {
                    "scan_target": cleaned,
                    "target_type": "IP Address",
                    "reverse_dns": reverse_domain,
                    "geolocation_data": geo_results,
                    "shodan_data": shodan_results,
                    "whois_registry_data": whois_results
                },
                "error": None
            }
        else:
            # Target is a Domain name
            dns_results = dns_lookup(cleaned)
            whois_results = whois_lookup(cleaned)
            
            # Extract primary resolved IP address (take the first resolved A record)
            resolved_ip = None
            if dns_results.get("A"):
                resolved_ip = dns_results["A"][0]
            
            geo_results = {}
            shodan_results = {}
            
            if resolved_ip:
                logger.info(f"Domain '{cleaned}' resolved to primary host IP: {resolved_ip}")
                geo_results = ip_geolocation(resolved_ip)
                if geo_results.get("status") == "Success":
                    geo_results["map_path"] = generate_map(
                        geo_results["latitude"], 
                        geo_results["longitude"], 
                        {"ip": resolved_ip, "country": geo_results.get("country"), "city": geo_results.get("city"), "isp": geo_results.get("isp")}
                    )
                shodan_results = shodan_lookup(resolved_ip, api_key)
            else:
                logger.warning(f"Could not resolve an A record IP for domain '{cleaned}'. Skipping Geo & Shodan sweeps.")
                geo_results = {
                    "status": "Skipped",
                    "message": "Domain A record could not be resolved to an active IP address."
                }
                shodan_results = {
                    "status": "Skipped",
                    "message": "Domain A record could not be resolved to an active IP address."
                }

            return {
                "success": True,
                "results": {
                    "scan_target": cleaned,
                    "target_type": "Domain Name",
                    "resolved_host_ip": resolved_ip or "Unresolved",
                    "dns_records": dns_results,
                    "whois_registry_data": whois_results,
                    "geolocation_data": geo_results,
                    "shodan_data": shodan_results
                },
                "error": None
            }

    except Exception as e:
        logger.error(f"Global master recon script failed to execute: {e}")
        return {
            "success": False,
            "results": {},
            "error": f"OSINT master thread exception: {str(e)}"
        }
