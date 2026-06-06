"""
CyberGuard Pro - Network Diagnostics Module
===========================================
This module executes benign service reachability and diagnostic port checks:
1. Performs target domain resolution audits.
2. Probes specific TCP ports using standard socket connectivity (connect_ex).
3. Assigns administrative risk labels based on standard service exposure rules.

All operations are entirely non-intrusive and standard for administrative diagnostics.
"""

import re
import socket
import logging
from typing import List, Dict, Any

# Configure module-specific logger
logger = logging.getLogger(__name__)

# Hardcoded dictionary for well-known services
COMMON_PORTS_DICT = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

def get_service_name(port: int) -> str:
    """
    Returns the common service name for well known ports using a hardcoded dictionary.
    """
    return COMMON_PORTS_DICT.get(port, "Unknown")

def port_check(target: str, ports: List[int] = None) -> List[Dict[str, Any]]:
    """
    Use socket.connect_ex() to check if common ports are open or closed.
    Returns a list of dicts with port, status (open/closed), and common service name.
    """
    if not ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

    # Set default socket connection timeout to 1 second for fast checks
    socket.setdefaulttimeout(1.0)
    checked_ports = []

    logger.info(f"Initiating reachability probes for ports: {ports}")

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # connect_ex is robust and does not throw exception on connection blockages
            result_code = s.connect_ex((target, port))
            status = "open" if result_code == 0 else "closed"
            
            checked_ports.append({
                "port": port,
                "status": status,
                "service": get_service_name(port)
            })
        except Exception as e:
            logger.warning(f"Connection verification failed for port {port}: {e}")
            checked_ports.append({
                "port": port,
                "status": "closed",
                "service": get_service_name(port)
            })
        finally:
            s.close()

    return checked_ports

def run_network_check(target: str) -> Dict[str, Any]:
    """
    Master diagnostic function.
    Validates host, calls port_check, calculates open metrics, and assigns risk level.
    """
    # Print legal scanning warning disclaimer
    print("[WARNING] Ethical Notice: Scanning unauthorized target network nodes is illegal.")
    print("[WARNING] Ensure explicit authorization is granted by network asset owners before proceeding.")

    # Clean target string (remove protocol blocks, paths, and trailing flags)
    cleaned = target.strip()
    cleaned = re.sub(r'^https?://', '', cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split('/')[0].split('?')[0].split(':')[0]

    if not cleaned:
        raise ValueError("Provided network target resolves to an empty address space.")

    logger.info(f"Resolving network target hostname: {cleaned}")

    try:
        # Resolve target domain to valid IP address (catches invalid hosts)
        resolved_ip = socket.gethostbyname(cleaned)
    except socket.gaierror as e:
        logger.error(f"Hostname lookup resolution failed for target: {cleaned} - {e}")
        raise ValueError(f"Failed to resolve host '{cleaned}'. Please check target address syntax or connection state.")

    # Target ports to scan
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
    
    # Run socket check
    checked_ports = port_check(resolved_ip, ports_to_scan)
    
    # Compute active open counts
    open_ports_count = sum(1 for p in checked_ports if p["status"] == "open")

    # Risk Label Classification: 0-3 open = Low, 4-7 = Medium, 8+ = High
    if open_ports_count <= 3:
        risk_label = "Low"
    elif open_ports_count <= 7:
        risk_label = "Medium"
    else:
        risk_label = "High"

    combined_dict = {
        "target": cleaned,
        "resolved_ip": resolved_ip,
        "ports_checked": len(ports_to_scan),
        "checked_ports": checked_ports,
        "open_ports_count": open_ports_count,
        "risk_label": risk_label
    }

    return combined_dict

def run_network_scan(target: str, scan_type: str = "quick") -> Dict[str, Any]:
    """
    Master toolkit wrapper matching app.py routing expectations.
    Calls run_network_check internally and handles exceptions gracefully.
    """
    try:
        results = run_network_check(target)
        results["scan_type"] = scan_type
        return {
            "success": True,
            "results": results,
            "error": None
        }
    except Exception as e:
        logger.error(f"Network scan execution failed: {e}")
        return {
            "success": False,
            "results": {},
            "error": str(e)
        }
