import os
import re
import json
import hashlib
import datetime
import subprocess
import logging

logger = logging.getLogger(__name__)

def extract_metadata(filepath: str) -> dict:
    """
    Run ExifTool via subprocess to extract file metadata.
    Falls back gracefully to OS file statistics and PIL Image metadata if ExifTool is not present.
    """
    # 1. Attempt ExifTool subprocess execution
    try:
        # Run exiftool in json output mode
        res = subprocess.run(['exiftool', '-json', filepath], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            data = json.loads(res.stdout)
            if data and isinstance(data, list):
                logger.info("Successfully extracted rich ExifTool metadata via subprocess.")
                return data[0]
    except (subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError, IndexError):
        logger.warning("ExifTool binary execution failed or not found. Activating lightweight fallbacks.")

    # 2. Resilient Python Fallbacks (OS statistics + PIL Image attributes)
    metadata = {
        "FileName": os.path.basename(filepath),
        "FileSize": f"{os.path.getsize(filepath) / 1024:.2f} KB",
        "FileModifyDate": datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
        "FileAccessDate": datetime.datetime.fromtimestamp(os.path.getatime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
        "FileCreateDate": datetime.datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
        "Note": "ExifTool not found or failed; filesystem statistics returned."
    }

    # If the file is an image, attempt Pillow (PIL) extraction
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        with Image.open(filepath) as img:
            metadata["MimeType"] = getattr(img, "mime", f"image/{img.format.lower()}" if img.format else "unknown")
            metadata["ImageWidth"] = img.width
            metadata["ImageHeight"] = img.height
            metadata["FileType"] = img.format
            
            # Extract tags
            exif_info = img.getexif()
            if exif_info:
                for tag_id, value in exif_info.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if isinstance(value, bytes):
                        value = value.decode(errors='replace')
                    metadata[str(tag_name)] = str(value)
    except Exception:
        # Pillow not present or not an image file type - fail silently
        pass

    return metadata


def calculate_hashes(filepath: str) -> dict:
    """
    Reads the file in binary chunks to calculate MD5, SHA-1, and SHA-256 hashes safely
    without overloading memory on larger files.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(65536)  # 64KB blocks
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except Exception as e:
        logger.error(f"Error calculating file hashes for {filepath}: {e}")
        return {
            "md5": "Error",
            "sha1": "Error",
            "sha256": "Error"
        }


def check_hash_virustotal(sha256_hash: str, api_key: str) -> dict:
    """
    Queries the VirusTotal API v3 endpoint for the target file's SHA-256 reputation.
    Returns detection rates and clean verdicts.
    """
    if not api_key:
        return {
            "success": False,
            "ratio": "N/A",
            "verdict": "NO API KEY",
            "error": "VirusTotal API Key not configured in local environment."
        }
        
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        import requests
        res = requests.get(url, headers=headers, timeout=6)
        if res.status_code == 200:
            data = res.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            
            total = malicious + suspicious + harmless + undetected
            ratio = f"{malicious} / {total}" if total > 0 else "0 / 0"
            
            if malicious > 3:
                verdict = "MALICIOUS"
            elif malicious > 0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"
                
            return {
                "success": True,
                "ratio": ratio,
                "verdict": verdict,
                "stats": stats
            }
        elif res.status_code == 404:
            return {
                "success": True,
                "ratio": "0 / 0",
                "verdict": "UNKNOWN",
                "error": "File hash not found in VirusTotal database repository."
            }
        elif res.status_code == 429:
            return {
                "success": False,
                "ratio": "N/A",
                "verdict": "RATE LIMIT EXCEEDED",
                "error": "VirusTotal API rate limit hit (4 requests/min ceiling reached)."
            }
        else:
            return {
                "success": False,
                "ratio": "N/A",
                "verdict": "ERROR",
                "error": f"VirusTotal API returned status code {res.status_code}."
            }
    except Exception as e:
        logger.error(f"VirusTotal hash query failure: {e}")
        return {
            "success": False,
            "ratio": "N/A",
            "verdict": "ERROR",
            "error": str(e)
        }


def analyze_strings(filepath: str) -> dict:
    """
    Inspects target file bytes to extract printable ASCII strings (min length 6)
    and uses regex to extract URLs, emails, and IPv4 addresses found inside.
    """
    try:
        # Read the first 5MB of file bytes to protect server memory resources
        with open(filepath, 'rb') as f:
            data = f.read(5 * 1024 * 1024)
            
        # Match sequences of 6 or more printable ASCII characters (0x20 to 0x7E)
        pattern = b'[\x20-\x7e]{6,}'
        found_bytes = re.findall(pattern, data)
        
        decoded_strings = []
        for b_str in found_bytes:
            try:
                decoded_strings.append(b_str.decode('ascii'))
            except UnicodeDecodeError:
                pass
                
        # Regex engines to locate indicators of compromise (IOCs)
        url_rx = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
        email_rx = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        ip_rx = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        urls = set()
        emails = set()
        ips = set()
        
        for s in decoded_strings:
            # Audit URLs
            for match in url_rx.findall(s):
                clean_match = match.strip('.,()[]{}"\'')
                urls.add(clean_match)
            # Audit Emails
            for match in email_rx.findall(s):
                emails.add(match)
            # Audit IPv4s
            for match in ip_rx.findall(s):
                octets = match.split('.')
                if all(0 <= int(o) <= 255 for o in octets):
                    ips.add(match)
                    
        return {
            "urls": sorted(list(urls))[:50],  # Cap listings to protect frontend loading
            "emails": sorted(list(emails))[:50],
            "ips": sorted(list(ips))[:50],
            "total_strings_extracted": len(decoded_strings)
        }
    except Exception as e:
        logger.error(f"Strings analysis error on {filepath}: {e}")
        return {
            "urls": [],
            "emails": [],
            "ips": [],
            "error": str(e)
        }


def sleuthkit_analyze(image_path: str) -> dict:
    """
    Runs Sleuth Kit utilities 'ils' and 'fls' via subprocesses.
    Gracefully catches situations where Sleuth Kit binaries are not installed.
    """
    ils_output = []
    fls_output = []
    sleuthkit_installed = True
    
    # 1. Run 'ils' tool command
    try:
        res_ils = subprocess.run(['ils', image_path], capture_output=True, text=True, timeout=5)
        if res_ils.returncode == 0:
            ils_output = res_ils.stdout.splitlines()
    except (FileNotFoundError, subprocess.SubprocessError):
        sleuthkit_installed = False
        
    # 2. Run 'fls' tool command
    try:
        res_fls = subprocess.run(['fls', '-r', image_path], capture_output=True, text=True, timeout=5)
        if res_fls.returncode == 0:
            fls_output = res_fls.stdout.splitlines()
    except (FileNotFoundError, subprocess.SubprocessError):
        sleuthkit_installed = False
        
    return {
        "sleuthkit_installed": sleuthkit_installed,
        "ils_output": ils_output[:100],  # Cap to protect buffer sizes
        "fls_output": fls_output[:100]
    }


def run_forensics(filepath: str, api_key: str) -> dict:
    """
    Coordinating Master function. Gathers results from ExifTool, hash generators,
    VirusTotal API checks, ASCII string processors, and Sleuth Kit subprocess pipelines.
    """
    try:
        if not os.path.exists(filepath):
            return {
                "success": False,
                "results": None,
                "error": f"Target file '{filepath}' does not exist."
            }

        # Calculate hashes
        hashes = calculate_hashes(filepath)
        
        # Extract metadata
        metadata = extract_metadata(filepath)
        
        # VirusTotal Hash reputation checks
        vt_results = check_hash_virustotal(hashes["sha256"], api_key)
        
        # Extract printing strings & IOCs
        strings = analyze_strings(filepath)
        
        # Sleuth Kit image analysis
        sleuthkit = sleuthkit_analyze(filepath)
        
        return {
            "success": True,
            "results": {
                "filename": os.path.basename(filepath),
                "filepath": filepath,
                "file_size": f"{os.path.getsize(filepath) / 1024:.2f} KB",
                "hashes": hashes,
                "metadata": metadata,
                "virustotal": vt_results,
                "strings": strings,
                "sleuthkit": sleuthkit
            },
            "error": None
        }
    except Exception as e:
        logger.error(f"Failed running forensics suite: {e}")
        return {
            "success": False,
            "results": None,
            "error": str(e)
        }


def analyze_file_forensics(filepath: str) -> dict:
    """
    Main entrypoint wrapper expected by the Flask app.py controller route.
    Retrieves the VirusTotal API key from environment configuration and launches analysis.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    return run_forensics(filepath, api_key)
