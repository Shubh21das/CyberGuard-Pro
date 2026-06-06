"""
CyberGuard Pro - Password Strength & HIBP Exposure Validator
============================================================
Provides offline entropy analysis using zxcvbn and strictly private
k-Anonymity API queries to the Have I Been Pwned database.
"""

import hashlib
import logging
import random
import requests
try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None

logger = logging.getLogger(__name__)

def check_strength(password: str) -> dict:
    """
    Evaluates password strength metrics locally without transmitting the payload.
    """
    if not password:
        return {
            "score": 0,
            "crack_time_display": "instantly",
            "feedback": ["Password is empty."],
            "guesses": 0
        }
        
    if zxcvbn:
        result = zxcvbn(password)
        # Extract native feedback suggestions
        feedback = []
        if result.get('feedback', {}).get('warning'):
            feedback.append(result['feedback']['warning'])
        feedback.extend(result.get('feedback', {}).get('suggestions', []))
        
        return {
            "score": result.get("score", 0),
            "crack_time_display": result.get("crack_times_display", {}).get("offline_fast_hashing_1e10_per_second", "instantly"),
            "feedback": feedback if feedback else ["No structural warnings found."],
            "guesses": int(result.get("guesses", 0))
        }
    else:
        logger.warning("zxcvbn library is missing. Providing fallback entropy estimate.")
        # Very basic fallback if library fails to load
        score = min(4, len(password) // 4)
        return {
            "score": score,
            "crack_time_display": "unknown (library missing)",
            "feedback": ["System could not execute advanced entropy analysis."],
            "guesses": 0
        }

def check_pwned(password: str) -> tuple:
    """
    Queries the PwnedPasswords API using a secure k-Anonymity model.
    NEVER transmits the plaintext password. Only transmits the first 5 chars
    of the SHA-1 hash to download a block of anonymous matches.
    """
    if not password:
        return False, 0
        
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5.0)
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return True, int(count)
        return False, 0
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to query HIBP API: {e}")
        return False, 0

def generate_suggestions(password: str) -> list:
    """
    Applies structural mutations to generate 3 stronger password alternatives.
    """
    if not password:
        return ["MyS3cur3P@ssw0rd!"]
        
    suggestions = []
    
    # 1. Padding with symbols and randomized numbers
    suggestions.append(password + "-" + str(random.randint(100, 999)) + "!")
    
    # 2. Capitalization mutation (if not already capitalized) + secure suffix
    if password and not password[0].isupper():
        cap = password[0].upper() + password[1:]
        suggestions.append(cap + "_" + str(random.randint(10, 99)))
    else:
        suggestions.append(password + "_SECURE_" + str(random.randint(10, 99)))
        
    # 3. Mid-string injection of a special character
    mid = len(password) // 2
    if mid > 0:
        suggestions.append(password[:mid] + "@" + password[mid:] + str(random.randint(1, 9)))
    else:
        suggestions.append(password + "#$")
        
    return suggestions

def run_password_check(password: str) -> dict:
    """
    Master orchestrator combining zxcvbn analysis, HIBP exposure tests, and suggestions.
    """
    if not password:
        return {
            "success": False,
            "error": "No password provided."
        }
        
    try:
        # Execute tests
        strength_data = check_strength(password)
        is_pwned, times_pwned = check_pwned(password)
        suggestions = generate_suggestions(password)
        
        # Calculate a unified risk rating metric based on both entropy and exposure
        risk_rating = "LOW"
        if is_pwned:
            risk_rating = "CRITICAL"  # Automatically critical if actively breached
        elif strength_data['score'] <= 2:
            risk_rating = "HIGH"
        elif strength_data['score'] == 3:
            risk_rating = "MEDIUM"
            
        results = {
            "strength": strength_data,
            "pwned": {
                "is_pwned": is_pwned,
                "times_seen": times_pwned
            },
            "suggestions": suggestions,
            "risk_rating": risk_rating
        }
        
        return {
            "success": True,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Error during password evaluation: {e}")
        return {
            "success": False,
            "error": f"Internal execution failure: {str(e)}"
        }

def analyze_password(password: str) -> dict:
    """
    Wrapper alias to match the Flask endpoint import namespace perfectly.
    """
    return run_password_check(password)
