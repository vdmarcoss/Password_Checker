import argparse
import re
import sys
import hashlib
import requests
from pyzxcvbn import zxcvbn

COMMON_PASSWORDS_FILE = 'data/common_passwords.txt'
HIBP_API_URL = 'https://api.pwnedpasswords.com/range/'


def check_length(password: str, min_length: int = 10) -> bool:
    """Password length must be at least min_length"""
    return len(password) >= min_length


def check_char_types(password: str) -> dict:
    """Password must contain at least one lowercase, one uppercase, one digit, and one special character"""
    return {
        'lowercase': bool(re.search(r'[a-z]', password)),
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'digits':    bool(re.search(r'\d', password)),
        'special':   bool(re.search(r'[^A-Za-z0-9]', password)),
    }


def check_common(password: str) -> bool:
    """Checking if the password is in a list of common passwords"""
    try:
        with open(COMMON_PASSWORDS_FILE, 'r', encoding='utf-8') as f:
            common = set(line.strip() for line in f)
        return password not in common
    except FileNotFoundError:
        print(f"[!] Files {COMMON_PASSWORDS_FILE} not found. Skipping common password check.")
        return True


def check_pwned(password: str) -> int | None:
    """Check if the password has been pwned using the HIBP API."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(HIBP_API_URL + prefix)
        if resp.status_code != 200:
            return None
        for line in resp.text.splitlines():
            h, count = line.split(':')
            if h == suffix:
                return int(count)
        return 0
    except requests.RequestException as e:
        print(f"[!] Error connecting with HIBP: {e}")
        return None


def evaluate_strength(password: str) -> tuple[int, dict]:
    """Using zxcvbn to evaluate password strength."""
    result = zxcvbn(password)
    return result['score'], result['feedback']


def main():
    parser = argparse.ArgumentParser(description="Password Checker CLI - Marcos Vasquez")
    parser.add_argument('password', nargs='?', help='Password to check')
    parser.add_argument('-f', '--file', help='File with passwords to check (one per line)')
    parser.add_argument('--min-length', type=int, default=10, help='Minimum password length (default: 10)')
    args = parser.parse_args()

    pwds = []
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                pwds = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading {args.file}: {e}")
            sys.exit(1)
    elif args.password:
        pwds = [args.password]
    else:
        print("[!] Give a password or -f <file> with passwords to check.")
        sys.exit(1)

    for pwd in pwds:
        print(f"\n[+] Analyzing: {pwd}")
        print(f"  - Lenght >= {args.min_length}: {check_length(pwd, args.min_length)}")
        types = check_char_types(pwd)
        print(f"  - Characters types: {types}")
        print(f"  - Isn't common: {check_common(pwd)}")
        pwned = check_pwned(pwd)
        print(f"  - Times in breaches: {pwned if pwned is not None else 'Error or not found'}")
        score, feedback = evaluate_strength(pwd)
        print(f"  - Score of zxcvbn: {score}/4")
        if feedback['warning'] or feedback['suggestions']:
            print(f"    * Warning: {feedback['warning']}")
            for s in feedback['suggestions']:
                print(f"    * Suggestions: {s}")


if __name__ == '__main__':
    main()
