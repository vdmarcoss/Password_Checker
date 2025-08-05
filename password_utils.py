import re
import hashlib
import requests
from pyzxcvbn import zxcvbn
from config import DEFAULT_MIN_LENGTH

COMMON_PASSWORDS_FILE = 'data/common_passwords.txt'
HIBP_API_URL = 'https://api.pwnedpasswords.com/range/'


def check_length(password: str, min_length: int = DEFAULT_MIN_LENGTH) -> bool:
    return len(password) >= min_length


def check_char_types(password: str) -> dict:
    return {
        'lowercase': bool(re.search(r'[a-z]', password)),
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'digits':    bool(re.search(r'\d', password)),
        'special':   bool(re.search(r'[^A-Za-z0-9]', password)),
    }


def check_common(password: str) -> bool:
    try:
        with open(COMMON_PASSWORDS_FILE, 'r', encoding='utf-8') as f:
            common = set(line.strip() for line in f)
        return password not in common
    except FileNotFoundError:
        return True


def check_pwned(password: str) -> int | None:
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
    except requests.RequestException:
        return None


def evaluate_strength(password: str) -> tuple[int, dict]:
    result = zxcvbn(password)
    return result['score'], result['feedback']