# app.py - Web Password Checker con Flask

from flask import Flask, render_template_string, request
import re, hashlib, requests
from pyzxcvbn import zxcvbn

COMMON_PASSWORDS_FILE = 'data/common_passwords.txt'
HIBP_API_URL = 'https://api.pwnedpasswords.com/range/'


def check_length(password: str, min_length: int = 10) -> bool:
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

app = Flask(__name__)

HTML_TEMPLATE = '''
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Password Checker</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 2em auto; }
    input { padding: 0.5em; width: 100%; margin-bottom: 1em; }
    button { padding: 0.5em 1em; }
    .result { margin-top: 1em; background: #f5f5f5; padding: 1em; border-radius: 4px; }
    .true { color: green; }
    .false { color: red; }
  </style>
</head>
<body>
  <h1>Password Checker</h1>
  <form method="post">
    <input type="password" name="password" placeholder="Ingresa una contraseña" required>
    <button type="submit">Verificar</button>
  </form>
  {% if results %}
  <div class="result">
    <h2>Resultados para: "{{ results.password }}"</h2>
    <ul>
      <li>Longitud >= {{ results.min_length }}: <span class="{{ 'true' if results.length else 'false' }}">{{ results.length }}</span></li>
      <li>Tipos de caracteres: {{ results.types }}</li>
      <li>No es común: <span class="{{ 'true' if results.common else 'false' }}">{{ results.common }}</span></li>
      <li>Veces en breaches: {{ results.pwned if results.pwned is not none else 'Error' }}</li>
      <li>Puntaje zxcvbn: {{ results.score }}/4</li>
      {% if results.feedback.warning %}
      <li>Advertencia: {{ results.feedback.warning }}</li>
      {% endif %}
      {% for sug in results.feedback.suggestions %}
      <li>Sugerencia: {{ sug }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        password = request.form['password']
        min_length = 10
        length_ok = check_length(password, min_length)
        types = check_char_types(password)
        common = check_common(password)
        pwned = check_pwned(password)
        score, feedback = evaluate_strength(password)
        results = {
            'password': password,
            'min_length': min_length,
            'length': length_ok,
            'types': types,
            'common': common,
            'pwned': pwned,
            'score': score,
            'feedback': feedback
        }
    return render_template_string(HTML_TEMPLATE, results=results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)