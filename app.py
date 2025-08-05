from flask import Flask, render_template, request
from config import DEFAULT_MIN_LENGTH
from password_utils import (
    check_length, check_char_types,
    check_common, check_pwned,
    evaluate_strength
)

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Dynamic configuration from form
    config = {
        'min_length': int(request.form.get('min_length', DEFAULT_MIN_LENGTH)),
        'use_common': 'common' in request.form,
        'use_hibp':   'hibp'   in request.form,
        'use_zxcvbn': 'zxcvbn' in request.form
    }
    results_list = []
    result = None

    if request.method == 'POST':
        uploaded = request.files.get('file')
        if uploaded and uploaded.filename:
            lines = uploaded.stream.read().decode('utf-8').splitlines()
            for pwd in lines:
                pwd = pwd.strip()
                if not pwd:
                    continue
                length_ok = check_length(pwd, config['min_length'])
                types = check_char_types(pwd)
                common = check_common(pwd) if config['use_common'] else 'N/A'
                pwned = check_pwned(pwd)     if config['use_hibp']   else 'N/A'
                score, feedback = (
                    evaluate_strength(pwd)
                    if config['use_zxcvbn']
                    else (None, {'warning': '', 'suggestions': []})
                )
                results_list.append({
                    'password': pwd,
                    'length': length_ok,
                    'types': types,
                    'common': common,
                    'pwned': pwned,
                    'score': score,
                    'feedback': feedback
                })
        else:
            pwd = request.form.get('password', '')
            if pwd:
                length_ok = check_length(pwd, config['min_length'])
                types = check_char_types(pwd)
                common = check_common(pwd) if config['use_common'] else True
                pwned = check_pwned(pwd)     if config['use_hibp']   else None
                score, feedback = (
                    evaluate_strength(pwd)
                    if config['use_zxcvbn']
                    else (None, {'warning': '', 'suggestions': []})
                )
                result = {
                    'password': pwd,
                    'length': length_ok,
                    'types': types,
                    'common': common,
                    'pwned': pwned,
                    'score': score,
                    'feedback': feedback
                }

    return render_template(
        'index.html', config=config,
        results_list=results_list,
        result=result
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)