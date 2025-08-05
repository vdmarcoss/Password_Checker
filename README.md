# Password Checker

A web-based password strength and security checker built with Flask and Tailwind CSS. It provides:

- **Live feedback**: real-time strength meter as you type.  
- **Server-side validation**: checks against common password lists, HIBP API breaches, and zxcvbn scoring.  
- **File upload**: batch-check multiple passwords from a text file.  
- **Customizable rules**: minimum length and toggles for each check.  

---

## Features

- **Dynamic Strength Meter**: Updates bar, color, and label (Very Weak → Very Strong) based on:
  - Length ≥ 8  
  - Contains uppercase letters  
  - Contains digits  
  - Contains special characters  
- **Show/Hide Toggle** for password input.  
- **Common Password Check** against a local list (`data/common_passwords.txt`).  
- **Pwned Passwords** lookup via [Have I Been Pwned API](https://haveibeenpwned.com/).  
- **zxcvbn** scoring and feedback (if enabled).  
- **Batch Processing**: upload `.txt` file with one password per line.  
- **Configurable** minimum length and enable/disable each check.  

---

## Requirements

- Python 3.8+  
- `pip` package manager  

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Password_Checker.git
cd Password_Checker
```

# (Optional) Create and activate a virtual environment
```bash
python -m venv venv
# Windows (cmd): venv\Scripts\activate.bat
# Windows (PowerShell): .\venv\Scripts\Activate.ps1
# macOS/Linux: source venv/bin/activate
```

# Install dependencies
```bash
pip install -r requirements.txt
```

## Configuration
- Minimum Length: default is 10, can be overridden in the UI.
- Common Password List: data/common_passwords.txt (one password per line).
- Toggle Checks: Enable or disable Common, HIBP, zxcvbn from form.

## Usage
```bash
python app.py
```
### Open your browser at http://localhost:5000:
- Type a password for live client-side feedback.
- (Optional) Upload a .txt file to batch-verify passwords.
- Set minimum length and checkboxes.
- Click Verify to run server-side checks and view results.

## Project Structure
```bash
password_checker/
├── app.py              # Flask application and routes
├── config.py           # Default configuration values
├── password_utils.py   # Validation and API functions
├── requirements.txt    # Python dependencies
├── data/
│   └── common_passwords.txt  # Common passwords list
├── templates/
│   └── index.html      # Jinja2 template with Tailwind UI
└── static/
    ├── css/
    │   └── tailwind.css   # (Optional overrides)
    └── js/
        └── main.js        # Live feedback logic
```