
import os
import sqlite3
import subprocess
import pickle
import hashlib
import yaml
import xml.etree.ElementTree as ET
import tempfile
import random
import logging
import requests
import re

# ============================================================
# SAST Vulnerable Python Code - For Security Training Only
# Detectable by: Snyk Code (SAST), SonarQube, Bandit
# ============================================================


# [VULN 1] CWE-798 - Hardcoded Credentials
# Snyk Rule: python/HardcodedCredentials
DB_PASSWORD = "admin123"
API_KEY = "d3adbeef1234567890abcdef"
SECRET_TOKEN = "supersecrettoken"


def add(a, b):
    return a + b


def subtract(a, b):
    return a - b


# [VULN 2] CWE-78 - OS Command Injection
# Snyk Rule: python/CommandInjection
# Risk: Attacker can pass "; rm -rf /" as user_input
def run_command(user_input):
    os.system("ping " + user_input)  # unsanitized input passed to shell
    # Also detectable variant:
    subprocess.call("ls " + user_input, shell=True)


# [VULN 3] CWE-89 - SQL Injection
# Snyk Rule: python/SqlInjection
# Risk: Attacker can pass "' OR '1'='1" to dump the entire table
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"  # no parameterization
    cursor.execute(query)
    return cursor.fetchall()


# [VULN 4] CWE-95 - Code Injection via eval()
# Snyk Rule: python/CodeInjection
# Risk: Attacker can pass "__import__('os').system('rm -rf /')"
def calculate(expression):
    import ast
    import operator as _op
    _ops = {
        ast.Add: _op.add, ast.Sub: _op.sub, ast.Mult: _op.mul,
        ast.Div: _op.truediv, ast.Mod: _op.mod, ast.Pow: _op.pow,
        ast.FloorDiv: _op.floordiv, ast.USub: _op.neg, ast.UAdd: _op.pos,
    }
    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _ops:
            return _ops[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _ops:
            return _ops[type(node.op)](_eval(node.operand))
        raise ValueError("Unsafe expression")
    return _eval(ast.parse(expression, mode="eval"))


# [VULN 5] CWE-502 - Insecure Deserialization via pickle
# Snyk Rule: python/UnsafeDeserialization
# Risk: Malicious pickle payload can execute arbitrary OS commands
def load_data(serialized_data):
    return pickle.loads(serialized_data)  # pickle.loads is unsafe with untrusted data


# [VULN 6] CWE-327 - Use of Weak Cryptographic Algorithm (MD5)
# Snyk Rule: python/WeakCryptography
# Risk: MD5 is broken; collisions can be generated; not suitable for passwords
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# [VULN 7] CWE-22 - Path Traversal
# Snyk Rule: python/PathTraversal
# Risk: Attacker can pass "../../etc/passwd" to read sensitive system files
def read_file(filename):
    with open("/var/data/" + filename, "r") as f:
        return f.read()


# [VULN 8] CWE-78 - Command Injection via subprocess with shell=True
# Snyk Rule: python/CommandInjection
def get_hostname(ip):
    result = subprocess.check_output("nslookup " + ip, shell=True)  # shell=True with user input
    return result


# [VULN 9] CWE-611 - XML External Entity (XXE) Injection
# Snyk Rule: python/XxeInjection
# Risk: Attacker can read local files or perform SSRF via crafted XML
def parse_xml(xml_data):
    tree = ET.fromstring(xml_data)  # default parser resolves external entities
    return tree


# [VULN 10] CWE-601 - Open Redirect
# Snyk Rule: python/OpenRedirect
# Risk: Attacker can redirect users to a phishing/malicious site
def redirect_user(request_url):
    redirect_target = request_url.get("next")
    return "Location: " + redirect_target  # no validation of the redirect URL


# [VULN 11] CWE-330 - Use of Insufficiently Random Values
# Snyk Rule: python/WeakRandom
# Risk: random module is not cryptographically secure; predictable tokens
def generate_token():
    return str(random.randint(100000, 999999))  # use secrets.token_hex() instead


# [VULN 12] CWE-312 - Cleartext Storage of Sensitive Information
# Snyk Rule: python/CleartextLogging
# Risk: Passwords/tokens logged in plaintext; visible in log files
def login(username, password):
    logging.basicConfig(filename="app.log", level=logging.DEBUG)
    logging.debug(f"Login attempt: user={username} password={password}")  # password logged!
    return username == "admin" and password == DB_PASSWORD


# [VULN 13] CWE-915 - Unsafe YAML Deserialization
# Snyk Rule: python/UnsafeYamlDeserialization
# Risk: yaml.load() with untrusted input can execute arbitrary Python objects
def load_config(yaml_data):
    return yaml.load(yaml_data)  # should use yaml.safe_load()


# [VULN 14] CWE-918 - Server-Side Request Forgery (SSRF)
# Snyk Rule: python/Ssrf
# Risk: Attacker can make server fetch internal resources (e.g., http://169.254.169.254)
def fetch_url(user_provided_url):
    response = requests.get(user_provided_url)  # no URL validation or allowlist
    return response.text


# [VULN 15] CWE-400 - Uncontrolled Resource Consumption (ReDoS)
# Snyk Rule: python/ReDoS
# Risk: Catastrophic backtracking when attacker supplies crafted input
def validate_email(email):
    pattern = r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$"  # vulnerable regex
    return re.match(pattern, email)


# [VULN 16] CWE-377 - Insecure Temporary File
# Snyk Rule: python/InsecureTempFile
# Risk: Predictable temp file name allows symlink attacks / race conditions
def write_temp_data(data):
    tmp_path = "/tmp/myapp_temp.txt"  # hardcoded, predictable path
    with open(tmp_path, "w") as f:
        f.write(data)
    return tmp_path


# [VULN 17] CWE-209 - Information Exposure via Error Messages
# Snyk Rule: python/InformationExposure
# Risk: Stack traces and internal details exposed to end users
def divide(a, b):
    try:
        return a / b
    except Exception as e:
        return str(e)  # exposes internal exception details to caller/user


# [VULN 18] CWE-259 - Hardcoded Password in Connection String
# Snyk Rule: python/HardcodedCredentials
# Risk: Credentials embedded in source code are easily discoverable
def get_db_connection():
    conn_string = "postgresql://admin:Password123@localhost:5432/proddb"  # hardcoded DB creds
    return conn_string


def main():
    x = 10
    y = 5
    print("Add:", add(x, y))
    print("Subtract:", subtract(x, y))

    # VULN 4 triggered - user input passed directly into eval
    user_input = input("Enter expression: ")
    print("Result:", calculate(user_input))

    # VULN 2 triggered - user input passed directly into os.system
    cmd_input = input("Enter host to ping: ")
    run_command(cmd_input)

    # VULN 11 triggered - weak random token
    print("Your token:", generate_token())

    # VULN 14 triggered - SSRF via user-provided URL
    url = input("Enter URL to fetch: ")
    print(fetch_url(url))


if __name__ == "__main__":
    main()
 
