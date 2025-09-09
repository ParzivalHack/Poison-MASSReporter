# This is a comprehensive test script for PySpector.
# It contains 16 detectable vulnerabilities.

import subprocess
import os
import pickle
import hashlib
import tempfile
import yaml
import xml.etree.ElementTree
import shlex
import requests
from flask import Flask, escape, Markup

# This class simulates a web request object for taint analysis
class MockRequest:
    def get(self, key):
        # In a real app, this would get data from a web request
        if key == 'user_command':
            return '&& id' # Simulate malicious user input
        return 'safe_value'

# Simulate a web framework's request object
request = MockRequest()
app = Flask(__name__)

# --- VULNERABLE FUNCTIONS ---

# G101: Hardcoded password
api_key = "SECRET_KEY_1234567890abcdef"

# G102: Hardcoded private key
private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALDRv252s/b45a2+96a...
-----END RSA PRIVATE KEY-----
"""

# PY001: Use of eval()
def execute_code(untrusted_data):
    eval(untrusted_data)

# PY002: Use of pickle
def deserialize_data(data):
    pickle.loads(data)

# PY102: Taint Analysis - Command Injection
def run_user_command_tainted():
    user_input = request.get('user_command') # SOURCE
    # The taint from 'user_input' should flow to 'full_command'
    full_command = f"echo {user_input}"
    # SINK: Tainted data reaches shell=True call
    subprocess.run(full_command, shell=True)

# PY003: AST - Command Injection
def run_hardcoded_command_insecurely():
    # This call is not tainted, but is a bad pattern
    subprocess.run("ls -l /tmp", shell=True)

# PY103: Use of os.system
def run_os_command(cmd):
    os.system(cmd)

# PY105: Potential XSS with Markup
def render_html(raw_html):
    return Markup(raw_html)

# PY201 & PY202: Weak Hashing
def get_hashes(password):
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    return md5_hash, sha1_hash

# PY204: Discouraged crypto library
try:
    from Crypto.Cipher import AES
except ImportError:
    pass # Ignore if not installed

# PY302: Insecure yaml.load
def load_yaml(stream):
    yaml.load(stream)

# PY303: Insecure XML parsing
def parse_xml(xml_string):
    xml.etree.ElementTree.fromstring(xml_string)

# PY304: Insecure tempfile creation
def create_temp_file():
    tempfile.mktemp()

# G403: Flask debug mode enabled
@app.route("/")
def index():
    # G405: Requests with verify=False
    requests.get("https://example.com", verify=False)
    return "Hello, World!"

# --- SAFE FUNCTION (Should NOT be flagged) ---

def run_user_command_safe():
    user_input = request.get('user_command') # SOURCE
    # SANITIZER: The taint is removed here
    safe_input = shlex.quote(user_input)
    full_command = f"echo {safe_input}"
    # SINK: Only sanitized data reaches the sink
    subprocess.run(full_command, shell=True)

if __name__ == "__main__":
    # G403 is also triggered by this line
    app.run(debug=True)