# --- 1. Standard Library Imports ---
import os, re, sys, threading, json, time, socket, logging, uuid, ssl, base64, io
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode
from typing import Dict, Optional, List, Any
from concurrent.futures import ThreadPoolExecutor

# --- 2. Third-Party Libraries ---
import requests
import urllib3
import yaml
import pdfkit
import redis
from bs4 import BeautifulSoup, Comment
from dotenv import load_dotenv
from googletrans import Translator
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from itsdangerous import URLSafeTimedSerializer
from waitress import serve

# --- 3. Flask and Extensions ---
from flask import (Flask, render_template, request, jsonify, session, redirect,
                   url_for, make_response, flash, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                       login_required, current_user)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import pyotp
import qrcode
from flask_migrate import Migrate

# --- 4. Selenium / Webdriver ---
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager

# --- 5. Application Setup & Configuration ---
load_dotenv()
current_dir = os.path.dirname(os.path.abspath(__file__))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- [CORRECTED ORDER] ---
# Step 1: Configure logging FIRST.
LOG_FILE = 'security_scan_v8.log'
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(threadName)s] %(levelname)s - %(message)s', filename=LOG_FILE, filemode='w')
logger = logging.getLogger('EthicalScannerV8')

# Security Constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_PERIOD = timedelta(minutes=15)

# Step 2: Initialize Flask App.
app = Flask(__name__, template_folder=os.path.join(current_dir, 'templates'), static_folder='static')

# Step 3: Connect to external services (like Redis) now that logger is available.
try:
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        raise ValueError("REDIS_URL environment variable is not set.")
    redis_client = redis.from_url(redis_url, decode_responses=True) # decode_responses=True is helpful!
    redis_client.ping()
    logger.info("Successfully connected to Redis.")
except (ValueError, redis.exceptions.ConnectionError) as e:
    logger.critical(f"FATAL: Could not connect to Redis. Aborting scan functionality. Reason: {e}")
    redis_client = None

# Step 4: Load all other configurations into the Flask app object.
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a-real-secret-key-is-required-in-env-file')
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///' + os.path.join(current_dir, 'scanner_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Step 5: Initialize Flask extensions.
mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login_route'
login_manager.login_message_category = 'info'
login_manager.login_message = 'الرجاء تسجيل الدخول للوصول إلى هذه الصفحة.'

# General Constants
PAYLOADS_DIR = os.path.join(current_dir, 'payloads')
PAYLOADS_FILE = os.path.join(PAYLOADS_DIR, 'payloads.json')
SEVERITY_SCORES = {'Critical': 15, 'High': 10, 'Medium': 5, 'Low': 2, 'Info': 0}
translator = Translator()

# --- 6. Helper Functions for Email Confirmation ---
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        return serializer.loads(token, salt='email-confirm-salt', max_age=expiration)
    except Exception:
        return None

def send_confirmation_email(user_email):
    token = generate_confirmation_token(user_email)
    confirm_url = url_for('confirm_email_route', token=token, _external=True)
    html = render_template('email/activate.html', confirm_url=confirm_url)
    msg = Message('تأكيد حسابك - الماسح الأمني', sender=app.config['MAIL_USERNAME'], recipients=[user_email], html=html)
    try:
        mail.send(msg)
    except Exception as e:
        logger.error(f"Failed to send confirmation email to {user_email}: {e}")

# --- 7. Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime(timezone=True), nullable=True)
    otp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    is_email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    scans = db.relationship('Scan', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    target_url = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='queued')
    results = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- 8. Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    password = PasswordField('كلمة المرور', validators=[DataRequired()])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('إنشاء حساب')

    def validate_password(self, password):
        p = password.data
        if len(p) < 8: raise ValidationError('يجب أن تكون كلمة المرور 8 أحرف على الأقل.')
        if not re.search(r'[A-Z]', p): raise ValidationError('يجب أن تحتوي كلمة المرور على حرف كبير.')
        if not re.search(r'[a-z]', p): raise ValidationError('يجب أن تحتوي كلمة المرور على حرف صغير.')
        if not re.search(r'\d', p): raise ValidationError('يجب أن تحتوي كلمة المرور على رقم.')
        if not re.search(r'[\W_]', p): raise ValidationError('يجب أن تحتوي كلمة المرور على رمز خاص.')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('اسم المستخدم هذا محجوز.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('هذا البريد الإلكتروني مستخدم بالفعل.')

class LoginForm(FlaskForm):
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    password = PasswordField('كلمة المرور', validators=[DataRequired()])
    submit = SubmitField('تسجيل الدخول')

class TwoFaForm(FlaskForm):
    otp = StringField('رمز المصادقة', validators=[DataRequired()])
    submit = SubmitField('تحقق')

# --- 9. Flask-Login Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ####

class TwoFaForm(FlaskForm):
    otp = StringField('رمز المصادقة', validators=[DataRequired()])
    submit = SubmitField('تحقق')


# --- 9. Flask-Login Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ############################################################################
# --- Scanner Core Logic ---
# ############################################################################

class OOBInteractionManager:
    def __init__(self, base_url: str):
        if not base_url or '.' not in base_url: raise ValueError("OOB Manager requires a valid base URL.")
        self.base_url = base_url.replace('https://', '').replace('http://', '')
        self.logger = logging.getLogger(self.__class__.__name__)

    def generate_payload_url(self, vuln_type: str) -> (str, str):
        interaction_id = f"{vuln_type}-{uuid.uuid4().hex[:12]}"
        return interaction_id, f"http://{interaction_id}.{self.base_url}"


class ScannerModule:
    def __init__(self, scanner_core):
        self.core = scanner_core
        self.logger = logging.getLogger(self.__class__.__name__)
    def run(self):
        raise NotImplementedError("Each module must implement the 'run' method.")


class EthicalSecurityScannerV7:
    def __init__(self, app_context, target_url: str, scan_id: str, scan_options):
        self.app = app_context
        self.target_url = target_url if urlparse(target_url).scheme else 'https://' + target_url
        self.domain = urlparse(self.target_url).netloc
        self.scan_id = scan_id
        self.logger = logging.getLogger(self.__class__.__name__)
        self.options = scan_options
        self.session = self._create_session()
        oob_url = self.options.get('oob_url', '').strip()
        self.oob_manager = OOBInteractionManager(oob_url) if oob_url else None
        self.results = self._initialize_results()
        self.vulnerability_lock = threading.Lock()
        self.payloads = self.load_payloads()
        self.stored_xss_nonces: Dict[str, Dict] = {}
        self.log_buffer = []
        self.log_buffer_lock = threading.Lock()

    # في فئة EthicalSecurityScannerV7
    def _create_session(self) -> requests.Session:
        """
        Creates a new requests.Session with an optimized transport adapter.
        This increases the connection pool size to handle high concurrency.
        """
        # 1. احصل على عدد الخيوط (threads) من إعدادات الفحص
        # هذا يضمن أن حجم المجمع يتناسب مع عدد المهام التي سيتم تشغيلها
        pool_size = int(self.options.get('thread_count', os.cpu_count() or 4))

        # تأكد من وجود قيمة دنيا لمنع الأخطاء
        pool_size = max(pool_size, 10)

        self.logger.info(f"Initializing requests session with connection pool size of {pool_size}")

        # 2. أنشئ محول (Adapter) جديدًا بالإعدادات المخصصة
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size
        )

        # 3. أنشئ كائن الجلسة
        s = requests.Session()

        # 4. اربط المحول (Mount) بجميع الطلبات التي تبدأ بـ http:// و https://
        s.mount('http://', adapter)
        s.mount('https://', adapter)

        # بقية إعدادات الجلسة كما هي
        s.headers.update({'User-Agent': os.getenv('SCANNER_USER_AGENT', 'EthicalScanner/8.0')})
        s.verify = False
        s.timeout = int(self.options.get('timeout', 8))

        custom_headers_str = self.options.get('custom_headers', '{}')
        if custom_headers_str.strip():
            try:
                s.headers.update(json.loads(custom_headers_str))
            except json.JSONDecodeError:
                self.logger.error("Invalid JSON for custom headers.")

        return s
    def _initialize_results(self) -> Dict[str, Any]:
        return {"scan_id": self.scan_id, "target": self.target_url, "scan_time": datetime.now(timezone.utc).isoformat(),
                "vulnerabilities": [], "risk_score": 0,
                "scan_stats": {"start_time": time.time(), "end_time": None, "duration": None, "requests_made": 0,
                               "errors_encountered": 0},
                "context": {"technologies": {}, "urls_found": {self.target_url}, "forms_found": [],
                            "interesting_paths": []}}

    def load_payloads(self) -> Dict[str, List[Dict]]:
        try:
            with open(PAYLOADS_FILE, 'r', encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.logger.error(f"Payloads file '{PAYLOADS_FILE}' is missing or corrupt.")
            return {}

    def start(self):
        final_status = 'completed'
        try:
            with self.app.app_context():
                Scan.query.filter_by(id=self.scan_id).update({'status': 'running'})
                db.session.commit()

            self._update_progress(1, "Scan initialized...")
            selected_modules = self.options.getlist('modules') if hasattr(self.options, 'getlist') else []


            # هذه هي الوحدات التي تعتمد على الروابط والنماذج التي يجدها الزاحف
            dependent_modules_map = {
                'InformationDisclosureModule': InformationDisclosureModule,
                'SQLInjectionModuleV5': SQLInjectionModuleV5,
                'XSSModuleV5': XSSModuleV5,
                'SSRFModule': SSRFModule,
                'SSTIModule': SSTIModule,
                'CommandInjectionModule': CommandInjectionModule,
                'LFIModule': LFIModule,
                'BusinessLogicModule': BusinessLogicModule
            }

            # --- الأداء المحسن: تشغيل المهام المتزامنة بذكاء ---
            max_workers = int(self.options.get('thread_count', os.cpu_count() or 4))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:

                # 1. ابدأ بتشغيل جميع الوحدات المستقلة فورًا وبالتوازي
                futures = []
                executor.submit(self._perform_automated_login)  # تسجيل الدخول يتم بالتوازي

                for name, cls in dependent_modules_map.items():
                    if name in selected_modules:
                        self.logger.info(f"Submitting independent module: {name}")
                        futures.append(executor.submit(cls(self).run))

                # 2. انتظر فقط حتى تنتهي المهام المستقلة إذا كانت هناك مهام تعتمد عليها
                for future in futures:
                    future.result()

                # 3. الآن، قم بتشغيل الزاحف ثم الوحدات المعتمدة عليه
                run_dependent = any(name in selected_modules for name in dependent_modules_map.keys())
                if run_dependent:
                    self._update_progress(30, "Phase 2: Crawling application...")
                    CrawlerModuleV5(self).run()

                    dependent_futures = []
                    for name, cls in dependent_modules_map.items():
                        if name in selected_modules:
                            self.logger.info(f"Submitting dependent module: {name}")
                            dependent_futures.append(executor.submit(cls(self).run))

                    # انتظر حتى تنتهي جميع مهام الحقن
                    for future in dependent_futures:
                        future.result()

            self._update_progress(95, "Scan phases complete. Finalizing...")
        except Exception as e:
            self.logger.critical(f"CRITICAL ERROR in scan {self.scan_id}: {e}", exc_info=True)
            final_status = 'error'
        finally:
            self._finalize_scan(final_status)

    def _finalize_scan(self, status='completed'):
        self.results["scan_stats"]["end_time"] = time.time()
        self.results["scan_stats"]["duration"] = self.results["scan_stats"]["end_time"] - self.results["scan_stats"][
            "start_time"]
        if redis_client:
            redis_client.hset(f"scan:{self.scan_id}", 'status', status)
        try:
            with self.app.app_context():
                scan_to_update = Scan.query.get(self.scan_id)
                if scan_to_update:
                    scan_to_update.status = status
                    scan_to_update.results = json.dumps(clean_for_json(self.results))
                    db.session.commit()
        except Exception as e:
            self.logger.critical(f"DATABASE ERROR on finalize: {e}", exc_info=True)
        self._update_progress(100, f"Scan Finalized with status: {status}")
    def _perform_automated_login(self):
        login_url = self.options.get('login_url')
        username_selector = self.options.get('username_field')
        password_selector = self.options.get('password_field')
        username = self.options.get('username_value')
        password = self.options.get('password_value')
        submit_selector = self.options.get('submit_button')

        if not all([login_url, username_selector, password_selector, username, password, submit_selector]):
            self.logger.info("معلومات تسجيل الدخول التلقائي غير مكتملة، سيتم تخطي هذه الخطوة.")
            return
        self.logger.info(f"محاولة تسجيل الدخول التلقائي إلى {login_url}...")
        driver = None
        try:
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
            driver.get(login_url)
            time.sleep(2)
            driver.find_element("css selector", username_selector).send_keys(username)
            driver.find_element("css selector", password_selector).send_keys(password)
            driver.find_element("css selector", submit_selector).click()
            time.sleep(5)
            cookies = driver.get_cookies()
            if not cookies:
                self.logger.warning("فشل تسجيل الدخول، لم يتم العثور على ملفات تعريف الارتباط.")
                return
            for cookie in cookies:
                self.session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])
            self.logger.info(f"نجح تسجيل الدخول! تم تحميل {len(cookies)} ملف تعريف ارتباط في الجلسة.")
        except Exception as e:
            self.logger.error(f"حدث خطأ أثناء تسجيل الدخول التلقائي: {e}", exc_info=True)
        finally:
            if driver:
                driver.quit()

    def _update_progress(self, progress: int, message: str):
        if redis_client:
            log_message = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"

            with self.log_buffer_lock:
                self.log_buffer.append(log_message)
                # Flush the buffer to Redis only when it reaches a certain size,
                # or when progress is updated, to avoid too many network calls.
                should_flush = (len(self.log_buffer) >= 20) or (progress > -1)

                if should_flush:
                    pipe = redis_client.pipeline()
                    # Only update progress if a valid value is given
                    if progress > -1:
                        pipe.hset(f"scan:{self.scan_id}", 'progress', min(progress, 100))

                    if self.log_buffer:
                        pipe.rpush(f"scan_log:{self.scan_id}", *self.log_buffer)

                    pipe.execute()
                    self.log_buffer.clear()  # Clear the buffer after flushing

    def _run_modules_concurrently(self, modules_to_run: List[ScannerModule]):
        if not modules_to_run: return
        max_workers = int(self.options.get('thread_count', os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(lambda mod: mod.run(), modules_to_run)

    def _run_recon_modules(self, selected):
        modules = {'PortScanningModule': PortScanningModule, 'DirectoryBruteforceModule': DirectoryBruteforceModule}
                  # 'APIDiscoveryModule': APIDiscoveryModule} #API
        self._run_modules_concurrently([cls(self) for name, cls in modules.items() if name in selected])

    def _run_independent_modules(self, selected):
        modules = {'FingerprintModule': FingerprintModule, 'WAFDetectionModule': WAFDetectionModule,
                   'HttpsModule': HttpsModule, 'SecurityHeadersModule': SecurityHeadersModule,
                   'CookieSecurityModule': CookieSecurityModule}
        self._run_modules_concurrently([cls(self) for name, cls in modules.items() if name in selected])

    def _run_injection_modules(self, selected):
        modules = {'InformationDisclosureModule': InformationDisclosureModule,
                   'SQLInjectionModuleV5': SQLInjectionModuleV5, 'XSSModuleV5': XSSModuleV5, 'SSRFModule': SSRFModule,
                   'SSTIModule': SSTIModule, 'CommandInjectionModule': CommandInjectionModule, 'LFIModule': LFIModule}
        self._run_modules_concurrently([cls(self) for name, cls in modules.items() if name in selected])

    def make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        with self.vulnerability_lock:
            self.results['scan_stats']['requests_made'] += 1
        try:
            return self.session.request(method.upper(), url, **kwargs)
        except requests.RequestException as e:
            self.logger.warning(f"Request to {url} failed: {e}")
            with self.vulnerability_lock:
                self.results['scan_stats']['errors_encountered'] += 1
            return None

    def add_vulnerability(self, name: str, severity: str, description: str, cwe: str, remediation: str,
                          evidence: Dict[str, Any], cve: Optional[str] = None):
        with self.vulnerability_lock:
            key = (name, evidence.get('url', evidence.get('vulnerable_url', '')), evidence.get('parameter'),
                   evidence.get('port'))
            if any(key == (v['name'], v['evidence'].get('url', v['evidence'].get('vulnerable_url', '')),
                           v['evidence'].get('parameter'), v['evidence'].get('port')) for v in
                   self.results['vulnerabilities']): return
            entry = {'name': name, 'severity': severity, 'description': description, 'cwe': cwe,
                     'remediation': remediation, 'evidence': evidence, 'cve': cve}
            self.results['vulnerabilities'].append(entry)
            self.results['risk_score'] += SEVERITY_SCORES.get(severity, 0)


# ############################################################################
# --- Scanner Modules (Full Code for All Modules) ---
# ############################################################################

class PortScanningModule(ScannerModule):
    def run(self):
        self.core._update_progress(5, f"Port Scanning {self.core.domain}...")
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080,
                        8443}
        open_ports = {}
        try:
            target_ip = socket.gethostbyname(self.core.domain)
        except socket.gaierror:
            self.logger.error(f"Cannot resolve hostname: {self.core.domain}");
            return

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((target_ip, port)) == 0:
                        with self.core.vulnerability_lock: open_ports[port] = "Unknown"
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=50) as e:
            e.map(scan_port, common_ports)
        if open_ports:
            self.core.add_vulnerability("Open Network Ports Discovered", "Info",
                                        f"Host has {len(open_ports)} common ports open.", "CWE-200",
                                        "Review and close any non-essential ports.",
                                        {'host': self.core.domain, 'ip': target_ip,
                                         'open_ports': list(open_ports.keys())})
#API
# class APIDiscoveryModule(ScannerModule):
#     def run(self):
#         self.core._update_progress(8, "Searching for API specification files...")
#         # قائمة بالمسارات الشائعة لملفات تعريف API
#         common_api_paths = [
#             '/swagger.json', '/openapi.json', '/api/swagger.json', '/api/openapi.json',
#             '/v1/swagger.json', '/v2/swagger.json', '/api/v1/swagger.json',
#             '/swagger/v1/swagger.json',
#             '/swagger.yaml', '/openapi.yaml'
#         ]
#
#         for path in common_api_paths:
#             spec_url = urljoin(self.core.target_url, path)
#             response = self.core.make_request('get', spec_url)
#
#             if response and response.status_code == 200:
#                 self.logger.warning(f"Found potential API specification file at: {spec_url}")
#                 try:
#                     if spec_url.endswith('.json'):
#                         spec_data = response.json()
#                     elif spec_url.endswith(('.yaml', '.yml')):
#                         spec_data = yaml.safe_load(response.text)
#                     else:
#                         continue  # غير مدعوم
#
#                     self._parse_api_spec(spec_data)
#                     # وجدنا ملفًا، لا داعي لمواصلة البحث (يمكن تحسين هذا لاحقًا)
#                     break
#                 except (json.JSONDecodeError, yaml.YAMLError) as e:
#                     self.logger.error(f"Failed to parse API specification file {spec_url}: {e}")
#
#     def _parse_api_spec(self, spec_data):
#         """يحلل ملف OpenAPI/Swagger ويضيف نقاط النهاية إلى قائمة الفحص."""
#         paths = spec_data.get('paths', {})
#         self.logger.info(f"Parsing {len(paths)} API paths from specification file.")
#
#         for path, methods in paths.items():
#             full_path_url = urljoin(self.core.target_url, path)
#             # إضافة الرابط إلى قائمة الزحف العامة
#             self.core.results['context']['urls_found'].add(full_path_url)
#
#             for method, details in methods.items():
#                 # بالنسبة لواجهات API، لا يوجد "نموذج" بالمعنى التقليدي
#                 # سنقوم بإنشاء "شبه نموذج" لتمثيل نقطة النهاية
#                 inputs = []
#                 for param in details.get('parameters', []):
#                     # نستخرج اسم الپارامتر ومكانه (query, header, path, body)
#                     inputs.append({'name': param.get('name'), 'type': 'api', 'in': param.get('in')})
#
#                 # إنشاء سجل شبيه بالنموذج ليتم اختباره لاحقًا
#                 api_endpoint_form = {
#                     'url': full_path_url,
#                     'method': method.lower(),
#                     'inputs': inputs,
#                     'source_page': 'API Specification'
#                 }
#
#                 if api_endpoint_form not in self.core.results['context']['forms_found']:
#                     self.core.results['context']['forms_found'].append(api_endpoint_form)
#
#         self.logger.info(
#             f"Added {len(self.core.results['context']['forms_found'])} new API endpoints to the scan queue.")
class DirectoryBruteforceModule(ScannerModule):
    def run(self):
        self.core._update_progress(10, f"Directory Bruteforcing {self.core.target_url}...")
        paths = ["admin", "login", "dashboard", "test", "api", "uploads", "backup", "wp-admin", ".git", ".env", "config"]
        max_workers = max(1, int(self.core.options.get('thread_count', os.cpu_count() or 4)) // 2)
        self.logger.info(f"DirectoryBruteforceModule is using {max_workers} worker threads.")

        with ThreadPoolExecutor(max_workers=max_workers) as e:
            e.map(self.check_path, paths)
    def check_path(self, path):
        url = urljoin(self.core.target_url, path)
        try:
            res = self.core.make_request('head', url, timeout=5, allow_redirects=False)
            if res and res.status_code in [200, 301, 302, 401, 403]:
            # Using a lock here is fine because discoveries are rare events.
                with self.core.vulnerability_lock:
                    self.core.results['context']['interesting_paths'].append(url)
                    self.core.add_vulnerability("Interesting Path Discovered", "Low",
                                                f"Found potentially sensitive path: {url}", "CWE-538",
                                                "Ensure unnecessary files are not publicly accessible.",
                                                {'path': url, 'status': res.status_code})
        except Exception:
            pass


class CrawlerModuleV5(ScannerModule):
    def __init__(self, scanner_core, verification_mode=False):
        super().__init__(scanner_core)
        self.verification_mode = verification_mode
        self.driver = None

    def run(self):
        urls_to_crawl = {self.core.target_url}
        crawled = set()
        while urls_to_crawl and len(crawled) < 50:  # Limit crawl depth
            url = urls_to_crawl.pop()
            if url in crawled or urlparse(url).netloc != self.core.domain: continue
            crawled.add(url)
            self.logger.info(f"Crawling: {url}")
            self.core.results['context']['urls_found'].add(url)

            response = self.core.make_request('get', url)
            if not response or 'text/html' not in response.headers.get('Content-Type', ''): continue

            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                new_url = urljoin(url, link['href']).split('#')[0]
                if new_url not in crawled: urls_to_crawl.add(new_url)
            for form in soup.find_all('form'):
                form_details = self._parse_form(form, url)
                if form_details not in self.core.results['context']['forms_found']:
                    self.core.results['context']['forms_found'].append(form_details)

    def _parse_form(self, form_tag, base_url):
        action = form_tag.get('action')
        method = form_tag.get('method', 'get').lower()
        form_url = urljoin(base_url, action)
        inputs = [{'name': i.get('name'), 'type': i.get('type', 'text')} for i in
                  form_tag.find_all(['input', 'textarea']) if i.get('name')]
        return {'url': form_url, 'method': method, 'inputs': inputs}


class SQLInjectionModuleV5(ScannerModule):
    # [FIX] Refactored module for better clarity and to add CVEs
    def run(self):
        for url in list(self.core.results['context']['urls_found']):
            if '?' in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    self._test_param(url, 'get', param, {'params': params})

        for form in list(self.core.results['context']['forms_found']):
            for field in form['inputs']:
                if param := field.get('name'):
                    self._test_param(form['url'], form['method'], param, {'inputs': form['inputs']})

    def _send_payload(self, url, method, param, payload, context):
        if method.lower() == 'get':
            params = context['params'].copy()
            params[param] = [payload]
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(params, doseq=True)))
            return self.core.make_request('get', test_url), test_url
        else:  # POST
            data = {p['name']: 'test' for p in context.get('inputs', []) if p.get('name')}
            data[param] = payload
            return self.core.make_request(method, url, data=data), url

    def _test_param(self, url, method, param, context):
        # --- جديد: منطق الاختيار التكيفي ---
        all_sqli_payloads = self.core.payloads.get('sqli', [])
        detected_db = self.core.results['context']['technologies'].get('database')
        error_signatures = ["sql syntax", "mysql", "unclosed quotation mark", "odbc", "oracle",
                            "invalid input syntax for"]

        for p_data in all_sqli_payloads:
            payload = p_data['value']
            cwe = p_data.get('cwe', 'CWE-89')
            cve = p_data.get('cve_example')
        filtered_payloads = []
        if detected_db:
            # إذا تم اكتشاف قاعدة بيانات، استخدم فقط الحمولات الخاصة بها والحمولات العامة
            self.logger.info(f"Database detected: '{detected_db}'. Filtering SQLi payloads.")
            for p in all_sqli_payloads:
                if p.get('tech') == detected_db or 'tech' not in p:
                    filtered_payloads.append(p)
        else:
            # إذا لم يتم اكتشاف قاعدة بيانات، استخدم جميع الحمولات
            self.logger.info("No specific database detected. Using all SQLi payloads.")
            filtered_payloads = all_sqli_payloads

        if not filtered_payloads:
            self.logger.warning("No suitable SQLi payloads found after filtering.")
            return
        if p_data['type'] == 'error-based':
            response, test_url = self._send_payload(url, method, param, payload, context)
            if response and any(sig in response.text.lower() for sig in error_signatures):
                self.core.add_vulnerability("SQL Injection (Error-Based)", "Critical",
                                            f"Potential SQLi in parameter '{param}'. The application returned a SQL error message.",
                                            cwe,
                                            "Use parameterized queries (prepared statements) to prevent user input from interfering with SQL syntax.",
                                            {'url': test_url, 'method': method, 'parameter': param,
                                             'payload': payload}, cve=cve)
                return
            elif p_data['type'] == 'time-based':
                sleep_time = int(re.search(r'SLEEP\((\d+)\)', payload, re.IGNORECASE).group(1)) if re.search(
                    r'SLEEP\((\d+)\)', payload, re.IGNORECASE) else 5
                start_time = time.time()
                self._send_payload(url, method, param, payload, context)
                duration = time.time() - start_time
                if duration >= sleep_time and duration < sleep_time + 4:  # Add a little buffer
                    self.core.add_vulnerability("SQL Injection (Time-Based)", "Critical",
                                                f"Potential Blind SQLi in parameter '{param}'. The application took longer to respond with a time-delay payload.",
                                                cwe,
                                                "Use parameterized queries (prepared statements). Avoid time-based functions in queries where possible.",
                                                {'url': url, 'method': method, 'parameter': param, 'payload': payload},
                                                cve=cve)
                    return


class XSSModuleV5(ScannerModule):
    # [FIX] Refactored module with better false-positive reduction
    def run(self):
        # اختبار الروابط التي تحتوي على پارامترات
        for url in list(self.core.results['context']['urls_found']):
            if '?' in url:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                for param_name in params:
                    # نمرر الـ url والـ params
                    self._test(url, 'get', param_name, params)

        # اختبار النماذج
        for form in list(self.core.results['context']['forms_found']):
            data_payload = {field.get('name'): 'test' for field in form['inputs'] if field.get('name')}
            for field in form['inputs']:
                if param_name := field.get('name'):
                    # نمرر الـ url الخاص بالنموذج وحمولة البيانات
                    self._test(form['url'], form['method'], param_name, data_payload)

    def _test(self, url, method, param_to_test, base_payload):
        xss_payloads = self.core.payloads.get('xss', [])

        # --- Test for Reflected XSS ---
        reflected_p_data = next((p for p in xss_payloads if p['type'] == 'reflected'), None)
        if reflected_p_data:
            nonce = f"xss-{uuid.uuid4().hex[:6]}"
            payload_value = reflected_p_data['value'].replace('{{nonce}}', nonce)

            # --- [CORRECTED LOGIC] ---
            # ننشئ نسخة من الحمولة الأساسية لتعديلها
            injected_payload = base_payload.copy()
            # نضع الحمولة الخبيثة في الپارامتر المستهدف
            injected_payload[param_to_test] = payload_value

            if method.lower() == 'get':
                # بالنسبة لطلبات GET, الحمولة تكون في پارامترات الرابط
                test_url = urlunparse(urlparse(url)._replace(query=urlencode(injected_payload, doseq=True)))
                response = self.core.make_request('get', test_url)
            else:  # POST
                # بالنسبة لطلبات POST, الحمولة تكون في جسم الطلب (data)
                test_url = url
                response = self.core.make_request('post', test_url, data=injected_payload)

            if response and payload_value in response.text and 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                if not soup.find(string=lambda text: payload_value in text):
                    cwe = reflected_p_data.get('cwe', 'CWE-79')
                    cve = reflected_p_data.get('cve_example')
                    self.core.add_vulnerability("Reflected XSS", "High",
                                                f"Payload reflected for parameter '{param_to_test}' and was rendered by the browser.",
                                                cwe,
                                                "Implement context-aware output encoding for all user-supplied data.",
                                                {'url': test_url, 'method': method, 'parameter': param_to_test,
                                                 'payload': payload_value}, cve=cve)
                    # وجدنا ثغرة، لا داعي لاختبار الأنواع الأخرى على نفس الپارامتر
                    return

        # --- Test for Stored XSS ---
        stored_p_data = next((p for p in xss_payloads if p['type'] == 'stored'), None)
        if stored_p_data:
            nonce = f"st-xss-{uuid.uuid4().hex[:8]}"
            payload_value = stored_p_data['value'].replace('{{nonce}}', nonce)

            self.core.stored_xss_nonces[nonce] = {'injection_url': url, 'method': method, 'parameter': param_to_test,
                                                  'payload': payload_value}

            injected_payload = base_payload.copy()
            injected_payload[param_to_test] = payload_value

            if method.lower() == 'get':
                test_url = urlunparse(urlparse(url)._replace(query=urlencode(injected_payload, doseq=True)))
                self.core.make_request('get', test_url)
            else:  # POST
                self.core.make_request('post', url, data=injected_payload)

class FingerprintModule(ScannerModule):
    def run(self):
        self.core._update_progress(16, "Fingerprinting web technologies...")
        response = self.core.make_request('get', self.core.target_url)
        if not response: return

        technologies = self.core.results['context']['technologies']

        # 1. بصمات الترويسات (Headers)
        if 'server' in response.headers:
            server = response.headers['server'].lower()
            technologies['server'] = response.headers['server']
            if 'nginx' in server: technologies['webserver'] = 'nginx'
            if 'apache' in server: technologies['webserver'] = 'apache'
            if 'iis' in server: technologies['webserver'] = 'iis'

        if 'x-powered-by' in response.headers:
            powered_by = response.headers['x-powered-by'].lower()
            if 'php' in powered_by: technologies['language'] = 'php'
            if 'asp.net' in powered_by: technologies['language'] = 'asp.net'
            if 'express' in powered_by: technologies['framework'] = 'express'

        # 2. بصمات ملفات تعريف الارتباط (Cookies)
        if 'set-cookie' in response.headers:
            cookies = response.headers['set-cookie'].lower()
            if 'phpsessid' in cookies: technologies['language'] = 'php'
            if 'jsessionid' in cookies: technologies['framework'] = 'java_spring' # أو أي إطار Java آخر
            if 'csrftoken' in cookies and 'django' in cookies: technologies['framework'] = 'django'

        # 3. بصمات محتوى الصفحة (Content)
        # هذا يمكن أن يصبح معقدًا جدًا، سنبقيه بسيطًا
        if 'wp-content' in response.text:
            technologies['cms'] = 'wordpress'
            technologies['language'] = 'php' # WordPress يعمل بـ PHP
            technologies['database'] = 'mysql' # WordPress يستخدم MySQL بشكل افتراضي

        self.logger.info(f"Technologies identified: {technologies}")


class WAFDetectionModule(ScannerModule):
    def run(self):
        malicious_url = urljoin(self.core.target_url,
                                f"?param=<script>alert('waf-test-{uuid.uuid4().hex[:4]}')</script>")
        resp_norm = self.core.make_request('get', self.core.target_url)
        resp_mal = self.core.make_request('get', malicious_url)
        if resp_norm and resp_mal and resp_norm.status_code in range(200, 303) and resp_mal.status_code in [403, 406,
                                                                                                            501, 429]:
            self.core.add_vulnerability("WAF Detected", "Info",
                                        f"Behavioral Anomaly Detected (Normal: {resp_norm.status_code}, Malicious: {resp_mal.status_code}). This indicates a Web Application Firewall (WAF) may be in place, which can affect scan results.",
                                        "N/A",
                                        "Be aware that a WAF can mask vulnerabilities or slow down scanning. Consider tuning scan speed.",
                                        {'url': self.core.target_url})


class HttpsModule(ScannerModule):
    # ... (Code is unchanged) ...
    def run(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.core.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.core.domain) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    if not cert_binary: return
                    cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                    days_left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
                    if days_left < 30:
                        sev = "High" if days_left < 0 else "Medium"
                        desc = f"Certificate expired {abs(days_left)} days ago." if days_left < 0 else f"Certificate expires in {days_left} days."
                        self.core.add_vulnerability("SSL Certificate Issue", sev, desc, "CWE-295",
                                                    "Renew the SSL certificate immediately to maintain trust and security.",
                                                    {'host': self.core.domain, 'days_left': days_left})
        except Exception as e:
            self.core.add_vulnerability("HTTPS/SSL Error", "High", f"Could not establish a secure connection: {e}",
                                        "CWE-319",
                                        "Ensure correct HTTPS configuration, a valid certificate chain, and support for modern TLS protocols.",
                                        {'host': self.core.domain})


class SecurityHeadersModule(ScannerModule):
    def run(self):
        response = self.core.make_request('get', self.core.target_url)
        if not response: return
        headers_to_check = {
            'Strict-Transport-Security': {'severity': 'High', 'cwe': 'CWE-319'},
            'X-Content-Type-Options': {'severity': 'Medium', 'cwe': 'CWE-693'},
            'X-Frame-Options': {'severity': 'Medium', 'cwe': 'CWE-1021'},
            'Content-Security-Policy': {'severity': 'Low', 'cwe': 'CWE-693'}
        }
        for h, info in headers_to_check.items():
            if h.lower() not in [k.lower() for k in response.headers.keys()]:
                self.core.add_vulnerability(f"Missing Security Header: {h}", info['severity'],
                                            f"The '{h}' header is missing, which can expose the application to various attacks like clickjacking or MIME-sniffing.",
                                            info['cwe'],
                                            f"Implement the {h} header according to security best practices.",
                                            {'header': h, 'url': self.core.target_url})


class CookieSecurityModule(ScannerModule):
    def run(self):
        response = self.core.make_request('get', self.core.target_url)
        if not response or not response.cookies: return
        for cookie in response.cookies:
            if not cookie.secure:
                self.core.add_vulnerability("Cookie Without Secure Flag", "Medium",
                                            f"Cookie '{cookie.name}' is sent over non-HTTPS connections, exposing it to interception.",
                                            "CWE-614",
                                            "Add the 'Secure' flag to all cookies handling sensitive information.",
                                            {'cookie_name': cookie.name})
            if not cookie.has_nonstandard_attr('httponly') and not getattr(cookie, '_rest', {}).get('HttpOnly'):
                self.core.add_vulnerability("Cookie Lacks HttpOnly Flag", "Medium",
                                            f"Cookie '{cookie.name}' can be accessed by client-side scripts, making it vulnerable to XSS attacks.",
                                            "CWE-1004",
                                            "Add the 'HttpOnly' flag to prevent JavaScript access to the cookie.",
                                            {'cookie_name': cookie.name})


class InformationDisclosureModule(ScannerModule):
    # ... (Code is unchanged) ...
    def run(self):
        for path in ["/.git/config", "/.env", "/phpinfo.php", "/.DS_Store", "/WEB-INF/web.xml",
                     "/.well-known/security.txt"]: self._check_path(path)
        for url in list(self.core.results['context']['urls_found']):
            response = self.core.make_request('get', url)
            if response:
                if 'Server' in response.headers: self._check_server_header(response.headers['Server'], url)
                if 'text/html' in response.headers.get('Content-Type', ''): self._check_content_comments(response.text,
                                                                                                         url)
                self._check_content_emails(response.text, url)

    def _check_path(self, path):
        url = urljoin(self.core.target_url, path)
        response = self.core.make_request('head', url, allow_redirects=False)
        if response and response.status_code == 200:
            self.core.add_vulnerability("Exposed Sensitive Path", "High",
                                        f"The path '{path}' is publicly accessible, potentially exposing configuration, source code, or other sensitive data.",
                                        "CWE-538", "Restrict access to this path using web server configuration rules.",
                                        {'url': url})

    def _check_server_header(self, server, url):
        if re.search(r'[\d\.]', server):
            self.core.add_vulnerability("Verbose Server Header", "Low",
                                        f"The server header exposes version information: {server}", "CWE-200",
                                        "Configure the web server to suppress the exact version number in the 'Server' header.",
                                        {'url': url, 'header': server})

    def _check_content_emails(self, content, url):
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content))
        if emails:
            self.core.add_vulnerability("Email Address Exposure", "Low",
                                        f"Found {len(emails)} email address(es) in the page content.", "CWE-200",
                                        "Remove email addresses from public-facing content to prevent harvesting by spammers.",
                                        {'url': url, 'emails_found': list(emails)[:3]})

    def _check_content_comments(self, content, url):
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
        sensitive_keywords = ['debug', 'fixme', 'todo', 'password', 'key', 'secret', 'admin', 'ldap']
        for comment in comments:
            if any(keyword in comment.lower() for keyword in sensitive_keywords):
                self.core.add_vulnerability("Sensitive Data in HTML Comment", "Low",
                                            "A sensitive keyword was found inside an HTML comment, suggesting leftover developer notes.",
                                            "CWE-615",
                                            "Remove all developer comments and sensitive information from production code.",
                                            {'url': url, 'comment_snippet': comment[:100]})
                break


class SSRFModule(ScannerModule):
    # ... (Code is unchanged) ...
    def run(self):
        if not self.core.oob_manager: self.logger.warning("SSRFModule skipped: OOB URL not configured."); return
        for url in list(self.core.results['context']['urls_found']):
            if '?' not in url: continue
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            for param, values in params.items():
                if any(re.match(r'https?://', v, re.I) for v in values):
                    self._test_ssrf(url, 'get', param, {'params': params})

    def _test_ssrf(self, url, method, param, context):
        interaction_id, payload_url = self.core.oob_manager.generate_payload_url("ssrf")
        self.logger.info(f"Testing SSRF on param '{param}' with payload: {payload_url}")
        original_params = context['params'].copy()
        original_params[param] = [payload_url]
        test_url = urlunparse(urlparse(url)._replace(query=urlencode(original_params, doseq=True)))
        self.core.make_request('get', test_url)
        self.core.add_vulnerability("Potential Server-Side Request Forgery (SSRF)", "High",
                                    f"Instructed the application to request an external server via the '{param}' parameter. Check your Out-of-Band (OAST) client for an interaction with ID '{interaction_id}'. If an interaction was received, this is a confirmed Critical SSRF.",
                                    "CWE-918",
                                    "Disable requests to user-supplied URLs. Use a strict, validated allow-list of domains and protocols that the server is permitted to access.",
                                    {'url': url, 'parameter': param, 'payload_sent': payload_url,
                                     'oob_interaction_id': interaction_id}, cve="CVE-2021-41773")  # Example


class SSTIModule(ScannerModule):
    def run(self):
        targets = []
        [targets.append({'type': 'url', 'url': url}) for url in list(self.core.results['context']['urls_found']) if
         '?' in url]
        [targets.append({'type': 'form', 'details': form}) for form in
         list(self.core.results['context']['forms_found'])]

        for target in targets:
            # [CORRECTED LOGIC] Handle URL parameters (GET)
            if target['type'] == 'url':
                parsed_url = urlparse(target['url'])
                params_context = {'params': parse_qs(parsed_url.query)}
                for param in params_context['params']:
                    self._test_param(target['url'], 'get', param, params_context)

            # [CORRECTED LOGIC] Handle Form parameters (POST/GET)
            elif target['type'] == 'form':
                form_details = target['details']
                inputs_context = {'inputs': form_details['inputs']}
                for field in form_details['inputs']:
                    if param := field.get('name'):
                        self._test_param(form_details['url'], form_details['method'], param, inputs_context)

    def _send_payload(self, url, method, param, payload, context):
        if method.lower() == 'get':
            params = context.get('params', {}).copy()
            params[param] = [payload]
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(params, doseq=True)))
            return self.core.make_request('get', test_url), test_url
        else:  # POST
            data = {p.get('name'): 'test' for p in context.get('inputs', []) if p.get('name')}
            data[param] = payload
            return self.core.make_request(method, url, data=data), url

    def _test_param(self, url, method, param, context):
        ssti_payloads = self.core.payloads.get('ssti', [])
        if not ssti_payloads: return
        for p_data in ssti_payloads:
            payload, expected = p_data['value'], p_data['expected']
            response, test_url = self._send_payload(url, method, param, payload, context)
            if response and expected in response.text:
                cwe = p_data.get('cwe', 'CWE-94')
                cve = p_data.get('cve_example')
                self.core.add_vulnerability(f"Server-Side Template Injection ({p_data['engine']})", "Critical",
                                            "User input appears to be embedded into a server-side template, leading to potential Remote Code Execution (RCE). A mathematical payload was successfully evaluated.",
                                            cwe,
                                            "Do not allow users to control template content. Sanitize all input before passing it to template engines. Use sandboxed environments if possible.",
                                            {'url': test_url, 'parameter': param, 'payload': payload}, cve=cve)
                return

class LFIModule(ScannerModule):
    def run(self):
        targets = []
        [targets.append({'type': 'url', 'url': url}) for url in list(self.core.results['context']['urls_found']) if
         '?' in url]
        [targets.append({'type': 'form', 'details': form}) for form in
         list(self.core.results['context']['forms_found'])]

        for target in targets:
            # [CORRECTED LOGIC] Handle URL parameters (GET)
            if target['type'] == 'url':
                parsed_url = urlparse(target['url'])
                params_context = {'params': parse_qs(parsed_url.query)}
                for param in params_context['params']:
                    self._test_param(target['url'], 'get', param, params_context)

            # [CORRECTED LOGIC] Handle Form parameters (POST/GET)
            elif target['type'] == 'form':
                form_details = target['details']
                inputs_context = {'inputs': form_details['inputs']}
                for field in form_details['inputs']:
                    if param := field.get('name'):
                        self._test_param(form_details['url'], form_details['method'], param, inputs_context)

    def _send_payload(self, url, method, param, payload, context):
        if method.lower() == 'get':
            params = context.get('params', {}).copy()
            params[param] = [payload]
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(params, doseq=True)))
            return self.core.make_request('get', test_url), test_url
        else:  # POST
            data = {p.get('name'): 'test' for p in context.get('inputs', []) if p.get('name')}
            data[param] = payload
            return self.core.make_request(method, url, data=data), url

    def _test_param(self, url, method, param, context):
        lfi_payloads = self.core.payloads.get('lfi', [])
        success_signatures = {"/etc/passwd": "root:x:0:0", "boot.ini": "[boot loader]", "php://filter": "PD9waH"}

        for p_data in lfi_payloads:
            payload = p_data['value']
            cwe = p_data.get('cwe', 'CWE-98')
            cve = p_data.get('cve_example')

            response, test_url = self._send_payload(url, method, param, payload, context)
            if not response: continue

            signature_key = next((key for key in success_signatures if key in payload), None)
            if signature_key and success_signatures[signature_key] in response.text:
                self.core.add_vulnerability("Local File Inclusion (LFI)", "High",
                                            "The application includes local files from the server based on user input. This can lead to sensitive information disclosure or Remote Code Execution.",
                                            cwe,
                                            "Avoid passing user-controlled data to file inclusion functions. Maintain a strict allow-list of files that can be included and validate all input.",
                                            {'url': test_url, 'parameter': param, 'payload': payload,
                                             'method': method.upper(),
                                             'confirmation': f"Found signature '{success_signatures[signature_key]}'."},
                                            cve=cve)
                return


#### --- 2. المُصحَّح: `CommandInjectionModule` ---

class CommandInjectionModule(ScannerModule):
    def run(self):
        targets = []
        [targets.append({'type': 'url', 'url': url}) for url in list(self.core.results['context']['urls_found']) if
         '?' in url]
        [targets.append({'type': 'form', 'details': form}) for form in
         list(self.core.results['context']['forms_found'])]

        for target in targets:
            # [CORRECTED LOGIC] Handle URL parameters (GET)
            if target['type'] == 'url':
                parsed_url = urlparse(target['url'])
                params_context = {'params': parse_qs(parsed_url.query)}
                for param in params_context['params']:
                    self._test_param(target['url'], 'get', param, params_context)

            # [CORRECTED LOGIC] Handle Form parameters (POST/GET)
            elif target['type'] == 'form':
                form_details = target['details']
                inputs_context = {'inputs': form_details['inputs']}
                for field in form_details['inputs']:
                    if param := field.get('name'):
                        self._test_param(form_details['url'], form_details['method'], param, inputs_context)

    def _send_payload(self, url, method, param, payload, context):
        if method.lower() == 'get':
            params = context.get('params', {}).copy()
            params[param] = [payload]
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(params, doseq=True)))
            return self.core.make_request('get', test_url), test_url
        else:  # POST
            data = {p.get('name'): 'test' for p in context.get('inputs', []) if p.get('name')}
            data[param] = payload
            return self.core.make_request(method, url, data=data), url

    def _test_param(self, url, method, param, context):
        cmd_payloads = self.core.payloads.get('command_injection', [])
        common_users = ['root', 'admin', 'www-data', 'apache', 'system', 'tomcat', 'ec2-user']

        for p_data in cmd_payloads:
            payload = p_data['value']
            cwe = p_data.get('cwe', 'CWE-77')
            cve = p_data.get('cve_example')

            if p_data['type'] == 'blind':
                response, test_url = self._send_payload(url, method, param, payload, context)
                if response and any(user in response.text for user in common_users):
                    self.core.add_vulnerability("Command Injection", "Critical",
                                                "The application appears to execute system commands based on user input. The output of a command (like 'whoami') was found in the response.",
                                                cwe,
                                                "Never call system commands with user-supplied input. Use language-specific, safe APIs and validate all input against a strict allow-list.",
                                                {'url': test_url, 'parameter': param, 'payload': payload,
                                                 'method': method.upper()}, cve=cve)
                    return

            elif p_data['type'] == 'time-based':
                sleep_match = re.search(r'ping -(c|n) (\d+)', payload)
                if sleep_match:
                    sleep_time = int(sleep_match.group(2))
                    start_time = time.time()
                    self._send_payload(url, method, param, payload, context)
                    duration = time.time() - start_time
                    if duration >= sleep_time and duration < sleep_time + 4:
                        self.core.add_vulnerability("Command Injection (Time-Based)", "Critical",
                                                    "The application is likely vulnerable to blind command injection. A time-delay payload was successfully executed, causing a measurable delay in the response.",
                                                    cwe,
                                                    "Never call system commands with user-supplied input. Use language-specific, safe APIs and validate all input against a strict allow-list.",
                                                    {'url': url, 'parameter': param, 'payload': payload,
                                                     'method': method.upper()}, cve=cve)
                        return

# <<< جديد: وحدة فحص منطق العمل المتقدمة >>>
class BusinessLogicModule(ScannerModule):
    def run(self):
        self.core._update_progress(80, "Phase 5: Business Logic Analysis...")
        workflow_dir = os.path.join(current_dir, 'workflows')
        if not os.path.isdir(workflow_dir):
            return

        for filename in os.listdir(workflow_dir):
            if filename.endswith('.json'):
                self.logger.info(f"Executing workflow: {filename}")
                self._execute_workflow(os.path.join(workflow_dir, filename))

    def _execute_workflow(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                workflow = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.logger.error(f"Failed to load or parse workflow {filepath}: {e}")
            return

        # تنفيذ كل حالة اختبار في سير العمل
        for test_case in workflow.get('test_cases', []):
            self.logger.info(f"  - Running Test Case: {test_case['name']}")
            self._run_test_case(workflow, test_case)



    # ... (هذه الدوال يجب أن تكون methods داخل فئة BusinessLogicModule)
    def _run_test_case(self, workflow: dict, test_case: dict):
        """
        ينفذ حالة اختبار كاملة: يشغل الخطوات التمهيدية، يجمع السياق، يطبق الطفرات، ويتحقق من النتيجة.
        """
        self.logger.info(f"  Executing Test Case: '{test_case['name']}'")

        # 1. تهيئة السياق من المتغيرات الأولية في ملف workflow.json
        context_variables = workflow.get('variables', {}).copy()

        target_step_id = test_case.get('target_step')
        if not target_step_id:
            self.logger.error("  - Test case is missing 'target_step'. Aborting.")
            return

        try:
            target_step_index = next(i for i, step in enumerate(workflow['steps']) if step['step_id'] == target_step_id)
        except StopIteration:
            self.logger.error(f"  - Target step '{target_step_id}' not found in workflow. Aborting test case.")
            return

        # 2. تنفيذ الخطوات التمهيدية (Prerequisite Steps) بالترتيب
        for i in range(target_step_index):
            step = workflow['steps'][i]
            self.logger.info(f"  - Executing prerequisite step: '{step.get('description', step['step_id'])}'")

            # تنفيذ طلب واحد
            response = self._execute_single_step(step, context_variables)

            # إذا فشلت خطوة تمهيدية، يجب إيقاف حالة الاختبار بأكملها
            if not response or not (200 <= response.status_code < 300):
                status = response.status_code if response else "No Response"
                self.logger.error(f"  - Prerequisite step failed with status {status}. Aborting test case.")
                return

            # استخلاص البيانات من الاستجابة وتحديث السياق
            self._extract_context(step, response, context_variables)

        # 3. تطبيق الطفرات على الخطوة المستهدفة وإرسال الطلبات
        target_step = workflow['steps'][target_step_index]
        mutations = test_case.get('mutations', {})

        for param_to_mutate, values in mutations.items():
            for mutated_value in values:
                # إنشاء الطلب الخبيث
                mutated_request = self._mutate_request(target_step['request'], param_to_mutate, mutated_value,
                                                       context_variables)

                # إرسال الطلب الخبيث
                response = self.core.make_request(
                    mutated_request['method'],
                    urljoin(self.core.target_url, mutated_request['path']),
                    headers=mutated_request.get('headers', {}),
                    json=mutated_request.get('json_body', {}),
                    params=mutated_request.get('params', {})
                )

                if not response:
                    continue

                # 4. التحقق من التأكيد (Assertion)
                assertion = test_case.get('assertion')
                if self._check_assertion(response, assertion):
                    self.logger.warning(f"  - VULNERABILITY FOUND by test case '{test_case['name']}'!")
                    self.core.add_vulnerability(
                        f"Business Logic Flaw: {test_case['name']}",
                        test_case.get('severity', "High"),
                        test_case['description'],
                        "CWE-840",  # Business Logic Errors
                        test_case['remediation'],
                        {'workflow_file': os.path.basename(workflow.get('name', 'N/A')),
                         'mutated_param': param_to_mutate,
                         'mutated_value': str(mutated_value),
                         'assertion_type': assertion.get('type')},
                        cve="N/A"
                    )
                    # أوقف الاختبار لهذه الطفرة بمجرد العثور على ثغرة
                    return

    # --- الدوال المساعدة الجديدة (يجب إضافتها أيضًا داخل فئة BusinessLogicModule) ---

    def _execute_single_step(self, step: dict, context: dict) -> Optional[requests.Response]:
        """ينفذ طلب HTTP واحد بعد تعويض المتغيرات السياقية."""
        request_data = step.get('request', {})
        # تعويض المتغيرات في الطلب قبل إرساله
        request_data = self._substitute_context_variables(request_data, context)

        response = self.core.make_request(
            request_data.get('method', 'GET'),
            urljoin(self.core.target_url, request_data.get('path', '/')),
            headers=request_data.get('headers', {}),
            json=request_data.get('json_body', {}),
            params=request_data.get('params', {})
        )
        return response

    def _extract_context(self, step: dict, response: requests.Response, context: dict):
        extractions = step.get('extract', {})

        for var_name, extract_rule in extractions.items():
            source = extract_rule.get('from')

            extracted_value = None
            if source == 'json_body':
                try:
                    # منطق بسيط لاستخلاص البيانات من JSON. يمكن جعله أكثر تعقيدًا لاحقًا.
                    data = response.json()
                    keys = os.path.split('.')
                    value = data
                    for key in keys:
                        value = value[key]
                    extracted_value = value
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    self.logger.warning(f"  - Could not extract '{os.path}' from JSON body: {e}")
            elif source == 'header':
                extracted_value = response.headers.get(os.path)
            elif source == 'body_regex':
                regex = extract_rule.get('regex')
                if regex:
                    match = re.search(regex, response.text)
                    if match and match.groups():
                        extracted_value = match.group(1)  # استخلاص أول مجموعة مطابقة
                    else:
                        self.logger.warning(f"  - Regex '{regex}' did not find any match or capture group.")

            if extracted_value is not None:
                context[var_name] = extracted_value
                self.logger.info(f"  - Extracted '{var_name}' = '{str(extracted_value)[:30]}...'")

    def _check_assertion(self, response: requests.Response, assertion: dict) -> bool:
        """يتحقق مما إذا كانت الاستجابة تطابق التأكيد المحدد في حالة الاختبار."""
        if not assertion:
            return False

        assertion_type = assertion.get('type')
        assertion_value = assertion.get('value')

        is_vulnerable = False

        if assertion_type == 'status_code_is':
            is_vulnerable = response.status_code == int(assertion_value)

        elif assertion_type == 'status_code_in_range':
            start, end = map(int, assertion_value.split('-'))
            is_vulnerable = start <= response.status_code <= end

        elif assertion_type == 'body_contains':
            is_vulnerable = str(assertion_value) in response.text

        elif assertion_type == 'body_not_contains':
            is_vulnerable = str(assertion_value) not in response.text

        elif assertion_type == 'header_contains':
            key, val = assertion_value.split(':', 1)
            header_value = response.headers.get(key.strip(), '')
            is_vulnerable = val.strip() in header_value

        elif assertion_type == 'header_not_contains':
            key, val = assertion_value.split(':', 1)
            header_value = response.headers.get(key.strip(), '')
            is_vulnerable = val.strip() not in header_value

        elif assertion_type == 'json_key_is':
            # assertion_value: "user.id=123"
            try:
                key_path, expected_value = assertion_value.split('=')
                keys = key_path.strip().split('.')
                data = response.json()
                for key in keys:
                    data = data.get(key, {})
                is_vulnerable = str(data) == expected_value.strip()
            except Exception:
                is_vulnerable = False

        elif assertion_type == 'json_key_exists':
            # assertion_value: "user.email"
            try:
                keys = assertion_value.strip().split('.')
                data = response.json()
                for key in keys:
                    if key not in data:
                        is_vulnerable = False
                        break
                    data = data[key]
                else:
                    is_vulnerable = True
            except Exception:
                is_vulnerable = False

        elif assertion_type == 'redirects_to_url':
            # assertion_value: expected final URL after redirects
            is_vulnerable = response.history and response.url == assertion_value

        elif assertion_type == 'content_type_is':
            # assertion_value: "application/json"
            is_vulnerable = response.headers.get('Content-Type', '').startswith(assertion_value)

        elif assertion_type == 'response_time_less_than':
            # assertion_value: max time in seconds
            is_vulnerable = response.elapsed.total_seconds() < float(assertion_value)

        if is_vulnerable:
            self.logger.info(f"  - Assertion PASSED: {assertion_type} '{assertion_value}'")
        else:
            self.logger.info(f"  - Assertion FAILED: {assertion_type} '{assertion_value}'")

        return is_vulnerable

    def _mutate_request(self, original_request: dict, param_to_mutate: str, new_value: any, context: dict) -> dict:
        """
        تنشئ نسخة من طلب HTTP، تعوض المتغيرات السياقية، ثم تطبق طفرة محددة.

        هذه الدالة هي المحرك الأساسي لوحدة فحص منطق العمل.

        Args:
            original_request (dict): القاموس الأصلي للطلب كما هو معرف في ملف workflow.
            param_to_mutate (str): اسم الحقل أو الپارامتر المراد تغيير قيمته.
            new_value (any): القيمة الجديدة (الخبيثة) التي سيتم وضعها في الپارامتر.
            context (dict): قاموس يحتوي على المتغيرات المستخرجة من الخطوات السابقة (مثل user_id, token).

        Returns:
            dict: قاموس يمثل الطلب الجديد الجاهز للإرسال بعد تطبيق الطفرات.
        """
        try:
            # الخطوة 1: إنشاء نسخة عميقة (Deep Copy) من الطلب الأصلي.
            # هذا أمر بالغ الأهمية لمنع التأثير على حالات الاختبار الأخرى التي قد تستخدم نفس الطلب الأصلي.
            mutated_request = json.loads(json.dumps(original_request))

            # الخطوة 2: استبدال جميع المتغيرات السياقية (مثل {{USER_ID}}) في الطلب بأكمله.
            # سنستخدم دالة مساعدة للقيام بذلك بشكل متكرر على جميع القيم النصية.
            mutated_request = self._substitute_context_variables(mutated_request, context)

            # الخطوة 3: تطبيق الطفرة المحددة على الپارامتر المستهدف.
            # نبحث عن الپارامتر في الأماكن الأكثر شيوعًا: پارامترات الرابط (query params) وجسم الطلب (JSON body).
            found_and_mutated = False

            # البحث في پارامترات الرابط (مثال: /api/users?id=123)
            if 'params' in mutated_request and param_to_mutate in mutated_request.get('params', {}):
                mutated_request['params'][param_to_mutate] = new_value
                found_and_mutated = True
                self.logger.info(f"  - Mutated query parameter '{param_to_mutate}' to: {new_value}")

            # البحث في جسم الطلب من نوع JSON (مثال: {"role": "user"})
            elif 'json_body' in mutated_request and param_to_mutate in mutated_request.get('json_body', {}):
                mutated_request['json_body'][param_to_mutate] = new_value
                found_and_mutated = True
                self.logger.info(f"  - Mutated JSON key '{param_to_mutate}' to: {new_value}")

            # يمكنك إضافة البحث في أماكن أخرى هنا إذا لزم الأمر، مثل الترويسات (headers).

            if not found_and_mutated:
                self.logger.warning(
                    f"  - Parameter '{param_to_mutate}' not found in the request to mutate. The workflow file might be misconfigured.")

            return mutated_request

        except (json.JSONDecodeError, TypeError) as e:
            self.logger.error(f"Failed to mutate request. Original: {original_request}. Error: {e}")
            # أرجع الطلب الأصلي في حالة حدوث خطأ لمنع انهيار الفحص
            return original_request

    # --- دالة مساعدة جديدة يجب إضافتها أيضًا داخل فئة BusinessLogicModule ---
    def _substitute_context_variables(self, data: any, context: dict) -> any:
        """
        دالة متكررة (recursive) لاستبدال المتغيرات المحاطة بـ {{}} بقيمها من السياق.
        """
        if isinstance(data, dict):
            return {k: self._substitute_context_variables(v, context) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._substitute_context_variables(item, context) for item in data]
        elif isinstance(data, str):
            for key, val in context.items():
                placeholder = f"{{{{{key}}}}}"  # يبحث عن {{KEY}}
                data = data.replace(placeholder, str(val))
            return data
        else:
            # أرجع أنواع البيانات الأخرى (أرقام، boolean) كما هي
            return data


# ############################################################################
# --- دوال ومسارات تطبيق Flask ---
# ############################################################################

def clean_for_json(data: Any) -> Any:
    if data is None or isinstance(data, (str, int, float, bool)): return data
    if isinstance(data, dict): return {str(k): clean_for_json(v) for k, v in data.items()}
    if isinstance(data, list): return [clean_for_json(item) for item in data]
    if isinstance(data, datetime): return data.isoformat()
    return f"Unserializable:{type(data).__name__}"


@app.template_filter('jinja2_filter_datetime')
def format_datetime_filter(value, fmt='%Y-%m-%d %H:%M:%S UTC'):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).strftime(fmt)
    except:
        return value


# --- Auth Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register_route():
    if current_user.is_authenticated: return redirect(url_for('index_route'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        # --- الجزء الجديد: إرسال بريد التحقق ---
        send_confirmation_email(user.email)
        flash('تم إنشاء حسابك بنجاح! الرجاء مراجعة بريدك الإلكتروني لتفعيل الحساب.', 'success')
        return redirect(url_for('login_route'))

    return render_template('register.html', title='إنشاء حساب', form=form)


@app.route('/confirm/<token>')
def confirm_email_route(token):
    try:
        email = confirm_token(token)
    except:
        flash('رابط التفعيل غير صالح أو انتهت صلاحيته.', 'danger')
        return redirect(url_for('login_route'))

    user = User.query.filter_by(email=email).first_or_404()

    if user.is_email_confirmed:
        flash('تم تأكيد هذا الحساب بالفعل. الرجاء تسجيل الدخول.', 'success')
    else:
        user.is_email_confirmed = True
        db.session.commit()
        flash('تم تأكيد حسابك بنجاح! يمكنك الآن تسجيل الدخول.', 'success')
    return redirect(url_for('login_route'))


@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if current_user.is_authenticated: return redirect(url_for('index_route'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('البريد الإلكتروني أو كلمة المرور غير صحيحة.', 'danger')
            return render_template('login.html', title='تسجيل الدخول', form=form)

        last_fail_aware = user.last_failed_login.replace(tzinfo=timezone.utc) if user.last_failed_login else None
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS and last_fail_aware and datetime.now(
                timezone.utc) < last_fail_aware + LOCKOUT_PERIOD:
            flash(f'تم حظر حسابك مؤقتًا. الرجاء المحاولة مرة أخرى لاحقًا.', 'danger')
            return render_template('login.html', title='تسجيل الدخول', form=form)

        if user.check_password(form.password.data):
            if not user.is_email_confirmed:
                flash('الرجاء تأكيد بريدك الإلكتروني أولاً قبل تسجيل الدخول.', 'warning')
                return redirect(url_for('login_route'))

            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.session.commit()

            if user.is_2fa_enabled:
                session['user_id_for_2fa'] = user.id
                return redirect(url_for('verify_2fa_route'))
            else:
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index_route'))
        else:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(timezone.utc)
            db.session.commit()
            flash('البريد الإلكتروني أو كلمة المرور غير صحيحة.', 'danger')
    return render_template('login.html', title='تسجيل الدخول', form=form)


@app.route('/profile')
@login_required
def profile_route():
    return render_template('profile.html', title='ملفي الشخصي')


@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa_route():
    if current_user.is_2fa_enabled:
        return redirect(url_for('profile_route'))
    form = TwoFaForm()
    secret = pyotp.random_base32()
    if form.validate_on_submit():
        if pyotp.TOTP(secret).verify(form.otp.data):
            current_user.otp_secret = secret
            current_user.is_2fa_enabled = True
            db.session.commit()
            flash('تم تفعيل المصادقة الثنائية بنجاح!', 'success')
            return redirect(url_for('profile_route'))
        else:
            flash('الرمز غير صحيح، الرجاء المحاولة مرة أخرى.', 'danger')
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="Ethical Scanner")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    qr_code_data = base64.b64encode(buf.getvalue()).decode('ascii')
    return render_template('setup_2fa.html', title='إعداد 2FA', qr_code=qr_code_data, secret=secret,
                           form=form)  # Passing secret for verification


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa_route():
    user_id = session.get('user_id_for_2fa')
    if not user_id: return redirect(url_for('login_route'))
    form = TwoFaForm()
    if form.validate_on_submit():
        user = User.query.get(user_id)
        if user and pyotp.TOTP(user.otp_secret).verify(form.otp.data):
            session.pop('user_id_for_2fa', None)
            login_user(user)
            return redirect(url_for('index_route'))
        else:
            flash('الرمز غير صحيح.', 'danger')
    return render_template('verify_2fa.html', title='التحقق الثنائي', form=form)


@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa_route():
    current_user.is_2fa_enabled = False
    current_user.otp_secret = None
    db.session.commit()
    flash('تم تعطيل المصادقة الثنائية.', 'success')
    return redirect(url_for('profile_route'))


@app.route('/logout')
@login_required
def logout_route():
    logout_user()
    return redirect(url_for('login_route'))


# --- Application Routes ---
@app.route('/')
def index_route():
    return render_template('index_v5.html')


@app.route('/scan', methods=['POST'])
@login_required
def scan_route():
    target_url, options = request.form.get('target_url', '').strip(), request.form
    if not target_url:
        flash("عنوان الهدف مطلوب لبدء الفحص.", "danger")
        return redirect(url_for('index_route'))

    scan_id = str(uuid.uuid4())
    new_scan = Scan(id=scan_id, target_url=target_url, user_id=current_user.id)
    db.session.add(new_scan)
    db.session.commit()

    scanner = EthicalSecurityScannerV7(app, target_url, scan_id, options)

    url_pattern = re.compile(
        r'^(https?://)'  # http:// or https://
        r'((([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})|'  # domain...
        r'((([0-9]{1,3}\.){3}[0-9]{1,3})))'  # ...or ip
        r'(:[0-9]+)?'  # optional port
        r'(/.*)?$', re.IGNORECASE)  # optional path

    if not url_pattern.match(target_url):
        flash("عنوان URL المستهدف غير صالح. الرجاء إدخال عنوان URL كامل وصحيح (e.g., https://example.com).", "danger")
        return redirect(url_for('index_route'))
    if redis_client:
        scan_id = str(uuid.uuid4())
        new_scan = Scan(id=scan_id, target_url=target_url, user_id=current_user.id)
        db.session.add(new_scan)
        db.session.commit()

        scanner = EthicalSecurityScannerV7(app, target_url, scan_id, options)

        # Create a hash for scan metadata and a separate list for logs
        redis_client.hmset(f"scan:{scan_id}", {
            'status': 'queued',
            'progress': '0',
            'target_url': target_url
        })

        thread = threading.Thread(target=scanner.start, name=f"Scanner-{scan_id[:6]}")
        thread.daemon = True
        thread.start()
        return redirect(url_for('scan_progress_route', scan_id=scan_id))
    else:
        flash("خطأ حرج: خدمة تتبع الحالة (Redis) غير متاحة. لا يمكن بدء الفحص.", "danger")
        return redirect(url_for('index_route'))

@app.route('/scan_progress/<scan_id>')
@login_required
def scan_progress_route(scan_id):
    scan_info_db = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    if scan_info_db.status in ['completed', 'error']:
        return redirect(url_for('results_route', scan_id=scan_id))
    return render_template('scan_progress_v5.html', scan_id=scan_id, target_url=scan_info_db.target_url)


@app.route('/scan_status/<scan_id>')
@login_required
def scan_status_route(scan_id):
    scan_info_db = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    info = {}
    log = []

    # --- [MODIFIED] Read from Redis ---
    if redis_client:
        # Fetch metadata hash
        info = redis_client.hgetall(f"scan:{scan_id}")
        log = redis_client.lrange(f"scan_log:{scan_id}", -50, -1)

    results_url = url_for('results_route', scan_id=scan_id) if scan_info_db.status in ['completed', 'error'] else None

    return jsonify({
        'status': info.get('status', scan_info_db.status),
        'progress': int(info.get('progress', 100 if scan_info_db.status in ['completed', 'error'] else 0)),
        'log': log,
        'results_url': results_url
    })
@app.route('/results/<scan_id>')
@login_required
def results_route(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    if scan.status not in ['completed', 'error']:
        return redirect(url_for('scan_progress_route', scan_id=scan_id))

    try:
        results = json.loads(scan.results or '{}')
    except (json.JSONDecodeError, TypeError):
        results = {}
        flash('حدث خطأ في عرض النتائج.', 'danger')

    if results and 'vulnerabilities' in results:
        results['vulnerabilities'].sort(key=lambda v: SEVERITY_SCORES.get(v.get('severity'), 0), reverse=True)

    lang = request.args.get('lang', 'en')

    # الترجمة الديناميكية
    if lang == 'ar':
        for vuln in results.get('vulnerabilities', []):
            for key in ['description', 'remediation']:
                translated_key = f"{key}_translated"
                original_text = vuln.get(key)

                if original_text and not vuln.get(translated_key):
                    # --- [MODIFIED] Using Redis for persistent translation caching ---
                    if redis_client:
                        cached_translation = redis_client.hget("translation_cache:ar", original_text)
                    else:
                        cached_translation = None

                    if cached_translation:
                        # 1. Found in Redis cache
                        vuln[translated_key] = cached_translation.decode('utf-8')
                    else:
                        # 2. Not in cache, call API
                        try:
                            translated_text = translator.translate(original_text, src='en', dest='ar').text
                            vuln[translated_key] = translated_text
                            # 3. Store the new translation in Redis for future use
                            if redis_client:
                                redis_client.hset("translation_cache:ar", original_text, translated_text)
                        except Exception as e:
                            logger.error(f"Translation failed: {e}")
                            vuln[translated_key] = f"[تعذر الترجمة] {original_text}"

    severities = [v.get('severity', 'Info') for v in results.get('vulnerabilities', [])]
    chart_data = {
        'critical': severities.count('Critical'), 'high': severities.count('High'),
        'medium': severities.count('Medium'), 'low': severities.count('Low'), 'info': severities.count('Info')
    }
    risk_score = results.get('risk_score', 0)
    risk_level = {'text_en': 'Low', 'text_ar': 'منخفض', 'color': '#0dcaf0'}
    if risk_score >= 40:
        risk_level = {'text_en': 'Critical', 'text_ar': 'حرج', 'color': '#dc3545'}
    elif risk_score >= 20:
        risk_level = {'text_en': 'High', 'text_ar': 'مرتفع', 'color': '#fd7e14'}

    # --- [UPDATED] قاموس الترجمة الكامل ---
    translations = {
        'ar': {
            'security_assessment_report': 'تقرير تقييم أمني',
            'executive_summary': 'الملخص التنفيذي',
            'overall_risk_level': 'مستوى المخاطرة العام',
            'total_vulnerabilities': 'إجمالي الثغرات',
            'critical_findings': 'نتائج حرجة',
            'high_findings': 'نتائج عالية',
            'medium_findings': 'نتائج متوسطة',
            'low_findings': 'نتائج منخفضة',
            'info_findings': 'نتائج إعلامية',
            'key_observations': 'الملاحظات الرئيسية',
            'key_observations_text': 'كشف تقييم {} عن {} ثغرة، مما يشير إلى وضع مخاطرة بمستوى {}. قد تعرض هذه النقاط التطبيق لهجمات تؤدي إلى تسريب بيانات أو تعطيل الخدمة.',
            'strategic_recommendation': 'التوصية الاستراتيجية',
            'strategic_recommendation_text': 'يجب إعطاء أولوية قصوى لمعالجة كافة الثغرات ذات الخطورة الحرجة والعالية. نوصي بتخصيص الموارد التقنية فورًا لمواجهة هذه النتائج والحد من المخاطر الجوهرية على الأعمال.',
            'technical_findings': 'النتائج الفنية التفصيلية',
            'description_impact': 'الوصف والأثر',
            'remediation_steps': 'خطوات الإصلاح',
            'technical_evidence': 'الأدلة الفنية',
            'reference': 'مرجع',
            'example_cve': 'مثال CVE',
            'lang_switch': 'Switch to English'
        },
        'en': {
            'security_assessment_report': 'Security Assessment Report',
            'executive_summary': 'Executive Summary',
            'overall_risk_level': 'Overall Risk Level',
            'total_vulnerabilities': 'Total Vulnerabilities',
            'critical_findings': 'Critical',
            'high_findings': 'High',
            'medium_findings': 'Medium',
            'low_findings': 'Low',
            'info_findings': 'Info',
            'key_observations': 'Key Observations',
            'key_observations_text': 'The assessment of {} identified {} vulnerabilities, indicating a {} risk posture. These weaknesses could expose the application to attacks, leading to data breaches or service disruption.',
            'strategic_recommendation': 'Strategic Recommendation',
            'strategic_recommendation_text': 'Prioritize remediation of all Critical and High severity vulnerabilities. Allocate immediate technical resources to address these findings and mitigate significant business risks.',
            'technical_findings': 'Detailed Technical Findings',
            'description_impact': 'Description & Impact',
            'remediation_steps': 'Remediation Steps',
            'technical_evidence': 'Technical Evidence',
            'reference': 'Reference',
            'example_cve': 'Example CVE',
            'lang_switch': 'التحويل إلى العربية'
        }
    }

    tr = translations.get(lang, translations['en'])

    return render_template(
        'results_v5.html',  # <-- تأكد من استخدام اسم الملف الجديد
        results=results,
        chart_data=chart_data,
        risk_level=risk_level,
        tr=tr,
        lang=lang
    )

@app.route('/download_report/<scan_id>/<lang>')
@login_required
def download_report_route(scan_id, lang='en'):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    if scan.status not in ['completed', 'error']:
        flash("لا يمكن تنزيل تقرير لفحص لم يكتمل بعد.", 'warning')
        return redirect(url_for('scan_progress_route', scan_id=scan_id))
    try:
        results = json.loads(scan.results or '{}')
    except json.JSONDecodeError:
        flash("خطأ في بيانات التقرير.", 'danger')
        return redirect(url_for('index_route'))
    # Dummy data for PDF rendering
    chart_data = {}
    risk_level = {}
    tr = {}

    rendered_html = render_template('report_template.html', results=results, chart_data=chart_data,
                                    risk_level=risk_level, tr=tr, lang=lang)

    try:
        config = pdfkit.configuration(wkhtmltopdf=os.getenv('WKHTMLTOPDF_PATH')) if os.getenv(
            'WKHTMLTOPDF_PATH') else None
        pdf = pdfkit.from_string(rendered_html, False, configuration=config)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=Security_Report_{scan_id}.pdf'
        return response
    except Exception as e:
        logger.error(f"PDF Generation Error: {e}")
        flash("خطأ أثناء إنشاء ملف PDF. تأكد من تثبيت wkhtmltopdf.", "danger")
        return redirect(url_for('results_route', scan_id=scan_id))


# --- Main Execution ---
def verify_environment():
    if not os.path.isdir(os.path.join(current_dir, 'templates')):
        logger.critical("FATAL: 'templates' directory not found.")
        return False
    # Add other checks as needed
    return True


if __name__ == '__main__':
    print("--- Starting Application with Waitress WSGI Server ---")
    print("--- Running on http://127.0.0.1:5003 ---")
    print("--- Press CTRL+C to quit ---")

    serve(app, host='127.0.0.1', port=5003)
