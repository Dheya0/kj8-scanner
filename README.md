Ethical Security Scanner - الماسح الأمني الأخلاقي (V8)
![alt text](https://img.shields.io/badge/python-3.9%2B-blue.svg)

![alt text](https://img.shields.io/badge/flask-2.x-green.svg)

![alt text](https://img.shields.io/badge/license-MIT-lightgrey.svg)

![alt text](https://img.shields.io/badge/status-active-brightgreen)
An advanced, web-based vulnerability scanner designed for ethical hacking and penetration testing. Built with a powerful combination of Python, Flask, and a modular architecture, this tool provides comprehensive security analysis through a user-friendly interface.
أداة فحص ثغرات متقدمة قائمة على الويب، مصممة لأغراض القرصنة الأخلاقية واختبار الاختراق. تم بناء هذه الأداة بمزيج قوي من Python و Flask وبنية معيارية، وتوفر تحليلاً أمنياً شاملاً من خلال واجهة سهلة الاستخدام.
![alt text](https://via.placeholder.com/800x450.png?text=Ethical+Scanner+Dashboard)

(Note: Replace the placeholder image with an actual screenshot of your application's UI)
🚀 Key Features | الميزات الرئيسية
This is not just another simple scanner. It integrates advanced techniques and a robust framework to deliver near commercial-grade results.
هذه الأداة ليست مجرد ماسح بسيط آخر، بل تدمج تقنيات متقدمة وإطار عمل قوياً لتقديم نتائج تقترب من مستوى الأدوات التجارية.
🛡️ Comprehensive Vulnerability Detection | اكتشاف شامل للثغرات:
Injection Flaws: SQL Injection (Error-based, Time-based), Command Injection (Blind, Time-based), SSTI, LFI.
Cross-Site Scripting (XSS): Reflected & Stored XSS with intelligent payload reflection analysis to reduce false positives.
Out-of-Band Detection (OAST): Advanced detection for blind vulnerabilities like Server-Side Request Forgery (SSRF).
Configuration & Information Disclosure: Checks for sensitive files (.env, .git), verbose headers, and security headers (CSP, HSTS, etc.).
🧠 Advanced Business Logic Module | وحدة متقدمة لفحص منطق العمل:
The Crown Jewel! Define multi-step attack workflows in simple JSON files.
Test for complex vulnerabilities like IDOR (Insecure Direct Object References) and privilege escalation flaws that traditional scanners miss.
Automatically extract context (like session tokens or user IDs) from one step and use it in another.
⚙️ High-Performance & Scalable Architecture | بنية عالية الأداء وقابلة للتوسع:
Fully Asynchronous: Utilizes ThreadPoolExecutor to run modules and network requests concurrently for maximum speed.
Redis-Powered: Centralized state management using Redis for real-time progress tracking, allowing the application to scale across multiple workers (e.g., using Gunicorn).
Optimized HTTP Sessions: Custom HTTPAdapter with increased connection pooling to handle high-concurrency scans without bottlenecks.
🔐 Secure-by-Design Application Framework | إطار تطبيق آمن حسب التصميم:
Robust Authentication: Password hashing (PBKDF2), complexity policies, and brute-force protection (account lockout).
Two-Factor Authentication (2FA): TOTP-based 2FA for enhanced account security.
CSRF Protection: Integrated into all forms via Flask-WTF.
Secure Dependencies: Uses environment variables for all secrets and configurations.
📊 User-Friendly Interface & Reporting | واجهة سهلة الاستخدام وتقارير احترافية:
Real-time Scan Progress: A live-updating dashboard shows scan progress and a detailed log.
Dynamic Translation: Reports can be viewed in both English and Arabic with on-the-fly text translation.
Professional PDF Reports: Generate detailed, multilingual security assessment reports ready for stakeholders.
Data Visualization: Interactive doughnut charts to summarize vulnerability severity.
🛠️ Tech Stack | التقنيات المستخدمة
Backend: Python, Flask, Waitress (WSGI Server)
Database: SQLAlchemy (compatible with PostgreSQL & SQLite)
Async & State: Redis
Frontend: HTML, Jinja2, Bootstrap (via CDN in templates is assumed), Chart.js
Scanning Core: requests, selenium, beautifulsoup4
Security & Auth: flask-login, werkzeug, pyotp, cryptography
Reporting: pdfkit (requires wkhtmltopdf)
🏁 Getting Started | البدء
Follow these steps to get the scanner up and running on your local machine.
اتبع هذه الخطوات لتشغيل الماسح على جهازك المحلي.
Prerequisites | المتطلبات الأساسية
Python 3.9+
Redis Server: Ensure you have a Redis instance running. See Redis Docs.
wkhtmltopdf: Required for generating PDF reports. Download it from wkhtmltopdf.org and ensure its installation path is added to your system's PATH.
Google Chrome: Required for Selenium-based automated login.
Installation & Setup | التثبيت والإعداد
Clone the repository:
Generated bash
git clone https://github.com/your-username/ethical-security-scanner.git
cd ethical-security-scanner
Use code with caution.
Bash
Create and activate a virtual environment:
Generated bash
# For Windows
python -m venv .venv
.venv\Scripts\activate

# For macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
Use code with caution.
Bash
Install the required Python packages:
Generated bash
pip install -r requirements.txt
Use code with caution.
Bash
(Note: You will need to create a requirements.txt file by running pip freeze > requirements.txt in your project's activated environment.)
Configure environment variables:
Create a file named .env in the root directory and add the following configurations. Do not commit this file to Git.
Generated env
# Flask Secret Key (generate a long random string)
FLASK_SECRET_KEY='your-very-secret-and-long-random-string'

# Database URL (Example for PostgreSQL, or leave blank for default SQLite)
# DATABASE_URL='postgresql://user:password@localhost/scannerdb'

# Redis URL
REDIS_URL='redis://127.0.0.1:6379/0'

# Email configuration (for account confirmation) - Optional
# MAIL_SERVER='smtp.example.com'
# MAIL_PORT=587
# MAIL_USE_TLS=True
# MAIL_USERNAME='your-email@example.com'
# MAIL_PASSWORD='your-email-password'

# Path to wkhtmltopdf executable (only if not in system PATH)
# WKHTMLTOPDF_PATH='C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
Use code with caution.
Env
Initialize the database:
If you are running the application for the first time, set up the database schema.
Generated bash
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
Use code with caution.
Bash
(Note: This requires Flask-Migrate. You might need to set the FLASK_APP environment variable first: set FLASK_APP=ethical_v5.py on Windows or export FLASK_APP=ethical_v5.py on macOS/Linux.)
Running the Application | تشغيل التطبيق
With the virtual environment activated, run the application from the terminal:
Generated bash
python ethical_v5.py
Use code with caution.
Bash
The application will be served by Waitress and available at http://127.0.0.1:5003.
🤝 Contributing | المساهمة
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.
Fork the Project
Create your Feature Branch (git checkout -b feature/AmazingFeature)
Commit your Changes (git commit -m 'Add some AmazingFeature')
Push to the Branch (git push origin feature/AmazingFeature)
Open a Pull Request
