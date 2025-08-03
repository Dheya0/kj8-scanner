# Ethical Security Scanner - الماسح الأمني الأخلاقي (V8)

![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.x-green.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen)

## 🔍 Overview | نظرة عامة

**Ethical Security Scanner** is a powerful web-based vulnerability scanner designed for **ethical hacking** and **penetration testing**. Built using Python and Flask with a modular architecture, it provides advanced vulnerability detection through a modern and user-friendly interface.

**الماسح الأمني الأخلاقي** هو أداة متقدمة لفحص الثغرات قائمة على الويب، مخصصة لأغراض القرصنة الأخلاقية واختبار الاختراق. تم تطويرها باستخدام Python وFlask وبنية معيارية لتقديم تحليل أمني شامل من خلال واجهة سهلة الاستخدام.

> 📸 _**Replace the placeholder image below with a real screenshot of your dashboard UI**_

![Dashboard Screenshot](https://via.placeholder.com/800x450.png?text=Ethical+Scanner+Dashboard)

---

## 🚀 Key Features | الميزات الرئيسية

### 🛡️ Comprehensive Vulnerability Detection | اكتشاف شامل للثغرات

- **Injection Flaws**: SQL Injection (خطأ زمني وخطأ تقني)، Command Injection، SSTI، LFI.
- **Cross-Site Scripting (XSS)**: دعم للأنواع Reflected وStored، مع تحليل ذكي لتقليل الإنذارات الخاطئة.
- **Out-of-Band Detection (OAST)**: كشف متقدم لثغرات عمياء مثل SSRF.
- **Configuration & Info Disclosure**: فحص للملفات الحساسة مثل `.env` و`.git`، رؤوس الأمان، وغيرها.

### 🧠 Advanced Business Logic Testing | اختبار منطق العمل المتقدم

- اختبر ثغرات معقدة مثل IDOR وتصعيد الصلاحيات باستخدام ملفات JSON بسيطة.
- تدفق مكون من عدة خطوات مع استخراج تلقائي للسياق (مثل session tokens أو user IDs).

### ⚙️ High-Performance Architecture | بنية قابلة للتوسع

- تنفيذ غير متزامن بالكامل باستخدام `ThreadPoolExecutor`.
- إدارة حالة مركزية في الوقت الفعلي باستخدام Redis.
- تحسين جلسات HTTP لتقليل الاختناقات وزيادة الأداء.

### 🔐 Secure by Design | أمان مدمج في التصميم

- **مصادقة قوية**: دعم لتجزئة كلمات المرور (PBKDF2)، حماية من التخمين، وسياسات تعقيد.
- **المصادقة الثنائية (2FA)**: دعم TOTP.
- **حماية CSRF**: مدمجة باستخدام Flask-WTF.
- **إدارة الأسرار**: باستخدام ملفات `.env`.

### 📊 User Interface & Reporting | واجهة احترافية وتقارير ديناميكية

- **لوحة تحكم تفاعلية**: تعرض تقدم الفحص في الوقت الفعلي.
- **دعم لغتين**: تقارير ديناميكية بالإنجليزية والعربية.
- **تقارير PDF**: توليد تقارير مهنية متعددة اللغات.
- **رسوم بيانية**: رسوم دائرية تفاعلية لعرض نتائج الفحص حسب الخطورة.

---

## 🧰 Tech Stack | التقنيات المستخدمة

| Layer | Tools |
|-------|-------|
| **Backend** | Python, Flask, Waitress |
| **Database** | SQLAlchemy (PostgreSQL or SQLite) |
| **State Management** | Redis |
| **Frontend** | HTML, Jinja2, Bootstrap (CDN), Chart.js |
| **Scanning Engine** | requests, selenium, beautifulsoup4 |
| **Security & Auth** | flask-login, werkzeug, pyotp, cryptography |
| **Reporting** | pdfkit (requires wkhtmltopdf) |

---

## 🛠️ Getting Started | البدء

### 📋 Prerequisites | المتطلبات الأساسية

- Python 3.9 أو أعلى
- Redis
- [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html)
- Google Chrome (للدخول التلقائي عبر Selenium)

### 📦 Installation | التثبيت

```bash
# استنساخ المستودع
git clone https://github.com/your-username/ethical-security-scanner.git
cd ethical-security-scanner

# إنشاء بيئة افتراضية
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# تثبيت الحزم المطلوبة
pip install -r requirements.txt
