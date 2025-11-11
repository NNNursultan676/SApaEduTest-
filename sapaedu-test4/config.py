import os

# Telegram Bot Configuration
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8389213664:AAFna56fntKnkBUrQOPcmHz3YDx295hbuI8")
GROUP_ID = int(os.environ.get("GROUP_ID", "-1002723413852"))

# ID ветки для уведомлений о курсах (может быть None если не используется)
thread_id_str = os.environ.get("GROUP_THREAD_ID", "99999")
try:
    GROUP_THREAD_ID = int(thread_id_str) if thread_id_str and thread_id_str.strip() else None
except (ValueError, TypeError):
    GROUP_THREAD_ID = None

# Admin Levels
ADMIN_LEVELS = {
    1: "Преподаватель",
    2: "Администратор",
    3: "Главный администратор"
}

# Supported Languages
SUPPORTED_LANGUAGES = {
    'kz': 'Қазақша',
    'ru': 'Русский',
    'en': 'English'
}
# Database Configuration
# Replit PostgreSQL (if available)
REPLIT_DB_URL = os.environ.get("DATABASE_URL")
# External PostgreSQL (production)
POSTGRES_URL = "postgresql://admin:Aa123456@10.128.0.79:5432/sapaedu"
# Fallback SQLite (development)
SQLITE_URL = "sqlite:///sapaedu.db"

# Use Replit DB first, then external PostgreSQL, fallback to SQLite
DATABASE_URL = REPLIT_DB_URL or os.environ.get("POSTGRES_URL", SQLITE_URL)

# Flag to use fallback data if database is not available
USE_FALLBACK_DATA = os.environ.get("USE_FALLBACK_DATA", "false").lower() == "true"

# Flask Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-here-change-in-production")

# Email Configuration (for phishing emails)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = os.environ.get("EMAIL_USERNAME", "")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "noreply@sapaedu.kz")


HOST_ADMIN_LOGIN = os.environ.get("HOST_ADMIN_LOGIN", "admin@gmail.com")
HOST_ADMIN_PASSWORD = os.environ.get("HOST_ADMIN_PASSWORD", "Aa123456")
HOST_ADMIN_TELEGRAM_ID = os.environ.get("HOST_ADMIN_TELEGRAM_ID", "8090093417")

# Web Application Configuration
WEB_APP_URL = os.environ.get("WEB_APP_URL", "https://testedu.sapatechnologies.kz")
WEBSITE_URL = os.environ.get("WEBSITE_URL", "https://testedu.sapatechnologies.kz")
CERTIFICATE_VERIFICATION_URL = os.environ.get("CERTIFICATE_VERIFICATION_URL", "https://testedu.sapatechnologies.kz")

# Server Configuration
SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "5000"))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"

# Default Values
DEFAULT_CERTIFICATE_PASSING_SCORE = float(os.environ.get("DEFAULT_CERTIFICATE_PASSING_SCORE", "80.0"))
DEFAULT_EXAM_TIME_LIMIT = int(os.environ.get("DEFAULT_EXAM_TIME_LIMIT", "15"))
DEFAULT_EXAM_MAX_ATTEMPTS = int(os.environ.get("DEFAULT_EXAM_MAX_ATTEMPTS", "2"))

# Company List
COMPANIES = [
    'Sapa Technologies',
    'Neo Factoring', 
    'Sapa Digital Finance',
    'AlgaPay',
    'AI Parking',
    'Sapa Digital Communications',
    'Sapa Solutions'
]
