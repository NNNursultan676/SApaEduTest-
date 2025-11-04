
#!/usr/bin/env python3
"""
Главный файл запуска SapaEdu приложения
"""

import os
import sys
import logging
import subprocess
import signal
import time
from multiprocessing import Process
from datetime import datetime, timezone

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def start_web_app():
    """Запуск веб-приложения"""
    logger.info("🌐 Starting web application...")
    
    try:
        # Инициализация базы данных
        from database import init_db, test_database_connection
        logger.info("Initializing database...")
        
        if test_database_connection():
            logger.info("Database connection successful")
            init_db()
            logger.info("Database initialized")
        else:
            logger.error("Database connection failed")
            return
        
        # Импортируем Flask приложение
        from app import app
        
        # Запускаем приложение
        logger.info("Starting Flask application on 0.0.0.0:5000")
        app.run(
            host='0.0.0.0',
            port=5055,
            debug=False
        )
        
    except Exception as e:
        logger.error(f"Web app startup failed: {e}")

def start_bot():
    """Запуск Telegram бота"""
    logger.info("🤖 Starting Telegram bot...")
    subprocess.run([sys.executable, "bot.py"])

def signal_handler(sig, frame):
    """Обработчик сигнала завершения"""
    logger.info("\n⚠️ Stopping services...")
    sys.exit(0)

def main():
    """Главная функция запуска приложения"""
    
    # Переходим в директорию sapaedu
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Обработчик Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    logger.info("🚀 Starting SapaEdu services...")
    logger.info("=" * 50)
    
    try:
        # Создаем процессы
        web_process = Process(target=start_web_app, name="WebApp")
        bot_process = Process(target=start_bot, name="TelegramBot")
        
        # Запускаем процессы
        web_process.start()
        time.sleep(2)  # Даем веб-приложению время запуститься
        bot_process.start()
        
        logger.info("✅ Both services started successfully!")
        logger.info("🌐 Web app: http://0.0.0.0:5055")
        logger.info("🤖 Telegram bot: Active")
        logger.info("\nPress Ctrl+C to stop all services")
        
        # Ждем завершения процессов
        web_process.join()
        bot_process.join()
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ Stopping all services...")
        if 'web_process' in locals():
            web_process.terminate()
        if 'bot_process' in locals():
            bot_process.terminate()
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
