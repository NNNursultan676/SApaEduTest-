
#!/usr/bin/env python3
"""
Скрипт для запуска веб-приложения и бота одновременно
"""

import os
import sys
import subprocess
import signal
import time
from multiprocessing import Process

def start_web_app():
    """Запуск веб-приложения"""
    print("🌐 Starting web application...")
    subprocess.run([sys.executable, "main.py"])

def start_bot():
    """Запуск Telegram бота"""
    print("🤖 Starting Telegram bot...")
    subprocess.run([sys.executable, "bot.py"])

def signal_handler(sig, frame):
    """Обработчик сигнала завершения"""
    print("\n⚠️ Stopping services...")
    sys.exit(0)

def main():
    """Главная функция"""
    # Переходим в директорию sapaedu
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Обработчик Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🚀 Starting SapaEdu services...")
    print("=" * 50)
    
    try:
        # Создаем процессы
        web_process = Process(target=start_web_app, name="WebApp")
        bot_process = Process(target=start_bot, name="TelegramBot")
        
        # Запускаем процессы
        web_process.start()
        time.sleep(2)  # Даем веб-приложению время запуститься
        bot_process.start()
        
        print("✅ Both services started successfully!")
        print("🌐 Web app: http://0.0.0.0:5000")
        print("🤖 Telegram bot: Active")
        print("\nPress Ctrl+C to stop all services")
        
        # Ждем завершения процессов
        web_process.join()
        bot_process.join()
        
    except KeyboardInterrupt:
        print("\n⚠️ Stopping all services...")
        if 'web_process' in locals():
            web_process.terminate()
        if 'bot_process' in locals():
            bot_process.terminate()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
