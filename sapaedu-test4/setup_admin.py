#!/usr/bin/env python3
"""
Скрипт для создания главного администратора
"""

import sys
from database import get_db_session, init_db, Admin
from config import HOST_ADMIN_TELEGRAM_ID, HOST_ADMIN_LOGIN, HOST_ADMIN_PASSWORD
from datetime import datetime, timezone

def create_main_admin():
    """Создать главного администратора"""

    # Telegram ID админа из конфига
    main_admin_telegram_id = HOST_ADMIN_TELEGRAM_ID
    
    session = get_db_session()

    if session.query(Admin).filter(Admin.telegram_id == main_admin_telegram_id).first():
        print(f"❌ Главный администратор с Telegram ID {main_admin_telegram_id} уже существует.")
        sys.exit(1)

    new_admin = Admin(
        telegram_id=main_admin_telegram_id,
        login=HOST_ADMIN_LOGIN,
        password=HOST_ADMIN_PASSWORD,
        level=3,  # 3 - Главный админ
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    session.add(new_admin)
    session.commit()
    session.close()

    print(f"✅ Главный администратор создан!")
    print(f"Telegram ID: {main_admin_telegram_id}")
    print(f"Уровень: 3 (Главный админ)")
    print()
    print("Данные для входа в админку:")
    print(f"Логин: {HOST_ADMIN_LOGIN}")
    print(f"Пароль: {HOST_ADMIN_PASSWORD}")
    print()
    print("Теперь вы можете:")
    print("1. Запустить бота и веб-приложение")
    print("2. Зайти на сайт и войти с указанными данными")
    print("3. Или написать боту /start и войти через Telegram")
    print("4. Зайти в админ-панель по адресу /admin")


if __name__ == "__main__":
    init_db()
    create_main_admin()