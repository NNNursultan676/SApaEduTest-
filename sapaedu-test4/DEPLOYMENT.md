
# Развертывание SapaEdu на сервере

## Вариант 1: С использованием Docker (рекомендуется)

1. Склонируйте репозиторий:
```bash
git clone <ваш-репозиторий>
cd sapaedu
```

2. Создайте файл `.env` на основе `.env.example`:
```bash
cp .env.example .env
# Отредактируйте .env файл с вашими настройками
```

3. Запустите приложение:
```bash
docker compose up -d --build
```

Приложение будет доступно на порту 5055.

## Вариант 2: Прямой запуск на сервере

1. Установите зависимости:
```bash
sudo apt update
sudo apt install python3 python3-pip postgresql nginx
```

2. Склонируйте проект:
```bash
git clone <ваш-репозиторий>
cd sapaedu
```

3. Запустите скрипт установки:
```bash
chmod +x start_server.sh
./start_server.sh
```

## Вариант 3: Автозапуск через systemd

1. Скопируйте файл сервиса:
```bash
sudo cp sapaedu.service /etc/systemd/system/
```

2. Включите и запустите сервис:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sapaedu
sudo systemctl start sapaedu
```

3. Проверьте статус:
```bash
sudo systemctl status sapaedu
```

## Nginx конфигурация (опционально)

Создайте файл `/etc/nginx/sites-available/sapaedu`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Активируйте конфигурацию:
```bash
sudo ln -s /etc/nginx/sites-available/sapaedu /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Telegram Bot

Для запуска бота создайте отдельный процесс:
```bash
python3 bot.py
```

Или добавьте в systemd как отдельный сервис.
