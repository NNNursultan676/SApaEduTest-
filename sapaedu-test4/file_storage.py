
import os
import uuid
import logging
from werkzeug.utils import secure_filename
from flask import current_app
import mimetypes

logger = logging.getLogger(__name__)

# Допустимые типы файлов
ALLOWED_EXTENSIONS = {
    'images': {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'},
    'documents': {'pdf', 'doc', 'docx', 'txt', 'rtf'},
    'videos': {'mp4', 'avi', 'mov', 'webm'},
    'archives': {'zip', 'rar', '7z', 'tar', 'gz'}
}

def allowed_file(filename, file_type='all'):
    """Проверка допустимости файла"""
    if '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    
    if file_type == 'all':
        all_extensions = set()
        for extensions in ALLOWED_EXTENSIONS.values():
            all_extensions.update(extensions)
        return extension in all_extensions
    elif file_type in ALLOWED_EXTENSIONS:
        return extension in ALLOWED_EXTENSIONS[file_type]
    
    return False

def generate_unique_filename(filename):
    """Генерация уникального имени файла"""
    name, ext = os.path.splitext(secure_filename(filename))
    unique_name = f"{name}_{uuid.uuid4().hex[:8]}{ext}"
    return unique_name

def get_file_info(filename):
    """Получение информации о файле"""
    mimetype, _ = mimetypes.guess_type(filename)
    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    file_type = 'other'
    for type_name, extensions in ALLOWED_EXTENSIONS.items():
        if extension in extensions:
            file_type = type_name
            break
    
    return {
        'mimetype': mimetype or 'application/octet-stream',
        'extension': extension,
        'type': file_type
    }

class FileStorage:
    """Класс для работы с файловым хранилищем"""
    
    def __init__(self, storage_path='uploads'):
        self.storage_path = storage_path
        self.ensure_directories()
    
    def ensure_directories(self):
        """Создание необходимых директорий"""
        for file_type in ALLOWED_EXTENSIONS.keys():
            dir_path = os.path.join(self.storage_path, file_type)
            os.makedirs(dir_path, exist_ok=True)
    
    def save_file(self, file, file_type='images'):
        """Сохранение файла"""
        try:
            if not file or file.filename == '':
                return None, "Файл не выбран"
            
            if not allowed_file(file.filename, file_type):
                return None, f"Недопустимый тип файла для категории {file_type}"
            
            filename = generate_unique_filename(file.filename)
            file_path = os.path.join(self.storage_path, file_type, filename)
            
            # Создаем директорию если её нет
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            file.save(file_path)
            
            # Генерируем URL для доступа к файлу
            file_url = f"/uploads/{file_type}/{filename}"
            
            return {
                'filename': filename,
                'original_name': file.filename,
                'file_path': file_path,
                'file_url': file_url,
                'file_type': file_type,
                'file_info': get_file_info(filename)
            }, None
            
        except Exception as e:
            logger.error(f"Ошибка сохранения файла: {e}")
            return None, f"Ошибка сохранения файла: {str(e)}"
    
    def delete_file(self, filename, file_type):
        """Удаление файла"""
        try:
            file_path = os.path.join(self.storage_path, file_type, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                return True, "Файл удален"
            return False, "Файл не найден"
        except Exception as e:
            logger.error(f"Ошибка удаления файла: {e}")
            return False, f"Ошибка удаления файла: {str(e)}"
    
    def get_file_url(self, filename, file_type):
        """Получение URL файла"""
        return f"/uploads/{file_type}/{filename}"

# Глобальный экземпляр
file_storage = FileStorage()
