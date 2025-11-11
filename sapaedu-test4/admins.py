
import logging
from datetime import datetime, timezone
from database import get_db_session, Admin

logger = logging.getLogger(__name__)

import logging
from datetime import datetime, timezone
from database import get_db_session, Admin

logger = logging.getLogger(__name__)

def is_admin(telegram_id: str) -> int:
    """Check if user is admin and return admin level"""
    if not telegram_id:
        return 0
    
    try:
        db = get_db_session()
        try:
            admin = db.query(Admin).filter(Admin.telegram_id == str(telegram_id)).first()
            return admin.level if admin else 0
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        # Fallback - check if it's the default admin from config
        try:
            from config import HOST_ADMIN_TELEGRAM_ID
            if str(telegram_id) == HOST_ADMIN_TELEGRAM_ID:
                return 3
        except:
            pass
        return 0

def add_admin(telegram_id: str, level: int, added_by: str) -> tuple[bool, str]:
    """Add new admin"""
    if not telegram_id or level < 1 or level > 3:
        return False, "Неверные параметры"
    
    db = get_db_session()
    try:
        # Check if admin already exists
        existing = db.query(Admin).filter(Admin.telegram_id == telegram_id).first()
        if existing:
            return False, "Админ уже существует"
        
        # Check permissions
        if added_by != 'system' and added_by != 'host_admin':
            admin_level = is_admin(added_by)
            if admin_level < 2:
                return False, "Недостаточно прав для добавления админа"
            if admin_level <= level:
                return False, "Нельзя назначить админа уровня выше или равного вашему"
        
        # Add to Admin table
        admin = Admin(
            telegram_id=telegram_id,
            level=level,
            added_by=added_by,
            added_at=datetime.now(timezone.utc)
        )
        db.add(admin)
        
        # CRITICAL: Also update User table if user exists
        from database import User
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if user:
            user.is_admin = True
            user.updated_at = datetime.now(timezone.utc)
            logger.info(f"Updated existing user {telegram_id} to admin status")
        else:
            logger.info(f"User {telegram_id} not found in User table, will be updated on next login")
        
        db.commit()
        return True, "Админ добавлен успешно"
    except Exception as e:
        db.rollback()
        logger.error(f"Error adding admin: {e}")
        return False, f"Ошибка: {e}"
    finally:
        db.close()

def remove_admin(telegram_id: str, removed_by: str) -> tuple[bool, str]:
    """Remove admin"""
    if not telegram_id:
        return False, "Telegram ID обязателен"
    
    db = get_db_session()
    try:
        admin = db.query(Admin).filter(Admin.telegram_id == telegram_id).first()
        if not admin:
            return False, "Админ не найден"
        
        # Check permissions
        if removed_by != 'system' and removed_by != 'host_admin':
            admin_level = is_admin(removed_by)
            if admin_level < 2:
                return False, "Недостаточно прав для удаления админа"
            if admin_level <= admin.level:
                return False, "Нельзя удалить админа уровня выше или равного вашему"
        
        # Remove from Admin table
        db.delete(admin)
        
        # CRITICAL: Also update User table if user exists
        from database import User
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if user:
            user.is_admin = False
            user.updated_at = datetime.now(timezone.utc)
            logger.info(f"Updated user {telegram_id} admin status to False")
        else:
            logger.info(f"User {telegram_id} not found in User table")
        
        db.commit()
        return True, "Админ удален успешно"
    except Exception as e:
        db.rollback()
        logger.error(f"Error removing admin: {e}")
        return False, f"Ошибка: {e}"
    finally:
        db.close()

def get_admins_list():
    """Get list of all admins"""
    db = get_db_session()
    try:
        admins = db.query(Admin).all()
        return admins
    except Exception as e:
        logger.error(f"Error getting admins list: {e}")
        return []
    finally:
        db.close()

def can_manage_admin(manager_id: str, target_id: str) -> bool:
    """Check if manager can manage target admin"""
    manager_level = is_admin(manager_id)
    target_level = is_admin(target_id)
    
    return manager_level >= 2 and manager_level > target_level
