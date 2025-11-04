
import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey, Float, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timezone
import logging
from sqlalchemy.sql import func, text # Import text for raw SQL queries

logger = logging.getLogger(__name__)

# Database configuration
from config import DATABASE_URL

# Create engine
if DATABASE_URL.startswith('sqlite'):
    engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    telegram_id = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True)
    name = Column(String)
    is_admin = Column(Boolean, default=False)
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)
    company = Column(String, nullable=True)
    language = Column(String, default="ru")

    # Relationships
    course_progress = relationship("CourseProgress", back_populates="user")
    certificates = relationship("Certificate", back_populates="user")
    phishing_checks = relationship("PhishingCheck", back_populates="user")
    notifications = relationship("Notification", back_populates="user")

class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    telegram_id = Column(String, unique=True, index=True)
    level = Column(Integer)
    added_by = Column(String)
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    introduction = Column(Text)  # Введение
    conclusion = Column(Text)    # Заключение
    course_type = Column(String, default="revocable")  # revocable или static
    is_published = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Certificate settings
    certificate_title = Column(String, default="СЕРТИФИКАТ")
    certificate_subtitle = Column(String, default="о прохождении курса")
    certificate_organization = Column(String, default="SapaEdu")
    certificate_logo_url = Column(String)
    certificate_background_url = Column(String)
    certificate_background_color = Column(String, default="#ffffff")
    certificate_primary_color = Column(String, default="#007bff")
    certificate_secondary_color = Column(String, default="#6c757d")
    certificate_accent_color = Column(String, default="#28a745")
    certificate_border_style = Column(String, default="modern")  # modern, classic, elegant
    certificate_layout_style = Column(String, default="standard")  # standard, minimal, decorative
    certificate_watermark_text = Column(String, default="SapaEdu")
    certificate_watermark_opacity = Column(Float, default=0.1)
    certificate_show_qr = Column(Boolean, default=True)
    certificate_footer_text = Column(String)
    
    # Achievement elements instead of signatures
    certificate_achievement_badge = Column(String, default="graduation")  # graduation, shield, star, trophy
    certificate_achievement_text = Column(String, default="Успешно завершен курс")
    certificate_verification_url = Column(String)
    certificate_validity_text = Column(String, default="Действителен на момент выдачи")
    
    # Author/Signer fields
    certificate_author_name = Column(String)  # ФИО автора курса
    certificate_author_position = Column(String)  # Должность автора курса
    
    # Signature fields for people (deprecated, use author fields instead)
    certificate_signer1_name = Column(String)  # ФИО первого подписанта
    certificate_signer1_position = Column(String)  # Должность первого подписанта
    certificate_signer2_name = Column(String)  # ФИО второго подписанта
    certificate_signer2_position = Column(String)  # Должность второго подписанта

    # Relationships
    chapters = relationship("Chapter", back_populates="course", cascade="all, delete-orphan")
    exams = relationship("Exam", back_populates="course")
    progress = relationship("CourseProgress", back_populates="course")
    certificates = relationship("Certificate", back_populates="course")

class Chapter(Base):
    __tablename__ = "chapters"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    title = Column(String, nullable=False)
    content = Column(Text)  # HTML content
    content_blocks = Column(JSON, default=list)  # Блоки контента
    order_number = Column(Integer)  # порядок главы
    has_test = Column(Boolean, default=False)  # Есть ли тест в главе
    test_questions = Column(JSON, default=list)  # Вопросы теста главы
    test_passing_score = Column(Float, default=80.0)  # Минимальный балл для прохождения теста главы
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    course = relationship("Course", back_populates="chapters")

class Exam(Base):
    __tablename__ = "exams"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    title = Column(String, nullable=False, default="Итоговый экзамен")
    questions = Column(JSON)  # JSON с вопросами и ответами
    passing_score = Column(Float, default=80.0)  # минимальный балл для прохождения
    time_limit = Column(Integer, default=15)  # время в минутах
    max_attempts = Column(Integer, default=2)  # максимальное количество попыток
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    course = relationship("Course", back_populates="exams")
    attempts = relationship("ExamAttempt", back_populates="exam")

class ExamAttempt(Base):
    __tablename__ = "exam_attempts"

    id = Column(Integer, primary_key=True, index=True)
    exam_id = Column(Integer, ForeignKey("exams.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    answers = Column(JSON)  # ответы пользователя
    score = Column(Float)
    passed = Column(Boolean, default=False)  # прошел ли экзамен
    attempt_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    detailed_results = Column(JSON, default=list)  # Детальные результаты по каждому вопросу

    # Relationships
    exam = relationship("Exam", foreign_keys=[exam_id])
    user = relationship("User", foreign_keys=[user_id])

class ChapterTestAttempt(Base):
    __tablename__ = "chapter_test_attempts"

    id = Column(Integer, primary_key=True, index=True)
    chapter_id = Column(Integer, ForeignKey("chapters.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    answers = Column(JSON)  # JSON с ответами пользователя
    score = Column(Float)  # балл от 0 до 100
    passed = Column(Boolean, default=False)  # прошел ли тест
    attempt_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    detailed_results = Column(JSON, default=list)  # Детальные результаты по каждому вопросу

    # Relationships
    chapter = relationship("Chapter", foreign_keys=[chapter_id])
    user = relationship("User", foreign_keys=[user_id])

class CourseProgress(Base):
    __tablename__ = "course_progress"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    completed_chapters = Column(JSON, default=list)  # список ID завершенных глав
    current_chapter = Column(Integer, default=1)
    progress_percent = Column(Float, default=0.0)
    completed = Column(Boolean, default=False)
    completed_introduction = Column(Boolean, default=False)
    completed_conclusion = Column(Boolean, default=False)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = relationship("User", back_populates="course_progress")
    course = relationship("Course", back_populates="progress")

class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    certificate_id = Column(String, unique=True, index=True)  # UUID
    certificate_code = Column(String, unique=True, index=True)  # 6-значный код
    status = Column(String, default="active")  # active, revoked
    exam_score = Column(Float)  # балл экзамена
    issued_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String, nullable=True)

    # Relationships
    user = relationship("User", back_populates="certificates")
    course = relationship("Course", back_populates="certificates")

class PhishingCheck(Base):
    __tablename__ = "phishing_checks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    check_id = Column(String, unique=True, index=True)  # UUID
    email_subject = Column(String)
    email_content = Column(Text)
    status = Column(String, default="pending")  # pending, passed, failed
    sent_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    clicked_at = Column(DateTime, nullable=True)
    checked_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="phishing_checks")

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String)
    message = Column(Text)
    type = Column(String)  # course_assigned, certificate_issued, certificate_revoked, phishing_failed
    read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = relationship("User", back_populates="notifications")

class UsefulLink(Base):
    __tablename__ = "useful_links"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    url = Column(String, nullable=False)
    description = Column(Text)
    category = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

# Database helper functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_db_session():
    return SessionLocal()

def normalize_completed_chapters(completed_chapters):
    """Normalize completed_chapters to a list of integers"""
    if completed_chapters is None:
        return []
    
    if isinstance(completed_chapters, list):
        # Ensure all items are integers
        return [int(item) for item in completed_chapters if str(item).isdigit()]
    
    if isinstance(completed_chapters, str):
        try:
            import json
            parsed = json.loads(completed_chapters)
            if isinstance(parsed, list):
                return [int(item) for item in parsed if str(item).isdigit()]
        except:
            pass
    
    return []

def calculate_course_progress(course_id, user_id, db_session=None):
    """
    Упрощенная функция для расчета прогресса курса
    """
    should_close_db = False
    if db_session is None:
        db_session = get_db_session()
        should_close_db = True
    
    try:
        # Получаем прогресс пользователя
        progress = db_session.query(CourseProgress).filter(
            CourseProgress.user_id == user_id,
            CourseProgress.course_id == course_id
        ).first()

        # Получаем главы курса
        chapters = db_session.query(Chapter).filter(
            Chapter.course_id == course_id
        ).order_by(Chapter.order_number, Chapter.id).all()
        
        total_sections = len(chapters) + 2  # +2 для введения и заключения
        
        if not progress:
            return {
                'progress_percent': 0.0,
                'completed_sections': 0,
                'total_sections': total_sections,
                'all_completed': False,
                'completed_chapters': [],
                'completed_introduction': False,
                'completed_conclusion': False
            }

        completed_sections = 0
        
        # Нормализуем completed_chapters
        completed_chapters = normalize_completed_chapters(progress.completed_chapters)
        
        # Проверяем введение
        if progress.completed_introduction:
            completed_sections += 1

        # Проверяем заключение  
        if progress.completed_conclusion:
            completed_sections += 1

        # Проверяем главы
        for chapter in chapters:            
            if chapter.has_test:
                # Для глав с тестом проверяем лучший результат
                best_attempt = db_session.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.chapter_id == chapter.id,
                    ChapterTestAttempt.user_id == user_id
                ).order_by(ChapterTestAttempt.score.desc()).first()
                
                if best_attempt and best_attempt.score >= 100.0:
                    completed_sections += 1
                    if chapter.id not in completed_chapters:
                        completed_chapters.append(chapter.id)
                elif chapter.id in completed_chapters:
                    completed_chapters.remove(chapter.id)
            else:
                # Для глав без теста проверяем ручное завершение
                if chapter.id in completed_chapters:
                    completed_sections += 1

        # Обновляем progress
        if progress.completed_chapters != completed_chapters:
            progress.completed_chapters = completed_chapters
            progress.updated_at = datetime.now(timezone.utc)
            db_session.commit()
        
        # Рассчитываем процент
        progress_percent = (completed_sections / total_sections * 100.0) if total_sections > 0 else 0.0
        all_completed = completed_sections >= total_sections

        # Get chapter statuses for detailed view
        chapter_statuses = {}
        for chapter in chapters:
            if chapter.has_test:
                # For chapters with tests, get best attempt
                best_attempt = db_session.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.chapter_id == chapter.id,
                    ChapterTestAttempt.user_id == user_id
                ).order_by(ChapterTestAttempt.score.desc()).first()
                
                if best_attempt:
                    chapter_statuses[chapter.id] = {
                        'completed': best_attempt.score >= 100.0,
                        'has_test': True,
                        'test_passed': best_attempt.score >= 100.0,
                        'test_score': best_attempt.score
                    }
                else:
                    chapter_statuses[chapter.id] = {
                        'completed': False,
                        'has_test': True,
                        'test_passed': False,
                        'test_score': 0
                    }
            else:
                # For chapters without tests
                is_completed = chapter.id in completed_chapters
                chapter_statuses[chapter.id] = {
                    'completed': is_completed,
                    'has_test': False,
                    'test_passed': False,
                    'test_score': 0
                }

        return {
            'progress_percent': progress_percent,
            'completed_sections': completed_sections,
            'total_sections': total_sections,
            'all_completed': all_completed,
            'completed_chapters': completed_chapters,
            'completed_introduction': progress.completed_introduction,
            'completed_conclusion': progress.completed_conclusion,
            'chapter_statuses': chapter_statuses
        }

    except Exception as e:
        logger.error(f"Error calculating progress for course {course_id}, user {user_id}: {e}")
        return {
            'progress_percent': 0.0,
            'completed_sections': 0,
            'total_sections': total_sections if 'total_sections' in locals() else 0,
            'all_completed': False,
            'completed_chapters': [],
            'completed_introduction': False,
            'completed_conclusion': False,
            'chapter_statuses': {}
        }
    finally:
        if should_close_db:
            db_session.close()

def update_course_progress(course_id, user_id, db_session=None):
    """
    Обновляет прогресс курса в базе данных
    """
    should_close_db = False
    if db_session is None:
        db_session = get_db_session()
        should_close_db = True
    
    try:
        # Получаем текущий прогресс
        progress_data = calculate_course_progress(course_id, user_id, db_session)
        
        # Получаем или создаем запись прогресса
        progress = db_session.query(CourseProgress).filter(
            CourseProgress.user_id == user_id,
            CourseProgress.course_id == course_id
        ).first()
        
        if not progress:
            progress = CourseProgress(
                user_id=user_id,
                course_id=course_id,
                completed_chapters=[],
                current_chapter=1,
                progress_percent=0.0,
                completed_introduction=False,
                completed_conclusion=False,
                started_at=datetime.now(timezone.utc)
            )
            db_session.add(progress)
        
        # Обновляем данные
        progress.completed_chapters = progress_data['completed_chapters']
        progress.progress_percent = progress_data['progress_percent']
        progress.updated_at = datetime.now(timezone.utc)
        
        # Проверяем полное завершение курса
        if progress_data['all_completed'] and not progress.completed:
            progress.completed = True
            progress.progress_percent = 100.0
            progress.completed_at = datetime.now(timezone.utc)
        elif not progress_data['all_completed'] and progress.completed:
            # Если курс был завершен, но теперь не все разделы пройдены
            progress.completed = False
            progress.completed_at = None
        
        db_session.commit()
        return progress_data
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Error updating progress for course {course_id}, user {user_id}: {e}")
        raise
    finally:
        if should_close_db:
            db_session.close()

def get_course_progress_safe(course_id, user_id, db_session=None):
    """
    Безопасно получает прогресс курса с обработкой ошибок
    """
    try:
        return calculate_course_progress(course_id, user_id, db_session)
    except Exception as e:
        logger.error(f"Error getting course progress: {e}")
        return {
            'progress_percent': 0.0,
            'completed_sections': 0,
            'total_sections': 0,
            'all_completed': False,
            'completed_chapters': [],
            'completed_introduction': False,
            'completed_conclusion': False,
            'chapter_statuses': {}
        }

def sync_admin_status():
    """Sync admin status between Admin table and User table"""
    db = SessionLocal()
    try:
        # Get all admins from Admin table
        admins = db.query(Admin).all()
        admin_telegram_ids = [admin.telegram_id for admin in admins]

        # Update users who should be admins
        db.query(User).filter(User.telegram_id.in_(admin_telegram_ids)).update(
            {User.is_admin: True}, synchronize_session=False
        )

        # Update users who should not be admins
        db.query(User).filter(~User.telegram_id.in_(admin_telegram_ids)).update(
            {User.is_admin: False}, synchronize_session=False
        )

        db.commit()
        logger.info("Admin status synchronized")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to sync admin status: {e}")
    finally:
        db.close()

def test_database_connection():
    """Test if database connection is available"""
    try:
        with engine.connect() as test_connection:
            test_connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

def add_missing_columns(engine):
    """Add missing columns to existing tables"""
    try:
        with engine.connect() as conn:
            # Check if detailed_results column exists in exam_attempts table
            if DATABASE_URL.startswith('postgresql'):
                result = conn.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'exam_attempts' AND column_name = 'detailed_results'
                """))
                if not result.fetchone():
                    conn.execute(text("ALTER TABLE exam_attempts ADD COLUMN detailed_results JSON"))
                    conn.commit()
                    logger.info("Added detailed_results column to exam_attempts table")

                # Check for new certificate fields
                result = conn.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'courses' AND column_name = 'certificate_background_url'
                """))
                if not result.fetchone():
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_background_url VARCHAR"))
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_signature_url VARCHAR"))
                    conn.commit()
                    logger.info("Added certificate background and signature URL columns")
                    
                # Check for updated_at in course_progress
                result = conn.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'course_progress' AND column_name = 'updated_at'
                """))
                if not result.fetchone():
                    conn.execute(text("ALTER TABLE course_progress ADD COLUMN updated_at TIMESTAMP"))
                    conn.commit()
                    logger.info("Added updated_at column to course_progress table")

            else:
                # For SQLite
                try:
                    conn.execute(text("SELECT detailed_results FROM exam_attempts LIMIT 1"))
                except Exception:
                    conn.execute(text("ALTER TABLE exam_attempts ADD COLUMN detailed_results TEXT"))
                    conn.commit()
                    logger.info("Added detailed_results column to exam_attempts table")

                try:
                    conn.execute(text("SELECT certificate_background_url FROM courses LIMIT 1"))
                except Exception:
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_background_url TEXT"))
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_signature_url TEXT"))
                    conn.commit()
                    logger.info("Added certificate background and signature URL columns")
                    
                try:
                    conn.execute(text("SELECT updated_at FROM course_progress LIMIT 1"))
                except Exception:
                    conn.execute(text("ALTER TABLE course_progress ADD COLUMN updated_at TEXT"))
                    conn.commit()
                    logger.info("Added updated_at column to course_progress table")
                
                # Add certificate author fields
                try:
                    conn.execute(text("SELECT certificate_author_name FROM courses LIMIT 1"))
                except Exception:
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_author_name TEXT"))
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_author_position TEXT"))
                    conn.commit()
                    logger.info("Added certificate_author fields to courses table")
            
            # For PostgreSQL, add certificate_author fields if missing
            if DATABASE_URL.startswith('postgresql'):
                result = conn.execute(text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'courses' AND column_name IN ('certificate_author_name', 'certificate_author_position')
                """))
                existing_columns = [row[0] for row in result]
                
                if 'certificate_author_name' not in existing_columns:
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_author_name VARCHAR"))
                    conn.commit()
                    logger.info("Added certificate_author_name column to courses table (PostgreSQL)")
                
                if 'certificate_author_position' not in existing_columns:
                    conn.execute(text("ALTER TABLE courses ADD COLUMN certificate_author_position VARCHAR"))
                    conn.commit()
                    logger.info("Added certificate_author_position column to courses table (PostgreSQL)")

    except Exception as e:
        logger.error(f"Error adding missing columns: {e}")


def init_db():
    """Initialize database and create tables"""
    try:
        # Для PostgreSQL
        if DATABASE_URL.startswith('postgresql'):
            engine = create_engine(DATABASE_URL)
        else:
            # Для SQLite
            engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")

        # Add missing columns if they don't exist
        add_missing_columns(engine)

        # Sync admin status after creating tables
        sync_admin_status()

    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

def get_db_session_safe():
    """Get database session with fallback support"""
    from config import USE_FALLBACK_DATA

    if USE_FALLBACK_DATA or not test_database_connection():
        logger.info("Using fallback data mode")
        return None

    return SessionLocal()
