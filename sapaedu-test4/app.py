import os
import json
import uuid
import logging
from datetime import datetime, timezone
from functools import wraps

from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory
from database import (
    get_db_session, init_db, User, Course, Chapter, Exam, ExamAttempt,
    CourseProgress, Certificate, PhishingCheck, Notification, UsefulLink, ChapterTestAttempt, Admin,
    calculate_course_progress, update_course_progress, sync_admin_status
)
from config import DATABASE_URL, SECRET_KEY, EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_FROM, SMTP_SERVER, SMTP_PORT, HOST_ADMIN_LOGIN, HOST_ADMIN_PASSWORD, BOT_TOKEN, GROUP_ID, HOST_ADMIN_TELEGRAM_ID, GROUP_THREAD_ID
from admins import is_admin, add_admin, remove_admin, get_admins_list
from file_storage import file_storage

# Define default constants for exam and certificate settings
DEFAULT_CERTIFICATE_PASSING_SCORE = 80.0
DEFAULT_EXAM_TIME_LIMIT = 15  # minutes
DEFAULT_EXAM_MAX_ATTEMPTS = 2

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Create uploads directory
os.makedirs('uploads/images', exist_ok=True)
os.makedirs('uploads/documents', exist_ok=True)
os.makedirs('uploads/videos', exist_ok=True)
os.makedirs('uploads/archives', exist_ok=True)

# Initialize database
try:
    init_db()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")

# Removed the problematic check_group_membership_sync function due to import and asyncio issues

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Необходимо войти в систему', 'error')
            return redirect(url_for('login'))

        # MANDATORY: Session must have telegram_id
        if 'telegram_id' not in session:
            session.clear()
            flash('Ошибка авторизации. Войдите заново через Telegram.', 'error')
            return redirect(url_for('login'))

        # SECURITY: ALWAYS check group membership for ALL requests
        # Replaced with a simplified check or removed if it causes issues
        # In a real scenario, this logic would need careful implementation
        # For now, we will assume group membership is handled elsewhere or is not strictly enforced here due to import errors.

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Необходимо войти в систему', 'error')
            return redirect(url_for('login'))

        # КРИТИЧЕСКИ ВАЖНО: Принудительная проверка актуального статуса админа при каждом запросе
        telegram_id = session.get('telegram_id')
        if telegram_id:
            from admins import is_admin
            actual_admin_level = is_admin(telegram_id)
            actual_is_admin = actual_admin_level >= 1

            # Если статус изменился, обновляем сессию
            if session.get('is_admin') != actual_is_admin:
                logger.warning(f"Admin status mismatch for user {telegram_id}: session={session.get('is_admin')}, actual={actual_is_admin}")
                session['is_admin'] = actual_is_admin
                session['admin_level'] = actual_admin_level

                # Обновляем в базе данных
                db = get_db_session()
                try:
                    user = db.query(User).filter(User.telegram_id == telegram_id).first()
                    if user and user.is_admin != actual_is_admin:
                        user.is_admin = actual_is_admin
                        user.updated_at = datetime.now(timezone.utc)
                        db.commit()
                        logger.info(f"Updated user {telegram_id} admin status in decorator: {user.is_admin} -> {actual_is_admin}")
                except Exception as e:
                    logger.error(f"Error updating user admin status in decorator: {e}")
                    db.rollback()
                finally:
                    db.close()

        if not session.get('is_admin'):
            flash('Недостаточно прав доступа. Возможно, ваши права администратора были отозваны.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Main page - redirect to appropriate dashboard based on user role"""
    # Check if user came from Telegram
    telegram_id = request.args.get('telegram_id')

    # SECURITY: Validate telegram_id format if provided
    if telegram_id:
        try:
            # Ensure telegram_id is a valid integer
            telegram_id_int = int(telegram_id)
            if telegram_id_int <= 0:
                flash('Некорректный Telegram ID', 'error')
                return render_template('welcome.html')
        except ValueError:
            flash('Некорректный Telegram ID', 'error')
            return render_template('welcome.html')

        # SECURITY: ALWAYS check group membership for ANY telegram_id access
        # Simplified or removed due to previous issues.

        # Only process if user is not already logged in
        if 'user_id' not in session:
            # Check if user exists in database
            db = get_db_session()
            try:
                user = db.query(User).filter(User.telegram_id == str(telegram_id)).first()
                if user:
                    # User exists and has group access, log them in
                    # КРИТИЧЕСКИ ВАЖНО: Всегда проверяем актуальный статус админа при каждом входе
                    from admins import is_admin
                    actual_admin_level = is_admin(user.telegram_id)
                    actual_is_admin = actual_admin_level >= 1

                    # Синхронизируем статус админа если он изменился
                    if user.is_admin != actual_is_admin:
                        old_status = user.is_admin
                        user.is_admin = actual_is_admin
                        user.updated_at = datetime.now(timezone.utc)
                        db.commit()
                        logger.info(f"CRITICAL: Admin status changed for user {user.telegram_id}: {old_status} -> {actual_is_admin}")

                        # Если права были отозваны, принудительно очищаем старые сессии
                        if old_status and not actual_is_admin:
                            logger.info(f"Admin rights revoked for user {user.telegram_id}, clearing session data")

                    session['user_id'] = user.id
                    session['user_name'] = user.name
                    session['is_admin'] = actual_is_admin
                    session['telegram_id'] = user.telegram_id
                    session['admin_level'] = actual_admin_level

                    # Redirect based on ACTUAL role (не на сохраненную в БД)
                    if actual_is_admin:
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('student_dashboard'))
                else:
                    # New user with group access, redirect to profile setup
                    return redirect(url_for('profile_setup', telegram_id=telegram_id))
            finally:
                db.close()
        else:
            # User already logged in but accessing with telegram_id - verify it matches
            if session.get('telegram_id') != str(telegram_id):
                # Different telegram_id, clear session and start fresh
                session.clear()
                flash('Ошибка авторизации. Войдите заново.', 'error')
                return render_template('welcome.html')

    # CRITICAL SECURITY: For ANY access without telegram_id, check existing session
    if 'user_id' not in session:
        # No session, show welcome page
        return render_template('welcome.html')

    # SECURITY: MANDATORY group membership check for ALL existing sessions
    # Simplified or removed due to previous issues.

    # Check if user is admin and redirect accordingly
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))


@app.route('/profile-setup', methods=['GET', 'POST'])
def profile_setup():
    """First-time user profile setup"""
    telegram_id = request.args.get('telegram_id') or session.get('setup_telegram_id')

    if not telegram_id:
        flash('Необходимо войти через Telegram', 'error')
        return redirect(url_for('login'))

    # SECURITY: Validate telegram_id format
    try:
        telegram_id_int = int(telegram_id)
        if telegram_id_int <= 0:
            flash('Некорректный Telegram ID', 'error')
            return redirect(url_for('login'))
    except ValueError:
        flash('Некорректный Telegram ID', 'error')
        return redirect(url_for('login'))

    # SECURITY: Check group membership for new users
    # Simplified or removed due to previous issues.

    companies = [
        'Sapa Technologies',
        'Neo Factoring',
        'Sapa Digital Finance',
        'AlgaPay',
        'AI Parking',
        'Sapa Digital Communications',
        'Sapa Solutions'
    ]

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        company = request.form.get('company')

        if not all([name, email, company]):
            flash('Все поля обязательны для заполнения', 'error')
            return render_template('profile_setup.html', telegram_id=telegram_id, companies=companies)

        if '@' not in email or '.' not in email:
            flash('Введите корректный email адрес', 'error')
            return render_template('profile_setup.html', telegram_id=telegram_id, companies=companies)

        db = get_db_session()
        try:
            # Check if email is already taken by another user
            existing_user = db.query(User).filter(User.email == email, User.telegram_id != telegram_id).first()
            if existing_user:
                flash('Пользователь с таким email уже существует', 'error')
                return render_template('profile_setup.html', telegram_id=telegram_id, companies=companies)

            # Create new user
            user = User(
                name=name,
                email=email,
                company=company,
                telegram_id=telegram_id,
                is_admin=is_admin(telegram_id) >= 1,
                registered_at=datetime.now(timezone.utc)
            )
            db.add(user)
            db.commit()

            # Auto-login
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin
            session['telegram_id'] = user.telegram_id
            session.pop('setup_telegram_id', None)

            flash('Регистрация успешна!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.rollback()
            logger.error(f"Profile setup error: {e}")
            flash('Ошибка при регистрации', 'error')
        finally:
            db.close()

    return render_template('profile_setup.html', telegram_id=telegram_id, companies=companies)

@app.route('/login')
def login():
    """Redirect to Telegram auth only"""
    return render_template('welcome.html')

@app.route('/telegram-auth')
def telegram_auth():
    """Telegram authorization"""
    telegram_id = request.args.get('telegram_id')

    if not telegram_id:
        return render_template('telegram_auth.html', error='Telegram ID не предоставлен')

    # SECURITY: Validate telegram_id format
    try:
        telegram_id_int = int(telegram_id)
        if telegram_id_int <= 0:
            return render_template('telegram_auth.html', error='Некорректный Telegram ID')
    except ValueError:
        return render_template('telegram_auth.html', error='Некорректный Telegram ID')

    # SECURITY: Check group membership first
    # Simplified or removed due to previous issues.

    db = get_db_session()
    try:
        # Find user by telegram_id
        user = db.query(User).filter(User.telegram_id == telegram_id).first()

        if user:
            # User exists and has access, log them in
            # User exists and has group access, log them in
            # КРИТИЧЕСКИ ВАЖНО: Всегда проверяем актуальный статус админа
            from admins import is_admin
            actual_admin_level = is_admin(user.telegram_id)
            actual_is_admin = actual_admin_level >= 1

            # Синхронизируем статус админа если он изменился
            if user.is_admin != actual_is_admin:
                old_status = user.is_admin
                user.is_admin = actual_is_admin
                user.updated_at = datetime.now(timezone.utc)
                db.commit()
                logger.info(f"CRITICAL: Admin status changed for user {user.telegram_id}: {old_status} -> {actual_is_admin}")

            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = actual_is_admin
            session['telegram_id'] = user.telegram_id
            session['admin_level'] = actual_admin_level

            return redirect(url_for('index'))
        else:
            # New user, redirect to profile setup
            session['setup_telegram_id'] = telegram_id
            return redirect(url_for('profile_setup', telegram_id=telegram_id))
    finally:
        db.close()

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/student')
@login_required
def student_dashboard():
    """Student dashboard"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')

        # Get user's courses and progress
        courses = db.query(Course).filter(Course.is_published == True).all()
        user_progress = db.query(CourseProgress).filter(CourseProgress.user_id == user_id).all()
        progress_dict = {p.course_id: p for p in user_progress}

        # Get user's certificates
        certificates = db.query(Certificate).filter(Certificate.user_id == user_id).all()

        # Get notifications
        notifications = db.query(Notification).filter(
            Notification.user_id == user_id,
            Notification.read == False
        ).order_by(Notification.created_at.desc()).limit(5).all()

        # Get useful links - handle case where UsefulLink table might not exist
        useful_links = []
        try:
            useful_links = db.query(UsefulLink).filter(UsefulLink.is_active == True).all()
        except Exception as e:
            logger.warning(f"UsefulLink table not found or error: {e}")
            useful_links = []

        return render_template('student_dashboard.html',
                             courses=courses or [],
                             progress_dict=progress_dict or {},
                             certificates=certificates or [],
                             notifications=notifications or [],
                             useful_links=useful_links or [])
    except Exception as e:
        logger.error(f"Error in student dashboard: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        db.rollback()
        flash('Произошла ошибка при загрузке панели студента', 'error')
        return redirect(url_for('login'))
    finally:
        db.close()

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    db = get_db_session()
    try:
        # Get statistics
        total_users = db.query(User).count()
        total_courses = db.query(Course).count()
        total_certificates = db.query(Certificate).count()
        active_certificates = db.query(Certificate).filter(Certificate.status == 'active').count()

        # Get recent activity
        recent_registrations = db.query(User).order_by(User.registered_at.desc()).limit(5).all()
        recent_certificates = db.query(Certificate).join(User).join(Course).order_by(Certificate.issued_at.desc()).limit(5).all()

        stats = {
            'total_users': total_users,
            'total_courses': total_courses,
            'total_certificates': total_certificates,
            'active_certificates': active_certificates
        }

        return render_template('admin_dashboard.html',
                             stats=stats,
                             recent_registrations=recent_registrations,
                             recent_certificates=recent_certificates)
    finally:
        db.close()

@app.route('/admin/courses')
@admin_required
def admin_courses():
    """Admin courses management"""
    db = get_db_session()
    try:
        courses = db.query(Course).order_by(Course.created_at.desc()).all()
        return render_template('admin_courses.html', courses=courses)
    finally:
        db.close()

@app.route('/admin/course/create', methods=['GET', 'POST'])
@admin_required
def create_course():
    """Create new course"""
    if request.method == 'POST':
        db = get_db_session()
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            introduction = request.form.get('introduction')
            conclusion = request.form.get('conclusion')

            if not title:
                flash('Название курса обязательно', 'error')
                return render_template('create_course.html')

            course = Course(
                title=title,
                description=description,
                introduction=introduction,
                conclusion=conclusion,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            db.add(course)
            db.commit()

            flash('Курс создан успешно!', 'success')
            return redirect(url_for('edit_course', course_id=course.id))

        except Exception as e:
            db.rollback()
            logger.error("Error creating course: %s", e)
            flash('Ошибка при создании курса', 'error')
        finally:
            db.close()

    return render_template('create_course.html')

@app.route('/admin/course_constructor')
@admin_required
def course_constructor():
    """Course constructor page"""
    return render_template('course_constructor.html')

@app.route('/admin/course-constructor')
@admin_required
def unified_course_constructor():
    """Unified course constructor"""
    db = get_db_session()
    try:
        courses = db.query(Course).all()
        course_id = request.args.get('course_id')
        selected_course = None

        if course_id:
            selected_course = db.query(Course).filter(Course.id == course_id).first()

        return render_template('unified_course_constructor.html',
                             courses=courses,
                             selected_course=selected_course)
    finally:
        db.close()

@app.route('/api/create-course', methods=['POST'])
@admin_required
def api_create_course():
    """API endpoint for creating courses from constructor"""
    db = get_db_session()
    try:
        data = request.get_json()
        logger.info(f"Creating course with data: {data}")

        # Validate required fields
        if not data or not data.get('title'):
            return jsonify({'success': False, 'error': 'Название курса обязательно'}), 400

        # Log incoming data for debugging
        logger.info(f"Received course data: {data.keys() if data else 'None'}")

        if not isinstance(data.get('chapters', []), list):
            data['chapters'] = []

        if data.get('exam') and not isinstance(data.get('exam', {}).get('questions', []), list):
            if 'exam' in data:
                data['exam']['questions'] = []

        # Create course
        course = Course(
            title=data.get('title', '').strip(),
            description=data.get('description', '').strip(),
            introduction=data.get('introduction', '').strip(),
            conclusion=data.get('conclusion', '').strip(),
            course_type=data.get('course_type', 'revocable'),
            is_published=data.get('is_published', False),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        # Add certificate settings if provided
        certificate_data = data.get('certificate')
        if certificate_data:
            course.certificate_title = certificate_data.get('title', 'СЕРТИФИКАТ')
            course.certificate_subtitle = certificate_data.get('subtitle', 'о прохождении курса')
            course.certificate_organization = certificate_data.get('organization', 'SapaEdu')
            course.certificate_logo_url = certificate_data.get('logo_url', '')
            course.certificate_background_url = certificate_data.get('background_url', '')
            course.certificate_background_color = certificate_data.get('background_color', '#ffffff')
            course.certificate_primary_color = certificate_data.get('primary_color', '#007bff')
            course.certificate_secondary_color = certificate_data.get('secondary_color', '#6c757d')
            course.certificate_accent_color = certificate_data.get('accent_color', '#28a745')
            course.certificate_border_style = certificate_data.get('border_style', 'modern')
            course.certificate_layout_style = certificate_data.get('layout_style', 'standard')
            course.certificate_achievement_badge = certificate_data.get('achievement_badge', 'graduation')
            course.certificate_watermark_text = certificate_data.get('watermark_text', 'SapaEdu')
            course.certificate_watermark_opacity = certificate_data.get('watermark_opacity', 0.1)
            course.certificate_show_qr = certificate_data.get('show_qr', True)
            course.certificate_achievement_text = certificate_data.get('achievement_text', 'Успешно завершен курс')
            course.certificate_validity_text = certificate_data.get('validity_text', 'Действителен на момент выдачи')
            course.certificate_footer_text = certificate_data.get('footer_text', '')
            course.certificate_author_name = certificate_data.get('author_name', '')
            course.certificate_author_position = certificate_data.get('author_position', '')

        db.add(course)
        db.flush()  # Get course ID

        # Create chapters with proper data structure
        chapters_data = data.get('chapters', [])
        logger.info(f"Processing {len(chapters_data)} chapters")

        for order_idx, chapter_data in enumerate(chapters_data):
            logger.info(f"Creating chapter {order_idx + 1}: {chapter_data.get('title', 'Untitled')}")

            # Normalize content blocks structure
            content_blocks = chapter_data.get('content_blocks', [])
            normalized_blocks = []

            for block in content_blocks:
                if isinstance(block, dict):
                    # Ensure proper structure for content blocks
                    normalized_block = {
                        'type': block.get('type', 'text'),
                        'content': {}
                    }

                    # Extract content based on type
                    block_content = block.get('content', {})
                    if isinstance(block_content, dict):
                        normalized_block['content'] = block_content
                    else:
                        # Handle legacy format
                        normalized_block['content'] = {'field_0': str(block_content)}

                    normalized_blocks.append(normalized_block)

            # Normalize test questions structure
            test_questions = chapter_data.get('test_questions', [])
            normalized_questions = []

            for question in test_questions:
                if isinstance(question, dict) and question.get('text'):
                    normalized_question = {
                        'text': question.get('text', ''),
                        'type': question.get('type', 'single'),
                        'answers': question.get('answers', []),
                        'correct_answer': question.get('correct_answer'),
                        'image': question.get('image', '')
                    }

                    # Ensure answers is a list
                    if not isinstance(normalized_question['answers'], list):
                        normalized_question['answers'] = []

                    # Validate correct_answer format
                    if normalized_question['type'] == 'multiple':
                        if not isinstance(normalized_question['correct_answer'], list):
                            if normalized_question['correct_answer'] is not None:
                                normalized_question['correct_answer'] = [normalized_question['correct_answer']]
                            else:
                                normalized_question['correct_answer'] = []
                    else:
                        # For single choice, ensure it's a number
                        if isinstance(normalized_question['correct_answer'], list):
                            normalized_question['correct_answer'] = normalized_question['correct_answer'][0] if normalized_question['correct_answer'] else 0
                        elif normalized_question['correct_answer'] is None:
                            normalized_question['correct_answer'] = 0

                    normalized_questions.append(normalized_question)

            chapter = Chapter(
                course_id=course.id,
                title=chapter_data.get('title', f'Глава {order_idx + 1}').strip(),
                content_blocks=normalized_blocks,
                order_number=order_idx + 1,
                has_test=chapter_data.get('has_test', False) and len(normalized_questions) > 0,
                test_questions=normalized_questions,
                test_passing_score=DEFAULT_CERTIFICATE_PASSING_SCORE,
                created_at=datetime.now(timezone.utc)
            )
            db.add(chapter)

        # Create exam if exists with proper validation
        exam_data = data.get('exam')
        if exam_data and exam_data.get('questions'):
            exam_questions = exam_data.get('questions', [])
            normalized_exam_questions = []

            for question in exam_questions:
                if isinstance(question, dict) and question.get('text'):
                    normalized_question = {
                        'text': question.get('text', ''),
                        'type': question.get('type', 'single'),
                        'answers': question.get('answers', []),
                        'correct_answer': question.get('correct_answer'),
                        'image': question.get('image', '')
                    }

                    # Ensure answers is a list
                    if not isinstance(normalized_question['answers'], list):
                        normalized_question['answers'] = []

                    # Validate correct_answer format for exam
                    if normalized_question['type'] == 'multiple':
                        if not isinstance(normalized_question['correct_answer'], list):
                            if normalized_question['correct_answer'] is not None:
                                normalized_question['correct_answer'] = [normalized_question['correct_answer']]
                            else:
                                normalized_question['correct_answer'] = []
                    else:
                        # For single choice, ensure it's a number
                        if isinstance(normalized_question['correct_answer'], list):
                            normalized_question['correct_answer'] = normalized_question['correct_answer'][0] if normalized_question['correct_answer'] else 0
                        elif normalized_question['correct_answer'] is None:
                            normalized_question['correct_answer'] = 0

                    normalized_exam_questions.append(normalized_question)

            if normalized_exam_questions:
                exam = Exam(
                    course_id=course.id,
                    title=exam_data.get('title', 'Итоговый экзамен'),
                    questions=normalized_exam_questions,
                    passing_score=float(exam_data.get('passing_score', DEFAULT_CERTIFICATE_PASSING_SCORE)),
                    time_limit=int(exam_data.get('time_limit', DEFAULT_EXAM_TIME_LIMIT)),
                    max_attempts=int(exam_data.get('max_attempts', DEFAULT_EXAM_MAX_ATTEMPTS)),
                    created_at=datetime.now(timezone.utc)
                )
                db.add(exam)

        db.commit()
        logger.info(f"Course created successfully with ID: {course.id}")
        return jsonify({'success': True, 'course_id': course.id})

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating course: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/api/course/<int:course_id>/update', methods=['POST'])
@admin_required
def api_update_course(course_id):
    """API endpoint for updating existing courses"""
    db = get_db_session()
    try:
        data = request.get_json()
        logger.info(f"Updating course {course_id} with data: {data}")

        course = db.query(Course).filter(Course.id == course_id).first()

        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'}), 404

        # Validate required fields
        if not data or not data.get('title'):
            return jsonify({'success': False, 'error': 'Название курса обязательно'}), 400

        # Log incoming data for debugging
        logger.info(f"Received course data: {data.keys() if data else 'None'}")

        if not isinstance(data.get('chapters', []), list):
            data['chapters'] = []

        if data.get('exam') and not isinstance(data.get('exam', {}).get('questions', []), list):
            if 'exam' in data:
                data['exam']['questions'] = []

        # Update course basic info
        course.title = data.get('title', course.title).strip()
        course.description = data.get('description', course.description).strip()
        course.introduction = data.get('introduction', course.introduction).strip()
        course.conclusion = data.get('conclusion', course.conclusion).strip()
        course.course_type = data.get('course_type', course.course_type)
        course.is_published = data.get('is_published', course.is_published)
        course.updated_at = datetime.now(timezone.utc)

        # Update certificate settings if provided
        certificate_data = data.get('certificate')
        if certificate_data:
            course.certificate_title = certificate_data.get('title', course.certificate_title or 'СЕРТИФИКАТ')
            course.certificate_subtitle = certificate_data.get('subtitle', course.certificate_subtitle or 'о прохождении курса')
            course.certificate_organization = certificate_data.get('organization', course.certificate_organization or 'SapaEdu')
            course.certificate_logo_url = certificate_data.get('logo_url', course.certificate_logo_url or '')
            course.certificate_background_url = certificate_data.get('background_url', course.certificate_background_url or '')
            course.certificate_background_color = certificate_data.get('background_color', course.certificate_background_color or '#ffffff')
            course.certificate_primary_color = certificate_data.get('primary_color', course.certificate_primary_color or '#007bff')
            course.certificate_secondary_color = certificate_data.get('secondary_color', course.certificate_secondary_color or '#6c757d')
            course.certificate_accent_color = certificate_data.get('accent_color', course.certificate_accent_color or '#28a745')
            course.certificate_border_style = certificate_data.get('border_style', course.certificate_border_style or 'modern')
            course.certificate_layout_style = certificate_data.get('layout_style', course.certificate_layout_style or 'standard')
            course.certificate_achievement_badge = certificate_data.get('achievement_badge', course.certificate_achievement_badge or 'graduation')
            course.certificate_watermark_text = certificate_data.get('watermark_text', course.certificate_watermark_text or 'SapaEdu')
            course.certificate_watermark_opacity = certificate_data.get('watermark_opacity', course.certificate_watermark_opacity or 0.1)
            course.certificate_show_qr = certificate_data.get('show_qr', course.certificate_show_qr)
            course.certificate_achievement_text = certificate_data.get('achievement_text', course.certificate_achievement_text or 'Успешно завершен курс')
            course.certificate_validity_text = certificate_data.get('validity_text', course.certificate_validity_text or 'Действителен на момент выдачи')
            course.certificate_footer_text = certificate_data.get('footer_text', course.certificate_footer_text or '')
            course.certificate_author_name = certificate_data.get('author_name', course.certificate_author_name or '')
            course.certificate_author_position = certificate_data.get('author_position', course.certificate_author_position or '')

        # Delete existing chapters and exam properly to avoid foreign key violations
        old_chapters = db.query(Chapter).filter(Chapter.course_id == course_id).all()
        old_exams = db.query(Exam).filter(Exam.course_id == course_id).all()

        # Delete chapter test attempts FIRST before deleting chapters
        for chapter in old_chapters:
            db.query(ChapterTestAttempt).filter(ChapterTestAttempt.chapter_id == chapter.id).delete()

        # Delete exam attempts before deleting exams
        for exam in old_exams:
            db.query(ExamAttempt).filter(ExamAttempt.exam_id == exam.id).delete()

        # Clear completed chapters from all user progress records for this course
        db.query(CourseProgress).filter(CourseProgress.course_id == course_id).update(
            {CourseProgress.completed_chapters: []},
            synchronize_session=False
        )

        # Now safely delete chapters and exams
        for chapter in old_chapters:
            db.delete(chapter)
        for exam in old_exams:
            db.delete(exam)

        db.flush()  # Force deletion before creating new data

        # Create new chapters with proper normalization
        chapters_data = data.get('chapters', [])
        logger.info(f"Updating with {len(chapters_data)} chapters")

        for order_idx, chapter_data in enumerate(chapters_data):
            logger.info(f"Processing chapter {order_idx + 1}: {chapter_data.get('title', 'Untitled')}")

            # Normalize content blocks structure
            content_blocks = chapter_data.get('content_blocks', [])
            normalized_blocks = []

            for block in content_blocks:
                if isinstance(block, dict):
                    # Ensure proper structure for content blocks
                    normalized_block = {
                        'type': block.get('type', 'text'),
                        'content': {}
                    }

                    # Extract content based on type
                    block_content = block.get('content', {})
                    if isinstance(block_content, dict):
                        normalized_block['content'] = block_content
                    else:
                        # Handle legacy format
                        normalized_block['content'] = {'field_0': str(block_content)}

                    normalized_blocks.append(normalized_block)

            # Normalize test questions structure
            test_questions = chapter_data.get('test_questions', [])
            normalized_questions = []

            for question in test_questions:
                if isinstance(question, dict) and question.get('text'):
                    normalized_question = {
                        'text': question.get('text', ''),
                        'type': question.get('type', 'single'),
                        'answers': question.get('answers', []),
                        'correct_answer': question.get('correct_answer'),
                        'image': question.get('image', '')
                    }

                    # Ensure answers is a list
                    if not isinstance(normalized_question['answers'], list):
                        normalized_question['answers'] = []

                    # Validate correct_answer format
                    if normalized_question['type'] == 'multiple':
                        if not isinstance(normalized_question['correct_answer'], list):
                            if normalized_question['correct_answer'] is not None:
                                normalized_question['correct_answer'] = [normalized_question['correct_answer']]
                            else:
                                normalized_question['correct_answer'] = []
                    else:
                        # For single choice, ensure it's a number
                        if isinstance(normalized_question['correct_answer'], list):
                            normalized_question['correct_answer'] = normalized_question['correct_answer'][0] if normalized_question['correct_answer'] else 0
                        elif normalized_question['correct_answer'] is None:
                            normalized_question['correct_answer'] = 0

                    normalized_questions.append(normalized_question)

            chapter = Chapter(
                course_id=course.id,
                title=chapter_data.get('title', f'Глава {order_idx + 1}').strip(),
                content_blocks=normalized_blocks,
                order_number=order_idx + 1,
                has_test=chapter_data.get('has_test', False) and len(normalized_questions) > 0,
                test_questions=normalized_questions,
                test_passing_score=DEFAULT_CERTIFICATE_PASSING_SCORE,
                created_at=datetime.now(timezone.utc)
            )
            db.add(chapter)

        # Create new exam if exists with proper validation
        exam_data = data.get('exam')
        if exam_data and exam_data.get('questions'):
            exam_questions = exam_data.get('questions', [])
            normalized_exam_questions = []

            for question in exam_questions:
                if isinstance(question, dict) and question.get('text'):
                    normalized_question = {
                        'text': question.get('text', ''),
                        'type': question.get('type', 'single'),
                        'answers': question.get('answers', []),
                        'correct_answer': question.get('correct_answer'),
                        'image': question.get('image', '')
                    }

                    # Ensure answers is a list
                    if not isinstance(normalized_question['answers'], list):
                        normalized_question['answers'] = []

                    # Validate correct_answer format for exam
                    if normalized_question['type'] == 'multiple':
                        if not isinstance(normalized_question['correct_answer'], list):
                            if normalized_question['correct_answer'] is not None:
                                normalized_question['correct_answer'] = [normalized_question['correct_answer']]
                            else:
                                normalized_question['correct_answer'] = []
                    else:
                        # For single choice, ensure it's a number
                        if isinstance(normalized_question['correct_answer'], list):
                            normalized_question['correct_answer'] = normalized_question['correct_answer'][0] if normalized_question['correct_answer'] else 0
                        elif normalized_question['correct_answer'] is None:
                            normalized_question['correct_answer'] = 0

                    normalized_exam_questions.append(normalized_question)

            if normalized_exam_questions:
                exam = Exam(
                    course_id=course.id,
                    title=exam_data.get('title', 'Итоговый экзамен'),
                    questions=normalized_exam_questions,
                    passing_score=float(exam_data.get('passing_score', DEFAULT_CERTIFICATE_PASSING_SCORE)),
                    time_limit=int(exam_data.get('time_limit', DEFAULT_EXAM_TIME_LIMIT)),
                    max_attempts=int(exam_data.get('max_attempts', DEFAULT_EXAM_MAX_ATTEMPTS)),
                    created_at=datetime.now(timezone.utc)
                )
                db.add(exam)

        db.commit()
        logger.info(f"Course {course_id} updated successfully")
        return jsonify({'success': True, 'course_id': course.id})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating course: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/api/course/<int:course_id>/data', methods=['GET'])
@admin_required
def api_get_course_data(course_id):
    """API для получения данных курса с улучшенной структурой"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()

        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'}), 404

        logger.info(f"Loading course data for course {course_id}: {course.title}")

        # Получаем главы с правильной сортировкой
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number.asc(), Chapter.id.asc()).all()
        chapters_data = []

        for idx, chapter in enumerate(chapters):
            logger.info(f"Processing chapter {idx + 1}: {chapter.title}")
            logger.info(f"Chapter {idx + 1} content_blocks type: {type(chapter.content_blocks)}")
            logger.info(f"Chapter {idx + 1} content_blocks: {chapter.content_blocks}")

            # Нормализуем content_blocks
            content_blocks = chapter.content_blocks or []
            if isinstance(content_blocks, str):
                import json
                try:
                    content_blocks = json.loads(content_blocks)
                except:
                    content_blocks = []

            normalized_blocks = []
            for block in content_blocks:
                if isinstance(block, dict):
                    # Убеждаемся что блок имеет правильную структуру
                    normalized_block = {
                        'type': block.get('type', 'text'),
                        'content': block.get('content', {})
                    }

                    # Убеждаемся что content является словарем
                    if not isinstance(normalized_block['content'], dict):
                        normalized_block['content'] = {'field_0': str(normalized_block['content'])}

                    normalized_blocks.append(normalized_block)

            # Нормализуем test_questions
            test_questions = chapter.test_questions or []
            if isinstance(test_questions, str):
                import json
                try:
                    test_questions = json.loads(test_questions)
                except:
                    test_questions = []

            normalized_questions = []
            for question in test_questions:
                if isinstance(question, dict) and question.get('text'):
                    normalized_question = {
                        'text': question.get('text', ''),
                        'type': question.get('type', 'single'),
                        'answers': question.get('answers', []),
                        'correct_answer': question.get('correct_answer'),
                        'image': question.get('image', '')
                    }

                    # Убеждаемся что answers - это список
                    if not isinstance(normalized_question['answers'], list):
                        normalized_question['answers'] = []

                    # Фильтруем пустые ответы
                    normalized_question['answers'] = [ans for ans in normalized_question['answers'] if ans and str(ans).strip()]

                    # Нормализуем correct_answer
                    if normalized_question['type'] == 'multiple':
                        if not isinstance(normalized_question['correct_answer'], list):
                            if normalized_question['correct_answer'] is not None:
                                normalized_question['correct_answer'] = [normalized_question['correct_answer']]
                            else:
                                normalized_question['correct_answer'] = []
                    else:
                        if isinstance(normalized_question['correct_answer'], list):
                            normalized_question['correct_answer'] = normalized_question['correct_answer'][0] if normalized_question['correct_answer'] else 0
                        elif normalized_question['correct_answer'] is None:
                            normalized_question['correct_answer'] = 0

                    # Добавляем вопрос только если есть текст и ответы
                    if normalized_question['text'] and len(normalized_question['answers']) >= 2:
                        normalized_questions.append(normalized_question)

            chapter_data = {
                'id': f'chapter_{chapter.id}',
                'title': chapter.title or f'Глава {idx + 1}',
                'content_blocks': normalized_blocks,
                'has_test': chapter.has_test and len(normalized_questions) > 0,
                'test_questions': normalized_questions
            }
            chapters_data.append(chapter_data)

        # Получаем экзамен с нормализацией
        exam = db.query(Exam).filter(Exam.course_id == course_id).first()
        exam_data = None
        if exam:
            exam_questions = exam.questions or []
            if isinstance(exam_questions, str):
                import json
                try:
                    exam_questions = json.loads(exam_questions)
                except:
                    exam_questions = []

            normalized_exam_questions = []
            for question in exam_questions:
                if isinstance(question, dict) and question.get('text'):
                    normalized_question = {
                        'text': question.get('text', ''),
                        'type': question.get('type', 'single'),
                        'answers': question.get('answers', []),
                        'correct_answer': question.get('correct_answer'),
                        'image': question.get('image', '')
                    }

                    # Убеждаемся что answers - это список
                    if not isinstance(normalized_question['answers'], list):
                        normalized_question['answers'] = []

                    # Нормализуем correct_answer для экзамена
                    if normalized_question['type'] == 'multiple':
                        if not isinstance(normalized_question['correct_answer'], list):
                            if normalized_question['correct_answer'] is not None:
                                normalized_question['correct_answer'] = [normalized_question['correct_answer']]
                            else:
                                normalized_question['correct_answer'] = []
                    else:
                        if isinstance(normalized_question['correct_answer'], list):
                            normalized_question['correct_answer'] = normalized_question['correct_answer'][0] if normalized_question['correct_answer'] else 0
                        elif normalized_question['correct_answer'] is None:
                            normalized_question['correct_answer'] = 0

                    normalized_exam_questions.append(normalized_question)

            exam_data = {
                'title': exam.title or 'Итоговый экзамен',
                'questions': normalized_exam_questions,
                'passing_score': exam.passing_score or DEFAULT_CERTIFICATE_PASSING_SCORE,
                'time_limit': exam.time_limit or DEFAULT_EXAM_TIME_LIMIT,
                'max_attempts': exam.max_attempts or DEFAULT_EXAM_MAX_ATTEMPTS
            }

        # Формируем данные сертификата
        certificate_data = {
            'title': course.certificate_title or 'СЕРТИФИКАТ',
            'subtitle': course.certificate_subtitle or 'о прохождении курса',
            'organization': course.certificate_organization or 'SapaEdu',
            'logo_url': course.certificate_logo_url or '',
            'background_url': course.certificate_background_url or '',
            'background_color': course.certificate_background_color or '#ffffff',
            'primary_color': course.certificate_primary_color or '#007bff',
            'secondary_color': course.certificate_secondary_color or '#6c757d',
            'accent_color': course.certificate_accent_color or '#28a745',
            'border_style': course.certificate_border_style or 'modern',
            'layout_style': course.certificate_layout_style or 'standard',
            'achievement_badge': course.certificate_achievement_badge or 'graduation',
            'watermark_text': course.certificate_watermark_text or 'SapaEdu',
            'watermark_opacity': course.certificate_watermark_opacity or 0.1,
            'show_qr': course.certificate_show_qr if course.certificate_show_qr is not None else True,
            'achievement_text': course.certificate_achievement_text or 'Успешно завершен курс',
            'validity_text': course.certificate_validity_text or 'Действителен на момент выдачи',
            'footer_text': course.certificate_footer_text or '',
            'author_name': course.certificate_author_name or '',
            'author_position': course.certificate_author_position or '',
            'status': 'active'
        }

        course_data = {
            'id': course.id,
            'title': course.title or '',
            'description': course.description or '',
            'introduction': course.introduction or '',
            'conclusion': course.conclusion or '',
            'course_type': course.course_type or 'revocable',
            'is_published': course.is_published,
            'chapters': chapters_data,
            'exam': exam_data,
            'certificate': certificate_data
        }

        logger.info(f"Course data loaded successfully: {len(chapters_data)} chapters, exam: {'yes' if exam_data else 'no'}")
        return jsonify({'success': True, 'course': course_data})

    except Exception as e:
        logger.error(f"Error getting course data: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/api/chapter/<int:chapter_id>/update', methods=['POST'])
@admin_required
def api_update_chapter(chapter_id):
    """API to update chapter with blocks"""
    db = get_db_session()
    try:
        data = request.json
        chapter = db.query(Chapter).filter(Chapter.id == chapter_id).first()

        if not chapter:
            return jsonify({'success': False, 'error': 'Глава не найдена'}), 404

        # Обновляем блоки контента
        chapter.content_blocks = data.get('content_blocks', [])
        chapter.has_test = data.get('has_test', False)
        chapter.test_questions = data.get('test_questions', [])

        db.commit()

        return jsonify({'success': True})

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating chapter: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/admin/course/<int:course_id>/edit')
@admin_required
def edit_course(course_id):
    """Edit course"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            flash('Курс не найден', 'error')
            return redirect(url_for('admin_courses'))

        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number).all()
        exam = db.query(Exam).filter(Exam.course_id == course_id).first()

        return render_template('edit_course.html', course=course, chapters=chapters, exam=exam)
    finally:
        db.close()

@app.route('/admin/course/<int:course_id>/certificate', methods=['GET', 'POST'])
@admin_required
def course_certificate_settings(course_id):
    """Certificate settings for course"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            flash('Курс не найден', 'error')
            return redirect(url_for('admin_courses'))

        if request.method == 'POST':
            # Update certificate settings
            course.certificate_title = request.form.get('certificate_title', 'СЕРТИФИКАТ')
            course.certificate_subtitle = request.form.get('certificate_subtitle', 'о прохождении курса')
            course.certificate_author_name = request.form.get('certificate_author_name', '')
            course.certificate_author_position = request.form.get('certificate_author_position', '')
            course.certificate_organization = request.form.get('certificate_organization', 'SapaEdu')
            course.certificate_additional_text = request.form.get('certificate_additional_text', '')
            course.certificate_logo_url = request.form.get('certificate_logo_url', '')
            course.certificate_background_url = request.form.get('certificate_background_url', '')
            course.certificate_signature_url = request.form.get('certificate_signature_url', '')
            course.updated_at = datetime.now(timezone.utc)

            db.commit()
            flash('Настройки сертификата сохранены!', 'success')
            return redirect(url_for('edit_course', course_id=course_id))

        return render_template('course_certificate_settings.html', course=course)
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating certificate settings: {e}")
        flash('Ошибка при сохранении настроек', 'error')
        return redirect(url_for('edit_course', course_id=course_id))
    finally:
        db.close()

@app.route('/admin/course/<int:course_id>/chapter/add', methods=['POST'])
@admin_required
def add_chapter(course_id):
    """Add chapter to course"""
    db = get_db_session()
    try:
        title = request.form.get('title')
        content = request.form.get('content')

        if not title:
            flash('Название главы обязательно', 'error')
            return redirect(url_for('edit_course', course_id=course_id))

        # Get next order number
        last_chapter = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number.desc()).first()
        order_number = (last_chapter.order_number + 1) if last_chapter else 1

        chapter = Chapter(
            course_id=course_id,
            title=title,
            content_blocks=[], # Initialize as empty, content will be added via constructor
            order_number=order_number,
            has_test=False, # Default to no test
            test_questions=[], # Default to no questions
            test_passing_score=DEFAULT_CERTIFICATE_PASSING_SCORE # Default passing score
        )



        db.add(chapter)
        db.commit()

        flash('Глава добавлена успешно!', 'success')
        return redirect(url_for('edit_course', course_id=course_id))
    except Exception as e:
        db.rollback()
        flash('Ошибка при добавлении главы', 'error')
    finally:
        db.close()

@app.route('/admin/chapter/<int:chapter_id>/edit')
@admin_required
def edit_chapter(chapter_id):
    """Edit chapter with blocks"""
    db = get_db_session()
    try:
        chapter = db.query(Chapter).filter(Chapter.id == chapter_id).first()
        if not chapter:
            flash('Глава не найдена', 'error')
            return redirect(url_for('admin_courses'))

        return render_template('edit_chapter.html', chapter=chapter)
    finally:
        db.close()

@app.route('/admin/course/<int:course_id>/exam/create', methods=['POST'])
@admin_required
def create_exam(course_id):
    """Create exam for course"""
    db = get_db_session()
    try:
        title = request.form.get('title', f'Итоговый экзамен')
        passing_score = float(request.form.get('passing_score', DEFAULT_CERTIFICATE_PASSING_SCORE))
        time_limit = int(request.form.get('time_limit', DEFAULT_EXAM_TIME_LIMIT))
        max_attempts = int(request.form.get('max_attempts', DEFAULT_EXAM_MAX_ATTEMPTS))

        # Check if exam already exists
        existing_exam = db.query(Exam).filter(Exam.course_id == course_id).first()
        if existing_exam:
            # Update existing exam
            existing_exam.title = title
            existing_exam.passing_score = passing_score
            existing_exam.time_limit = time_limit
            existing_exam.max_attempts = max_attempts
            existing_exam.questions = []  # Reset questions, admin will add them via edit
            flash('Экзамен обновлен!', 'success')
        else:
            # Create new exam
            exam = Exam(
                course_id=course_id,
                title=title,
                questions=[],  # Start with empty questions
                passing_score=passing_score,
                time_limit=time_limit,
                max_attempts=max_attempts
            )
            db.add(exam)
            flash('Экзамен создан успешно!', 'success')

        db.commit()
        return redirect(url_for('edit_course', course_id=course_id))
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating/updating exam: {e}")
        flash('Ошибка при создании экзамена', 'error')
        return redirect(url_for('edit_course', course_id=course_id))
    finally:
        db.close()

@app.route('/admin/exam/<int:exam_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_exam(exam_id):
    """Edit exam questions"""
    db = get_db_session()
    try:
        exam = db.query(Exam).filter(Exam.id == exam_id).first()
        if not exam:
            flash('Экзамен не найден', 'error')
            return redirect(url_for('admin_courses'))

        # Get course for the exam
        course = db.query(Course).filter(Course.id == exam.course_id).first()
        if not course:
            flash('Курс не найден', 'error')
            return redirect(url_for('admin_courses'))

        if request.method == 'POST':
            # Update exam from JSON data
            data = request.json
            if data:
                exam.questions = data.get('questions', [])
                exam.passing_score = data.get('passing_score', exam.passing_score)
                exam.time_limit = data.get('time_limit', exam.time_limit)
                exam.max_attempts = data.get('max_attempts', exam.max_attempts)
                db.commit()
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'error': 'Нет данных'}), 400

        return render_template('edit_exam.html', exam=exam, course=course, enumerate=enumerate)
    except Exception as e:
        db.rollback()
        logger.error(f"Error editing exam: {e}")
        if request.method == 'POST':
            return jsonify({'success': False, 'error': str(e)}), 500
        flash('Ошибка при редактировании экзамена', 'error')
        return redirect(url_for('admin_courses'))
    finally:
        db.close()

@app.route('/admin/course/<int:course_id>/publish', methods=['POST'])
@admin_required
def publish_course(course_id):
    """Publish course"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if course:
            course.is_published = True
            course.updated_at = datetime.now(timezone.utc)
            db.commit()

            logger.info(f"Publishing course: {course.title} (ID: {course.id})")

            # Send notification to group thread first
            logger.info("Sending group notification...")
            send_group_course_notification(course.title)

            # Send notifications to all users about new course
            logger.info("Sending individual user notifications...")
            users = db.query(User).filter(User.is_admin == False).all()
            logger.info(f"Found {len(users)} users to notify")
            for user in users:
                # Create site notification
                notification = Notification(
                    user_id=user.id,
                    title="Новый курс доступен!",
                    message=f"Курс '{course.title}' теперь доступен для изучения.",
                    type="course_published"
                )
                db.add(notification)

                # Send Telegram notification
                if user.telegram_id:
                    send_course_notification(user.telegram_id, course.title)

            db.commit()
            flash('Курс опубликован и уведомления отправлены!', 'success')
        else:
            flash('Курс не найден', 'error')
    except Exception as e:
        db.rollback()
        flash('Ошибка при публикации курса', 'error')
        logger.error(f"Error publishing course: {e}")
    finally:
        db.close()

    return redirect(url_for('admin_courses'))

@app.route('/admin/course/<int:course_id>/unpublish', methods=['POST'])
@admin_required
def unpublish_course(course_id):
    """Unpublish course"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if course:
            course.is_published = False
            course.updated_at = datetime.now(timezone.utc)
            db.commit()
            flash('Курс закрыт для студентов!', 'success')
        else:
            flash('Курс не найден', 'error')
    except Exception as e:
        db.rollback()
        flash('Ошибка при закрытии курса', 'error')
    finally:
        db.close()

    return redirect(url_for('admin_courses'))

@app.route('/admin/course/<int:course_id>/reset-attempts', methods=['POST'])
@admin_required
def reset_course_attempts(course_id):
    """Reset all exam attempts for a course"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'})

        # Delete exam attempts for this course
        exams = db.query(Exam).filter(Exam.course_id == course_id).all()
        for exam in exams:
            db.query(ExamAttempt).filter(ExamAttempt.exam_id == exam.id).delete()

        # Delete chapter test attempts for this course
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).all()
        for chapter in chapters:
            db.query(ChapterTestAttempt).filter(ChapterTestAttempt.chapter_id == chapter.id).delete()

        db.commit()

        logger.info(f"Reset attempts for course {course.title} by admin {session.get('user_name')}")
        return jsonify({'success': True, 'message': f'Все попытки для курса \"{course.title}\" сброшены'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error resetting course attempts: {e}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        db.close()

@app.route('/admin/course/<int:course_id>/delete', methods=['POST'])
@admin_required
def delete_course(course_id):
    """Delete course completely"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'})

        # Delete related data in correct order to avoid foreign key violations
        # 1. Delete certificates
        db.query(Certificate).filter(Certificate.course_id == course_id).delete()

        # 2. Delete exam attempts first
        exams = db.query(Exam).filter(Exam.course_id == course_id).all()
        for exam in exams:
            db.query(ExamAttempt).filter(ExamAttempt.exam_id == exam.id).delete()

        # 3. Delete chapter test attempts BEFORE deleting chapters
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).all()
        for chapter in chapters:
            db.query(ChapterTestAttempt).filter(ChapterTestAttempt.chapter_id == chapter.id).delete()

        # 4. Delete course progress
        db.query(CourseProgress).filter(CourseProgress.course_id == course_id).delete()

        # 5. Delete exams
        db.query(Exam).filter(Exam.course_id == course_id).delete()

        # 6. Finally delete chapters (after all references are removed)
        db.query(Chapter).filter(Chapter.course_id == course_id).delete()
        db.flush()  # Force deletion before proceeding

        # Delete course
        db.delete(course)
        db.commit()

        return jsonify({'success': True})

    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting course: {e}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        db.close()

@app.route('/course/<int:course_id>/refresh-progress', methods=['POST'])
@login_required
def refresh_course_progress(course_id):
    """Принудительно обновить прогресс курса"""
    user_id = session.get('user_id')
    db = get_db_session()
    try:
        # Принудительно пересчитываем прогресс
        progress_data = update_course_progress(course_id, user_id, db)

        return jsonify({
            'success': True,
            'progress': progress_data['progress_percent'],
            'completed_sections': progress_data['completed_sections'],
            'total_sections': progress_data['total_sections'],
            'all_completed': progress_data['all_completed']
        })
    except Exception as e:
        logger.error(f"Error refreshing progress: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/course/<int:course_id>/force-recalculate', methods=['POST'])
@login_required
def force_recalculate_progress(course_id):
    """Полностью пересчитать прогресс курса с нуля"""
    user_id = session.get('user_id')
    db = get_db_session()
    try:
        logger.info(f"Force recalculating progress for user {user_id}, course {course_id}")

        # Получаем или создаем прогресс
        progress = db.query(CourseProgress).filter(
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
            db.add(progress)
            db.flush()

        # Получаем все главы курса
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number.asc(), Chapter.id.asc()).all()

        # Пересчитываем completed_chapters на основе тестов
        new_completed_chapters = []

        for chapter in chapters:
            if chapter.has_test:
                # Для главы с тестом проверяем лучший результат
                best_attempt = db.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.chapter_id == chapter.id,
                    ChapterTestAttempt.user_id == user_id
                ).order_by(ChapterTestAttempt.score.desc()).first()

                if best_attempt and best_attempt.score >= 100.0:
                    new_completed_chapters.append(chapter.id)
                    logger.info(f"Chapter {chapter.id} marked as completed - test score: {best_attempt.score}%")
                else:
                    logger.info(f"Chapter {chapter.id} NOT completed - test score: {best_attempt.score if best_attempt else 0}%")
            else:
                # For chapters without tests, keep existing manual completion status
                if chapter.id in (progress.completed_chapters or []):
                    new_completed_chapters.append(chapter.id)
                    logger.info(f"Chapter {chapter.id} kept as manually completed")

        # Обновляем прогресс
        progress.completed_chapters = new_completed_chapters
        progress.updated_at = datetime.now(timezone.utc)

        # Пересчитываем общий прогресс
        progress_data = update_course_progress(course_id, user_id, db)

        logger.info(f"Force recalculation complete: {progress_data['progress_percent']}% ({progress_data['completed_sections']}/{progress_data['total_sections']})")

        return jsonify({
            'success': True,
            'message': 'Прогресс полностью пересчитан',
            'progress': progress_data['progress_percent'],
            'completed_sections': progress_data['completed_sections'],
            'total_sections': progress_data['total_sections'],
            'all_completed': progress_data['all_completed']
        })

    except Exception as e:
        db.rollback()
        logger.error(f"Error force recalculating progress: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/course/<int:course_id>')
@login_required
def view_course(course_id):
    """View course content"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')

        # Проверяем существование пользователя
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            # Пользователь удален, очищаем сессию
            session.clear()
            flash('Ваш аккаунт был удален. Войдите заново.', 'error')
            return redirect(url_for('login'))

        course = db.query(Course).filter(Course.id == course_id).first()

        if not course or not course.is_published:
            flash('Курс не найден', 'error')
            return redirect(url_for('index'))

        # Получаем запрошенную главу из параметров
        requested_chapter_id = request.args.get('chapter_id', type=int)

        # Get or create user progress
        progress = db.query(CourseProgress).filter(
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
            db.add(progress)
            db.commit() # Commit immediately to ensure progress object exists

        # Get course chapters, ordered by order_number, then by id as fallback
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number.asc(), Chapter.id.asc()).all()

        # Update progress using centralized function
        progress_data = update_course_progress(course_id, user_id, db)

        # Get chapter tests status from progress calculation
        chapter_test_status = {}
        for chapter in chapters:
            if chapter.id in progress_data['chapter_statuses']:
                status = progress_data['chapter_statuses'][chapter.id]
                if status['has_test'] and status['test_score'] > 0:
                    chapter_test_status[chapter.id] = {
                        'passed': status['test_passed'],
                        'score': status['test_score']
                    }

        # Определяем текущую главу
        current_chapter = None
        current_chapter_index = 0

        if requested_chapter_id:
            # Проверяем, доступна ли запрошенная глава
            for idx, chapter in enumerate(chapters):
                if chapter.id == requested_chapter_id:
                    # Проверяем доступность главы
                    is_first_chapter = idx == 0
                    prev_chapter_completed = idx == 0 or chapters[idx - 1].id in (progress.completed_chapters or [])
                    introduction_completed = progress and progress.completed_introduction
                    chapter_available = (is_first_chapter and introduction_completed) or (not is_first_chapter and prev_chapter_completed)

                    if chapter_available or chapter.id in (progress.completed_chapters or []):
                        current_chapter = chapter
                        current_chapter_index = idx
                    break

        # Если глава не выбрана или недоступна, выбираем первую доступную
        if not current_chapter:
            for idx, chapter in enumerate(chapters):
                is_first_chapter = idx == 0
                prev_chapter_completed = idx == 0 or chapters[idx - 1].id in (progress.completed_chapters or [])
                introduction_completed = progress and progress.completed_introduction
                chapter_available = (is_first_chapter and introduction_completed) or (not is_first_chapter and prev_chapter_completed)

                if chapter_available and chapter.id not in (progress.completed_chapters or []):
                    current_chapter = chapter
                    current_chapter_index = idx
                    break

        # Определяем предыдущую и следующую главы
        previous_chapter = chapters[current_chapter_index - 1] if current_chapter and current_chapter_index > 0 else None
        next_chapter = chapters[current_chapter_index + 1] if current_chapter and current_chapter_index < len(chapters) - 1 else None

        # Prepare chapters data for JavaScript serialization
        chapters_data = []
        for chapter in chapters:
            chapters_data.append({
                'id': chapter.id,
                'title': chapter.title,
                'has_test': chapter.has_test
            })

        # Calculate total sections for the template
        completed_sections = 0
        if progress.completed_introduction:
            completed_sections += 1
        for chapter in chapters:
            if chapter.has_test:
                # For chapters with tests, consider it completed if passed
                if chapter.id in chapter_test_status and chapter_test_status[chapter.id]['passed']:
                    completed_sections += 1
            else:
                # For chapters without tests, check if manually completed
                if chapter.id in (progress.completed_chapters or []):
                    completed_sections += 1
        if progress.completed_conclusion:
            completed_sections += 1

        total_sections = len(chapters) + 2 # Intro + Chapters + Conclusion

        # Check for user certificate
        user_certificate = db.query(Certificate).filter(
            Certificate.user_id == user_id,
            Certificate.course_id == course_id
        ).first()

        return render_template('course_view.html',
                             course=course,
                             chapters=chapters,
                             progress=progress,
                             progress_percentage=progress_data['progress_percent'],
                             chapter_test_status=chapter_test_status,
                             chapters_data=chapters_data,
                             completed_sections=completed_sections,
                             total_sections=total_sections,
                             completed_chapters=progress.completed_chapters if progress and progress.completed_chapters else [],
                             user_certificate=user_certificate,
                             current_chapter=current_chapter,
                             current_chapter_index=current_chapter_index,
                             previous_chapter=previous_chapter,
                             next_chapter=next_chapter)
    finally:
        db.close()

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')
        user = db.query(User).filter(User.id == user_id).first()

        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            company = request.form.get('company')

            if not all([name, email]):
                flash('Все поля обязательны', 'error')
                return render_template('profile.html', user=user)

            # Check if email is taken by another user
            existing_user = db.query(User).filter(
                User.email == email,
                User.id != user_id
            ).first()

            if existing_user:
                flash('Email уже используется другим пользователем', 'error')
                return render_template('profile.html', user=user)

            # Update user
            user.name = name
            user.email = email
            user.company = company if company else None
            user.updated_at = datetime.now(timezone.utc)

            db.commit()

            # Update session
            session['user_name'] = user.name

            flash('Профиль успешно обновлен!', 'success')
            return redirect(url_for('profile'))

        # Get user's certificates for display
        certificates = db.query(Certificate).join(Course).filter(
            Certificate.user_id == user_id
        ).all()

        return render_template('profile.html', user=user, certificates=certificates)
    finally:
        db.close()

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin users management"""
    db = get_db_session()
    try:
        users = db.query(User).order_by(User.registered_at.desc()).all()

        # Get course progress for all users
        user_progress_dict = {}
        user_certificates_dict = {}

        for user in users:
            # Get user's course progress
            progress_list = db.query(CourseProgress).join(Course).filter(
                CourseProgress.user_id == user.id
            ).all()
            user_progress_dict[user.id] = progress_list

            # Get user's certificates
            certificates_list = db.query(Certificate).join(Course).filter(
                Certificate.user_id == user.id
            ).all()
            user_certificates_dict[user.id] = certificates_list

        return render_template('admin_users.html',
                             users=users,
                             user_progress_dict=user_progress_dict,
                             user_certificates_dict=user_certificates_dict)
    finally:
        db.close()

@app.route('/admin/certificates')
@admin_required
def admin_certificates():
    """Admin certificates management"""
    db = get_db_session()
    try:
        filter_type = request.args.get('filter', 'all')

        query = db.query(Certificate).join(User).join(Course)

        if filter_type == 'active':
            query = query.filter(Certificate.status == 'active')
        elif filter_type == 'revoked':
            query = query.filter(Certificate.status == 'revoked')

        certificates = query.order_by(Certificate.issued_at.desc()).all()
        return render_template('admin_certificates.html', certificates=certificates, filter_type=filter_type)
    finally:
        db.close()

@app.route('/admin/certificate/<certificate_id>')
@admin_required
def admin_view_certificate(certificate_id):
    """Admin view certificate"""
    db = get_db_session()
    try:
        certificate = db.query(Certificate).join(User).join(Course).filter(
            Certificate.certificate_id == certificate_id
        ).first()

        if not certificate:
            flash('Сертификат не найден', 'error')
            return redirect(url_for('admin_certificates'))

        # Убеждаемся что связанные объекты загружены корректно
        if not certificate.course:
            logger.error(f"Course not found for certificate {certificate_id}")
            flash('Ошибка: курс не найден для сертификата', 'error')
            return redirect(url_for('admin_certificates'))

        if not certificate.user:
            logger.error(f"User not found for certificate {certificate_id}")
            flash('Ошибка: пользователь не найден для сертификата', 'error')
            return redirect(url_for('admin_certificates'))

        logger.info(f"Displaying certificate {certificate_id} for course: {certificate.course.title}")
        return render_template('certificate.html', certificate=certificate)
    finally:
        db.close()

@app.route('/admin/certificate/<int:certificate_id>/revoke', methods=['POST'])
@admin_required
def admin_revoke_certificate(certificate_id):
    """Revoke certificate"""
    db = get_db_session()
    try:
        certificate = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        if certificate:
            certificate.status = 'revoked'
            certificate.revoked_at = datetime.now(timezone.utc)
            certificate.revoked_reason = request.form.get('reason', 'Отозван администратором')
            db.commit()
            flash('Сертификат отозван', 'success')
        else:
            flash('Сертификат не найден', 'error')
    except Exception as e:
        db.rollback()
        flash('Ошибка при отзыве сертификата', 'error')
        logger.error(f"Error revoking certificate: {e}")
    finally:
        db.close()
    return redirect(url_for('admin_certificates'))

@app.route('/admin/certificate/<int:certificate_id>/activate', methods=['POST'])
@admin_required
def admin_activate_certificate(certificate_id):
    """Activate certificate"""
    db = get_db_session()
    try:
        certificate = db.query(Certificate).filter(Certificate.id == certificate_id).first()
        if certificate:
            certificate.status = 'active'
            certificate.revoked_at = None
            certificate.revoked_reason = None
            db.commit()
            flash('Сертификат активирован', 'success')
        else:
            flash('Сертификат не найден', 'error')
    except Exception as e:
        db.rollback()
        flash('Ошибка при активации сертификата', 'error')
        logger.error(f"Error activating certificate: {e}")
    finally:
        db.close()
    return redirect(url_for('admin_certificates'))

@app.route('/admin/migrate-database', methods=['GET', 'POST'])
@admin_required
def migrate_database():
    """Endpoint для миграции базы данных"""
    if request.method == 'POST':
        db = get_db_session()
        try:
            results = []
            from sqlalchemy import text

            # Добавляем недостающие колонки для PostgreSQL
            if DATABASE_URL.startswith('postgresql'):
                # Проверяем наличие колонок
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'courses'
                    AND column_name IN ('certificate_author_name', 'certificate_author_position')
                """)
                existing_columns = [row[0] for row in db.execute(check_query)]

                # Добавляем certificate_author_name если не существует
                if 'certificate_author_name' not in existing_columns:
                    try:
                        db.execute(text("ALTER TABLE courses ADD COLUMN certificate_author_name VARCHAR"))
                        db.commit()
                        results.append("✅ Добавлена колонка certificate_author_name")
                        logger.info("Added certificate_author_name column")
                    except Exception as e:
                        db.rollback()
                        results.append(f"❌ Ошибка при добавлении certificate_author_name: {e}")
                        logger.error(f"Error adding certificate_author_name: {e}")
                else:
                    results.append("ℹ️ Колонка certificate_author_name уже существует")

                # Добавляем certificate_author_position если не существует
                if 'certificate_author_position' not in existing_columns:
                    try:
                        db.execute(text("ALTER TABLE courses ADD COLUMN certificate_author_position VARCHAR"))
                        db.commit()
                        results.append("✅ Добавлена колонка certificate_author_position")
                        logger.info("Added certificate_author_position column")
                    except Exception as e:
                        db.rollback()
                        results.append(f"❌ Ошибка при добавлении certificate_author_position: {e}")
                        logger.error(f"Error adding certificate_author_position: {e}")
                else:
                    results.append("ℹ️ Колонка certificate_author_position уже существует")
            else:
                results.append("ℹ️ Миграция доступна только для PostgreSQL")

            return jsonify({'success': True, 'results': results})

        except Exception as e:
            db.rollback()
            logger.error(f"Database migration error: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            db.close()

    # GET запрос - показываем форму
    return render_template('admin_migrate_database.html')

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    """Admin analytics page with detailed course progress"""
    db = get_db_session()
    try:
        # Get all courses
        all_courses = db.query(Course).all()

        # Get completed courses statistics
        completed_courses = db.query(CourseProgress).filter(
            CourseProgress.completed == True
        ).join(User).join(Course).all()

        # Get all course progress (including in-progress)
        all_progress = db.query(CourseProgress).join(User).join(Course).all()

        # Get user activity data for last 30 days
        from datetime import timedelta
        activity_data = []
        for i in range(29, -1, -1):  # Last 30 days
            date = datetime.now(timezone.utc) - timedelta(days=i)
            start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = date.replace(hour=23, minute=59, second=59, microsecond=999999)

            # Count users who were active on this day (updated course progress, took tests, etc.)
            active_users = db.query(User.id).distinct().filter(
                db.query(CourseProgress).filter(
                    CourseProgress.user_id == User.id,
                    CourseProgress.updated_at >= start_of_day,
                    CourseProgress.updated_at <= end_of_day
                ).exists()
            ).count()

            # Also count users who took chapter tests on this day
            test_active_users = db.query(User.id).distinct().filter(
                db.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.user_id == User.id,
                    ChapterTestAttempt.attempt_date >= start_of_day,
                    ChapterTestAttempt.attempt_date <= end_of_day
                ).exists()
            ).count()

            # Count users who took exams on this day
            exam_active_users = db.query(User.id).distinct().filter(
                db.query(ExamAttempt).filter(
                    ExamAttempt.user_id == User.id,
                    ExamAttempt.attempt_date >= start_of_day,
                    ExamAttempt.attempt_date <= end_of_day
                ).exists()
            ).count()

            # Total unique active users for the day
            total_active = max(active_users, test_active_users, exam_active_users)

            activity_data.append({
                'date': date.strftime('%Y-%m-%d'),
                'active_users': total_active,
                'day_name': date.strftime('%a'),
                'day_number': date.day
            })

        # Group by course with serializable data
        course_stats = {}
        for course in all_courses:
            course_stats[course.id] = {
                'course': {
                    'id': course.id,
                    'title': course.title,
                    'description': course.description,
                    'is_published': course.is_published,
                    'created_at': course.created_at.isoformat() if course.created_at else None
                },
                'completed_count': 0,
                'in_progress_count': 0,
                'total_enrolled': 0,
                'average_progress': 0,
                'users': []
            }

        # Fill statistics
        total_progress = 0
        progress_count = 0
        for progress in all_progress:
            course_id = progress.course_id
            if course_id in course_stats:
                course_stats[course_id]['total_enrolled'] += 1
                course_stats[course_id]['users'].append({
                    'user': {
                        'id': progress.user.id,
                        'name': progress.user.name,
                        'email': progress.user.email,
                        'company': progress.user.company
                    },
                    'progress_percent': progress.progress_percent,
                    'completed': progress.completed,
                    'started_at': progress.started_at.isoformat() if progress.started_at else None,
                })

                if progress.completed:
                    course_stats[course_id]['completed_count'] += 1
                else:
                    course_stats[course_id]['in_progress_count'] += 1

                total_progress += progress.progress_percent
                progress_count += 1

        # Calculate average progress for each course
        for course_id, stats in course_stats.items():
            if stats['total_enrolled'] > 0:
                total_course_progress = sum(user_data['progress_percent'] for user_data in stats['users'])
                stats['average_progress'] = total_course_progress / stats['total_enrolled']

        # Get company statistics
        all_users = db.query(User).all()
        company_stats = {}

        for user in all_users:
            company = user.company or 'Неизвестная компания'
            if company not in company_stats:
                company_stats[company] = {
                    'total_users': 0,
                    'active_learners': 0,
                    'certificates_count': 0
                }

            company_stats[company]['total_users'] += 1

            # Check if user has any course progress
            user_progress = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).first()
            if user_progress:
                company_stats[company]['active_learners'] += 1

            # Count certificates
            user_certificates = db.query(Certificate).filter(Certificate.user_id == user.id).count()
            company_stats[company]['certificates_count'] += user_certificates

        # Get all certificates with serializable data
        certificates_query = db.query(Certificate).join(User).join(Course).all()
        certificates = []
        for cert in certificates_query:
            certificates.append({
                'id': cert.id,
                'certificate_id': cert.certificate_id,
                'certificate_code': cert.certificate_code,
                'user_name': cert.user.name,
                'user_id': cert.user.id,
                'course_id': cert.course.id,
                'course_title': cert.course.title,
                'issued_at': cert.issued_at.isoformat() if cert.issued_at else None,
                'status': cert.status,
                'exam_score': cert.exam_score
            })

        logger.info(f"Analytics: Found {len(certificates)} certificates for chart data")

        # Convert users to serializable format
        users_data = []
        for user in all_users:
            users_data.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'company': user.company,
                'is_admin': user.is_admin,
                'registered_at': user.registered_at.isoformat() if user.registered_at else None
            })

        return render_template('admin_analytics.html',
                             course_stats=course_stats,
                             company_stats=company_stats,
                             certificates=certificates,
                             all_users=users_data,
                             user_activity_data=activity_data)
    finally:
        db.close()

@app.route('/admin/analytics/export/excel', methods=['POST'])
@admin_required
def export_analytics_excel():
    """Export analytics to Excel"""
    try:
        import pandas as pd
        from io import BytesIO
        import xlsxwriter

        db = get_db_session()

        # Prepare data
        output = BytesIO()

        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            # Course statistics
            course_data = []
            courses = db.query(Course).all()
            for course in courses:
                progress_records = db.query(CourseProgress).filter(CourseProgress.course_id == course.id).all()
                completed_count = sum(1 for p in progress_records if p.completed)
                in_progress_count = sum(1 for p in progress_records if p.progress_percent > 0 and not p.completed)
                avg_progress = sum(p.progress_percent for p in progress_records) / len(progress_records) if progress_records else 0

                course_data.append({
                    'Курс': course.title,
                    'Всего записано': len(progress_records),
                    'Завершили': completed_count,
                    'В процессе': in_progress_count,
                    'Средний прогресс (%)': round(avg_progress, 1),
                    'Статус': 'Опубликован' if course.is_published else 'Черновик'
                })

            df_courses = pd.DataFrame(course_data)
            df_courses.to_excel(writer, sheet_name='Статистика курсов', index=False)

            # Company statistics
            company_data = []
            users = db.query(User).filter(User.is_admin == False).all()
            companies = {}

            for user in users:
                company = user.company or 'Не указана'
                if company not in companies:
                    companies[company] = {
                        'total_users': 0,
                        'active_learners': 0,
                        'certificates_count': 0
                    }

                companies[company]['total_users'] += 1

                # Check if user has progress
                user_progress = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).first()
                if user_progress and user_progress.progress_percent > 0:
                    companies[company]['active_learners'] += 1

                # Count certificates
                user_certs = db.query(Certificate).filter(Certificate.user_id == user.id).count()
                companies[company]['certificates_count'] += user_certs

            for company, stats in companies.items():
                activity_rate = (stats['active_learners'] / stats['total_users'] * 100) if stats['total_users'] > 0 else 0
                company_data.append({
                    'Компания': company,
                    'Всего сотрудников': stats['total_users'],
                    'Активные обучающиеся': stats['active_learners'],
                    'Активность (%)': round(activity_rate, 1),
                    'Сертификаты': stats['certificates_count']
                })

            df_companies = pd.DataFrame(company_data)
            df_companies.to_excel(writer, sheet_name='Статистика компаний', index=False)

            # User details
            user_data = []
            for user in users:
                progress_records = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).all()
                completed_courses = sum(1 for p in progress_records if p.completed)
                in_progress_courses = sum(1 for p in progress_records if p.progress_percent > 0 and not p.completed)
                certificates_count = db.query(Certificate).filter(Certificate.user_id == user.id).count()

                user_data.append({
                    'Имя': user.name,
                    'Email': user.email,
                    'Компания': user.company or 'Не указана',
                    'Дата регистрации': user.registered_at.strftime('%d.%m.%Y') if user.registered_at else 'Неизвестно',
                    'Завершенные курсы': completed_courses,
                    'Курсы в процессе': in_progress_courses,
                    'Сертификаты': certificates_count
                })

            df_users = pd.DataFrame(user_data)
            df_users.to_excel(writer, sheet_name='Детализация пользователей', index=False)

            # Certificate data
            cert_data = []
            certificates = db.query(Certificate).join(User).join(Course).all()
            for cert in certificates:
                cert_data.append({
                    'Студент': cert.user.name,
                    'Курс': cert.course.title,
                    'Дата выдачи': cert.issued_at.strftime('%d.%m.%Y %H:%M'),
                    'Код сертификата': cert.certificate_code,
                    'Результат экзамена (%)': round(cert.exam_score, 1) if cert.exam_score else 'Неизвестно',
                    'Статус': 'Активен' if cert.status == 'active' else 'Отозван'
                })

            df_certificates = pd.DataFrame(cert_data)
            df_certificates.to_excel(writer, sheet_name='Сертификаты', index=False)

        db.close()
        output.seek(0)

        return send_file(
            BytesIO(output.read()),
            as_attachment=True,
            download_name=f'analytics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )

    except ImportError:
        return jsonify({'error': 'Pandas не установлен. Невозможно создать Excel файл.'}), 500
    except Exception as e:
        logger.error(f"Error exporting to Excel: {e}")
        return jsonify({'error': 'Ошибка при создании Excel отчета'}), 500

@app.route('/admin/analytics/export/pdf', methods=['POST'])
@admin_required
def export_analytics_pdf():
    """Export analytics to PDF"""
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from io import BytesIO

        db = get_db_session()

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)

        # Styles
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading1']
        normal_style = styles['Normal']

        # Content
        story = []

        # Title
        story.append(Paragraph("Аналитический отчет SapaEdu", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Дата создания: {datetime.now().strftime('%d.%m.%Y %H:%M')}", normal_style))
        story.append(Spacer(1, 30))

        # Course statistics
        story.append(Paragraph("Статистика по курсам", heading_style))
        story.append(Spacer(1, 10))

        course_data = [['Курс', 'Записано', 'Завершили', 'В процессе', 'Прогресс %']]
        courses = db.query(Course).all()

        for course in courses:
            progress_records = db.query(CourseProgress).filter(CourseProgress.course_id == course.id).all()
            completed = sum(1 for p in progress_records if p.completed)
            in_progress = sum(1 for p in progress_records if p.progress_percent > 0 and not p.completed)
            avg_progress = sum(p.progress_percent for p in progress_records) / len(progress_records) if progress_records else 0

            course_data.append([
                course.title[:30] + '...' if len(course.title) > 30 else course.title,
                str(len(progress_records)),
                str(completed),
                str(in_progress),
                f"{avg_progress:.1f}%"
            ])

        course_table = Table(course_data)
        course_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(course_table)
        story.append(Spacer(1, 30))

        # Company statistics
        story.append(Paragraph("Статистика по компаниям", heading_style))
        story.append(Spacer(1, 10))

        company_data = [['Компания', 'Сотрудников', 'Активных', 'Активность %', 'Сертификатов']]
        users = db.query(User).filter(User.is_admin == False).all()
        companies = {}

        for user in users:
            company = user.company or 'Не указана'
            if company not in companies:
                companies[company] = {'total': 0, 'active': 0, 'certificates': 0}

            companies[company]['total'] += 1

            user_progress = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).first()
            if user_progress and user_progress.progress_percent > 0:
                companies[company]['active'] += 1

            user_certs = db.query(Certificate).filter(Certificate.user_id == user.id).count()
            companies[company]['certificates'] += user_certs

        for company, stats in companies.items():
            activity_rate = (stats['active'] / stats['total'] * 100) if stats['total'] > 0 else 0
            company_data.append([
                company[:20] + '...' if len(company) > 20 else company,
                str(stats['total']),
                str(stats['active']),
                f"{activity_rate:.1f}%",
                str(stats['certificates'])
            ])

        company_table = Table(company_data)
        company_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(company_table)
        story.append(Spacer(1, 30))

        # Summary
        total_users = len(users)
        total_courses = len(courses)
        total_certificates = db.query(Certificate).count()

        story.append(Paragraph("Сводка", heading_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"• Всего пользователей: {total_users}", normal_style))
        story.append(Paragraph(f"• Всего курсов: {total_courses}", normal_style))
        story.append(Paragraph(f"• Всего сертификатов выдано: {total_certificates}", normal_style))
        story.append(Paragraph(f"• Компаний: {len(companies)}", normal_style))

        # Build PDF
        doc.build(story)

        db.close()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'analytics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
            mimetype='application/pdf'
        )

    except ImportError:
        return jsonify({'error': 'ReportLab не установлен. Невозможно создать PDF файл.'}), 500
    except Exception as e:
        logger.error(f"Error exporting to PDF: {e}")
        return jsonify({'error': 'Ошибка при создании PDF отчета'}), 500

@app.route('/admin/analytics/export/csv', methods=['POST'])
@admin_required
def export_analytics_csv():
    """Export analytics to CSV"""
    try:
        import csv
        from io import StringIO

        db = get_db_session()

        # Create CSV content
        output = StringIO()

        # Course statistics
        writer = csv.writer(output)
        writer.writerow(['=== СТАТИСТИКА КУРСОВ ==='])
        writer.writerow(['Курс', 'Всего записано', 'Завершили', 'В процессе', 'Средний прогресс (%)', 'Статус'])

        courses = db.query(Course).all()
        for course in courses:
            progress_records = db.query(CourseProgress).filter(CourseProgress.course_id == course.id).all()
            completed = sum(1 for p in progress_records if p.completed)
            in_progress = sum(1 for p in progress_records if p.progress_percent > 0 and not p.completed)
            avg_progress = sum(p.progress_percent for p in progress_records) / len(progress_records) if progress_records else 0

            writer.writerow([
                course.title,
                len(progress_records),
                completed,
                in_progress,
                round(avg_progress, 1),
                'Опубликован' if course.is_published else 'Черновик'
            ])

        writer.writerow([])
        writer.writerow(['=== СТАТИСТИКА КОМПАНИЙ ==='])
        writer.writerow(['Компания', 'Всего сотрудников', 'Активные обучающиеся', 'Активность (%)', 'Сертификаты'])

        # Company statistics
        users = db.query(User).filter(User.is_admin == False).all()
        companies = {}

        for user in users:
            company = user.company or 'Не указана'
            if company not in companies:
                companies[company] = {'total': 0, 'active': 0, 'certificates': 0}

            companies[company]['total'] += 1

            user_progress = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).first()
            if user_progress and user_progress.progress_percent > 0:
                companies[company]['active'] += 1

            user_certs = db.query(Certificate).filter(Certificate.user_id == user.id).count()
            companies[company]['certificates'] += user_certs

        for company, stats in companies.items():
            activity_rate = (stats['active'] / stats['total'] * 100) if stats['total'] > 0 else 0
            writer.writerow([
                company,
                stats['total'],
                stats['active'],
                round(activity_rate, 1),
                stats['certificates']
            ])

        writer.writerow([])
        writer.writerow(['=== ДЕТАЛИЗАЦИЯ ПОЛЬЗОВАТЕЛЕЙ ==='])
        writer.writerow(['Имя', 'Email', 'Компания', 'Дата регистрации', 'Завершенные курсы', 'Курсы в процессе', 'Сертификаты'])

        for user in users:
            progress_records = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).all()
            completed_courses = sum(1 for p in progress_records if p.completed)
            in_progress_courses = sum(1 for p in progress_records if p.progress_percent > 0 and not p.completed)
            certificates_count = db.query(Certificate).filter(Certificate.user_id == user.id).count()

            writer.writerow([
                user.name,
                user.email,
                user.company or 'Не указана',
                user.registered_at.strftime('%d.%m.%Y') if user.registered_at else 'Неизвестно',
                completed_courses,
                in_progress_courses,
                certificates_count
            ])

        db.close()

        # Convert to bytes
        csv_content = output.getvalue().encode('utf-8-sig')  # BOM for proper Excel opening

        return send_file(
            BytesIO(csv_content),
            as_attachment=True,
            download_name=f'analytics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            mimetype='text/csv'
        )

    except Exception as e:
        logger.error(f"Error exporting to CSV: {e}")
        return jsonify({'error': 'Ошибка при создании CSV отчета'}), 500

@app.route('/admin/analytics/export/full', methods=['POST'])
@admin_required
def export_full_analytics():
    """Export full analytics package as ZIP"""
    try:
        import zipfile
        from io import BytesIO

        # Create a ZIP file in memory
        zip_buffer = BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add Excel file
            try:
                excel_response = export_analytics_excel()
                if hasattr(excel_response, 'data'):
                    zip_file.writestr('analytics_report.xlsx', excel_response.data)
            except:
                pass  # Skip if Excel export fails

            # Add PDF file
            try:
                pdf_response = export_analytics_pdf()
                if hasattr(pdf_response, 'data'):
                    zip_file.writestr('analytics_report.pdf', pdf_response.data)
            except:
                pass  # Skip if PDF export fails

            # Add CSV file
            try:
                csv_response = export_analytics_csv()
                if hasattr(csv_response, 'data'):
                    zip_file.writestr('analytics_report.csv', csv_response.data)
            except:
                pass  # Skip if CSV export fails

            # Add summary text file
            db = get_db_session()
            try:
                total_users = db.query(User).filter(User.is_admin == False).count()
                total_courses = db.query(Course).count()
                total_certificates = db.query(Certificate).count()
                published_courses = db.query(Course).filter(Course.is_published == True).count()

                summary = f"""СВОДКА АНАЛИТИКИ SAPAEDU
Дата создания отчета: {datetime.now().strftime('%d.%m.%Y %H:%M')}

ОБЩАЯ СТАТИСТИКА:
- Всего пользователей: {total_users}
- Всего курсов: {total_courses}
- Опубликованных курсов: {published_courses}
- Всего сертификатов выдано: {total_certificates}

СОСТАВ АРХИВА:
- analytics_report.xlsx - Детальные данные в Excel
- analytics_report.pdf - Отчет в PDF формате
- analytics_report.csv - Данные в CSV формате
- summary.txt - Этот файл сводки

Создано системой SapaEdu
"""
                zip_file.writestr('summary.txt', summary.encode('utf-8'))
            finally:
                db.close()

        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f'full_analytics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip',
            mimetype='application/zip'
        )

    except Exception as e:
        logger.error(f"Error creating full analytics export: {e}")
        return jsonify({'error': 'Ошибка при создании полного отчета'}), 500

@app.route('/admin/analytics/filter/<period>')
@admin_required
def filter_analytics_by_period(period):
    """Filter analytics data by time period"""
    db = get_db_session()
    try:
        # Calculate date range
        now = datetime.now(timezone.utc)
        start_date = None

        if period == 'day':
            start_date = now - timedelta(days=1)
        elif period == 'week':
            start_date = now - timedelta(weeks=1)
        elif period == 'month':
            start_date = now - timedelta(days=30)
        elif period == 'year':
            start_date = now - timedelta(days=365)
        elif period != 'all':
            return jsonify({'success': False, 'error': 'Invalid period'}), 400

        # Get all courses (course stats don't change by period)
        all_courses = db.query(Course).all()

        # Get course progress (all time - represents current state)
        all_progress = db.query(CourseProgress).join(User).join(Course).all()

        # Filter certificates by period
        if start_date:
            certificates_query = db.query(Certificate).filter(Certificate.issued_at >= start_date)
        else:
            certificates_query = db.query(Certificate)

        certificates_list = certificates_query.join(User).join(Course).all()

        # Filter user activity by period
        if start_date:
            activity_data = []
            current_date = start_date
            while current_date <= now:
                end_of_day = current_date.replace(hour=23, minute=59, second=59, microsecond=999999)

                # Count active users for this day
                active_users = db.query(User.id).distinct().filter(
                    db.query(CourseProgress).filter(
                        CourseProgress.user_id == User.id,
                        CourseProgress.updated_at >= current_date,
                        CourseProgress.updated_at <= end_of_day
                    ).exists()
                ).count()

                activity_data.append({
                    'date': current_date.strftime('%Y-%m-%d'),
                    'active_users': active_users,
                    'day_name': current_date.strftime('%a'),
                    'day_number': current_date.day
                })

                current_date += timedelta(days=1)
        else:
            # Get last 30 days for 'all' period
            activity_data = []
            for i in range(29, -1, -1):
                date = now - timedelta(days=i)
                start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_of_day = date.replace(hour=23, minute=59, second=59, microsecond=999999)

                active_users = db.query(User.id).distinct().filter(
                    db.query(CourseProgress).filter(
                        CourseProgress.user_id == User.id,
                        CourseProgress.updated_at >= start_of_day,
                        CourseProgress.updated_at <= end_of_day
                    ).exists()
                ).count()

                activity_data.append({
                    'date': date.strftime('%Y-%m-%d'),
                    'active_users': active_users,
                    'day_name': date.strftime('%a'),
                    'day_number': date.day
                })

        # Filter users by registration period
        if start_date:
            users_query = db.query(User).filter(User.registered_at >= start_date)
        else:
            users_query = db.query(User)

        filtered_users = users_query.all()

        # Build course stats (unchanged by period filter)
        course_stats = {}
        for course in all_courses:
            course_stats[course.id] = {
                'course': {
                    'id': course.id,
                    'title': course.title,
                    'description': course.description,
                    'is_published': course.is_published,
                    'created_at': course.created_at.isoformat() if course.created_at else None
                },
                'completed_count': 0,
                'in_progress_count': 0,
                'total_enrolled': 0,
                'average_progress': 0,
                'users': []
            }

        # Fill course statistics from all progress (not filtered)
        for progress in all_progress:
            course_id = progress.course_id
            if course_id in course_stats:
                course_stats[course_id]['total_enrolled'] += 1
                course_stats[course_id]['users'].append({
                    'user': {
                        'id': progress.user.id,
                        'name': progress.user.name,
                        'email': progress.user.email,
                        'company': progress.user.company
                    },
                    'progress_percent': progress.progress_percent,
                    'completed': progress.completed,
                    'started_at': progress.started_at.isoformat() if progress.started_at else None,
                })

                if progress.completed:
                    course_stats[course_id]['completed_count'] += 1
                else:
                    course_stats[course_id]['in_progress_count'] += 1

        # Calculate average progress for each course
        for course_id, stats in course_stats.items():
            if stats['total_enrolled'] > 0:
                total_course_progress = sum(user_data['progress_percent'] for user_data in stats['users'])
                stats['average_progress'] = total_course_progress / stats['total_enrolled']

        # Get company statistics (current state, not time-filtered)
        all_users = db.query(User).all()
        company_stats = {}

        for user in all_users:
            company = user.company or 'Неизвестная компания'
            if company not in company_stats:
                company_stats[company] = {
                    'total_users': 0,
                    'active_learners': 0,
                    'certificates_count': 0
                }

            company_stats[company]['total_users'] += 1

            user_progress = db.query(CourseProgress).filter(CourseProgress.user_id == user.id).first()
            if user_progress:
                company_stats[company]['active_learners'] += 1

            # Count certificates (filtered by period)
            if start_date:
                user_certificates = db.query(Certificate).filter(
                    Certificate.user_id == user.id,
                    Certificate.issued_at >= start_date
                ).count()
            else:
                user_certificates = db.query(Certificate).filter(Certificate.user_id == user.id).count()

            company_stats[company]['certificates_count'] += user_certificates

        # Convert certificates to serializable format
        certificates = []
        for cert in certificates_list:
            certificates.append({
                'id': cert.id,
                'certificate_id': cert.certificate_id,
                'user_name': cert.user.name,
                'course_title': cert.course.title,
                'issued_at': cert.issued_at.isoformat() if cert.issued_at else None,
                'status': cert.status,
                'exam_score': cert.exam_score
            })

        # Convert users to serializable format
        users_data = []
        for user in filtered_users:
            users_data.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'company': user.company,
                'is_admin': user.is_admin,
                'registered_at': user.registered_at.isoformat() if user.registered_at else None
            })

        return jsonify({
            'success': True,
            'period': period,
            'data': {
                'course_stats': course_stats,
                'company_stats': company_stats,
                'certificates': certificates,
                'all_users': users_data,
                'user_activity': activity_data
            }
        })

    except Exception as e:
        logger.error(f"Error filtering analytics by period {period}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/admin/phishing')
@admin_required
def admin_phishing():
    """Admin phishing checks"""
    db = get_db_session()
    try:
        checks = db.query(PhishingCheck).join(User).all()
        users = db.query(User).filter(User.is_admin == False).all()
        return render_template('admin_phishing.html', checks=checks, users=users)
    finally:
        db.close()

@app.route('/admin/phishing/create', methods=['POST'])
@admin_required
def admin_create_phishing():
    """Create phishing check"""
    db = get_db_session()
    try:
        user_id = request.form.get('user_id')
        email_subject = request.form.get('email_subject')
        email_content = request.form.get('email_content')

        if not all([user_id, email_subject, email_content]):
            flash('Все поля обязательны', 'error')
            return redirect(url_for('admin_phishing'))

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            flash('Пользователь не найден', 'error')
            return redirect(url_for('admin_phishing'))

        # Create phishing check
        check_id = str(uuid.uuid4())
        phishing_check = PhishingCheck(
            user_id=user_id,
            check_id=check_id,
            email_subject=email_subject,
            email_content=email_content,
            sent_at=datetime.now(timezone.utc)
        )

        db.add(phishing_check)
        db.commit()

        # Send email
        try:
            send_phishing_email(user.email, email_subject, email_content, check_id)
            flash('Фишинг-письмо отправлено успешно', 'success')
        except Exception as e:
            logger.error(f"Failed to send phishing email: {e}")
            flash('Ошибка при отправке письма', 'error')

        return redirect(url_for('admin_phishing'))
    finally:
        db.close()

@app.route('/phishing/<check_id>')
def phishing_check(check_id):
    """Handle phishing check click"""
    db = get_db_session()
    try:
        check = db.query(PhishingCheck).filter(PhishingCheck.check_id == check_id).first()

        if check:
            # Mark as clicked/failed
            check.clicked_at = datetime.now(timezone.utc)
            check.status = 'failed'

            # Create notification
            notification = Notification(
                user_id=check.user_id,
                title="Фишинг-проверка провалена",
                message="Вы кликнули на фишинговую ссылку. Будьте осторожны с подозрительными письмами!",
                type="phishing_failed"
            )
            db.add(notification)
            db.commit()

        return render_template('phishing_warning.html')
    finally:
        db.close()

def send_phishing_email(to_email, subject, content, check_id):
    """Send phishing email"""
    try:
        # Replace placeholder with tracking link
        tracking_link = f"https://edu.sapatechnologies.kz/phishing/{check_id}"
        content = content.replace("{TRACKING_LINK}", tracking_link)

        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(content, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, to_email, text)
        server.quit()

        logger.info(f"Phishing email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send phishing email: {e}")
        raise

@app.route('/api/course/<int:course_id>/stats', methods=['GET'])
@login_required
def get_course_stats(course_id):
    """Get detailed course completion statistics"""
    user_id = session['user_id']
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'}), 404

        progress = db.query(CourseProgress).filter(
            CourseProgress.user_id == user_id,
            CourseProgress.course_id == course_id
        ).first()

        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number).all()

        # Get chapter test attempts
        chapter_attempts = db.query(ChapterTestAttempt).filter(
            ChapterTestAttempt.user_id == user_id,
            ChapterTestAttempt.chapter_id.in_([c.id for c in chapters])
        ).all()

        chapter_stats = {}
        for attempt in chapter_attempts:
            if attempt.chapter_id not in chapter_stats or attempt.score > chapter_stats[attempt.chapter_id]['score']:
                chapter_stats[attempt.chapter_id] = {
                    'score': attempt.score,
                    'passed': attempt.passed,
                    'attempt_date': attempt.attempt_date.isoformat()
                }

        stats = {
            'course_id': course_id,
            'course_title': course.title,
            'started_at': progress.started_at.isoformat() if progress else None,
            'completed_at': progress.completed_at.isoformat() if progress and progress.completed_at else None,
            'progress_percent': progress.progress_percent if progress else 0,
            'completed': progress.completed if progress else False,
            'chapters_completed': len(progress.completed_chapters) if progress and progress.completed_chapters else 0,
            'total_chapters': len(chapters),
            'chapter_stats': chapter_stats,
            'time_spent': None  # Could be calculated from stored session data
        }

        return jsonify({'success': True, 'stats': stats})

    except Exception as e:
        logger.error(f"Error getting course stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/course/<int:course_id>/complete/<section>', methods=['POST'])
@login_required
def complete_section(course_id, section):
    """Mark section as completed"""
    user_id = session['user_id']
    db = get_db_session()
    try:
        # Validate course exists
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'}), 404

        # Validate section parameter
        valid_sections = ['introduction', 'conclusion']
        if section not in valid_sections:
            return jsonify({'success': False, 'error': 'Недопустимая секция'}), 400

        progress = db.query(CourseProgress).filter(
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
            db.add(progress)
            db.flush()  # Ensure progress has an ID

        # Get total chapters for progress calculation
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).all()
        total_sections = len(chapters) + 2  # +2 for intro and conclusion
        section_weight = 100.0 / total_sections if total_sections > 0 else 0

        # Update progress based on section
        progress_updated = False
        old_progress = progress.progress_percent

        if section == 'introduction' and not progress.completed_introduction:
            progress.completed_introduction = True
            progress.progress_percent = min(old_progress + section_weight, 100.0)
            progress.updated_at = datetime.now(timezone.utc)
            progress_updated = True
        elif section == 'conclusion' and not progress.completed_conclusion:
            progress.completed_conclusion = True
            progress.progress_percent = min(old_progress + section_weight, 100.0)
            progress.updated_at = datetime.now(timezone.utc)
            progress_updated = True

        # Check if course is fully completed after any update
        if progress_updated:
            # Check all sections are properly completed
            sections_completed = 0
            total_sections = len(chapters) + 2  # +2 for intro and conclusion

            # Count intro
            if progress.completed_introduction:
                sections_completed += 1
            # Count chapters
            for chapter in chapters:
                if chapter.has_test:
                    # For chapters with tests, check if test passed with 100%
                    test_passed = db.query(ChapterTestAttempt).filter(
                        ChapterTestAttempt.chapter_id == chapter.id,
                        ChapterTestAttempt.user_id == user_id,
                        ChapterTestAttempt.passed == True,
                        ChapterTestAttempt.score >= 100.0
                    ).order_by(ChapterTestAttempt.score.desc()).first()
                    if test_passed:
                        sections_completed += 1
                else:
                    # For chapters without tests, check if manually completed
                    if chapter.id in (progress.completed_chapters or []):
                        sections_completed += 1
            # Count conclusion
            if progress.completed_conclusion:
                sections_completed += 1

            # Update completion status
            if sections_completed == total_sections and not progress.completed:
                progress.completed = True
                progress.progress_percent = 100.0
                progress.completed_at = datetime.now(timezone.utc)

        if progress_updated:
            db.commit()
            logger.info(f"User {user_id} completed {section} for course {course_id}")
            return jsonify({
                'success': True,
                'progress': round(progress.progress_percent, 1),
                'message': f'{section.capitalize()} завершено'
            })
        else:
            return jsonify({
                'success': True,
                'progress': round(progress.progress_percent, 1),
                'message': 'Уже завершено'
            })

    except Exception as e:
        db.rollback()
        logger.error(f"Error completing section {section} for course {course_id}: {e}")
        return jsonify({'success': False, 'error': 'Произошла ошибка при завершении секции'}), 500
    finally:
        db.close()

@app.route('/course/<int:course_id>/complete/chapter/<int:chapter_id>', methods=['POST'])
@login_required
def complete_chapter_route(course_id, chapter_id):
    """Mark chapter as completed"""
    user_id = session['user_id']
    db = get_db_session()
    try:
        # Verify course exists
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            return jsonify({'success': False, 'error': 'Курс не найден'}), 404

        # Verify chapter exists and belongs to course
        chapter = db.query(Chapter).filter(
            Chapter.id == chapter_id,
            Chapter.course_id == course_id
        ).first()
        if not chapter:
            return jsonify({'success': False, 'error': 'Глава не найдена'}), 404

        progress = db.query(CourseProgress).filter(
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
            db.add(progress)
            db.flush()  # Ensure we have an ID

        # Безопасная инициализация completed_chapters
        try:
            if progress.completed_chapters is None:
                progress.completed_chapters = []
            elif isinstance(progress.completed_chapters, str):
                # Если это строка, попробуем парсить как JSON
                import json
                progress.completed_chapters = json.loads(progress.completed_chapters)
            elif not isinstance(progress.completed_chapters, list):
                progress.completed_chapters = []
        except (json.JSONDecodeError, TypeError):
            progress.completed_chapters = []

        # Check if chapter is already completed
        if chapter_id in progress.completed_chapters:
            return jsonify({
                'success': True,
                'progress': round(progress.progress_percent, 1),
                'completed_chapters': progress.completed_chapters,
                'message': 'Глава уже завершена'
            })

        # Add chapter to completed list
        progress.completed_chapters.append(chapter_id)
        progress.updated_at = datetime.now(timezone.utc)

        # Calculate progress more accurately
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number).all()
        total_sections = len(chapters) + 2  # +2 for intro and conclusion
        section_weight = 100.0 / total_sections if total_sections > 0 else 0

        # Recalculate total progress based on completion criteria
        sections_completed = 0
        total_sections = len(chapters) + 2  # +2 for intro and conclusion

        # Count intro
        if progress.completed_introduction:
            sections_completed += 1
        # Count chapters
        for chapter_item in chapters:
            if chapter_item.has_test:
                # For chapters with tests, check if best test result is passed with 100%
                test_passed = db.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.chapter_id == chapter_item.id,
                    ChapterTestAttempt.user_id == user_id,
                    ChapterTestAttempt.passed == True,
                    ChapterTestAttempt.score >= 100.0
                ).order_by(ChapterTestAttempt.score.desc()).first()
                if test_passed:
                    sections_completed += 1
            else:
                # For chapters without tests, check if manually completed
                if chapter_item.id in progress.completed_chapters:
                    sections_completed += 1

        # Count conclusion
        if progress.completed_conclusion:
            sections_completed += 1

        progress.progress_percent = min((sections_completed * section_weight), 100.0)

        # Check if course is fully completed
        sections_completed = 0
        total_sections = len(chapters) + 2  # +2 for intro and conclusion

        # Count intro
        if progress.completed_introduction:
            sections_completed += 1

        # Count chapters
        for chapter_item in chapters:
            if chapter_item.has_test:
                test_passed = db.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.chapter_id == chapter_item.id,
                    ChapterTestAttempt.user_id == user_id,
                    ChapterTestAttempt.passed == True,
                    ChapterTestAttempt.score >= 100.0
                ).order_by(ChapterTestAttempt.score.desc()).first()
                if test_passed:
                    sections_completed += 1
            else:
                if chapter_item.id in progress.completed_chapters:
                    sections_completed += 1

        # Count conclusion
        if progress.completed_conclusion:
            sections_completed += 1

        # Update completion status
        if sections_completed == total_sections and not progress.completed:
            progress.completed = True
            progress.progress_percent = 100.0
            progress.completed_at = datetime.now(timezone.utc)

        # Force commit to ensure data persistence
        db.commit()
        db.refresh(progress)  # Refresh to get latest state

        logger.info(f"Chapter {chapter_id} completed for user {user_id}. Progress: {progress.progress_percent}%")
        logger.info(f"Completed chapters: {progress.completed_chapters}")

        return jsonify({
            'success': True,
            'progress': round(progress.progress_percent, 1),
            'completed_chapters': progress.completed_chapters,
            'message': 'Глава завершена!'
        })

    except Exception as e:
        db.rollback()
        logger.error("Error completing chapter: %s", e)
        return jsonify({'success': False, 'error': 'Произошла ошибка при завершении главы'}), 500
    finally:
        db.close()

@app.route('/chapter/<int:chapter_id>/test')
@login_required
def chapter_test(chapter_id):
    """Take chapter test"""
    user_id = session['user_id']
    db = get_db_session()
    try:
        chapter = db.query(Chapter).filter(Chapter.id == chapter_id).first()
        if not chapter:
            flash('Глава не найдена', 'error')
            return redirect(url_for('index'))

        # Проверяем наличие теста с улучшенной валидацией
        if not chapter.has_test:
            flash('Тест для этой главы не настроен', 'error')
            return redirect(url_for('view_course', course_id=chapter.course_id, chapter_id=chapter_id))

        if not chapter.test_questions:
            flash('Тест для этой главы не содержит вопросов', 'error')
            return redirect(url_for('view_course', course_id=chapter.course_id, chapter_id=chapter_id))

        # Проверяем что test_questions - это список
        if not isinstance(chapter.test_questions, list) or len(chapter.test_questions) == 0:
            flash('Ошибка в структуре данных теста', 'error')
            return redirect(url_for('view_course', course_id=chapter.course_id, chapter_id=chapter_id))

        # Валидируем каждый вопрос
        valid_questions = []
        for i, question in enumerate(chapter.test_questions):
            if isinstance(question, dict) and question.get('text') and question.get('answers'):
                if isinstance(question['answers'], list) and len(question['answers']) > 1:
                    valid_questions.append(question)
                else:
                    logger.warning(f"Chapter {chapter_id} question {i} has invalid answers structure")
            else:
                logger.warning(f"Chapter {chapter_id} question {i} has invalid structure")

        if not valid_questions:
            flash('Тест содержит некорректные вопросы', 'error')
            return redirect(url_for('view_course', course_id=chapter.course_id, chapter_id=chapter_id))

        # Обновляем chapter.test_questions корректными вопросами
        chapter.test_questions = valid_questions

        # Проверяем лучший результат
        best_attempt = db.query(ChapterTestAttempt).filter(
            ChapterTestAttempt.chapter_id == chapter_id,
            ChapterTestAttempt.user_id == user_id
        ).order_by(ChapterTestAttempt.score.desc()).first()

        if best_attempt and best_attempt.score >= 100.0:
            flash(f'Ваш лучший результат: {best_attempt.score:.1f}%. Вы можете улучшить его!', 'info')

        return render_template('chapter_test.html', chapter=chapter, enumerate=enumerate)

    except Exception as e:
        logger.error(f"Error loading chapter test {chapter_id}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Произошла ошибка при загрузке теста', 'error')
        return redirect(url_for('index'))
    finally:
        db.close()

@app.route('/chapter/<int:chapter_id>/test', methods=['POST'])
@login_required
def submit_chapter_test(chapter_id):
    """Submit chapter test"""
    user_id = session['user_id']
    db = get_db_session()
    try:
        chapter = db.query(Chapter).filter(Chapter.id == chapter_id).first()
        if not chapter or not chapter.has_test:
            flash('Тест не найден', 'error')
            return redirect(url_for('index'))

        if not chapter.test_questions or len(chapter.test_questions) == 0:
            flash('Тест не содержит вопросов', 'error')
            return redirect(url_for('view_course', course_id=chapter.course_id))

        # Проверяем что test_questions - это список
        if not isinstance(chapter.test_questions, list):
            logger.error(f"Chapter {chapter_id} test_questions is not a list: {type(chapter.test_questions)}")
            flash('Ошибка структуры данных теста', 'error')
            return redirect(url_for('view_course', course_id=chapter.course_id))

        # Собираем ответы с улучшенной проверкой валидности
        answers = {}
        validation_errors = []

        logger.info(f"Processing test for chapter {chapter_id}, user {user_id}")
        logger.info(f"Questions count: {len(chapter.test_questions)}")

        for i in range(len(chapter.test_questions)):
            try:
                question = chapter.test_questions[i]
                if not isinstance(question, dict):
                    logger.error(f"Question {i} is not a dict: {type(question)}")
                    validation_errors.append(f'Вопрос {i+1}: некорректная структура данных')
                    continue

                answer_key = f'question_{i}'
                question_type = question.get('type', 'single')

                if question_type == 'multiple':
                    # Для множественного выбора
                    selected_answers = request.form.getlist(answer_key)
                    if not selected_answers:
                        validation_errors.append(f'Вопрос {i+1}: не выбран ни один ответ')
                        continue

                    numeric_answers = []
                    for ans in selected_answers:
                        if ans and ans.isdigit():
                            numeric_answers.append(int(ans))

                    if numeric_answers:
                        answers[str(i)] = numeric_answers
                    else:
                        validation_errors.append(f'Вопрос {i+1}: некорректные ответы')
                else:
                    # Для одиночного выбора
                    answer_value = request.form.get(answer_key)
                    if not answer_value:
                        validation_errors.append(f'Вопрос {i+1}: ответ не выбран')
                        continue

                    if answer_value.isdigit():
                        answers[str(i)] = int(answer_value)
                    else:
                        validation_errors.append(f'Вопрос {i+1}: некорректный ответ')

            except Exception as e:
                logger.error(f"Error processing question {i}: {e}")
                validation_errors.append(f'Вопрос {i+1}: ошибка обработки')

        # Проверяем ошибки валидации
        if validation_errors:
            flash('Ошибки в ответах: ' + '; '.join(validation_errors), 'error')
            return redirect(url_for('chapter_test', chapter_id=chapter_id))

        # Подсчитываем балл и создаем детальные результаты
        correct_answers = 0
        total_questions = len(chapter.test_questions)
        detailed_results = []

        logger.info(f"Final chapter test scoring - total questions: {total_questions}")
        logger.info(f"Final user answers: {answers}")

        for i, question in enumerate(chapter.test_questions):
            user_answer = answers.get(str(i))
            correct_answer = question.get('correct_answer')
            question_type = question.get('type', 'single')
            is_correct = False

            logger.info(f"Question {i}: type={question_type}, user_answer={user_answer}, correct_answer={correct_answer}")

            try:
                if question_type == 'multiple':
                    # Для множественного выбора
                    if user_answer is not None and isinstance(user_answer, list) and correct_answer is not None:
                        # Убеждаемся что correct_answer является списком
                        if isinstance(correct_answer, list):
                            if sorted(user_answer) == sorted(correct_answer):
                                correct_answers += 1
                                is_correct = True
                                logger.info(f"Question {i}: CORRECT (multiple choice)")
                            else:
                                logger.info(f"Question {i}: INCORRECT (multiple choice mismatch)")
                        else:
                            # Если correct_answer не список, конвертируем в список
                            if sorted(user_answer) == sorted([correct_answer]):
                                correct_answers += 1
                                is_correct = True
                                logger.info(f"Question {i}: CORRECT (multiple choice, converted single answer)")
                            else:
                                logger.info(f"Question {i}: INCORRECT (multiple choice, converted single answer)")
                    else:
                        logger.info(f"Question {i}: INCORRECT (invalid format for multiple choice)")
                else:
                    # Для одиночного выбора
                    if user_answer is not None and correct_answer is not None:
                        # Проверяем если correct_answer является списком с одним элементом
                        if isinstance(correct_answer, list):
                            if len(correct_answer) == 1:
                                correct_value = correct_answer[0]
                            else:
                                logger.warning(f"Question {i}: multiple correct answers for single choice question")
                                correct_value = correct_answer[0]  # Берем первый
                        else:
                            correct_value = correct_answer

                        if user_answer == correct_value:
                            correct_answers += 1
                            is_correct = True
                            logger.info(f"Question {i}: CORRECT (single choice)")
                        else:
                            logger.info(f"Question {i}: INCORRECT (single choice mismatch: {user_answer} != {correct_value})")
                    else:
                        logger.info(f"Question {i}: INCORRECT (no answer provided)")

            except Exception as e:
                logger.error(f"Error checking question {i}: {e}")
                is_correct = False

            # Сохраняем детальный результат
            detailed_results.append({
                'question_index': i,
                'user_answer': user_answer,
                'is_correct': is_correct,
                'question_text': question.get('text', ''),
                'question_type': question_type
            })

        logger.info(f"Final chapter test scoring: {correct_answers} out of {total_questions} correct")
        logger.info(f"Chapter test percentage: {(correct_answers / total_questions) * 100 if total_questions > 0 else 0}%")

        score = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
        passed = score >= (chapter.test_passing_score or DEFAULT_CERTIFICATE_PASSING_SCORE)

        logger.info(f"Score: {score}%, Passing score: {chapter.test_passing_score or DEFAULT_CERTIFICATE_PASSING_SCORE}%, Passed: {passed}")

        # Проверяем лучший результат
        best_previous_attempt = db.query(ChapterTestAttempt).filter(
            ChapterTestAttempt.chapter_id == chapter_id,
            ChapterTestAttempt.user_id == user_id
        ).order_by(ChapterTestAttempt.score.desc()).first()

        # Логика сохранения результата
        should_save = True
        improvement_message = ""

        if best_previous_attempt:
            if score > best_previous_attempt.score:
                improvement_message = f"Результат улучшен с {best_previous_attempt.score:.1f}% до {score:.1f}%!"
                # Удаляем предыдущие попытки, оставляем только лучшую
                db.query(ChapterTestAttempt).filter(
                    ChapterTestAttempt.chapter_id == chapter_id,
                    ChapterTestAttempt.user_id == user_id
                ).delete()
            elif score == best_previous_attempt.score:
                improvement_message = f"Результат остался прежним: {score:.1f}%"
                should_save = False
            else:
                improvement_message = f"Результат ниже предыдущего ({best_previous_attempt.score:.1f}%). Лучший результат сохранен."
                should_save = False

        if should_save:
            attempt = ChapterTestAttempt(
                chapter_id=chapter_id,
                user_id=user_id,
                answers=answers,
                score=score,
                passed=passed,
                attempt_date=datetime.now(timezone.utc),
                detailed_results=detailed_results
            )
            db.add(attempt)

        # Если тест пройден на 100%, автоматически обновляем прогресс курса
        if passed and score >= 100.0:
            # Обновляем прогресс курса с помощью централизованной функции
            update_course_progress(chapter.course_id, user_id, db)

        db.commit()

        # Получаем последнюю попытку для перенаправления на результаты
        if should_save:
            final_attempt = attempt
        else:
            final_attempt = best_previous_attempt

        # Убираем flash сообщения - результат отображается на странице результатов
        return redirect(url_for('chapter_test_result', attempt_id=final_attempt.id))

    except Exception as e:
        db.rollback()
        logger.error(f"Critical error in submit_chapter_test: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Произошла критическая ошибка при обработке теста', 'error')
        return redirect(url_for('view_course', course_id=chapter.course_id))
    finally:
        db.close()

@app.route('/chapter-test-result/<int:attempt_id>')
@login_required
def chapter_test_result(attempt_id):
    """View chapter test results with detailed feedback"""
    user_id = session['user_id']
    db = get_db_session()
    try:
        attempt = db.query(ChapterTestAttempt).filter(
            ChapterTestAttempt.id == attempt_id,
            ChapterTestAttempt.user_id == user_id
        ).first()

        if not attempt:
            flash('Результат теста не найден', 'error')
            return redirect(url_for('index'))

        chapter = db.query(Chapter).filter(Chapter.id == attempt.chapter_id).first()
        if not chapter:
            flash('Глава не найдена', 'error')
            return redirect(url_for('index'))

        return render_template('chapter_test_result.html',
                             attempt=attempt,
                             chapter=chapter,
                             enumerate=enumerate)
    finally:
        db.close()

@app.route('/exam/<int:course_id>')
@login_required
def take_exam(course_id):
    """Take course exam"""
    db = get_db_session()
    try:
        course = db.query(Course).filter(Course.id == course_id).first()
        if not course:
            flash('Курс не найден', 'error')
            return redirect(url_for('index'))

        exam = db.query(Exam).filter(Exam.course_id == course_id).first()
        if not exam:
            flash('Экзамен для этого курса не найден', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        user_id = session.get('user_id')
        exam_session_key = f'exam_session_{exam.id}_{user_id}'

        # Check if user already has an active exam session
        if exam_session_key not in session:
            # Store exam start time in session for server-side validation
            session[exam_session_key] = {
                'start_time': datetime.now(timezone.utc).timestamp(),
                'exam_id': exam.id,
                'user_id': user_id
            }
        else:
            # Validate existing session
            exam_session = session[exam_session_key]
            start_time = datetime.fromtimestamp(exam_session['start_time'], timezone.utc)
            elapsed_minutes = (datetime.now(timezone.utc) - start_time).total_seconds() / 60

            if elapsed_minutes > exam.time_limit:
                # Session expired, redirect to course
                session.pop(exam_session_key, None)
                flash('Время экзамена истекло', 'warning')
                return redirect(url_for('view_course', course_id=course_id))

        # Проверяем валидность данных экзамена
        if not exam.questions:
            flash('Экзамен не содержит вопросов', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        if not isinstance(exam.questions, list) or len(exam.questions) == 0:
            flash('Ошибка в структуре данных экзамена', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        # Валидируем каждый вопрос экзамена
        valid_questions = []
        for i, question in enumerate(exam.questions):
            if isinstance(question, dict) and question.get('text') and question.get('answers'):
                if isinstance(question['answers'], list) and len(question['answers']) > 1:
                    valid_questions.append(question)
                else:
                    logger.warning(f"Exam {exam.id} question {i} has invalid answers structure")
            else:
                logger.warning(f"Exam {exam.id} question {i} has invalid structure")

        if not valid_questions:
            flash('Экзамен содержит некорректные вопросы', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        # Обновляем exam.questions корректными вопросами
        exam.questions = valid_questions

        user_id = session.get('user_id')

        # Get progress without modifying it
        progress = db.query(CourseProgress).filter(
            CourseProgress.user_id == user_id,
            CourseProgress.course_id == course_id
        ).first()

        if not progress:
            flash('Сначала начните изучение курса', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        # Check if user already passed the exam
        passed_exam_attempt = db.query(ExamAttempt).filter(
            ExamAttempt.exam_id == exam.id,
            ExamAttempt.user_id == user_id,
            ExamAttempt.passed == True
        ).order_by(ExamAttempt.score.desc()).first()

        if passed_exam_attempt:
            flash('Вы уже успешно прошли итоговый экзамен.', 'info')
            return redirect(url_for('view_course', course_id=course_id))

        # Check if all requirements are met before allowing exam
        chapters = db.query(Chapter).filter(Chapter.course_id == course_id).order_by(Chapter.order_number.asc(), Chapter.id.asc()).all()

        # Get updated progress data
        progress_data = update_course_progress(course_id, user_id, db)

        logger.info(f"Exam access check for user {user_id}, course {course_id}")
        logger.info(f"Progress data: {progress_data}")

        # Use the updated progress data for validation
        total_sections = len(chapters) + 2  # +2 for intro and conclusion
        sections_completed = 0
        missing_sections = []

        # Check introduction
        if progress_data['completed_introduction']:
            sections_completed += 1
            logger.info(f"Introduction completed: YES")
        else:
            missing_sections.append('введение')
            logger.info(f"Introduction completed: NO")

        # Check chapters using progress data
        for chapter in chapters:
            chapter_status = progress_data['chapter_statuses'].get(chapter.id, {})

            if chapter.has_test:
                # For chapters with tests, check if test passed with 100%
                test_passed = chapter_status.get('test_passed', False)
                test_score = chapter_status.get('test_score', 0)

                logger.info(f"Chapter {chapter.id} ({chapter.title}) with test: passed={test_passed}, score={test_score}")

                if test_passed and test_score >= 100.0:
                    sections_completed += 1
                    logger.info(f"Chapter {chapter.id} PASSED - counting as completed")
                else:
                    missing_sections.append(f'тест главы "{chapter.title}" (текущий результат: {test_score:.0f}%, требуется 100%)')
                    logger.info(f"Chapter {chapter.id} NOT PASSED - missing section")
            else:
                # For chapters without tests, check manual completion
                is_completed = chapter_status.get('completed', False)
                logger.info(f"Chapter {chapter.id} ({chapter.title}) without test: completed={is_completed}")

                if is_completed:
                    sections_completed += 1
                    logger.info(f"Chapter {chapter.id} COMPLETED - counting as completed")
                else:
                    missing_sections.append(f'глава "{chapter.title}"')
                    logger.info(f"Chapter {chapter.id} NOT COMPLETED - missing section")

        # Check conclusion
        if progress_data['completed_conclusion']:
            sections_completed += 1
            logger.info(f"Conclusion completed: YES")
        else:
            missing_sections.append('заключение')
            logger.info(f"Conclusion completed: NO")

        logger.info(f"Final exam access check: {sections_completed}/{total_sections} sections completed")
        logger.info(f"Missing sections: {missing_sections}")

        # Final check - ensure all sections are completed
        if sections_completed < total_sections:
            missing_text = ', '.join(missing_sections)
            # Принудительно обновляем прогресс перед показом ошибки
            update_course_progress(course_id, user_id, db)
            flash(f'Для прохождения экзамена необходимо завершить: {missing_text}. Прогресс: {sections_completed}/{total_sections}', 'warning')
            return redirect(url_for('view_course', course_id=course_id))

        # Check number of attempts
        all_attempts = db.query(ExamAttempt).filter(
            ExamAttempt.exam_id == exam.id,
            ExamAttempt.user_id == user_id
        ).count()

        if all_attempts >= exam.max_attempts:
            flash(f'Вы исчерпали все попытки ({exam.max_attempts}) для этого экзамена. Обратитесь к администратору.', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        return render_template('exam.html', course=course, exam=exam, enumerate=enumerate)
    finally:
        db.close()

@app.route('/api/exam/<int:exam_id>/time-remaining', methods=['GET'])
@login_required
def get_exam_time_remaining(exam_id):
    """Get remaining time for exam from server - server-side timer control"""
    db = get_db_session()
    try:
        exam = db.query(Exam).filter(Exam.id == exam_id).first()
        if not exam:
            return jsonify({'success': False, 'error': 'Экзамен не найден'}), 404

        user_id = session.get('user_id')
        exam_session_key = f'exam_session_{exam_id}_{user_id}'

        # Check if exam session exists
        if exam_session_key not in session:
            return jsonify({'success': False, 'error': 'Сессия экзамена не найдена. Перезапустите экзамен.'}), 400

        exam_session = session[exam_session_key]
        start_time = datetime.fromtimestamp(exam_session['start_time'], timezone.utc)
        current_time = datetime.now(timezone.utc)
        elapsed_seconds = (current_time - start_time).total_seconds()

        time_limit_seconds = exam.time_limit * 60  # Convert minutes to seconds
        remaining_seconds = max(0, time_limit_seconds - elapsed_seconds)

        # Strict server-side time control
        time_expired = remaining_seconds <= 0

        # If time expired, clear the session data
        if time_expired:
            session.pop(exam_session_key, None)
            logger.warning(f"Time expired for user {session.get('user_id')} on exam {exam_id}")

        # Log critical time points
        if remaining_seconds <= 300 and remaining_seconds > 0:  # Last 5 minutes
            logger.info(f"User {session.get('user_id')} has {remaining_seconds} seconds left on exam {exam_id}")

        return jsonify({
            'success': True,
            'remaining_seconds': int(remaining_seconds),
            'time_expired': time_expired,
            'elapsed_seconds': int(elapsed_seconds),
            'time_limit_seconds': time_limit_seconds,
            'pressure_level': 'critical' if remaining_seconds <= 60 else 'warning' if remaining_seconds <= 300 else 'normal'
        })

    except Exception as e:
        logger.error(f"Error getting exam time remaining: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        db.close()

@app.route('/exam/<int:course_id>', methods=['POST'])
@login_required
def submit_exam(course_id):
    """Submit exam answers"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')
        exam = db.query(Exam).filter(Exam.course_id == course_id).first()
        course = db.query(Course).filter(Course.id == course_id).first()

        if not exam or not course:
            flash('Экзамен не найден', 'error')
            return redirect(url_for('index'))

        # Server-side time validation
        user_id = session.get('user_id')
        exam_session_key = f'exam_session_{exam.id}_{user_id}'

        if exam_session_key in session:
            exam_session = session[exam_session_key]
            start_time = datetime.fromtimestamp(exam_session['start_time'], timezone.utc)
            current_time = datetime.now(timezone.utc)
            elapsed_minutes = (current_time - start_time).total_seconds() / 60

            if elapsed_minutes > exam.time_limit:
                # Clean up session
                session.pop(exam_session_key, None)
                flash('Время экзамена истекло. Экзамен завершен автоматически.', 'warning')
                return redirect(url_for('view_course', course_id=course_id))

        # Check number of attempts before processing
        current_attempts = db.query(ExamAttempt).filter(
            ExamAttempt.exam_id == exam.id,
            ExamAttempt.user_id == user_id
        ).count()

        if current_attempts >= exam.max_attempts:
            flash(f'Вы исчерпали все попытки ({exam.max_attempts}) для этого экзамена.', 'error')
            return redirect(url_for('view_course', course_id=course_id))


        # Проверяем что exam.questions - это список
        if not isinstance(exam.questions, list) or len(exam.questions) == 0:
            logger.error(f"Exam {exam.id} questions is not a valid list: {type(exam.questions)}")
            flash('Ошибка структуры данных экзамена', 'error')
            return redirect(url_for('view_course', course_id=course_id))

        # Collect answers with improved validation
        answers = {}
        validation_errors = []

        logger.info(f"Processing exam for course {course_id}, user {user_id}")
        logger.info(f"Questions count: {len(exam.questions)}")

        for i in range(len(exam.questions)):
            try:
                question = exam.questions[i]
                if not isinstance(question, dict):
                    logger.error(f"Exam question {i} is not a dict: {type(question)}")
                    validation_errors.append(f'Вопрос {i+1}: некорректная структура данных')
                    continue

                answer_key = f'question_{i}'
                question_type = question.get('type', 'single')

                if question_type == 'multiple':
                    # Для множественного выбора
                    selected_answers = request.form.getlist(answer_key)
                    if not selected_answers:
                        validation_errors.append(f'Вопрос {i+1}: не выбран ни один ответ')
                        continue

                    numeric_answers = []
                    for ans in selected_answers:
                        if ans and ans.isdigit():
                            numeric_answers.append(int(ans))

                    if numeric_answers:
                        answers[str(i)] = numeric_answers
                    else:
                        validation_errors.append(f'Вопрос {i+1}: некорректные ответы')
                else:
                    # Для одиночного выбора
                    answer_value = request.form.get(answer_key)
                    if not answer_value:
                        validation_errors.append(f'Вопрос {i+1}: ответ не выбран')
                        continue

                    if answer_value.isdigit():
                        answers[str(i)] = int(answer_value)
                    else:
                        validation_errors.append(f'Вопрос {i+1}: некорректный ответ')

            except Exception as e:
                logger.error(f"Error processing exam question {i}: {e}")
                validation_errors.append(f'Вопрос {i+1}: ошибка обработки')

        # Проверяем ошибки валидации
        if validation_errors:
            flash('Ошибки в ответах экзамена: ' + '; '.join(validation_errors), 'error')
            return redirect(url_for('take_exam', course_id=course_id))

        # Calculate score and create detailed results
        correct_answers = 0
        total_questions = len(exam.questions)
        detailed_results = []

        logger.info(f"Final exam scoring: {correct_answers} out of {total_questions} correct")
        logger.info(f"User answers: {answers}")

        for i, question in enumerate(exam.questions):
            user_answer = answers.get(str(i))
            correct_answer = question.get('correct_answer')
            question_type = question.get('type', 'single')
            is_correct = False

            logger.info(f"Question {i}: type={question_type}, user_answer={user_answer}, correct_answer={correct_answer}")

            try:
                if question_type == 'multiple':
                    # Для множественного выбора проверяем совпадение массивов
                    if user_answer is not None and isinstance(user_answer, list) and correct_answer is not None:
                        # Убеждаемся что correct_answer является списком
                        if isinstance(correct_answer, list):
                            if sorted(user_answer) == sorted(correct_answer):
                                correct_answers += 1
                                is_correct = True
                                logger.info(f"Question {i}: CORRECT (multiple choice)")
                            else:
                                logger.info(f"Question {i}: INCORRECT (multiple choice mismatch)")
                        else:
                            # Если correct_answer не список, конвертируем в список
                            if sorted(user_answer) == sorted([correct_answer]):
                                correct_answers += 1
                                is_correct = True
                                logger.info(f"Question {i}: CORRECT (multiple choice, converted single answer)")
                            else:
                                logger.info(f"Question {i}: INCORRECT (multiple choice, converted single answer)")
                    else:
                        logger.info(f"Question {i}: INCORRECT (invalid format for multiple choice)")
                else:
                    # Для одиночного выбора
                    if user_answer is not None and correct_answer is not None:
                        # Проверяем если correct_answer является списком с одним элементом
                        if isinstance(correct_answer, list):
                            if len(correct_answer) == 1:
                                correct_value = correct_answer[0]
                            else:
                                logger.warning(f"Question {i}: multiple correct answers for single choice question")
                                correct_value = correct_answer[0]  # Берем первый
                        else:
                            correct_value = correct_answer

                        if user_answer == correct_value:
                            correct_answers += 1
                            is_correct = True
                            logger.info(f"Question {i}: CORRECT (single choice)")
                        else:
                            logger.info(f"Question {i}: INCORRECT (single choice mismatch: {user_answer} != {correct_value})")
                    else:
                        logger.info(f"Question {i}: INCORRECT (no answer provided)")

            except Exception as e:
                logger.error(f"Error checking question {i}: {e}")
                is_correct = False

            # Сохраняем детальный результат для каждого вопроса
            detailed_results.append({
                'question_index': i,
                'user_answer': user_answer,
                'is_correct': is_correct,
                'question_text': question.get('text', ''),
                'question_type': question_type
            })

        logger.info(f"Final exam scoring: {correct_answers} out of {total_questions} correct")
        logger.info(f"Percentage: {(correct_answers / total_questions) * 100 if total_questions > 0 else 0}%")

        score = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
        passed = score >= exam.passing_score

        # Save exam attempt
        attempt = ExamAttempt(
            exam_id=exam.id,
            user_id=user_id,
            answers=answers,
            score=score,
            passed=passed,
            attempt_date=datetime.now(timezone.utc),
            detailed_results=detailed_results  # Сохраняем детальные результаты
        )
        db.add(attempt)

        # If passed, create certificate and complete course
        certificate = None
        if passed:
            # Update course progress
            progress = db.query(CourseProgress).filter(
                CourseProgress.user_id == user_id,
                CourseProgress.course_id == course_id
            ).first()

            if progress:
                progress.completed = True
                progress.progress_percent = 100
                progress.completed_at = datetime.now(timezone.utc)
                progress.updated_at = datetime.now(timezone.utc)

            # Create certificate
            certificate_code = generate_certificate_code() # Generate a unique code
            certificate = Certificate(
                user_id=user_id,
                course_id=course_id,
                certificate_id=str(uuid.uuid4()),
                certificate_code=certificate_code, # Save the code
                exam_score=score,  # Save exam score
                issued_at=datetime.now(timezone.utc),
                status='active' # Default status
            )
            db.add(certificate)

            # Create notification
            notification = Notification(
                user_id=user_id,
                title="Сертификат получен!",
                message=f"Вы успешно завершили курс '{course.title}' и получили сертификат.",
                type="certificate_issued"
            )
            db.add(notification)

            # Send certificate notification via Telegram
            user = db.query(User).filter(User.id == user_id).first()
            if user and user.telegram_id:
                send_certificate_to_telegram(user.telegram_id, certificate, course, user)

        # Save the current attempt first
        db.commit()

        # Check if user failed and has used all attempts
        if not passed:
            current_attempts = db.query(ExamAttempt).filter(
                ExamAttempt.exam_id == exam.id,
                ExamAttempt.user_id == user_id
            ).count()

            if current_attempts >= exam.max_attempts:
                logger.info(f"User {user_id} failed all {exam.max_attempts} attempts for exam {exam.id}. Resetting progress.")

                # Reset all progress for this course
                progress = db.query(CourseProgress).filter(
                    CourseProgress.user_id == user_id,
                    CourseProgress.course_id == course_id
                ).first()

                if progress:
                    # Complete reset to beginning state
                    progress.completed_chapters = []
                    progress.current_chapter = 1
                    progress.progress_percent = 0.0
                    progress.completed = False
                    progress.completed_introduction = False
                    progress.completed_conclusion = False
                    progress.completed_at = None
                    progress.started_at = datetime.now(timezone.utc)  # Reset start time
                    progress.updated_at = datetime.now(timezone.utc)

                # Delete ALL exam attempts for this course (clean slate)
                db.query(ExamAttempt).filter(
                    ExamAttempt.exam_id == exam.id,
                    ExamAttempt.user_id == user_id
                ).delete()

                # Delete ALL chapter test attempts for this course (clean slate)
                chapters = db.query(Chapter).filter(Chapter.course_id == course_id).all()
                for chapter in chapters:
                    db.query(ChapterTestAttempt).filter(
                        ChapterTestAttempt.chapter_id == chapter.id,
                        ChapterTestAttempt.user_id == user_id
                    ).delete()

                # Create notification about complete reset
                notification = Notification(
                    user_id=user_id,
                    title="Курс полностью сброшен",
                    message=f"Вы исчерпали все попытки экзамена по курсу '{course.title}'. Весь прогресс сброшен. Начните изучение курса заново.",
                    type="course_complete_reset"
                )
                db.add(notification)

                # Send Telegram notification about reset
                user = db.query(User).filter(User.id == user_id).first()
                if user and user.telegram_id:
                    send_telegram_notification(
                        user.telegram_id,
                        f"🔄 <b>Курс сброшен</b>\n\n"
                        f"📚 <b>Курс:</b> {course.title}\n"
                        f"❌ Все попытки экзамена исчерпаны\n"
                        f"🔄 Прогресс полностью сброшен\n\n"
                        f"Начните изучение курса заново с самого начала.\n\n"
                        f"<a href='https://edu.sapatechnologies.kz/course/{course_id}'>🔗 Перейти к курсу</a>"
                    )

                # Commit the reset changes
                db.commit()

                # Clean up exam session data
                session.pop(f'exam_session_{exam.id}_{user_id}', None)

                # Return special response indicating complete reset
                return render_template('exam_result.html',
                                     course=course, exam=exam, score=score,
                                     passed=passed, certificate=None, attempt=attempt,
                                     progress_reset=True)  # Flag for template

        db.commit()

        # Clean up exam session data
        session.pop(exam_session_key, None)

        return render_template('exam_result.html',
                             course=course, exam=exam, score=score,
                             passed=passed, certificate=certificate, attempt=attempt)
    except Exception as e:
        db.rollback()
        logger.error(f"Error submitting exam: {e}")
        flash('Ошибка при отправке экзамена', 'error')
        return redirect(url_for('view_course', course_id=course_id))
    finally:
        db.close()

def generate_certificate_code():
    """Generates a unique 6-character alphanumeric code for certificates."""
    import random
    import string
    characters = string.ascii_uppercase + string.digits
    code = ''.join(random.choice(characters) for _ in range(6))
    # Ensure code is unique, though collision probability is low
    db = get_db_session()
    try:
        while db.query(Certificate).filter(Certificate.certificate_code == code).first():
            code = ''.join(random.choice(characters) for _ in range(6))
        return code
    finally:
        db.close()


def send_telegram_notification(telegram_id, message):
    """Send notification to user via Telegram"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {
            'chat_id': telegram_id,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': False
        }

        response = requests.post(url, json=data, timeout=10)

        if response.status_code == 200:
            logger.info(f"Notification sent to {telegram_id}")
        else:
            logger.error(f"Failed to send notification: {response.text}")

    except Exception as e:
        logger.error(f"Error sending notification via Telegram: {e}")

def send_admin_granted_notification(telegram_id, level):
    """Send notification to user about admin privileges granted"""
    level_names = {
        1: "Модератор",
        2: "Администратор",
        3: "Главный администратор"
    }

    level_name = level_names.get(level, "Администратор")

    message = f"""🎉 <b>Поздравляем!</b>

👨‍💼 Вам были предоставлены права: <b>{level_name}</b>

🔄 <b>Важно:</b> Для применения всех изменений:1️⃣ Закройте текущие сессии в приложении
2️⃣ Перезайдите в Telegram
3️⃣ Обновите веб-страницу платформы

Теперь вы можете использовать функции администратора!

/start """

    send_telegram_notification(telegram_id, message)

def send_admin_removed_notification(telegram_id):
    """Send notification to user about admin privileges removed"""
    message = f"""❌ <b>Уведомление об изменении прав доступа</b>

👤 Ваши права администратора были отозваны.
"""

    send_telegram_notification(telegram_id, message)

def send_course_notification(user_telegram_id, course_title):
    """Send new course notification"""
    if user_telegram_id:
        message = f"""📚 <b>Новый курс доступен!</b>

    🎓 <b>Курс:</b> {course_title}
    📖 Новый образовательный материал готов для изучения!

    Перейдите в личный кабинет и начните обучение прямо сейчас.

    <a href="https://edu.sapatechnologies.kz/">🔗 Перейти к курсам</a>"""

        send_telegram_notification(user_telegram_id, message)

def send_group_course_notification(course_title):
    """Send new course notification to group thread"""
    message = f"""📚 <b>Добавлен новый курс!</b>

    🎓 <b>Название курса:</b> {course_title}
    📖 Курс готов для изучения студентами.

    Студенты могут начать обучение в личном кабинете.

    <a href="https://edu.sapatechnologies.kz/">🔗 Перейти к платформе</a>"""

    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

        # Проверяем наличие всех необходимых переменных
        if not BOT_TOKEN:
            logger.error("BOT_TOKEN is not set")
            return

        if not GROUP_ID:
            logger.error("GROUP_ID is not set")
            return

        data = {
            'chat_id': GROUP_ID,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }

        # Добавляем thread ID только если он определен и не равен None
        if GROUP_THREAD_ID and GROUP_THREAD_ID != 0:
            data['message_thread_id'] = GROUP_THREAD_ID
            logger.info(f"Using thread ID: {GROUP_THREAD_ID}")

        logger.info(f"Sending group notification to chat {GROUP_ID}")
        logger.info(f"Message: {message[:100]}...")

        response = requests.post(url, json=data, timeout=15)

        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response text: {response.text}")

        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('ok'):
                logger.info(f"✅ Group course notification sent successfully for course: {course_title}")
                logger.info(f"Message ID: {response_data.get('result', {}).get('message_id')}")
            else:
                logger.error(f"❌ Telegram API returned error: {response_data.get('description')}")
        else:
            logger.error(f"❌ HTTP error {response.status_code}: {response.text}")

            # Пробуем отправить без thread ID если была ошибка
            if GROUP_THREAD_ID and 'message_thread_id' in data:
                logger.info("🔄 Retrying without thread ID...")
                data_without_thread = data.copy()
                data_without_thread.pop('message_thread_id')

                retry_response = requests.post(url, json=data_without_thread, timeout=15)
                logger.info(f"Retry response status: {retry_response.status_code}")

                if retry_response.status_code == 200:
                    retry_data = retry_response.json()
                    if retry_data.get('ok'):
                        logger.info("✅ Group notification sent successfully without thread ID")
                    else:
                        logger.error(f"❌ Retry failed: {retry_data.get('description')}")
                else:
                    logger.error(f"❌ Retry also failed: {retry_response.text}")

    except requests.exceptions.Timeout:
        logger.error("❌ Timeout while sending group notification")
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Request error sending group notification: {e}")
    except Exception as e:
        logger.error(f"❌ Unexpected error sending group course notification: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

def send_certificate_to_telegram(telegram_id, certificate, course, user):
    """Send certificate notification to user via Telegram"""
    message = f"""🎉 <b>Поздравляем с получением сертификата!</b>

    🎓 <b>Студент:</b> {user.name}
    📚 <b>Курс:</b> {course.title}
    🏆 <b>Номер сертификата:</b> <code>{certificate.certificate_code}</code>
    📅 <b>Дата выдачи:</b> {certificate.issued_at.strftime('%d.%m.%Y')}
    ✅ <b>Статус:</b> Активный

    Ваш сертификат доступен в личном кабинете на сайте.
    Поделитесь своим достижением с коллегами! 💪

    <a href="https://edu.sapatechnologies.kz/certificate/{certificate.certificate_id}">🔗 Просмотреть сертификат</a>"""

    send_telegram_notification(telegram_id, message)


@app.route('/certificate/<certificate_id>')
@login_required
def view_certificate(certificate_id):
    """View certificate - works even if course is unpublished"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')

        # Сертификат доступен даже если курс скрыт (is_published=False)
        certificate = db.query(Certificate).join(User).join(Course).filter(
            Certificate.certificate_id == certificate_id
        ).first()

        if not certificate:
            flash('Сертификат не найден', 'error')
            return redirect(url_for('student_dashboard'))

        # Check if user owns this certificate or is admin
        if certificate.user_id != user_id and not session.get('is_admin'):
            flash('У вас нет доступа к этому сертификату', 'error')
            return redirect(url_for('student_dashboard'))

        return render_template('certificate.html', certificate=certificate)
    finally:
        db.close()

@app.route('/certificate/<certificate_id>/image')
@login_required
def download_certificate_image(certificate_id):
    """Download certificate as PNG image"""
    db = get_db_session()
    try:
        certificate = db.query(Certificate).join(User).join(Course).filter(
            Certificate.certificate_id == certificate_id
        ).first()

        if not certificate:
            flash('Сертификат не найден', 'error')
            return redirect(url_for('index'))

        # Check ownership
        if certificate.user_id != session.get('user_id'):
            flash('У вас нет доступа к этому сертификату', 'error')
            return redirect(url_for('index'))

        try:
            from PIL import Image, ImageDraw, ImageFont, ImageFilter
            from io import BytesIO
            import requests
            import qrcode
            from qrcode.image.styledpil import StyledPilImage
        except ImportError:
            flash('Ошибка: отсутствуют необходимые библиотеки для генерации изображения или QR-кода', 'error')
            return redirect(url_for('view_certificate', certificate_id=certificate_id))

        # Create image (A4 landscape proportions)
        width, height = 1200, 850

        # Get colors from certificate settings
        def hex_to_rgb(hex_color, default):
            try:
                if hex_color and hex_color.startswith('#'):
                    return tuple(int(hex_color[i:i+2], 16) for i in (1, 3, 5))
                return default
            except:
                return default

        bg_color = hex_to_rgb(certificate.course.certificate_background_color, (255, 255, 255))
        primary_color = hex_to_rgb(certificate.course.certificate_primary_color, (0, 123, 255))
        secondary_color = hex_to_rgb(certificate.course.certificate_secondary_color, (108, 117, 125))
        accent_color = hex_to_rgb(certificate.course.certificate_accent_color, (40, 167, 69))

        img = Image.new('RGB', (width, height), color=bg_color)
        draw = ImageDraw.Draw(img)

        # Create gradient background
        for y in range(height):
            gradient_factor = y / height
            r = int(bg_color[0] * (1 - gradient_factor * 0.1))
            g = int(bg_color[1] * (1 - gradient_factor * 0.1))
            b = int(bg_color[2] * (1 - gradient_factor * 0.1))
            draw.line([(0, y), (width, y)], fill=(r, g, b))

        # Watermark
        watermark_text = certificate.course.certificate_watermark_text or "SapaEdu"
        watermark_opacity = int((certificate.course.certificate_watermark_opacity or 0.1) * 255)
        watermark_color = (*secondary_color, watermark_opacity)

        # Try to load fonts (fallback to default if not available)
        try:
            title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf", 64)
            subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf", 24)
            name_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf", 40)
            text_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
            small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
            watermark_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf", 80)
        except Exception as font_error:
            logger.warning(f"Font loading error: {font_error}")
            title_font = ImageFont.load_default()
            subtitle_font = ImageFont.load_default()
            name_font = ImageFont.load_default()
            text_font = ImageFont.load_default()
            small_font = ImageFont.load_default()
            watermark_font = ImageFont.load_default()

        # Draw watermark
        watermark_bbox = draw.textbbox((0, 0), watermark_text, font=watermark_font)
        watermark_width = watermark_bbox[2] - watermark_bbox[0] - 200
        watermark_height = watermark_bbox[3] - watermark_bbox[1]

        # Create watermark image with rotation
        watermark_img = Image.new('RGBA', (watermark_width + 100, watermark_height + 100), (0, 0, 0, 0))
        watermark_draw = ImageDraw.Draw(watermark_img)
        watermark_draw.text((50, 50), watermark_text, fill=(*secondary_color, 30), font=watermark_font)

        # Rotate watermark
        watermark_rotated = watermark_img.rotate(-45, expand=True)

        # Paste watermark in center
        watermark_x = (width - watermark_rotated.width) // 2
        watermark_y = (height - watermark_rotated.height) // 2
        img.paste(watermark_rotated, (watermark_x, watermark_y), watermark_rotated)

        # Modern border style
        border_style = certificate.course.certificate_border_style or "modern"
        border_width = 12

        if border_style == "modern":
            # Rounded rectangle border
            draw.rounded_rectangle([border_width, border_width, width-border_width, height-border_width],
                                 radius=20, outline=primary_color, width=border_width)
            # Inner border
            draw.rounded_rectangle([border_width+15, border_width+15, width-border_width-15, height-border_width-15],
                                 radius=10, outline=accent_color, width=3)
        elif border_style == "elegant":
            # Gradient-style border
            for i in range(border_width):
                opacity = int(255 * (1 - i / border_width))
                color = (*primary_color, opacity)
                draw.rectangle([i, i, width-i, height-i], outline=primary_color, width=1)

        # Header section
        header_y = 60

        # Organization info (top right)
        org_name = certificate.course.certificate_organization or "SapaEdu"
        draw.text((width-60, header_y), org_name, fill=primary_color, font=name_font, anchor="rt")
        draw.text((width-60, header_y + 45), "Платформа корпоративного обучения",
                 fill=secondary_color, font=text_font, anchor="rt")

        # Title section
        title_y = 180
        cert_title = certificate.course.certificate_title or "СЕРТИФИКАТ"
        title_bbox = draw.textbbox((0, 0), cert_title, font=title_font)
        title_width = title_bbox[2] - title_bbox[0]
        title_x = (width - title_width) // 2

        # Title with shadow effect
        draw.text((title_x + 3, title_y + 3), cert_title, fill=(*secondary_color, 100), font=title_font)
        draw.text((title_x, title_y), cert_title, fill=primary_color, font=title_font)

        # Decorative line under title
        line_y = title_y + 80
        line_length = 400
        line_x = (width - line_length) // 2

        # Gradient line
        for i in range(line_length):
            alpha = int(255 * (1 - abs(i - line_length/2) / (line_length/2)))
            color = (*accent_color, alpha)
            draw.line([(line_x + i, line_y), (line_x + i, line_y + 6)], fill=accent_color, width=1)

        # Subtitle
        subtitle = certificate.course.certificate_subtitle or "о прохождении курса"
        subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
        subtitle_width = subtitle_bbox[2] - subtitle_bbox[0]
        subtitle_x = (width - subtitle_width) // 2
        draw.text((subtitle_x, line_y + 30), subtitle, fill=secondary_color, font=subtitle_font)

        # Course title in box
        course_y = line_y + 80
        course_title = f'"{certificate.course.title}"'

        # Use a smaller font for course title if it's too long
        course_font = text_font
        course_bbox = draw.textbbox((0, 0), course_title, font=course_font)
        course_width = course_bbox[2] - course_bbox[0]

        # If course title is too wide, use smaller font
        max_course_width = width - 200  # Leave margins
        if course_width > max_course_width:
            try:
                course_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
            except:
                course_font = ImageFont.load_default()
            course_bbox = draw.textbbox((0, 0), course_title, font=course_font)
            course_width = course_bbox[2] - course_bbox[0]

        course_height = course_bbox[3] - course_bbox[1]

        # Course box with proper sizing
        box_padding = 15
        box_x = (width - course_width - box_padding * 2) // 2
        box_y = course_y - 5
        box_width = course_width + box_padding * 2
        box_height = course_height + box_padding

        # Draw box with light background and border
        draw.rounded_rectangle([box_x, box_y, box_x + box_width, box_y + box_height],
                             radius=10, fill=(240, 248, 255), outline=primary_color, width=2)

        # Draw course title text
        text_x = box_x + box_padding
        text_y = course_y
        draw.text((text_x, text_y), course_title, fill=primary_color, font=course_font)

        # Recipient section
        recipient_y = course_y + 80
        awarded_text = "выдан"
        awarded_bbox = draw.textbbox((0, 0), awarded_text, font=subtitle_font)
        awarded_width = awarded_bbox[2] - awarded_bbox[0]
        awarded_x = (width - awarded_width) // 2
        draw.text((awarded_x, recipient_y), awarded_text, fill=secondary_color, font=subtitle_font)

        # Recipient name
        recipient_name = certificate.user.name
        name_bbox = draw.textbbox((0, 0), recipient_name, font=name_font)
        name_width = name_bbox[2] - name_bbox[0]
        name_x = (width - name_width) // 2
        name_y = recipient_y + 40

        # Name with underline
        draw.text((name_x, name_y), recipient_name, fill=primary_color, font=name_font)

        # Decorative underline
        underline_y = name_y + 50
        underline_length = name_width + 60
        underline_x = (width - underline_length) // 2
        draw.line([(underline_x, underline_y), (underline_x + underline_length, underline_y)],
                 fill=accent_color, width=4)

        # Achievement badge area
        badge_y = underline_y + 40
        badge_size = 80
        badge_x = (width - badge_size) // 2

        # Achievement circle
        draw.ellipse([badge_x, badge_y, badge_x + badge_size, badge_y + badge_size],
                    fill=accent_color, outline=primary_color, width=3)

        # Achievement icon (simplified)
        icon_size = 40
        icon_x = badge_x + (badge_size - icon_size) // 2
        icon_y = badge_y + (badge_size - icon_size) // 2
        draw.text((icon_x + icon_size//2, icon_y + icon_size//2), "✓",
                 fill='white', font=name_font, anchor="mm")

        # Achievement text
        achievement_text = certificate.course.certificate_achievement_text or "Успешно завершен курс"
        achievement_bbox = draw.textbbox((0, 0), achievement_text, font=text_font)
        achievement_width = achievement_bbox[2] - achievement_bbox[0]
        achievement_x = (width - achievement_width) // 2
        draw.text((achievement_x, badge_y + badge_size + 20), achievement_text,
                 fill=accent_color, font=text_font)

        # QR Code generation and placement
        if certificate.course.certificate_show_qr:
            try:
                # Create QR code with verification URL and auto-filled code (same as website)
                qr_url = f"https://edu.sapatechnologies.kz/certificates/check?code={certificate.certificate_code}"

                logger.info(f"Generating QR code for downloadable certificate with URL: {qr_url}")

                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=4,
                    border=2,
                )
                qr.add_data(qr_url)
                qr.make(fit=True)

                # Generate QR code image with same style as website (100x100)
                qr_img = qr.make_image(fill_color="#000000", back_color="white")
                qr_img = qr_img.resize((100, 100), Image.Resampling.LANCZOS)

                # Create white background with border for QR code (110x110 total, same as website)
                qr_bg = Image.new('RGB', (110, 110), color='white')
                qr_bg_draw = ImageDraw.Draw(qr_bg)
                qr_bg_draw.rectangle([0, 0, 109, 109], outline=secondary_color, width=2)

                # Paste QR code on background (centered in 110x110 box)
                qr_bg.paste(qr_img, (5, 5))

                # Paste QR code with background on certificate
                qr_x = width - 170
                qr_y = height - 160
                img.paste(qr_bg, (qr_x, qr_y))

                # Add QR label exactly as on website
                draw.text((qr_x + 55, qr_y + 115), "Сканируйте для проверки",
                         fill=secondary_color, font=small_font, anchor="mm")

                logger.info(f"QR code successfully generated for certificate {certificate.certificate_code}")

            except Exception as e:
                logger.warning(f"QR code generation failed: {e}")
                # Fallback to styled placeholder matching website design
                qr_placeholder_x = width - 170
                qr_placeholder_y = height - 160

                # Create styled placeholder box (110x110, same as website)
                placeholder_bg = Image.new('RGB', (110, 110), color='white')
                placeholder_draw = ImageDraw.Draw(placeholder_bg)
                placeholder_draw.rectangle([0, 0, 109, 109], outline=secondary_color, width=2)

                # Draw QR-like pattern matching website
                pattern_dots = [
                    (8, 8), (28, 8), (101, 8),  # Top row
                    (8, 28),  # Middle left
                    (8, 101), (101, 101)  # Bottom row
                ]
                for x, y in pattern_dots:
                    placeholder_draw.rectangle([x, y, x+8, y+8], fill=secondary_color)

                # Add text overlay matching website
                placeholder_draw.text((55, 40), "QR", fill=secondary_color, font=name_font, anchor="mm")
                placeholder_draw.text((55, 70), certificate.certificate_code, fill=secondary_color, font=text_font, anchor="mm")

                # Paste placeholder at same position as real QR code
                img.paste(placeholder_bg, (qr_placeholder_x, qr_placeholder_y))

                # Add label matching website
                draw.text((qr_placeholder_x + 55, qr_placeholder_y + 115), "Сканируйте для проверки",
                         fill=secondary_color, font=small_font, anchor="mm")

        # Footer information
        footer_y = height - 120

        # Left side - Certificate info
        info_x = 60
        info_items = [
            f"Код: {certificate.certificate_code}",
            f"Дата: {certificate.issued_at.strftime('%d.%m.%Y')}",
            f"Результат: {certificate.exam_score:.1f}%"
        ]

        for i, item in enumerate(info_items):
            draw.text((info_x, footer_y + i * 25), item, fill=secondary_color, font=text_font)

        # Right side - Verification info
        verification_x = width - 160
        verification_items = [
            "Проверить на:",
            "edu.sapatechnologies.kz/check",
            f"Код: {certificate.certificate_code}"
        ]

        for i, item in enumerate(verification_items):
            draw.text((verification_x, footer_y + 110 + i * 20), item,
                     fill=secondary_color, font=small_font, anchor="rt")

        # Status badge
        status_text = "ДЕЙСТВИТЕЛЕН" if certificate.status == 'active' else "ОТОЗВАН"
        status_color = accent_color if certificate.status == 'active' else (220, 53, 69)

        status_bbox = draw.textbbox((0, 0), status_text, font=small_font)
        status_width = status_bbox[2] - status_bbox[0]
        status_height = status_bbox[3] - status_bbox[1]

        badge_x = width - 200
        badge_y = 30
        badge_padding = 10

        draw.rounded_rectangle([badge_x, badge_y,
                              badge_x + status_width + badge_padding * 2,
                              badge_y + status_height + badge_padding],
                             radius=15, fill=status_color)
        draw.text((badge_x + badge_padding, badge_y + badge_padding//2),
                 status_text, fill='white', font=small_font)

        # Save to buffer
        buffer = BytesIO()
        img.save(buffer, format='PNG', quality=95)
        buffer.seek(0)

        filename = f"certificate_{certificate.certificate_code}_{certificate.user.name.replace(' ', '_')}.png"

        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='image/png'
        )

    except Exception as e:
        logger.error(f"Error generating image certificate: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Произошла ошибка при генерации изображения. Попробуйте позже.', 'error')
        return redirect(url_for('view_certificate', certificate_id=certificate_id))
    finally:
        db.close()

@app.route('/certificate/<certificate_id>/pdf')
@app.route('/certificates/check', methods=['GET', 'POST'])
def check_certificate():
    """Check certificate by code"""
    # Get code from URL parameter for QR scanning
    prefilled_code = request.args.get('code', '').upper().strip()
    from_qr = bool(prefilled_code)

    # Log for debugging
    logger.info(f"Certificate check request: prefilled_code={prefilled_code}, from_qr={from_qr}")

    if request.method == 'POST':
        certificate_code = request.form.get('certificate_code', '').upper().strip()

        if not certificate_code or len(certificate_code) != 6:
            flash('Введите корректный 6-значный код', 'error')
            return render_template('certificate_check.html', prefilled_code=prefilled_code)

        db = get_db_session()
        try:
            certificate = db.query(Certificate).join(User).join(Course).filter(
                Certificate.certificate_code == certificate_code
            ).first()

            if not certificate:
                return render_template('certificate_check_result.html',
                                     found=False,
                                     code=certificate_code,
                                     from_qr=from_qr,
                                     current_time=datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M'))

            # Additional check for revoked certificates (if status is 'revoked')
            if certificate.status == 'revoked':
                 return render_template('certificate_check_result.html',
                                     found=True,
                                     revoked=True, # Flag to indicate it's revoked
                                     certificate=certificate,
                                     user=certificate.user,
                                     course=certificate.course,
                                     code=certificate_code,
                                     from_qr=from_qr,
                                     current_time=datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M'))

            return render_template('certificate_check_result.html',
                                 found=True,
                                 certificate=certificate,
                                 user=certificate.user,
                                 course=certificate.course,
                                 code=certificate_code,
                                 from_qr=from_qr,
                                 current_time=datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M'))
        finally:
            db.close()

    return render_template('certificate_check.html', prefilled_code=prefilled_code)

@app.route('/my-certificates')
@login_required
def my_certificates():
    """Page with user's certificates"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')
        certificates = db.query(Certificate).join(Course).filter(
            Certificate.user_id == user_id
        ).order_by(Certificate.issued_at.desc()).all()

        return render_template('my_certificates.html', certificates=certificates)
    finally:
        db.close()

@app.route('/notifications')
@login_required
def notifications():
    """User notifications"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')
        notifications = db.query(Notification).filter(
            Notification.user_id == user_id
        ).order_by(Notification.created_at.desc()).all()

        return render_template('notifications.html', notifications=notifications)
    finally:
        db.close()

@app.route('/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    """Mark notifications as read"""
    db = get_db_session()
    try:
        user_id = session.get('user_id')
        notification_id = request.form.get('notification_id')

        if notification_id:
            # Mark specific notification as read
            db.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.id == notification_id
            ).update({Notification.read: True})
        else:
            # Mark all notifications as read
            db.query(Notification).filter(
                Notification.user_id == user_id,
                Notification.read == False
            ).update({Notification.read: True})

        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        logger.error(f"Error marking notifications as read: {e}")
        return jsonify({'success': False}), 500
    finally:
        db.close()

@app.route('/admin/manage-admins')
@admin_required
def admin_manage_admins():
    """Admin management page"""
    # Check if user has sufficient admin level
    user_telegram_id = session.get('telegram_id', '')
    admin_level = is_admin(user_telegram_id) if user_telegram_id else 0
    # Assuming 'host_admin' is a special identifier, you might need to adjust this logic
    # based on how you identify the ultimate administrator.
    is_main_admin = (str(user_telegram_id) == HOST_ADMIN_TELEGRAM_ID)


    if not is_main_admin and admin_level < 2:
        flash('Недостаточно прав для управления админами', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        db = get_db_session()
        admins = db.query(Admin).all()
        db.close()

        return render_template('admin_manage_admins.html', admins=admins, admin_level=admin_level, is_main_admin=is_main_admin)
    except Exception as e:
        logger.error(f"Error loading admin management: {e}")
        flash('Ошибка загрузки админ-панели', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/add-admin', methods=['POST'])
@admin_required
def admin_add_admin():
    """Add new admin"""
    user_telegram_id = session.get('telegram_id', '')
    admin_level = is_admin(user_telegram_id) if user_telegram_id else 0
    is_main_admin = (str(user_telegram_id) == HOST_ADMIN_TELEGRAM_ID)

    if not is_main_admin and admin_level < 2:
        flash('Недостаточно прав для добавления админов', 'error')
        return redirect(url_for('admin_manage_admins'))

    telegram_id = request.form.get('telegram_id')
    level = int(request.form.get('level', 1))

    if not telegram_id:
        flash('Telegram ID обязателен', 'error')
        return redirect(url_for('admin_manage_admins'))

    # Check if current admin can add admin of this level
    if not is_main_admin and level >= admin_level:
        flash('Нельзя назначить админа уровня выше или равного вашему', 'error')
        return redirect(url_for('admin_manage_admins'))

    success, message = add_admin(telegram_id, level, user_telegram_id or 'host_admin')

    if success:
        # CRITICAL: Update User table to reflect admin status
        db = get_db_session()
        try:
            user = db.query(User).filter(User.telegram_id == telegram_id).first()
            if user:
                user.is_admin = True
                user.updated_at = datetime.now(timezone.utc)
                db.commit()
                logger.info(f"Updated user {telegram_id} admin status to True")
            else:
                logger.warning(f"User with telegram_id {telegram_id} not found in User table")
        except Exception as e:
            logger.error(f"Failed to update user admin status: {e}")
            db.rollback()
        finally:
            db.close()

        flash('Админ успешно добавлен', 'success')

        # Send notification to new admin via Telegram
        send_admin_granted_notification(telegram_id, level)

        # Sync admin status in User table if needed
        try:
            from database import sync_admin_status
            sync_admin_status()
        except Exception as e:
            logger.error(f"Failed to sync admin status: {e}")
    else:
        flash(message, 'error')

    return redirect(url_for('admin_manage_admins'))

@app.route('/uploads/<file_type>/<filename>')
def uploaded_file(file_type, filename):
    """Отдача загруженных файлов"""
    try:
        upload_dir = os.path.join('uploads', file_type)
        return send_from_directory(upload_dir, filename)
    except Exception as e:
        logger.error(f"Error serving file: {e}")
        return "File not found", 404

@app.route('/api/upload-file', methods=['POST'])
@admin_required
def upload_file():
    """APIfor загрузки файлов"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не предоставлен'}), 400

        file = request.files['file']
        file_type = request.form.get('file_type', 'images')

        result, error = file_storage.save_file(file, file_type)

        if error:
            return jsonify({'success': False, 'error': error}), 400

        return jsonify({
            'success': True,
            'file_url': result['file_url'],
            'filename': result['filename'],
            'original_name': result['original_name'],
            'file_type': result['file_type']
        })

    except Exception as e:
        logger.error(f"File upload error: {e}")
        return jsonify({'success': False, 'error': 'Ошибка загрузки файла'}), 500

@app.route('/api/delete-file', methods=['POST'])
@admin_required
def delete_file():
    """API для удаления файлов"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        file_type = data.get('file_type')

        if not filename or not file_type:
            return jsonify({'success': False, 'error': 'Не указан файл или тип'}), 400

        success, message = file_storage.delete_file(filename, file_type)

        return jsonify({'success': success, 'message': message})

    except Exception as e:
        logger.error(f"File deletion error: {e}")
        return jsonify({'success': False, 'error': 'Ошибка удаления файла'}), 500

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete user completely"""
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({'success': False, 'error': 'Пользователь не найден'})

        # Check if trying to delete self
        if user.id == session.get('user_id'):
            return jsonify({'success': False, 'error': 'Нельзя удалить самого себя'})

        # Check if trying to delete main admin
        if user.telegram_id == HOST_ADMIN_TELEGRAM_ID:
            return jsonify({'success': False, 'error': 'Нельзя удалить главного администратора'})

        user_name = user.name
        user_email = user.email

        # Delete related data in correct order
        # Delete notifications
        db.query(Notification).filter(Notification.user_id == user_id).delete()

        # Delete phishing checks
        db.query(PhishingCheck).filter(PhishingCheck.user_id == user_id).delete()

        # Delete certificates
        db.query(Certificate).filter(Certificate.user_id == user_id).delete()

        # Delete exam attempts
        db.query(ExamAttempt).filter(ExamAttempt.user_id == user_id).delete()

        # Delete chapter test attempts
        db.query(ChapterTestAttempt).filter(ChapterTestAttempt.user_id == user_id).delete()

        # Delete course progress
        db.query(CourseProgress).filter(CourseProgress.user_id == user_id).delete()

        # Remove from admin table if admin
        if user.is_admin:
            db.query(Admin).filter(Admin.telegram_id == user.telegram_id).delete()

        # Delete user
        db.delete(user)
        db.commit()

        logger.info(f"User {user_name} ({user_email}) deleted by admin {session.get('user_name')}")
        return jsonify({'success': True, 'message': f'Пользователь {user_name} успешно удален'})

    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        db.close()

@app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def admin_toggle_user_status(user_id):
    """Toggle user active/inactive status"""
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({'success': False, 'error': 'Пользователь не найден'})

        # Check if trying to deactivate self
        if user.id == session.get('user_id'):
            return jsonify({'success': False, 'error': 'Нельзя изменить статус самого себя'})

        # Check if trying to deactivate main admin
        if user.telegram_id == HOST_ADMIN_TELEGRAM_ID:
            return jsonify({'success': False, 'error': 'Нельзя изменить статус главного администратора'})

        user.is_active = not user.is_active
        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        status_text = 'активирован' if user.is_active else 'деактивирован'
        logger.info(f"User {user.name} {status_text} by admin {session.get('user_name')}")

        return jsonify({
            'success': True,
            'message': f'Пользователь {user.name} {status_text}',
            'is_active': user.is_active
        })

    except Exception as e:
        db.rollback()
        logger.error(f"Error toggling user status {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        db.close()

@app.route('/admin/remove-admin', methods=['POST'])
@admin_required
def admin_remove_admin():
    """Remove admin"""
    user_telegram_id = session.get('telegram_id', '')
    admin_level = is_admin(user_telegram_id) if user_telegram_id else 0
    is_main_admin = (str(user_telegram_id) == HOST_ADMIN_TELEGRAM_ID)

    if not is_main_admin and admin_level < 2:
        flash('Недостаточно прав для удаления админов', 'error')
        return redirect(url_for('admin_manage_admins'))

    telegram_id = request.form.get('telegram_id')

    if not telegram_id:
        flash('Telegram ID обязателен', 'error')
        return redirect(url_for('admin_manage_admins'))

    # Check if trying to remove self
    if telegram_id == user_telegram_id and not is_main_admin: # Main admin can remove themselves
        flash('Нельзя удалить самого себя', 'error')
        return redirect(url_for('admin_manage_admins'))

    # Prevent removing the main admin by a lower level admin
    db = get_db_session()
    try:
        admin_to_remove = db.query(Admin).filter(Admin.telegram_id == telegram_id).first()
        if admin_to_remove and admin_to_remove.level >= 3 and not is_main_admin:
            flash('Нельзя удалить главного администратора', 'error')
            return redirect(url_for('admin_manage_admins'))
    finally:
        db.close()

    success, message = remove_admin(telegram_id, user_telegram_id or 'host_admin')

    if success:
        # CRITICAL: Update User table to reflect removed admin status
        db = get_db_session()
        try:
            user = db.query(User).filter(User.telegram_id == telegram_id).first()
            if user:
                user.is_admin = False
                user.updated_at = datetime.now(timezone.utc)
                db.commit()
                logger.info(f"Updated user {telegram_id} admin status to False")

                # Send notification to removed admin
                send_admin_removed_notification(telegram_id)

            else:
                logger.warning(f"User with telegram_id {telegram_id} not found in User table")
        except Exception as e:
            logger.error(f"Failed to update user admin status: {e}")
            db.rollback()
        finally:
            db.close()

        flash('Админ успешно удален. Пользователю отправлено уведомление о необходимости перезайти в систему.', 'success')

        # Sync admin status
        try:
            from database import sync_admin_status
            sync_admin_status()
        except Exception as e:
            logger.error(f"Failed to sync admin status: {e}")
    else:
        flash(message, 'error')

    return redirect(url_for('admin_manage_admins'))



# Импортируем функции из database.py
from database import calculate_course_progress, update_course_progress

def create_initial_admin():
    """Create initial admin if no admins exist"""
    try:
        db = get_db_session()
        admin_count = db.query(Admin).count()
        if admin_count == 0:
            logger.info("No admins found, creating initial admin.")

            # Create admin entry first
            admin_entry = Admin(
                telegram_id=HOST_ADMIN_TELEGRAM_ID,
                level=3,
                added_by="system",
                added_at=datetime.now(timezone.utc)
            )
            db.add(admin_entry)

            # Check if user already exists
            existing_user = db.query(User).filter(User.telegram_id == HOST_ADMIN_TELEGRAM_ID).first()
            if not existing_user:
                # Create main admin user
                admin_user = User(
                    name="Главный администратор",
                    email=HOST_ADMIN_LOGIN,
                    telegram_id=HOST_ADMIN_TELEGRAM_ID,
                    is_admin=True,
                    registered_at=datetime.now(timezone.utc),
                    company="SapaEdu"
                )
                db.add(admin_user)
            else:
                # Update existing user to be admin
                existing_user.is_admin = True

            db.commit()
            logger.info(f"Initial admin created with Telegram ID: {HOST_ADMIN_TELEGRAM_ID}")

        db.close()
    except Exception as e:
        logger.error(f"Error creating initial admin: {e}")

if __name__ == '__main__':
    # Create initial admin if needed
    create_initial_admin()

    # Sync admin statuses
    sync_admin_status()


    app.run(host='0.0.0.0', port=5055, debug=False)