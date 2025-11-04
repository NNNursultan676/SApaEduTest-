
import os
import logging
import asyncio
from datetime import datetime, timezone
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.error import TelegramError

from config import BOT_TOKEN, GROUP_ID, HOST_ADMIN_TELEGRAM_ID
from database import get_db_session, User
from bot_translations import get_text
from admins import is_admin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# User states for registration process
USER_STATES = {}

class RegistrationState:
    AWAITING_NAME = "awaiting_name"
    AWAITING_SURNAME = "awaiting_surname"
    AWAITING_EMAIL = "awaiting_email"
    AWAITING_COMPANY = "awaiting_company"
    COMPLETED = "completed"

class BotKeyboards:
    @staticmethod
    def get_language_keyboard():
        """Language selection keyboard"""
        keyboard = [
            [InlineKeyboardButton("🇰🇿 Қазақша", callback_data="lang_kz")],
            [InlineKeyboardButton("🇷🇺 Русский", callback_data="lang_ru")],
            [InlineKeyboardButton("🇺🇸 English", callback_data="lang_en")]
        ]
        return InlineKeyboardMarkup(keyboard)

    @staticmethod
    def get_main_menu_keyboard(user_language, user_id=None):
        """Main menu keyboard with website link and web app"""
        from config import WEB_APP_URL
        website_url = f"{WEB_APP_URL}/"
        if user_id:
            website_url = f"{WEB_APP_URL}/?telegram_id={user_id}"

        keyboard = [
            [InlineKeyboardButton(
                get_text(user_language, 'open_webapp'), 
                web_app={'url': website_url}
            )]
        ]
        
        # Add website button for all users (both students and admins)
        if user_id:
            keyboard.append([InlineKeyboardButton(
                get_text(user_language, 'website'), 
                url=website_url
            )])
        
        return InlineKeyboardMarkup(keyboard)

    @staticmethod
    def get_company_selection_keyboard(user_language):
        """Company selection keyboard"""
        from config import COMPANIES
        
        company_mapping = {
            'Sapa Technologies': 'company_sapa_tech',
            'Neo Factoring': 'company_neo_factoring', 
            'Sapa Digital Finance': 'company_sapa_finance',
            'AlgaPay': 'company_algapay',
            'AI Parking': 'company_ai_parking',
            'Sapa Digital Communications': 'company_sapa_communications',
            'Sapa Solutions': 'company_sapa_solutions'
        }
        
        keyboard = []
        for company in COMPANIES:
            callback_data = company_mapping.get(company, f"company_{company.lower().replace(' ', '_')}")
            keyboard.append([InlineKeyboardButton(company, callback_data=callback_data)])
            
        return InlineKeyboardMarkup(keyboard)

async def check_group_membership(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> bool:
    """Check if user is member of the required group"""
    try:
        member = await context.bot.get_chat_member(chat_id=GROUP_ID, user_id=user_id)
        return member.status in ['member', 'administrator', 'creator']
    except TelegramError as e:
        logger.error(f"Error checking group membership: {e}")
        return False

async def get_user_language(user_id: int) -> str:
    """Get user's preferred language from database"""
    return 'ru'  # Default to Russian

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    user = update.effective_user
    user_id = user.id

    # Check group membership first  
    is_member = await check_group_membership(context, user_id)
    is_host_admin = str(user_id) == HOST_ADMIN_TELEGRAM_ID

    if not is_member and not is_host_admin:
        # Send access denied message in all languages
        message = (
            "🇰🇿 Кешіріңіз, сізге қол жетімділік жоқ. Сіз біздің топта емессіз.\n\n"
            "🇷🇺 Извините, у вас нет доступа. Вас нет в нашей группе.\n\n"
            "🇺🇸 Sorry, you don't have access. You are not in our group."
        )
        await update.message.reply_text(message)
        return

    # Check if user exists in database
    db = get_db_session()
    try:
        existing_user = db.query(User).filter(User.telegram_id == str(user_id)).first()
        
        if existing_user:
            # User exists, show main menu
            await update.message.reply_text(
                get_text('ru', 'welcome_back'),
                reply_markup=BotKeyboards.get_main_menu_keyboard('ru', user_id)
            )
            return

        # New user - start registration process
        USER_STATES[user_id] = {
            'state': RegistrationState.AWAITING_NAME,
            'data': {},
            'telegram_user': user
        }

        welcome_message = (
            "👋 Добро пожаловать в SapaEdu!\n\n"
            "Для начала работы мне нужно собрать несколько данных о вас.\n\n"
            "📝 Пожалуйста, напишите ваше имя:"
        )
        await update.message.reply_text(welcome_message)

    finally:
        db.close()

async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages during registration"""
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if user_id not in USER_STATES:
        return

    user_state = USER_STATES[user_id]
    current_state = user_state['state']

    if current_state == RegistrationState.AWAITING_NAME:
        if len(text) < 2:
            await update.message.reply_text("❌ Пожалуйста, введите корректное имя (минимум 2 символа):")
            return

        user_state['data']['name'] = text
        user_state['state'] = RegistrationState.AWAITING_SURNAME
        
        await update.message.reply_text(
            f"✅ Имя: {text}\n\n"
            "📝 Теперь напишите вашу фамилию:"
        )

    elif current_state == RegistrationState.AWAITING_SURNAME:
        if len(text) < 2:
            await update.message.reply_text("❌ Пожалуйста, введите корректную фамилию (минимум 2 символа):")
            return

        user_state['data']['surname'] = text
        user_state['state'] = RegistrationState.AWAITING_EMAIL
        
        full_name = f"{user_state['data']['name']} {text}"
        await update.message.reply_text(
            f"✅ ФИО: {full_name}\n\n"
            "📧 Теперь напишите ваш email адрес:"
        )

    elif current_state == RegistrationState.AWAITING_EMAIL:
        # Simple email validation
        if '@' not in text or '.' not in text or len(text) < 5:
            await update.message.reply_text("❌ Пожалуйста, введите корректный email адрес:")
            return

        # Check if email already exists
        db = get_db_session()
        try:
            existing_email = db.query(User).filter(User.email == text).first()
            if existing_email:
                await update.message.reply_text("❌ Пользователь с таким email уже существует. Введите другой email:")
                return
        finally:
            db.close()

        user_state['data']['email'] = text
        user_state['state'] = RegistrationState.AWAITING_COMPANY
        
        await update.message.reply_text(
            f"✅ Email: {text}\n\n"
            "🏢 Выберите вашу компанию:",
            reply_markup=BotKeyboards.get_company_selection_keyboard('ru')
        )

async def company_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle company selection"""
    query = update.callback_query
    user_id = query.from_user.id

    # Company mapping
    company_map = {
        'company_sapa_tech': 'Sapa Technologies',
        'company_neo_factoring': 'Neo Factoring',
        'company_sapa_finance': 'Sapa Digital Finance',
        'company_algapay': 'AlgaPay',
        'company_ai_parking': 'AI Parking',
        'company_sapa_solutions': 'Sapa Solutions',
        'company_sapa_communications': 'Sapa Digital Communications'
    }

    company_code = query.data
    company = company_map.get(company_code)
    
    if not company:
        await query.answer("Неверный выбор компании.")
        return

    if user_id not in USER_STATES:
        await query.answer("Ошибка состояния. Начните регистрацию заново с /start")
        return

    user_state = USER_STATES[user_id]
    if user_state['state'] != RegistrationState.AWAITING_COMPANY:
        await query.answer("Неверное состояние регистрации.")
        return

    user_state['data']['company'] = company
    user_state['state'] = RegistrationState.COMPLETED

    # Create user in database
    db = get_db_session()
    try:
        telegram_user = user_state['telegram_user']
        full_name = f"{user_state['data']['name']} {user_state['data']['surname']}"
        
        # Check if user should be admin
        admin_level = is_admin(str(user_id))
        is_user_admin = admin_level >= 1
        
        new_user = User(
            telegram_id=str(user_id),
            name=full_name,
            email=user_state['data']['email'],
            company=company,
            is_admin=is_user_admin,
            registered_at=datetime.now(timezone.utc)
        )
        db.add(new_user)
        db.commit()

        # Clean up user state
        del USER_STATES[user_id]

        # Show completion message
        completion_message = (
            f"🎉 Регистрация завершена!\n\n"
            f"👤 ФИО: {full_name}\n"
            f"📧 Email: {user_state['data']['email']}\n"
            f"🏢 Компания: {company}\n\n"
            f"Теперь вы можете перейти на платформу для обучения:"
        )

        await query.edit_message_text(
            completion_message,
            reply_markup=BotKeyboards.get_main_menu_keyboard('ru', user_id)
        )

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        await query.edit_message_text(
            "❌ Произошла ошибка при регистрации. Попробуйте позже или обратитесь к администратору."
        )
    finally:
        db.close()

async def language_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle language selection (for existing users)"""
    query = update.callback_query
    user_id = query.from_user.id
    language = query.data.split('_')[1]

    # Get user's company selection status
    db = get_db_session()
    company = None
    try:
        user = db.query(User).filter(User.telegram_id == str(user_id)).first()
        if user:
            company = user.company
    finally:
        db.close()

    if not company:
        # Show company selection if not selected yet
        await query.edit_message_text(
            get_text(language, 'select_company'),
            reply_markup=BotKeyboards.get_company_selection_keyboard(language)
        )
    else:
        # Show welcome message and main menu
        welcome_msg = get_text(language, 'language_selected')
        await query.edit_message_text(
            welcome_msg,
            reply_markup=BotKeyboards.get_main_menu_keyboard(language, user_id)
        )

async def handle_unknown_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle unknown callbacks"""
    query = update.callback_query
    await query.answer("Неизвестная команда.")

def main():
    """Start the bot"""
    # Kill any existing bot processes to prevent conflicts
    import psutil
    import os
    current_pid = os.getpid()

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if (proc.info['pid'] != current_pid and 
                proc.info['cmdline'] and 
                any('bot.py' in str(cmd) for cmd in proc.info['cmdline'])):
                logger.warning(f"Stopping existing bot process (PID: {proc.info['pid']})")
                proc.terminate()
                proc.wait(timeout=3)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            continue

    application = Application.builder().token(BOT_TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))
    application.add_handler(CallbackQueryHandler(language_callback, pattern="^lang_"))
    application.add_handler(CallbackQueryHandler(company_callback, pattern="^company_"))
    application.add_handler(CallbackQueryHandler(handle_unknown_callback))

    logger.info("🤖 Telegram bot started with registration survey")
    application.run_polling()

if __name__ == '__main__':
    main()
