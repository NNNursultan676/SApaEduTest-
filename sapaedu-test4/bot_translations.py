# Bot translations for different languages
BOT_TRANSLATIONS = {
    'kz': {
        'access_denied': 'Кешіріңіз, сізге қол жетімділік жоқ. Сіз біздің топта емессіз.',
        'welcome': 'Қош келдіңіз! Тіл таңдаңыз:',
        'language_selected': 'Тіл таңдалды: Қазақша\nҚош келдіңіз SapaEdu жүйесіне!',
        'main_menu': '🏠 Басты мәзір',
        'open_webapp': '📱 Қолданбаны ашу',
        'website': '🌐 Сайтқа өту',
        'admin_panel': '⚙️ Админ панель',
        'manage_admins': '👥 Админдарды басқару',
        'add_admin': '➕ Админ қосу',
        'remove_admin': '➖ Админ жою',
        'courses': '📚 Курстар',
        'statistics': '📊 Статистика',
        'back': '⬅️ Артқа',
        'cancel': '❌ Бас тарту',
        'insufficient_rights': 'Сізде жеткіліксіз құқықтар жоқ',
        'admin_added': '✅ Админ сәтті қосылды!',
        'admin_removed': '✅ Админ сәтті жойылды!',
        'invalid_level': 'Дұрыс емес деңгей. 1-ден 3-ке дейінгі сан көрсетіңіз.',
        'welcome_back': '👋 SapaEdu-ға қош келдіңіз!\n\nӘрекетті таңдаңыз:'
    },
    'ru': {
        'access_denied': 'Извините, у вас нет доступа. Вас нет в нашей группе.',
        'welcome': 'Добро пожаловать! Выберите язык:',
        'language_selected': 'Язык выбран! Добро пожаловать в SapaEdu! 🎓',
        'main_menu': '🏠 Главное меню',
        'open_webapp': '📱 Открыть приложение',
        'website': '🌐 Перейти на сайт',
        'admin_panel': '⚙️ Админ панель',
        'manage_admins': '👥 Управление админами',
        'add_admin': '➕ Добавить админа',
        'remove_admin': '➖ Удалить админа',
        'courses': '📚 Курсы',
        'statistics': '📊 Статистика',
        'back': '⬅️ Назад',
        'cancel': '❌ Отмена',
        'insufficient_rights': 'У вас недостаточно прав',
        'admin_added': '✅ Админ успешно добавлен!',
        'admin_removed': '✅ Админ успешно удален!',
        'invalid_level': 'Неверный уровень. Укажите число от 1 до 3.',
        'welcome_back': '👋 Добро пожаловать в SapaEdu!\n\nВыберите действие:'
    },
    'en': {
        'access_denied': 'Sorry, you don\'t have access. You are not in our group.',
        'welcome': 'Welcome! Choose language:',
        'language_selected': 'Language selected: English\nWelcome to SapaEdu system!',
        'main_menu': '🏠 Main Menu',
        'open_webapp': '📱 Open App',
        'website': '🌐 Go to Website',
        'admin_panel': '⚙️ Admin Panel',
        'manage_admins': '👥 Manage Admins',
        'add_admin': '➕ Add Admin',
        'remove_admin': '➖ Remove Admin',
        'courses': '📚 Courses',
        'statistics': '📊 Statistics',
        'back': '⬅️ Back',
        'cancel': '❌ Cancel',
        'insufficient_rights': 'You don\'t have sufficient rights',
        'admin_added': '✅ Admin successfully added!',
        'admin_removed': '✅ Admin successfully removed!',
        'invalid_level': 'Invalid level. Please specify a number from 1 to 3.',
        'welcome_back': '👋 Welcome to SapaEdu!\n\nChoose an action:'
    }
}

def get_text(language, key, default=None):
    """Get translated text for given language and key"""
    return BOT_TRANSLATIONS.get(language, {}).get(key, default or key)