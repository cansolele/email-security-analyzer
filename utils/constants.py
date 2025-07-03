"""
Constants and configuration for Email Security Analyzer
"""


PHISHING_KEYWORDS = {
    'urgent': ['urgent', 'urgently', 'срочно', 'срочный', 'немедленно'],
    'security': ['security alert', 'угроза безопасности', 'нарушение безопасности', 'security update', 'password'],
    'verify': ['verify', 'verification', 'проверить', 'верификация', 'validate', 'confirm'],
    'suspend': ['suspend', 'suspended', 'заблокировать', 'заблокирован', 'locked'],
    'click': ['click here', 'нажмите здесь', 'перейти по ссылке'],
    'account': ['account locked', 'аккаунт заблокирован', 'account suspended', 'login', 'username']
}


HIGH_RISK_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar', 
    '.ps1', '.psm1', '.psd1', '.lnk', '.sh', '.py'
]


MEDIUM_RISK_EXTENSIONS = [
    '.zip', '.rar', '.7z', '.ace', '.cab', '.msi', '.dll', '.tar', '.tgz', '.bz', '.gz',
    '.docm', '.xlsm', '.pptm' 
]


URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link', 'is.gd', 'soo.gd',
    '0rz.tw', '1link.in', '2big.at', 'clck.ru', 'vk.cc', 'u.to', 'cutt.ly'
]


SUSPICIOUS_URL_KEYWORDS = [
    'phishing', 'scam', 'malware', 'login', 'verify', 'account', 'credential',
    'update', 'secure', 'support', 'billing', 'invoice', 'payment', 'free', 'win',
    'click-here', 'urgent-action', 'suspicious-domain', '.xyz', '.top', '.club'
]


DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar', '.ps1'
]


JS_PATTERNS = [
    r'<script[^>]*>(.*?)</script>',
    r'javascript:',
    r'eval\s*\(',
    r'document\.write',
    r'window\.location',
    r'innerHTML\s*=',
    r'onclick\s*=',
    r'onload\s*=',
    r'onerror\s*='
]


RISK_LEVELS = {
    'MINIMAL': {'threshold': 0, 'color': 'success', 'name': 'Минимальный'},
    'LOW': {'threshold': 10, 'color': 'info', 'name': 'Низкий'},
    'MEDIUM': {'threshold': 25, 'color': 'warning', 'name': 'Средний'},
    'HIGH': {'threshold': 50, 'color': 'danger', 'name': 'Высокий'}
}


RISK_WEIGHTS = {
 
    'NO_DKIM': 20,
    'INVALID_DKIM': 10,
    
    'JAVASCRIPT': 15,
    'PHISHING_KEYWORD': 5, 
    
    'HIGH_RISK_ATTACHMENT': 25,
    'MEDIUM_RISK_ATTACHMENT': 10,
    
    'HYPERLINK_MISMATCH': 15,
    'INSECURE_LINK_HTTP': 5,
    'LINK_SHORTENER': 10,
    'SUSPICIOUS_URL_KEYWORD': 5
}


MAX_CONTENT_DISPLAY = 2000
MAX_HTML_DISPLAY = 3000
MAX_URLS_DISPLAY = 10
MAX_JS_FRAGMENTS = 10
MAX_HEADER_DISPLAY = 300


REPORT_CONFIG = {
    'main_file': 'email_security_report.html',
    'reports_dir': 'reports',
    'individual_prefix': 'email_',
    'max_emails_summary': 50
}


SUPPORTED_LANGUAGES = ['en', 'ru']
DEFAULT_LANGUAGE = 'ru'


LOCALIZATION = {
    'en': {

        'starting_analysis': '🔍 Email Security Analyzer - Starting batch analysis...',
        'target_folder': '📁 Target folder: {}',
        'folder_not_found': '❌ Folder {} not found!',
        'no_files_found': '❌ No files found for analysis in folder {}!',
        'files_found': '📧 Found {} files for analysis...',
        'analyzing_file': '📄 Analyzing {}/{}: {}',
        'analyzing_email': '  📧 Processing: {}',
        'analysis_completed': '✅ Analysis completed! Processed {} emails',
        'no_emails_analyzed': '❌ No emails analyzed. Exiting.',
        'creating_report': '📄 Creating report: {}',
        'individual_reports_created': '📁 Created {} individual reports:',
        'report_file': '  📄 {}',
        'view_in_browser': '🌐 Open the HTML files in your browser to view the results',
        'decoded_image': '  🖼️ Decoded image: {} ({:,} bytes)',
        'analysis_error': '  ❌ Analysis error {}: {}',
        

        'email_security_analysis': 'Email Security Analysis',
        'analysis_summary': 'Analysis Summary',
        'total_emails': 'Total Emails',
        'quick_navigation': 'Quick Navigation',
        'detailed_analysis': 'Detailed Analysis',
        'analysis_from': 'Analysis from {}',
        'risk_level_high': 'High',
        'risk_level_medium': 'Medium', 
        'risk_level_low': 'Low',
        'risk_level_minimal': 'Minimal',
        'basic_information': 'Basic Information',
        'from': 'From',
        'to': 'To',
        'subject': 'Subject',
        'date': 'Date',
        'return_path': 'Return-Path',
        'message_id': 'Message-ID',
        'content_type': 'Content Type',
        'size': 'Size',
        'bytes': 'bytes',
        'security_status': 'Security Status',
        'dkim_valid': 'DKIM Valid',
        'dkim_present': 'DKIM Present',
        'dkim_missing': 'DKIM Missing',
        'html_content': 'HTML Content',
        'javascript_detected': 'JavaScript Detected',
        'attachments': 'Attachments',
        'base64_content': 'Base64 Content',
        'risk_factors': 'Risk Factors',
        'no_risk_factors': 'No risk factors detected',
        'threat_indicators': 'Threat Indicators',
        'no_threats_detected': 'No threats detected',
        'phishing': 'Phishing',
        'malware_impact': 'Malware Impact',
        'malware': 'Malware',
        'decoded_images': 'Decoded Images from Attachments',
        'javascript_fragments': 'Detected JavaScript Fragments',
        'javascript_warning': 'JavaScript code detected in email. Below are code fragments for analysis:',
        'javascript_detected_warning': 'JavaScript code detected in email. Below are code fragments for analysis:',
        'fragment': 'Fragment',
        'showing_fragments': 'Showing {} of {} found fragments',
        'detailed_attachments': 'Detailed Attachment Analysis',
        'attachment': 'Attachment',
        'type': 'Type',
        'encoding': 'Encoding',
        'suspicious_extension': 'Suspicious extension: {}',
        'found_urls': 'Found URL Links',
        'delivery_route': 'Delivery Route',
        'hop': 'Hop',
        'suspicious_ip': 'Suspicious IP: {}',
        'email_content': 'Email Content',
        'text_version': 'Text Version',
        'html_code': 'HTML Code',
        'html_display': 'HTML Email Display',
        'html_rendering': 'HTML Email Rendering',
        'routing_analysis': 'Routing Analysis',
        'all_headers': 'All Email Headers',
        'footer_text': 'email-security-analyzer by cansolele © 2025',
        'individual_footer': 'email-security-analyzer by cansolele © 2025',
        'file': 'File',
        'analysis_time': 'Analysis Time',
        'risk_level': 'Risk Level',
        'points': 'points',
        'unknown': 'unknown',
        'not_specified': 'not specified',
        'time': 'Time',
        'and_more_links': '... and {} more links',
        'and_more_fragments': 'Showing {} of {} found fragments',
        'attachment_num': 'Attachment {}',
        

        'missing_dkim': 'Missing DKIM signature',
        'invalid_dkim': 'Invalid DKIM signature', 
        'javascript_found': 'JavaScript code detected',
        'suspicious_links': 'Suspicious links: {}',
        'dangerous_attachments': 'Potentially dangerous attachments: {}',
        'phishing_indicators': 'Phishing indicators: {}',
        

        'analysis_error_file': 'Analysis error for {}: {}',
        'unknown_error': 'Unknown error',
        'no_report_data': 'No data to create report'
    },
    
    'ru': {

        'starting_analysis': '🔍 Анализатор безопасности Email - Запуск пакетного анализа...',
        'target_folder': '📁 Целевая папка: {}',
        'folder_not_found': '❌ Папка {} не найдена!',
        'no_files_found': '❌ В папке {} не найдено файлов для анализа!',
        'files_found': '📧 Найдено {} файлов для анализа...',
        'analyzing_file': '📄 Анализирую {}/{}: {}',
        'analyzing_email': '  📧 Обрабатываю: {}',
        'analysis_completed': '✅ Анализ завершен! Обработано {} писем',
        'no_emails_analyzed': '❌ Письма не проанализированы. Выход.',
        'creating_report': '📄 Создаю отчет: {}',
        'individual_reports_created': '📁 Создано {} индивидуальных отчетов:',
        'report_file': '  📄 {}',
        'view_in_browser': '🌐 Откройте HTML файлы в браузере для просмотра результатов',
        'decoded_image': '  🖼️ Декодировано изображение: {} ({:,} байт)',
        'analysis_error': '  ❌ Ошибка анализа {}: {}',
        

        'email_security_analysis': 'Анализ безопасности Email',
        'analysis_summary': 'Сводка анализа',
        'total_emails': 'Всего писем',
        'quick_navigation': 'Быстрая навигация',
        'detailed_analysis': 'Детальный анализ',
        'analysis_from': 'Анализ от {}',
        'risk_level_high': 'Высокий',
        'risk_level_medium': 'Средний',
        'risk_level_low': 'Низкий',
        'risk_level_minimal': 'Минимальный',
        'basic_information': 'Основная информация',
        'from': 'От',
        'to': 'Кому',
        'subject': 'Тема',
        'date': 'Дата',
        'return_path': 'Return-Path',
        'message_id': 'Message-ID',
        'content_type': 'Тип содержимого',
        'size': 'Размер',
        'bytes': 'байт',
        'security_status': 'Статус безопасности',
        'dkim_valid': 'DKIM Валиден',
        'dkim_present': 'DKIM Присутствует',
        'dkim_missing': 'DKIM Отсутствует',
        'html_content': 'HTML содержимое',
        'javascript_detected': 'JavaScript обнаружен',
        'attachments': 'Вложения',
        'base64_content': 'Base64 контент',
        'risk_factors': 'Факторы риска',
        'no_risk_factors': 'Факторы риска не обнаружены',
        'threat_indicators': 'Индикаторы угроз',
        'no_threats_detected': 'Угрозы не обнаружены',
        'phishing': 'Фишинг',
        'malware_impact': 'Вредоносное воздействие',
        'malware': 'Вредоносное ПО',
        'decoded_images': 'Декодированные изображения из вложений',
        'javascript_fragments': 'Обнаруженные JavaScript фрагменты',
        'javascript_warning': 'В письме обнаружен JavaScript код. Ниже приведены фрагменты кода для анализа:',
        'javascript_detected_warning': 'В письме обнаружен JavaScript код. Ниже приведены фрагменты кода для анализа:',
        'fragment': 'Фрагмент',
        'showing_fragments': 'Показано {} из {} найденных фрагментов',
        'detailed_attachments': 'Детальный анализ вложений',
        'attachment': 'Вложение',
        'type': 'Тип',
        'encoding': 'Кодировка',
        'suspicious_extension': 'Подозрительное расширение: {}',
        'found_urls': 'Найденные URL ссылки',
        'delivery_route': 'Маршрут доставки',
        'hop': 'Хоп',
        'suspicious_ip': 'Подозрительный IP: {}',
        'email_content': 'Содержимое письма',
        'text_version': 'Текстовая версия',
        'html_code': 'HTML код',
        'html_display': 'Отображение HTML письма',
        'html_rendering': 'Отображение HTML письма',
        'routing_analysis': 'Маршрут доставки',
        'all_headers': 'Все заголовки письма',
        'footer_text': 'email-security-analyzer от cansolele © 2025',
        'individual_footer': 'email-security-analyzer от cansolele © 2025',
        'file': 'Файл',
        'analysis_time': 'Время анализа',
        'risk_level': 'Уровень риска',
        'points': 'баллов',
        'unknown': 'неизвестно',
        'not_specified': 'не указан',
        'time': 'Время',
        'and_more_links': '... и еще {} ссылок',
        'and_more_fragments': 'Показано {} из {} найденных фрагментов',
        'attachment_num': 'Вложение {}',
        
        
        'missing_dkim': 'Отсутствует DKIM подпись',
        'invalid_dkim': 'Невалидная DKIM подпись',
        'javascript_found': 'Обнаружен JavaScript код',
        'phishing_indicators': 'Найдены фишинговые индикаторы: {}',
        'high_risk_attachment': 'Найдено вложение высокого риска: {}',
        'medium_risk_attachment': 'Найдено вложение среднего риска: {}',
        'insecure_link_http': 'Найдена небезопасная ссылка (HTTP): {}',
        'hyperlink_mismatch': "Текст ссылки '{}' не совпадает с адресом",
        'suspicious_link_keyword': 'Ссылка содержит подозрительное слово: {}',
        'link_shortener': 'Ссылка использует сокращатель: {}',

        
        'dangerous_extension_warning': 'Опасное расширение: {}',
        'suspicious_extension_warning': 'Подозрительное расширение: {}',
        
        
        'analysis_error_file': 'Ошибка анализа {}: {}',
        'unknown_error': 'Неизвестная ошибка',
        'no_report_data': 'Нет данных для создания отчета'
    }
}

def get_text(key: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """Get localized text by key"""
    if lang not in LOCALIZATION:
        lang = DEFAULT_LANGUAGE
    return LOCALIZATION[lang].get(key, key)

def get_risk_level_name(level: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """Get localized risk level name"""
    level_map = {
        'en': {
            'Высокий': 'High',
            'Средний': 'Medium',
            'Низкий': 'Low', 
            'Минимальный': 'Minimal'
        },
        'ru': {
            'High': 'Высокий',
            'Medium': 'Средний',
            'Low': 'Низкий',
            'Minimal': 'Минимальный'
        }
    }
    
    if lang in level_map and level in level_map[lang]:
        return level_map[lang][level]
    return level 