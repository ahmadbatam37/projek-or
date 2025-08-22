from telegram import InlineKeyboardButton, InlineKeyboardMarkup

# Keyboard untuk autentikasi
def get_auth_keyboard():
    keyboard = [[InlineKeyboardButton("🔐 Masukkan Password", callback_data='auth_password')]]
    return InlineKeyboardMarkup(keyboard)

# Keyboard menu utama setelah berhasil login (digabung)
def get_main_menu_keyboard():
    keyboard = [
        [
            InlineKeyboardButton("CRLF Injection", callback_data='vuln_crlf'),
            InlineKeyboardButton("LFI", callback_data='vuln_lfi')
        ],
        [
            InlineKeyboardButton("Open Redirect", callback_data='vuln_open_redirect'),
            InlineKeyboardButton("SQL Injection", callback_data='vuln_sqli')
        ],
        [
            InlineKeyboardButton("XSS", callback_data='vuln_xss'),
            InlineKeyboardButton("Info Gathering", callback_data='vuln_secretfinder')
        ],
        [
            InlineKeyboardButton("🚀 Uji Semua Kerentanan", callback_data='menu_all_vuln')
        ],
        [
            InlineKeyboardButton("ℹ️ Bantuan", callback_data='menu_help'),
            InlineKeyboardButton("🚪 Keluar", callback_data='menu_exit')
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

# Keyboard baru untuk prompt subdomain dengan tombol kembali
def get_subdomain_prompt_keyboard():
    keyboard = [[InlineKeyboardButton("⬅️ Kembali ke Menu Utama", callback_data='menu_back')]]
    return InlineKeyboardMarkup(keyboard)

# Keyboard konfirmasi subdomain
def get_subdomain_confirmation_keyboard(vuln_choice):
    keyboard = [
        [
            InlineKeyboardButton("✅ Lanjutkan", callback_data=f'confirm_scan_{vuln_choice}'),
            InlineKeyboardButton("🔄 Ganti Subdomain", callback_data=f'change_subdomain_{vuln_choice}'),
        ],
        [InlineKeyboardButton("❌ Batal", callback_data='cancel_process')]
    ]
    return InlineKeyboardMarkup(keyboard)

# Keyboard untuk membatalkan proses yang sedang berjalan
def get_cancel_keyboard():
    keyboard = [[InlineKeyboardButton("❌ Batalkan Proses", callback_data='cancel_process')]]
    return InlineKeyboardMarkup(keyboard)

# Keyboard setelah proses selesai
def get_completion_keyboard():
    keyboard = [[InlineKeyboardButton("⬅️ Kembali ke Menu Utama", callback_data='menu_back')]]
    return InlineKeyboardMarkup(keyboard) 


def get_restart_keyboard():
    """Membuat keyboard dengan tombol untuk memulai ulang sesi."""
    keyboard = [[InlineKeyboardButton("🚀 Mulai Uji Lagi", callback_data='restart_session')]]
    return InlineKeyboardMarkup(keyboard) 
