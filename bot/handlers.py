import asyncio
import re
import os
import logging
import shutil
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ContextTypes,
    ConversationHandler,
)
from telegram.constants import ParseMode
from telegram.helpers import escape_markdown
from datetime import datetime

from . import keyboards
from . import utils
# Hapus ALLOWED_USER_IDS dari import karena tidak digunakan lagi
from .config import SCRIPT_BASE_DIR, AUTH_PASSWORD

# States for conversation handler
(
    AUTH,
    SELECT_VULN,
    ASK_SUBDOMAIN,
    CONFIRM_SUBDOMAIN,
    RUNNING_SCAN,
    EXITED,
) = range(6)

# Muat daftar user yang sudah diautentikasi saat bot dimulai
authenticated_users = utils.load_authenticated_users()


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Memulai bot dan memeriksa autentikasi. Bisa dipanggil via /start atau callback."""
    user = update.effective_user
    # Gunakan chat_id dari update, yang berfungsi untuk pesan dan callback
    chat_id = update.effective_chat.id

    if user.id in authenticated_users:
        welcome_text = (
            f"*✅ Autentikasi Berhasil\\!* \n\n"
            f"Selamat datang kembali, *{user.first_name}*\\.\n"
            f"Anda siap untuk memulai pengujian\\.\n\n"
            f"*Pilih salah satu kerentanan di bawah ini untuk memulai:*"
        )
        # Menggunakan context.bot.send_message agar bisa dipanggil dari mana saja
        await context.bot.send_message(
            chat_id=chat_id,
            text=welcome_text,
            reply_markup=keyboards.get_main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return SELECT_VULN
    else:
        welcome_text = (
            "*🛡️ Selamat Datang di VulnStrike Bot 🛡️*\n\n"
            "Bot ini adalah asisten pribadi Anda untuk melakukan uji penetrasi otomatis\\.\n\n"
            "Untuk menjaga keamanan dan memastikan hanya pengguna yang berwenang yang dapat mengakses fungsionalitasnya, silakan lakukan autentikasi terlebih dahulu\\.\n\n"
            "⬇️ *Klik tombol di bawah untuk memasukkan password\\.*\n"
            "_Dibuat oleh: Ahmad Izza A\\._"
        )
        # Menggunakan context.bot.send_message agar bisa dipanggil dari mana saja
        await context.bot.send_message(
            chat_id=chat_id,
            text=welcome_text,
            reply_markup=keyboards.get_auth_keyboard(),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return AUTH


async def ask_for_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Meminta pengguna memasukkan password."""
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(text="🔑 Silakan masukkan password Anda:")
    context.user_data["password_message_id"] = query.message.message_id
    return AUTH


async def check_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Memeriksa password yang dimasukkan."""
    password = update.message.text
    password_message_id = context.user_data.get("password_message_id")
    user = update.effective_user

    # Hapus pesan permintaan password dan pesan password yang dikirim user
    if password_message_id:
        await context.bot.delete_message(
            chat_id=update.effective_chat.id, message_id=password_message_id
        )
    await context.bot.delete_message(
        chat_id=update.effective_chat.id, message_id=update.message.message_id
    )

    if password == AUTH_PASSWORD:
        # Simpan user ID ke file dan memory
        utils.add_authenticated_user(user.id)
        authenticated_users.add(user.id)
        
        success_text = (
            f"*✅ Autentikasi berhasil\\! Sesi Anda telah disimpan\\.*\n\n"
            f"Selamat datang, *{user.first_name}*\\.\n"
            f"Silakan pilih kerentanan untuk diuji:"
        )
        await update.message.reply_text(
            text=success_text,
            reply_markup=keyboards.get_main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return SELECT_VULN
    else:
        await update.message.reply_text(
            "❌ Password salah. Silakan coba lagi.",
            reply_markup=keyboards.get_auth_keyboard(),
        )
        return AUTH


async def main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan menu utama (sekarang menu terpadu)."""
    query = update.callback_query
    await query.answer()

    # PERBAIKAN: Tangani pesan media/dokumen
    # Cek apakah pesan yang akan diedit berisi dokumen
    if query.message.document:
        # Jika ya, hapus pesan tersebut dan kirim menu baru
        await query.message.delete()
        await query.message.reply_text(
            "Silakan pilih kerentanan untuk diuji:",
            reply_markup=keyboards.get_main_menu_keyboard(),
        )
    else:
        # Jika tidak (pesan teks biasa), edit seperti biasa
        await query.edit_message_text(
            "Silakan pilih kerentanan untuk diuji:",
            reply_markup=keyboards.get_main_menu_keyboard(),
        )
    return SELECT_VULN


async def ask_for_subdomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Meminta subdomain dari pengguna."""
    query = update.callback_query
    await query.answer()
    
    query_data = query.data
    vuln_choice = None

    # PERBAIKAN: Logika baru untuk mengekstrak 'vuln_choice' dari berbagai sumber callback_data.
    if query_data.startswith('vuln_'):
        # Sumber: Menu utama (contoh: 'vuln_sqli')
        vuln_choice = query_data.replace('vuln_', '')
    elif query_data.startswith('change_subdomain_'):
        # Sumber: Tombol "Ganti Subdomain" (contoh: 'change_subdomain_sqli')
        vuln_choice = query_data.replace('change_subdomain_', '')
    elif query_data == 'menu_all_vuln':
        # Sumber: Menu utama untuk semua kerentanan
        vuln_choice = 'all'
    
    # Simpan pilihan yang sudah benar ke dalam user_data.
    # Ini penting agar `confirm_subdomain` bisa mengambilnya nanti.
    context.user_data["vuln_choice"] = vuln_choice
    
    vuln_map = {
        "crlf": "CRLF Injection", "lfi": "LFI (Local File Inclusion)", "open_redirect": "Open Redirect",
        "sqli": "SQL Injection", "xss": "XSS (Cross-Site Scripting)", "secretfinder": "Info Gathering",
        "all": "Semua Kerentanan"
    }
    
    vuln_name = vuln_map.get(vuln_choice, "Unknown")
    context.user_data["vuln_name"] = vuln_name

    # Escape nama kerentanan untuk mencegah error MarkdownV2
    safe_vuln_name = escape_markdown(vuln_name, version=2)

    sent_message = await query.edit_message_text(
        f"Anda memilih: *{safe_vuln_name}*\n\n"
        f"Masukkan subdomain target \\(contoh: `testphp\\.vulnweb\\.com`\\):",
        parse_mode=ParseMode.MARKDOWN_V2,
        # Gunakan keyboard baru dengan tombol kembali
        reply_markup=keyboards.get_subdomain_prompt_keyboard(),
    )
    # Simpan ID pesan prompt untuk diedit nanti
    context.user_data['prompt_message_id'] = sent_message.message_id
    
    return ASK_SUBDOMAIN


async def confirm_subdomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Konfirmasi subdomain dan pilihan scan."""
    subdomain = update.message.text.strip()
    vuln_choice = context.user_data.get("vuln_choice")
    vuln_name = context.user_data.get("vuln_name")
    prompt_message_id = context.user_data.get('prompt_message_id')

    # Validasi subdomain sederhana
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-z]{2,}$", subdomain):
        await update.message.reply_text(
            "Format subdomain tidak valid\\. Silakan coba lagi\\.",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        # Tetap di state yang sama, pengguna bisa mencoba input lagi.
        return ASK_SUBDOMAIN

    context.user_data["subdomain"] = subdomain
    
    # Escape nama kerentanan untuk keamanan
    safe_vuln_name = escape_markdown(vuln_name, version=2)
    
    # **PERUBAHAN UTAMA DI SINI**

    # 1. Edit pesan prompt sebelumnya untuk MENGHAPUS keyboard-nya.
    #    Ini menonaktifkan tombol "Kembali" yang sudah tidak relevan.
    if prompt_message_id:
        try:
            await context.bot.edit_message_reply_markup(
                chat_id=update.effective_chat.id,
                message_id=prompt_message_id,
                reply_markup=None # Menghapus keyboard
            )
        except Exception:
            # Abaikan jika pesan tidak bisa diedit (misalnya, terlalu lama)
            pass

    # 2. Kirim pesan konfirmasi BARU, membalas pesan subdomain dari pengguna.
    #    Ini menciptakan alur percakapan yang jelas dan logis.
    await update.message.reply_text(
        text=f"Anda akan menguji *{safe_vuln_name}* pada domain:\n`{subdomain}`\n\n"
             "Apakah Anda ingin melanjutkan?",
        reply_markup=keyboards.get_subdomain_confirmation_keyboard(vuln_choice),
        parse_mode=ParseMode.MARKDOWN_V2,
    )
    
    return CONFIRM_SUBDOMAIN


async def run_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menjalankan skrip dan mempersiapkan log."""
    query = update.callback_query
    await query.answer()

    vuln_choice = context.user_data.get("vuln_choice")
    subdomain = context.user_data.get("subdomain")
    vuln_name = context.user_data.get("vuln_name")

    script_map = {
        "crlf": "crlf/crlf_gather.sh",
        "lfi": "lfi/lfi_gather.sh",
        "open_redirect": "open_redirect/or_gather.sh",
        "sqli": "sqli/sqli_gather.sh",
        "xss": "xss/xss_gather.sh",
        "secretfinder": "secretfinder/api_gather.sh",
        "all": "vulnstrike.sh",
    }
    
    script_name = script_map.get(vuln_choice)
    if not script_name:
        await query.edit_message_text("Pilihan tidak valid.")
        return SELECT_VULN

    script_path = f"{SCRIPT_BASE_DIR}/{script_name}"
    
    # PERBAIKAN: Siapkan daftar argumen untuk skrip.
    # Untuk "semua kerentanan", argumennya adalah '7' dan subdomain.
    # Untuk yang lain, hanya subdomain.
    script_args = ['7', subdomain] if vuln_choice == 'all' else [subdomain]
    
    await query.edit_message_text(
        f"🚀 Memulai uji penetrasi *{escape_markdown(vuln_name, 2)}* pada `{escape_markdown(subdomain, 2)}`\\.\\.\\.",
        parse_mode=ParseMode.MARKDOWN_V2
    )

    cancel_keyboard = keyboards.get_cancel_keyboard()
    log_message = await query.message.reply_text(
        "```\nMempersiapkan lingkungan...\n```",
        reply_markup=cancel_keyboard
    )
    context.user_data['log_message_id'] = log_message.message_id
    context.user_data['log_keyboard'] = cancel_keyboard
    
    # PERBAIKAN: Kirim argumen yang sudah disiapkan ke fungsi proses.
    asyncio.create_task(process_scan_and_report(update, context, script_path, subdomain, vuln_name, script_args))
    
    return RUNNING_SCAN


async def cancel_process(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Membatalkan proses yang sedang berjalan."""
    query = update.callback_query
    await query.answer()
    
    # PERBAIKAN: Baca proses dari user_data
    process = context.user_data.get('process')
    if process and process.returncode is None:
        utils.kill_process_group(process.pid)
        # Hapus referensi proses agar tidak bisa dibatalkan dua kali
        del context.user_data['process']
        
        await query.edit_message_text(
            "🛑 Proses pemindaian telah dibatalkan oleh pengguna.",
            reply_markup=keyboards.get_completion_keyboard()
        )
    else:
        await query.edit_message_text(
            "Tidak ada proses yang sedang berjalan untuk dibatalkan.",
            reply_markup=keyboards.get_completion_keyboard()
        )
        
    return SELECT_VULN


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menampilkan pesan bantuan."""
    query = update.callback_query
    
    help_text = (
        "*🛡️ Panduan Penggunaan VulnStrike Bot 🛡️*\n\n"
        "Bot ini adalah tool uji penetrasi otomatis untuk melakukan serangkaian uji penetrasi keamanan web\\. Berikut adalah panduan singkatnya\\.\n\n"
        "_*Kerentanan yang Tersedia:*_\n"
        "• *CRLF Injection*: Menguji kerentanan *Carriage Return Line Feed Injection*\\.\n"
        "• *LFI \\(Local File Inclusion\\)*: Mencoba membaca file sensitif dari server\\.\n"
        "• *Open Redirect*: Mencari parameter yang bisa dialihkan ke domain eksternal\\.\n"
        "• *SQL Injection*: Menguji injeksi perintah SQL pada parameter URL\\.\n"
        "• *XSS \\(Cross\\-Site Scripting\\)*: Mencoba menyuntikkan skrip ke halaman web\\.\n"
        "• *Info Gathering*: Mengumpulkan informasi target secara komprehensif, meliputi direktori tersembunyi, teknologi, kebocoran API/Secret, dan file JavaScript\\.\n"
        "• *🚀 Uji Semua Kerentanan*: Menjalankan semua uji kerentanan di atas secara berurutan untuk analisis menyeluruh\\.\n\n"
        "_*Langkah Penggunaan:*_\n"
        "1️⃣ *Pilih Kerentanan*: Klik salah satu kerentanan dari menu utama\\.\n"
        "2️⃣ *Masukkan Target*: Ketik subdomain yang ingin diuji \\(misal: `testphp\\.vulnweb\\.com`\\)\\.\n"
        "3️⃣ *Lanjutkan, Ganti Subdomain, Batalkan*: Konfirmasi target untuk memulai proses uji penetrasi\\.\n"
        "4️⃣ *Pantau & Batalkan*: Log akan diperbarui secara live\\. Proses dapat dibatalkan kapan saja\\.\n"
        "5️⃣ *Lihat Laporan*: Setelah selesai, laporan HTML lengkap akan dikirimkan\\.\n\n"
        "_Dibuat oleh: Ahmad Izza A\\._"
    )

    await query.answer()
    await query.edit_message_text(
        text=help_text, 
        parse_mode=ParseMode.MARKDOWN_V2, 
        reply_markup=keyboards.get_completion_keyboard()
    )
    return SELECT_VULN


async def exit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Menangani permintaan keluar dan menampilkan opsi untuk memulai lagi."""
    query = update.callback_query
    await query.answer()

    farewell_text = "✅ Sesi pengujian telah diakhiri. Terima kasih telah menggunakan VulnStrike Bot."

    await query.edit_message_text(
        text=farewell_text, 
        reply_markup=keyboards.get_restart_keyboard()
    )

    return EXITED


async def restart_conversation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Memulai ulang alur percakapan setelah keluar."""
    query = update.callback_query
    await query.answer()

    # Hapus pesan lama ("Sesi telah diakhiri...") untuk membersihkan UI
    await query.message.delete()
    
    # Panggil kembali fungsi start_command untuk menampilkan menu awal
    return await start_command(update, context)


async def process_scan_and_report(update: Update, context: ContextTypes.DEFAULT_TYPE, script_path, subdomain, vuln_name, script_args):
    """Wrapper untuk menjalankan scan, membuat laporan, dan mengirimnya."""
    log_dir_to_clean = None
    try:
        full_log, error_log = await utils.run_script_and_log(update, context, script_path, script_args, vuln_name)

        report_data = {
            'vulnerability_name': vuln_name,
            'target_domain': subdomain,
            'scan_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': "", 'vulnerable_urls': [], 'sqli_findings': [], 'recommendations': {},
            'scan_duration': None, 'info_gathering_results': None, 'all_modules_findings': [],
            'all_modules_recommendations': [],
        }

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0?]*[ -/]*[@-~])')
        cleaned_log = ansi_escape.sub('', full_log)

        duration_match = re.search(r"Total waktu uji penetrasi semua modul:\s*(.*)", cleaned_log)
        if not duration_match:
            duration_match = re.search(r"⏱ Total waktu.*?:(.*?)\n", cleaned_log)
        if duration_match:
            report_data['scan_duration'] = duration_match.group(1).strip()

        if vuln_name == "Semua Kerentanan":
            all_modules_results = []
            log_dir_match = re.search(r"BOT_LOG_DIR::(.+)", cleaned_log)

            if log_dir_match:
                log_dir_path = log_dir_match.group(1).strip()
                log_dir_to_clean = log_dir_path

                module_definitions = [
                    {'name': "Open Redirect", 'file': "or_output.tmp", 'parser': 'standard'},
                    {'name': "Local File Inclusion", 'file': "lfi_output.tmp", 'parser': 'standard'},
                    {'name': "CRLF Injection", 'file': "crlf_output.tmp", 'parser': 'standard'},
                    {'name': "SQL Injection", 'file': "sqli_output.tmp", 'parser': 'sqli'},
                    {'name': "Cross-Site Scripting", 'file': "xss_output.tmp", 'parser': 'standard'},
                    {'name': "Info Gathering", 'file': "api_output.tmp", 'parser': 'info_gathering'},
                ]

                for module_def in module_definitions:
                    module_result = { 'name': module_def['name'], 'stats': {}, 'type': module_def['parser'], 'details': {} }
                    log_chunk = ""
                    
                    log_file_path = os.path.join(log_dir_path, module_def['file'])
                    if os.path.exists(log_file_path):
                        with open(log_file_path, 'r', encoding='utf-8') as f:
                            # Pembersihan ANSI tetap penting
                            log_chunk = ansi_escape.sub('', f.read())

                    # PERBAIKAN: Regex dibuat lebih tangguh dengan [\\s\\S]*? untuk menangani
                    # karakter kontrol atau emoji yang tidak terduga di antara kata kunci dan titik dua.
                    time_match = re.search(r"Total waktu (?:uji penetrasi|pengumpulan data)[\s\S]*?:\s*(.*?)\n", log_chunk, re.IGNORECASE)
                    module_result['stats']['exec_time'] = time_match.group(1).strip() if time_match else 'N/A'

                    if module_def['parser'] == 'info_gathering':
                        stats = {}
                        stat_map = { 'File JavaScript': 'js', 'API/Secret leaks': 'leaks', 'Direktori tersembunyi': 'dirs', 'Teknologi terdeteksi': 'tech', 'Exposure ditemukan': 'exp', 'Reverse IP results': 'revip' }
                        for display_name, _ in stat_map.items():
                            match = re.search(f"{display_name}\\s*:\\s*(\\d+)", log_chunk)
                            stats[display_name] = match.group(1) if match else '0'
                        module_result['stats'].update(stats)
                        
                        details = {}
                        detail_pattern = re.compile(r"\[✓\] Ditemukan .*? (kebocoran API/Secret|direktori tersembunyi|teknologi|exposure|hasil reverse IP|file JavaScript)\n\s*Detail .*?:\n([\s\S]*?)(?=\n\s*\[[✓x]\]|\Z)")
                        title_map = { 'kebocoran api/secret': 'Kebocoran API/Secret', 'direktori tersembunyi': 'Direktori Tersembunyi', 'teknologi': 'Teknologi Terdeteksi', 'exposure': 'Exposure Ditemukan', 'hasil reverse ip': 'Reverse IP', 'file javascript': 'File JavaScript Ditemukan' }
                        for match in detail_pattern.finditer(log_chunk):
                            raw_title = match.group(1).lower().strip()
                            title = title_map.get(raw_title, raw_title.capitalize())
                            items = [line.strip() for line in match.group(2).strip().splitlines() if line.strip()]
                            if items: details[title] = items
                        module_result['details']['findings'] = details
                    else:
                        total_tested_match = re.search(r"Total URL diuji\s*:\s*(\d+)", log_chunk)
                        module_result['stats']['total_tested'] = total_tested_match.group(1) if total_tested_match else '0'
                        
                        if module_def['parser'] == 'standard':
                            valid_count_match = re.search(r"Terbukti (?:rentan|redirect).*?:\s*(\d+)", log_chunk)
                            module_result['stats']['valid_results'] = valid_count_match.group(1) if valid_count_match else '0'
                            valid_blocks = re.findall(r"\[>\]\s*(https?://[^\s]+)[\s\S]*?\[✓\]", log_chunk)
                            module_result['details']['urls'] = sorted(list(set(valid_blocks)))
                        
                        elif module_def['parser'] == 'sqli':
                            findings = []
                            # PERBAIKAN UTAMA: Menggunakan logika yang sama persis dengan parser modul tunggal.
                            summary_content_match = re.search(
                                r"RINGKASAN VALIDASI SQLi"
                                r"[\s\S]*?\n\n"
                                r"([\s\S]*?)"
                                r"(?=\n\n\s*─+)",
                                log_chunk
                            )
                            summary_block = summary_content_match.group(1).strip() if summary_content_match else ""
                            
                            if summary_block:
                                test_blocks = re.split(r'(?=\n*\[>\])', summary_block)
                                for block in test_blocks:
                                    # Menggunakan kondisi yang sama persis untuk memastikan akurasi
                                    if not block.strip() or "[✓] Terbukti rentan & berhasil dump DB" not in block:
                                        continue
                                    url_match = re.search(r"\[>\]\s*(https?://[^\s]+)", block)
                                    if not url_match: continue
                                    
                                    finding = {'url': url_match.group(1)}
                                    technique_match = re.search(r"📌 Teknik Injeksi SQLi.*?:\n([\s\S]*?)(?=\n---|\n\s*\[✓\])", block)
                                    finding['technique'] = '\n'.join([line for line in technique_match.group(1).strip().splitlines() if line.strip()]) if technique_match else "Tidak terdeteksi."
                                    db_match = re.search(r"📦 Database ditemukan:\n([\s\S]*)", block)
                                    finding['databases'] = [db.strip() for db in re.findall(r"^\s*-\s*(.+)", db_match.group(1), re.MULTILINE)] if db_match else []
                                    finding['status'] = "Terbukti Rentan"
                                    findings.append(finding)
                            
                            module_result['details']['findings'] = findings
                            # Statistik 'valid_results' sekarang dihitung dari temuan yang berhasil diparsing
                            module_result['stats']['valid_results'] = str(len(findings))

                    all_modules_results.append(module_result)

                report_data['all_modules_findings'] = all_modules_results
                
                total_tested_all = 0
                total_valid_all = 0
                # PERBAIKAN 1: Logika kalkulasi total temuan valid yang disempurnakan.
                for module in all_modules_results:
                    # Hanya modul kerentanan (bukan info gathering) yang dihitung total URL diujinya.
                    if module['type'] != 'info_gathering':
                        total_tested_all += int(module['stats'].get('total_tested', 0))
                        # Hanya hasil valid dari modul kerentanan yang dijumlahkan.
                        total_valid_all += int(module['stats'].get('valid_results', 0))
                
                report_data['summary'] = f"Total URL diuji (akumulatif): {total_tested_all} | Total temuan valid: {total_valid_all}"

                final_recommendations = []
                rec_main_block_match = re.search(r"🔒 REKOMENDASI MITIGASI:([\s\S]*)", cleaned_log)
                if rec_main_block_match:
                    rec_block_content = rec_main_block_match.group(1)
                    rec_sections = re.split(r'^\s*────────────────────────────────────\s*$', rec_block_content, flags=re.MULTILINE)
                    for section in rec_sections:
                        if not section.strip(): continue
                        name_match = re.search(r'🔍\s*(.*?):', section)
                        if not name_match: continue
                        
                        rec_name = name_match.group(1).strip()
                        rec_header_match = re.search(r'🔒.*$', section, re.MULTILINE)
                        rec_header = rec_header_match.group(0).strip() if rec_header_match else ""
                        rec_points = re.findall(r'^\s*\d+\.\s*(.*?)$', section, re.MULTILINE)
                        
                        if rec_points:
                            final_recommendations.append({'name': rec_name, 'header': rec_header, 'points': rec_points})
                report_data['all_modules_recommendations'] = final_recommendations
            else:
                # Jika direktori log tidak ditemukan (proses dibatalkan), siapkan pesan.
                logging.warning("Direktori log tidak ditemukan. Kemungkinan proses dibatalkan. Membuat laporan parsial.")
                report_data['summary'] = "Proses dibatalkan sebelum hasil lengkap dapat dikumpulkan."
        
        elif vuln_name == "Info Gathering":
             # Parsing modul tunggal 'Info Gathering'
            summary_block_match = re.search(r"RINGKASAN PENGUMPULAN API/SECRET[\s\S]*", cleaned_log)
            summary_block = summary_block_match.group(0) if summary_block_match else cleaned_log

            results = {}
            # 2. Regex yang lebih cerdas untuk menemukan semua blok temuan.
            section_pattern = re.compile(
                # Cocokkan header, misal: "[✓] Ditemukan 5 direktori tersembunyi"
                # dan tangkap nama kategorinya.
                r"\[✓\] Ditemukan .*? (kebocoran API/Secret|direktori tersembunyi|teknologi|exposure|hasil reverse IP|file JavaScript)\n"
                # Cocokkan baris "Detail":
                r"\s*Detail .*?:\n"
                # Tangkap isi bloknya:
                r"([\s\S]*?)"
                # Berhenti mem-parsing sebelum bagian [✓] atau [x] berikutnya dimulai.
                r"(?=\n\s*\[[✓x]\]|\Z)"
            )

            title_map = {
                'kebocoran api/secret': 'Kebocoran API/Secret',
                'direktori tersembunyi': 'Direktori Tersembunyi',
                'teknologi': 'Teknologi Terdeteksi',
                'exposure': 'Exposure Ditemukan',
                'hasil reverse ip': 'Reverse IP',
                'file javascript': 'File JavaScript Ditemukan'
            }

            for match in section_pattern.finditer(summary_block):
                raw_title = match.group(1).lower().strip()
                title = title_map.get(raw_title, raw_title.capitalize())
                # Ambil konten, bersihkan, dan pisahkan per baris. Abaikan baris kosong.
                items = [line.strip() for line in match.group(2).strip().splitlines() if line.strip()]
                if items:
                    results[title] = items
            
            report_data['info_gathering_results'] = results

            # 3. Buat ringkasan eksekutif dari data yang sudah diparsing untuk memastikan konsistensi.
            dir_count = len(results.get('Direktori Tersembunyi', []))
            tech_count = len(results.get('Teknologi Terdeteksi', []))
            exp_count = len(results.get('Exposure Ditemukan', []))
            report_data['summary'] = f"Direktori: {dir_count} | Teknologi: {tech_count} | Exposure: {exp_count}"
        
        elif vuln_name == "SQL Injection":
            # --- Parser SQL Injection Versi Final (Tangguh & Akurat) ---
            
            # 1. Isolasi blok ringkasan yang bersih untuk menghindari log yang "kotor".
            #    Blok ini berisi output dari `cat "$summary_file"` di skrip Anda.
            summary_content_match = re.search(
                r"RINGKASAN VALIDASI SQLi"  # Tanda awal
                r"[\s\S]*?\n\n"              # Lewati header (Total URL diuji, dll.)
                r"([\s\S]*?)"                # Grup 1: Tangkap konten ringkasan yang sebenarnya
                r"(?=\n\n\s*─+)",          # Berhenti sebelum garis pemisah akhir
                full_log
            )
            
            summary_block = summary_content_match.group(1).strip() if summary_content_match else ""

            # 2. Pecah ringkasan bersih menjadi blok-blok untuk setiap URL yang diuji.
            test_blocks = re.split(r'(?=\n*\[>\])', summary_block)

            for block in test_blocks:
                # Cek jika blok ini adalah temuan yang valid sesuai definisi Anda.
                if not block.strip() or "[✓] Terbukti rentan & berhasil dump DB" not in block:
                    continue

                url_match = re.search(r"\[>\]\s*(https?://[^\s]+)", block)
                if not url_match:
                    continue
                
                finding = {'url': url_match.group(1)}

                # 3. Ekstrak detail Teknik Injeksi.
                # PERBAIKAN: Regex diubah untuk berhenti di '---' atau '[✓]'
                technique_match = re.search(r"📌 Teknik Injeksi SQLi.*?:\n([\s\S]*?)(?=\n---|\n\s*\[✓\])", block)
                if technique_match:
                    technique_text = technique_match.group(1).strip()
                    cleaned_technique = '\n'.join([line for line in technique_text.splitlines() if line.strip()])
                    finding['technique'] = cleaned_technique
                else:
                    finding['technique'] = "Tidak terdeteksi secara spesifik."

                # 4. Ekstrak daftar Database.
                db_match = re.search(r"📦 Database ditemukan:\n([\s\S]*)", block)
                if db_match:
                    databases = re.findall(r"^\s*-\s*(.+)", db_match.group(1), re.MULTILINE)
                    finding['databases'] = [db.strip() for db in databases]
                else:
                    finding['databases'] = []
                
                finding['status'] = "Terbukti Rentan"
                report_data['sqli_findings'].append(finding)

            # 5. Ambil statistik dari header ringkasan dan hasil parsing untuk konsistensi.
            total_tested_match = re.search(r"Total URL diuji\s*:\s*(\d+)", full_log)
            total_tested = int(total_tested_match.group(1)) if total_tested_match else 0
            
            # Jumlah valid sekarang PASTI sama dengan jumlah temuan yang berhasil kita parse.
            total_valid = len(report_data['sqli_findings'])
            
            report_data['summary'] = f"Total URL diuji: {total_tested} | Jumlah URL Valid: {total_valid}"

            # Parse Rekomendasi untuk SQLi
            recommendations = {}
            if report_data['sqli_findings']: # Cek jika ada temuan SQLi
                rec_header_match = re.search(r"🔒\s*(Rekomendasi untuk.*?)$", cleaned_log, re.MULTILINE)
                if rec_header_match:
                    recommendations['header'] = rec_header_match.group(0).strip()
                    
                    rec_block_match = re.search(r"🔒\s*Rekomendasi untuk.*?\n([\s\S]*)", cleaned_log, re.MULTILINE)
                    if rec_block_match:
                        rec_block = rec_block_match.group(1)
                        points = re.findall(r"^\s*\d+\.\s*(.*?)$", rec_block, re.MULTILINE)
                        recommendations['points'] = points
            
            report_data['recommendations'] = recommendations

        else: # Default untuk LFI, CRLF, Open Redirect, dll.
            # 1. Bersihkan log dari kode kontrol ANSI yang dapat merusak regex.
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            cleaned_log = ansi_escape.sub('', full_log)

            # 2. Parse URL yang HANYA terbukti valid dari dalam blok ringkasan.
            #    Pola ini mencari blok yang dimulai dengan '[>] <url>' dan diakhiri dengan '[✓]',
            #    yang konsisten di semua skrip validasi Anda (baik LFI maupun Open Redirect).
            valid_blocks = re.findall(r"\[>\]\s*(https?://[^\s]+)[\s\S]*?\[✓\]", cleaned_log)
            for url in valid_blocks:
                report_data['vulnerable_urls'].append(url)
            report_data['vulnerable_urls'] = sorted(list(set(report_data['vulnerable_urls'])))

            # 3. Parse statistik dari blok ringkasan untuk akurasi maksimal.
            total_tested_match = re.search(r"Total URL diuji\s*:\s*(\d+)", cleaned_log)
            total_tested = int(total_tested_match.group(1)) if total_tested_match else 0
            
            # SUMBER KEBENARAN UTAMA untuk jumlah temuan adalah hasil parsing URL di atas.
            # Ini memastikan data di "Detail Temuan" dan "Ringkasan" selalu sinkron.
            report_data['summary'] = f"Total URL diuji: {total_tested} | Jumlah URL Valid: {len(report_data['vulnerable_urls'])}"

            # 4. PARSE REKOMENDASI (YANG HILANG)
            recommendations = {}
            # Tampilkan rekomendasi hanya jika ada kerentanan yang ditemukan
            if report_data['vulnerable_urls']:
                rec_header_match = re.search(r"🔒\s*(Rekomendasi untuk.*?)$", cleaned_log, re.MULTILINE)
                if rec_header_match:
                    recommendations['header'] = rec_header_match.group(0).strip()
                    
                    # Cari blok teks setelah header untuk mengekstrak poin-poinnya
                    rec_block_match = re.search(r"🔒\s*Rekomendasi untuk.*?\n([\s\S]*)", cleaned_log, re.MULTILINE)
                    if rec_block_match:
                        rec_block = rec_block_match.group(1)
                        points = re.findall(r"^\s*\d+\.\s*(.*?)$", rec_block, re.MULTILINE)
                        recommendations['points'] = points
            
            report_data['recommendations'] = recommendations

        # --- MEMBUAT DAN MENGIRIM LAPORAN ---
        html_content = utils.generate_html_report(report_data)
        vuln_choice = context.user_data.get("vuln_choice", "report")
        
        # PERBAIKAN 6: Simpan laporan di direktori /tmp untuk menghindari kekacauan.
        report_filename = f"/tmp/vulnstrike_{vuln_choice}_{subdomain}_{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
        
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_content)

        # --- MENGIRIM HASIL (logika ini sudah diperbaiki sebelumnya) ---
        safe_vuln_name = escape_markdown(vuln_name, version=2)
        safe_subdomain = escape_markdown(subdomain, version=2)
        caption_text = f"✅ Uji penetrasi *{safe_vuln_name}* pada *{safe_subdomain}* selesai\\.\n\n📄 Laporan lengkap terlampir\\."
        
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(report_filename, 'rb'),
            filename=report_filename,
            caption=caption_text,
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=keyboards.get_completion_keyboard()
        )
        os.remove(report_filename)
    
    except Exception as e:
        logging.error(f"Error in process_scan_and_report: {e}", exc_info=True)
        try:
            safe_subdomain_err = escape_markdown(subdomain, version=2)
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"Terjadi kesalahan tak terduga saat memproses laporan untuk *{safe_subdomain_err}*\\. Silakan coba lagi atau periksa log konsol\\.",
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=keyboards.get_main_menu_keyboard()
            )
        except Exception as send_error:
            logging.error(f"Failed to send error message to user: {send_error}")

    finally:
        # Pembersihan sesi yang aman
        if 'log_message_id' in context.user_data:
            try:
                # Coba hapus pesan log, tetapi jangan crash jika gagal
                await context.bot.delete_message(chat_id=update.effective_chat.id, message_id=context.user_data['log_message_id'])
            except Exception:
                # Abaikan saja jika ada error (misalnya, pesan terlalu tua untuk dihapus)
                pass
        
        if log_dir_to_clean and os.path.isdir(log_dir_to_clean):
            shutil.rmtree(log_dir_to_clean)

        # Hapus sisa data sesi untuk pemindaian ini
        for key in ['process', 'log_message_id', 'log_keyboard']:
            context.user_data.pop(key, None)
    
    return SELECT_VULN
