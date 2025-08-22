import asyncio
import re
import os
import signal
import psutil
from telegram import Update
from telegram.ext import ContextTypes
from telegram.helpers import escape_markdown
from .config import AUTHENTICATED_USERS_FILE
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

# Regex untuk membersihkan output log dari karakter ANSI escape
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
# Regex untuk parsing ringkasan
SUMMARY_PATTERN = re.compile(r"RINGKASAN SEMUA MODUL KERENTANAN|RINGKASAN VALIDASI|RINGKASAN PENGUMPULAN API/SECRET")
RECOMMENDATION_PATTERN = re.compile(r"REKOMENDASI MITIGASI|Menampilkan rekomendasi mitigasi")

def clean_log(log_text):
    """Membersihkan log dari karakter ANSI dan pesan yang tidak perlu."""
    cleaned = ANSI_ESCAPE_PATTERN.sub('', log_text)
    
    # Hapus baris DEBUG dan baris kosong berlebih
    lines = [
        line for line in cleaned.splitlines() 
        if not line.strip().startswith(("[DEBUG]", "http", "[INFO]")) and line.strip()
    ]
    
    return "\n".join(lines)


def parse_for_telegram(text):
    """Memformat teks untuk ditampilkan dengan baik di Telegram."""
    # Ganti karakter yang bisa mengganggu parsing MarkdownV2
    # Telegram hanya mendukung subset Markdown yang terbatas
    text = text.replace('`', "'").replace('*', '#')
    
    # Hapus baris yang hanya berisi pemisah '─'
    text = re.sub(r'^[─]+$', '', text, flags=re.MULTILINE)
    
    # Parsing khusus untuk ringkasan agar lebih rapi
    if SUMMARY_PATTERN.search(text) or RECOMMENDATION_PATTERN.search(text):
         # Gunakan format tebal dan miring untuk judul
        text = SUMMARY_PATTERN.sub(r'*_\1_*', text)
        text = RECOMMENDATION_PATTERN.sub(r'*_\1_*', text)
        return f"```\n{text}\n```"
        
    # Untuk log biasa, cukup bersihkan dan bungkus dengan ```
    return f"```\n{clean_log(text)}\n```"


def load_authenticated_users():
    """Memuat daftar user ID yang sudah terautentikasi dari file."""
    try:
        with open(AUTHENTICATED_USERS_FILE, "r") as f:
            # Baca user ID, ubah ke integer, dan simpan dalam set untuk pencarian cepat
            return {int(line.strip()) for line in f if line.strip()}
    except FileNotFoundError:
        # Jika file tidak ada, kembalikan set kosong
        return set()

def add_authenticated_user(user_id):
    """Menambahkan user ID baru ke file autentikasi."""
    # Gunakan mode 'a' (append) untuk menambahkan user baru tanpa menimpa yang lama
    with open(AUTHENTICATED_USERS_FILE, "a") as f:
        f.write(f"{user_id}\n")


def generate_html_report(data: dict) -> str:
    """
    Generates an HTML report from a template using the provided data.
    
    Args:
        data: A dictionary containing all the necessary data for the report.
        
    Returns:
        The rendered HTML content as a string.
    """
    env = Environment(loader=FileSystemLoader('bot/'))
    template = env.get_template('report_template.html')
    # Perbaikan: Gunakan dictionary unpacking (**) untuk secara otomatis
    # meneruskan SEMUA data ke template. Ini lebih robust dan
    # akan mencegah error serupa di masa depan.
    return template.render(**data)

async def run_script_and_log(update: Update, context: ContextTypes.DEFAULT_TYPE, script_path, script_args, vuln_name):
    """Menjalankan skrip dan melakukan live-logging ke satu pesan."""
    
    log_message_id = context.user_data.get('log_message_id')
    if not log_message_id: return "", ""

    # PERBAIKAN: Gunakan `script_args` untuk membangun perintah subprocess.
    # Tanda bintang (*) akan "unpack" list menjadi argumen-argumen terpisah.
    process = await asyncio.create_subprocess_exec(
        'bash', script_path, *script_args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        preexec_fn=os.setsid
    )
    # PERBAIKAN: Simpan proses ke user_data yang benar
    context.user_data['process'] = process
    
    full_stdout = ""
    last_edit_time = 0
    # PERBAIKAN: Ambil keyboard dari user_data
    log_keyboard = context.user_data.get('log_keyboard')

    # PERBAIKAN: Logika untuk melewati banner.
    # Jika bukan scan semua modul, langsung mulai logging.
    # Jika scan semua modul, tunggu sampai baris "Author" muncul.
    start_logging = (vuln_name != "Semua Kerentanan")

    while process.returncode is None:
        # Cek jika proses dibatalkan dari luar
        if 'process' not in context.user_data or context.user_data['process'].pid != process.pid:
            break
            
        try:
            line_bytes = await asyncio.wait_for(process.stdout.readline(), timeout=1.5)
            if not line_bytes: break

            line = line_bytes.decode('utf-8', 'ignore').strip()
            
            if not start_logging:
                # Jika logging belum dimulai, cari pemicunya
                if "Author: Ahmad Izza" in line:
                    start_logging = True
                else:
                    # Lewati baris ini (bagian dari banner)
                    continue
            
            # Baris ini hanya akan dieksekusi jika start_logging=True
            if line:
                full_stdout += line + "\n"
                current_time = asyncio.get_event_loop().time()

                if current_time - last_edit_time > 2: # Edit setiap 2 detik
                    display_log = "\n".join(full_stdout.splitlines()[-15:])
                    try:
                        await context.bot.edit_message_text(
                            chat_id=update.effective_chat.id, message_id=log_message_id,
                            text=f"```\n--- LOG (15 baris terakhir) ---\n{clean_log(display_log)}\n```",
                            reply_markup=log_keyboard
                        )
                        last_edit_time = current_time
                    except Exception: pass
        except asyncio.TimeoutError: continue

    stdout_res, stderr_res = await process.communicate()
    full_stdout += stdout_res.decode('utf-8', 'ignore')
    full_stderr = stderr_res.decode('utf-8', 'ignore')

    return full_stdout, full_stderr

def kill_process_group(pid):
    """Menghentikan seluruh grup proses (termasuk child)."""
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False # Proses sudah tidak ada
    except Exception as e:
        print(f"Error killing process group {pid}: {e}")
        return False 
