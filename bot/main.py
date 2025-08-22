from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
    ConversationHandler,
)

from .config import BOT_TOKEN
from . import handlers

def main():
    """Jalankan bot."""
    application = Application.builder().token(BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", handlers.start_command)],
        states={
            handlers.AUTH: [
                CallbackQueryHandler(handlers.ask_for_password, pattern="^auth_password$"),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.check_password),
            ],
            handlers.SELECT_VULN: [
                CallbackQueryHandler(handlers.ask_for_subdomain, pattern="^vuln_"),
                CallbackQueryHandler(handlers.ask_for_subdomain, pattern="^menu_all_vuln$"),
                CallbackQueryHandler(handlers.help_command, pattern="^menu_help$"),
                CallbackQueryHandler(handlers.exit_command, pattern="^menu_exit$"),
            ],
            handlers.ASK_SUBDOMAIN: [
                CallbackQueryHandler(handlers.main_menu, pattern="^menu_back$"),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.confirm_subdomain)
            ],
            handlers.CONFIRM_SUBDOMAIN: [
                CallbackQueryHandler(handlers.run_scan, pattern="^confirm_scan_"),
                CallbackQueryHandler(handlers.ask_for_subdomain, pattern="^change_subdomain_"),
                CallbackQueryHandler(handlers.cancel_process, pattern="^cancel_process$"),
            ],
            handlers.RUNNING_SCAN: [
                CallbackQueryHandler(handlers.cancel_process, pattern="^cancel_process$")
            ],
            handlers.EXITED: [
                CallbackQueryHandler(handlers.restart_conversation, pattern="^restart_session$")
            ],
        },
        fallbacks=[
            CommandHandler("start", handlers.start_command),
            CallbackQueryHandler(handlers.main_menu, pattern="^menu_back$"),
            CallbackQueryHandler(handlers.exit_command, pattern="^menu_exit$"),
        ],
    )

    application.add_handler(conv_handler)
    
    print("Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main() 
