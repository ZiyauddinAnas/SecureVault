import os
import sys
import signal
import logging
from datetime import datetime
from app import app, setup_database

def setup_logging():
    """Setup logging for production deployment"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    log_level = logging.INFO if os.environ.get('FLASK_ENV') == 'production' else logging.DEBUG
    
    # File handler for all logs
    file_handler = logging.FileHandler(f'logs/securevault_{datetime.now().strftime("%Y%m%d")}.log')
    file_handler.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, console_handler]
    )
    
    # Configure Flask app logger
    app.logger.setLevel(log_level)
    app.logger.addHandler(file_handler)

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logging.info(f"Received signal {signum}. Shutting down gracefully...")
    sys.exit(0)

def main():
    """Main function to start the application"""
    # Setup logging first
    setup_logging()
    
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    logging.info("🔐 SecureVault - Starting up...")
    
    # Check if running in production
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    # Setup database
    try:
        setup_database()
        logging.info("✅ Database initialized successfully")
    except Exception as e:
        logging.error(f"❌ Database setup failed: {e}")
        sys.exit(1)
    
    # Get configuration from environment variables
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8095))
    debug = not is_production
    
    # Log startup information
    if is_production:
        logging.info("🚀 Starting SecureVault in PRODUCTION mode...")
        if not os.environ.get('SECRET_KEY'):
            logging.warning("⚠️  SECRET_KEY environment variable not set! Using generated key.")
        logging.info(f"🌐 Server will be available on {host}:{port}")
        logging.info("📝 Logs are being written to logs/ directory")
    else:
        logging.info("🚀 Starting SecureVault in DEVELOPMENT mode...")
        logging.info(f"📱 Access the application at: http://localhost:{port}")
        logging.info("🛑 Press Ctrl+C to stop the server")
    
    try:
        # Disable Flask's default request logging in production to avoid duplicate logs
        if is_production:
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)
        
        app.run(debug=debug, host=host, port=port, threaded=True)
    except KeyboardInterrupt:
        logging.info("👋 Shutting down SecureVault...")
    except Exception as e:
        logging.error(f"❌ Application error: {e}")
        raise

if __name__ == '__main__':
    main() 