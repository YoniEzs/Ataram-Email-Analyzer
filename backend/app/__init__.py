"""
Email Analyzer Backend Application
Ataram Email Security Platform
"""

from flask import Flask
from flask_cors import CORS
from app.config import Config
import logging
from logging.handlers import RotatingFileHandler
import os


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable CORS for frontend
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"]
        }
    })

    # Setup logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler(
            'logs/email_analyzer.log',
            maxBytes=10240000,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Email Analyzer startup')

    # Register blueprints
    from app.api import analysis
    app.register_blueprint(analysis.bp)

    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'healthy', 'service': 'Email Analyzer API'}, 200

    return app
