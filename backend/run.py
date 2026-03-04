"""
Email Analyzer Backend - Main Entry Point
"""

import os
from app import create_app
from app.config import config

# Determine environment
env = os.environ.get('FLASK_ENV', 'development')
app = create_app(config.get(env, config['default']))

if __name__ == '__main__':
    port = app.config['PORT']
    host = app.config['HOST']
    debug = env == 'development'

    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║  Email Analyzer API - Ataram Security Platform          ║
    ║  Environment: {env.upper().ljust(43)} ║
    ║  Server: http://{host}:{port}
    ║  Health: http://{host}:{port}/health
    ║  API Endpoint: http://{host}:{port}/api/analyze
    ╚══════════════════════════════════════════════════════════╝
    """)

    app.run(
        host=host,
        port=port,
        debug=debug
    )
