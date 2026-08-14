"""
Email Analyzer Backend - Main Entry Point
"""

import os
from app import create_app
from app.config import config

# Determine environment.
#
# An unrecognised FLASK_ENV must NOT fall back to DevelopmentConfig: that turns
# DEBUG on and disables the configured logging, and a typo ('prod', 'Production')
# is exactly how it would happen. config.py already treats anything other than
# 'development' as production for its safety checks, so this agrees with it.
env = os.environ.get('FLASK_ENV', 'development')
if env not in config:
    if env == 'development':
        config_class = config['development']
    else:
        print(f"FLASK_ENV={env!r} is not a known environment; using production settings.")
        config_class = config['production']
else:
    config_class = config[env]

app = create_app(config_class)

if __name__ == '__main__':
    port = app.config['PORT']
    host = app.config['HOST']
    debug = env == 'development'

    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║  Email Analyzer API - Itgalya Security Platform         ║
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
