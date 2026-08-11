"""
PhishGuard — Phishing Detection Platform
Powered by NexusCore (custom Python WSGI framework, no Django/Flask)

Run (development):  python main.py
Run (production):   gunicorn -w 4 -b 0.0.0.0:8003 'main:app'
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from nexuscore import NexusCore, LoggingMiddleware, CORSMiddleware, JWT, JWTAuthMiddleware
from phishguard.config import Config
from phishguard.routes.auth import register_auth_routes
from phishguard.routes.analyze import register_analyze_routes
from phishguard.routes.reports import register_report_routes


def create_app(config: Config = None) -> NexusCore:
    cfg = config or Config.from_env()

    app = NexusCore(settings={
        'SECRET_KEY':       cfg.SECRET_KEY,
        'RATE_LIMIT_RPM':   cfg.RATE_LIMIT_RPM,
        'RATE_LIMIT_BURST': cfg.RATE_LIMIT_BURST,
        'CSRF_ENABLED':     cfg.CSRF_ENABLED,
        'HSTS':             cfg.HSTS,
        'DEBUG':            cfg.DEBUG,
    })

    app.use(LoggingMiddleware())
    app.use(CORSMiddleware(
        allow_origins=cfg.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=['GET', 'POST', 'DELETE', 'OPTIONS'],
        allow_headers=['Authorization', 'Content-Type', 'X-CSRF-Token'],
    ))

    jwt = JWT(
        secret=cfg.JWT_SECRET,
        ttl=cfg.JWT_TTL,
        refresh_ttl=cfg.JWT_REFRESH_TTL,
        issuer='phishguard',
        audience='phishguard-api',
    )
    app.use(JWTAuthMiddleware(
        jwt=jwt,
        public_paths=('/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/health', '/'),
    ))

    app.cfg = cfg
    app.jwt = jwt

    register_auth_routes(app)
    register_analyze_routes(app)
    register_report_routes(app)

    @app.get('/health')
    def health(req):
        return app.json({'status': 'ok', 'service': 'phishguard', 'version': '1.0.0'})

    @app.get('/')
    def index(req):
        return app.json({
            'service':     'PhishGuard',
            'version':     '1.0.0',
            'description': 'Phishing Detection & Analysis Platform',
            'framework':   'NexusCore — custom Python WSGI framework (no Django/Flask)',
            'endpoints': {
                'auth':    ['/api/auth/register', '/api/auth/login', '/api/auth/logout',
                            '/api/auth/refresh', '/api/auth/me'],
                'analyze': ['/api/analyze/url', '/api/analyze/url/bulk',
                            '/api/analyze/email', '/api/analyze/domain',
                            '/api/analyze/history', '/api/analyze/:id'],
                'reports': ['/api/reports/summary'],
            },
        })

    @app.error_handler(404)
    def not_found(exc, req):
        return app.json({'error': 'Not found', 'path': req.path}, status=404)

    @app.error_handler(429)
    def rate_limited(exc, req):
        return app.json({'error': 'Rate limit exceeded.'}, status=429)

    @app.error_handler(500)
    def server_error(exc, req):
        return app.json({'error': 'Internal server error'}, status=500)

    return app


app = create_app()

if __name__ == '__main__':
    cfg = Config.from_env()
    print(f'PhishGuard running on http://{cfg.HOST}:{cfg.PORT}')
    app.run(host=cfg.HOST, port=cfg.PORT, debug=cfg.DEBUG)
