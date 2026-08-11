"""PhishGuard — Configuration"""
import os, secrets

class Config:
    SECRET_KEY: str
    JWT_SECRET: str
    HOST: str = '0.0.0.0'
    PORT: int = 8003
    DEBUG: bool = False
    RATE_LIMIT_RPM: int = 60
    RATE_LIMIT_BURST: int = 10
    CSRF_ENABLED: bool = True
    HSTS: bool = False
    JWT_TTL: int = 3600
    JWT_REFRESH_TTL: int = 604800
    CORS_ORIGINS: tuple = ('http://localhost:3000',)
    URL_FETCH_TIMEOUT: int = 5
    MAX_REDIRECT_DEPTH: int = 5

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    @classmethod
    def from_env(cls) -> 'Config':
        cors_raw = os.environ.get('CORS_ORIGINS', 'http://localhost:3000')
        return cls(
            SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
            JWT_SECRET=os.environ.get('JWT_SECRET') or secrets.token_hex(32),
            HOST=os.environ.get('HOST', '0.0.0.0'),
            PORT=int(os.environ.get('PORT', '8003')),
            DEBUG=os.environ.get('DEBUG', '').lower() in ('1', 'true'),
            RATE_LIMIT_RPM=int(os.environ.get('RATE_LIMIT_RPM', '60')),
            RATE_LIMIT_BURST=int(os.environ.get('RATE_LIMIT_BURST', '10')),
            CSRF_ENABLED=os.environ.get('CSRF_ENABLED', 'true').lower() != 'false',
            HSTS=os.environ.get('HSTS', '').lower() in ('1', 'true'),
            JWT_TTL=int(os.environ.get('JWT_TTL', '3600')),
            JWT_REFRESH_TTL=int(os.environ.get('JWT_REFRESH_TTL', '604800')),
            CORS_ORIGINS=tuple(o.strip() for o in cors_raw.split(',') if o.strip()),
            URL_FETCH_TIMEOUT=int(os.environ.get('URL_FETCH_TIMEOUT', '5')),
            MAX_REDIRECT_DEPTH=int(os.environ.get('MAX_REDIRECT_DEPTH', '5')),
        )
