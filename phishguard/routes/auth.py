"""PhishGuard — Auth Routes"""
from nexuscore import NexusCore, Request, Response, ValidationError, require_auth, sanitizer, password_hasher, EndpointRateLimiter
from phishguard.models.user import register_schema, login_schema, get_users, get_by_email

_auth_limiter = EndpointRateLimiter(requests_per_minute=10, burst=3)


def register_auth_routes(app: NexusCore):
    jwt = app.jwt
    _users = get_users()
    _by_email = get_by_email()

    @app.post('/api/auth/register')
    @_auth_limiter.limit
    def register(req: Request) -> Response:
        try:
            data = register_schema.validate(req.json or {})
        except ValidationError as e:
            return app.json({'errors': e.errors}, status=422)
        username = sanitizer.sanitize(data['username'])
        email = sanitizer.sanitize(data['email'])
        if username in _users:
            return app.json({'error': 'Username taken.'}, status=409)
        if email in _by_email:
            return app.json({'error': 'Email registered.'}, status=409)
        _users[username] = {'username': username, 'email': email, 'role': 'analyst', 'password_hash': password_hasher.hash(data['password']), 'active': True, 'failed_attempts': 0, 'locked': False}
        _by_email[email] = username
        return app.json({'message': 'Account created.', 'role': 'analyst'}, status=201)

    @app.post('/api/auth/login')
    @_auth_limiter.limit
    def login(req: Request) -> Response:
        try:
            data = login_schema.validate(req.json or {})
        except ValidationError as e:
            return app.json({'errors': e.errors}, status=422)
        username = data['username']
        user = _users.get(username)
        if not user:
            return app.json({'error': 'Invalid credentials.'}, status=401)
        if user.get('locked'):
            return app.json({'error': 'Account locked. Contact admin.'}, status=403)
        if not password_hasher.verify(data['password'], user['password_hash']):
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            if user['failed_attempts'] >= 5:
                user['locked'] = True
            return app.json({'error': 'Invalid credentials.'}, status=401)
        user['failed_attempts'] = 0
        payload = {'sub': username, 'role': user['role']}
        token = jwt.encode(payload)
        refresh_token = jwt.encode_refresh(payload)
        return app.json({'access_token': token, 'refresh_token': refresh_token, 'token_type': 'Bearer'})

    @app.post('/api/auth/refresh')
    def refresh(req: Request) -> Response:
        body = req.json or {}
        rt = body.get('refresh_token', '')
        try:
            payload = jwt.decode_refresh(rt)
        except Exception:
            return app.json({'error': 'Invalid refresh token.'}, status=401)
        new_token = jwt.encode({'sub': payload['sub'], 'role': payload['role']})
        return app.json({'access_token': new_token, 'token_type': 'Bearer'})

    @app.get('/api/auth/me')
    @require_auth
    def me(req: Request) -> Response:
        username = req.user.get('sub')
        user = _users.get(username, {})
        return app.json({'username': user.get('username'), 'email': user.get('email'), 'role': user.get('role')})

    @app.post('/api/auth/logout')
    @require_auth
    def logout(req: Request) -> Response:
        return app.json({'message': 'Logged out.'})
