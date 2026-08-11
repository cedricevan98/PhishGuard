"""
PhishGuard — Analysis Routes
POST /api/analyze/url        — analyze a single URL
POST /api/analyze/url/bulk   — analyze up to 10 URLs
POST /api/analyze/email      — analyze raw email
POST /api/analyze/domain     — check domain for typosquatting
GET  /api/analyze/history    — recent analysis history
GET  /api/analyze/:id        — get analysis result by ID
"""
import uuid
import time
from nexuscore import NexusCore, Request, Response, require_auth, require_role, ValidationError, sanitizer, EndpointRateLimiter
from phishguard.detectors.url_analyzer import analyze_url
from phishguard.detectors.domain_checker import check_domain
from phishguard.detectors.email_analyzer import analyze_email
from phishguard.models.analysis import (analysis_store, url_analyze_schema, email_analyze_schema, bulk_analyze_schema)

_analyze_limiter = EndpointRateLimiter(requests_per_minute=20, burst=5)


def register_analyze_routes(app: NexusCore):

    @app.post('/api/analyze/url')
    @require_auth
    @_analyze_limiter.limit
    def analyze_url_route(req: Request) -> Response:
        try:
            data = url_analyze_schema.validate(req.json or {})
        except ValidationError as e:
            return app.json({'errors': e.errors}, status=422)
        url = data['url']
        deep = data.get('deep_inspect', False)
        result = analyze_url(url, deep_inspect=deep, fetch_timeout=app.cfg.URL_FETCH_TIMEOUT)
        result['id'] = str(uuid.uuid4())
        result['analyzed_by'] = req.user.get('sub')
        analysis_store.save(result)
        return app.json(result, status=200)

    @app.post('/api/analyze/url/bulk')
    @require_auth
    @_analyze_limiter.limit
    def analyze_bulk(req: Request) -> Response:
        try:
            data = bulk_analyze_schema.validate(req.json or {})
        except ValidationError as e:
            return app.json({'errors': e.errors}, status=422)
        urls = data['urls'][:10]
        deep = data.get('deep_inspect', False)
        results = []
        for url in urls:
            if not isinstance(url, str) or len(url) > 2000:
                results.append({'url': str(url)[:100], 'error': 'Invalid URL'})
                continue
            result = analyze_url(url, deep_inspect=deep, fetch_timeout=3)
            result['id'] = str(uuid.uuid4())
            result['analyzed_by'] = req.user.get('sub')
            analysis_store.save(result)
            results.append(result)
        return app.json({'count': len(results), 'results': results})

    @app.post('/api/analyze/email')
    @require_auth
    @_analyze_limiter.limit
    def analyze_email_route(req: Request) -> Response:
        try:
            data = email_analyze_schema.validate(req.json or {})
        except ValidationError as e:
            return app.json({'errors': e.errors}, status=422)
        raw = data['raw_email']
        check_links = data.get('check_links', True)
        result = analyze_email(raw, check_links=check_links, url_timeout=app.cfg.URL_FETCH_TIMEOUT)
        result['id'] = str(uuid.uuid4())
        result['analyzed_by'] = req.user.get('sub')
        analysis_store.save(result)
        return app.json(result)

    @app.post('/api/analyze/domain')
    @require_auth
    def analyze_domain(req: Request) -> Response:
        body = req.json or {}
        domain = sanitizer.sanitize(str(body.get('domain', ''))).strip()
        if not domain or len(domain) > 253:
            return app.json({'error': 'Invalid domain.'}, status=422)
        result = check_domain(domain)
        return app.json(result)

    @app.get('/api/analyze/history')
    @require_auth
    def history(req: Request) -> Response:
        limit = min(int(req.query.get('limit', '20')), 100)
        recent = analysis_store.recent(limit=limit)
        return app.json({'count': len(recent), 'results': recent})

    @app.get('/api/analyze/:id')
    @require_auth
    def get_analysis(req: Request) -> Response:
        aid = req.path_params.get('id', '')
        result = analysis_store.get(aid)
        if not result:
            return app.json({'error': 'Analysis not found.'}, status=404)
        return app.json(result)
