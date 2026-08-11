"""PhishGuard — Reports Routes"""
import time
from nexuscore import NexusCore, Request, Response, require_auth, require_role
from phishguard.models.analysis import analysis_store


def register_report_routes(app: NexusCore):

    @app.get('/api/reports/summary')
    @require_auth
    def summary(req: Request) -> Response:
        stats = analysis_store.stats()
        recent = analysis_store.recent(limit=5)
        phishing = [r for r in analysis_store.recent(limit=500) if r.get('verdict') == 'phishing']
        return app.json({'generated_at': time.time(), 'stats': stats, 'recent_analyses': recent, 'top_phishing': phishing[:10]})
