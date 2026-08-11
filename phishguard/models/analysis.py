"""PhishGuard — Analysis Result Model"""
import time, uuid
from nexuscore import Schema, Field

url_analyze_schema = Schema({
    'url':          Field(str).required().url().max_length(2000),
    'deep_inspect': Field(bool).optional(False),
})

email_analyze_schema = Schema({
    'raw_email':    Field(str).required().min_length(10).max_length(500000),
    'check_links':  Field(bool).optional(True),
})

bulk_analyze_schema = Schema({
    'urls':         Field(list).required(),
    'deep_inspect': Field(bool).optional(False),
})


class AnalysisStore:
    def __init__(self):
        self._results: dict[str, dict] = {}
        self._index: list[str] = []

    def save(self, result: dict) -> dict:
        aid = result.get('id') or str(uuid.uuid4())
        result['id'] = aid
        result['saved_at'] = time.time()
        self._results[aid] = result
        self._index.append(aid)
        if len(self._index) > 10000:
            oldest = self._index.pop(0)
            self._results.pop(oldest, None)
        return result

    def get(self, analysis_id: str) -> dict | None:
        return self._results.get(analysis_id)

    def recent(self, limit: int = 20) -> list[dict]:
        ids = self._index[-limit:][::-1]
        return [self._results[i] for i in ids if i in self._results]

    def stats(self) -> dict:
        all_r = list(self._results.values())
        verdict_counts = {}
        for r in all_r:
            v = r.get('verdict', 'unknown')
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
        return {'total_analyzed': len(all_r), 'by_verdict': verdict_counts}


analysis_store = AnalysisStore()
