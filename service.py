from datetime import datetime

def authorized(grant, source, category, instant):
    start = datetime.fromisoformat(grant['starts_at'])
    end = datetime.fromisoformat(grant['ends_at']) if grant.get('ends_at') else None
    current = datetime.fromisoformat(instant)
    return source in grant['sources'] and category in grant['categories'] and start <= current and (end is None or current < end)
