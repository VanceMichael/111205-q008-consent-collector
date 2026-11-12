import json
from pathlib import Path
from service import authorized
from synthetic_source import SyntheticSource


def run():
    fixture = json.loads((Path(__file__).parent / 'fixtures/timeline.json').read_text())
    grant = fixture['grant']
    checks = [authorized(grant, 'ledger', 'invoice', instant) for instant in [grant['starts_at'], grant['ends_at']]]
    assert checks == [True, False]
    assert not authorized(grant, 'ledger', 'profile', grant['starts_at'])
    source = SyntheticSource(1)
    session = source.request('POST', '/session')['json']['session']
    page = source.request('GET', '/items', {'X-Session': session})
    assert page['status'] == 200
    final = source.request('GET', '/items?cursor=' + page['json']['next'], {'X-Session': session})
    assert final['json']['next'] is None
    return {'recording_authorization_boundaries': checks, 'synthetic_session': session, 'page': page, 'final_page': final}


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False, indent=2))
