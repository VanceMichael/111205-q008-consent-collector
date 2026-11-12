import json
from pathlib import Path
from service import authorized


def run():
    fixture = json.loads((Path(__file__).parent / 'fixtures/timeline.json').read_text())
    grant = fixture['grant']
    checks = [authorized(grant, 'ledger', 'invoice', instant) for instant in [grant['starts_at'], grant['ends_at']]]
    assert checks == [True, False]
    assert not authorized(grant, 'ledger', 'profile', grant['starts_at'])
    return {'valid_at_start_and_end': checks, 'race_events': [event['kind'] for event in fixture['events']]}


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False, indent=2))
