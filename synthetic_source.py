from urllib.parse import parse_qs, urlsplit


class SyntheticSource:
    def __init__(self, generation):
        self.session = 'SYNTHETIC-SESSION-' + str(generation)
        self.cursor = 'SYNTHETIC-CURSOR-' + str(generation)
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        headers = headers or {}
        path = urlsplit(url)
        self.calls.append({'method': method, 'url': url})
        if method == 'POST' and path.path == '/session':
            return {'status': 200, 'json': {'session': self.session}}
        if headers.get('X-Session') != self.session:
            return {'status': 403, 'json': {'error': 'unknown session'}}
        if path.path == '/items':
            cursor = parse_qs(path.query).get('cursor', [''])[0]
            if cursor and cursor != self.cursor:
                return {'status': 409, 'json': {'error': 'wrong cursor'}}
            return {'status': 200, 'json': {'items': [{'id': 'SYN-1', 'contact': 'fictional@example.invalid'}], 'next': None if cursor else self.cursor}}
        if path.path.startswith('/details/'):
            return {'status': 200, 'json': {'id': path.path.rsplit('/', 1)[-1], 'download_url': 'https://example.invalid/file?signature=SYNTHETIC-NOT-A-SECRET'}}
        return {'status': 404, 'json': {'error': 'unknown request'}}
