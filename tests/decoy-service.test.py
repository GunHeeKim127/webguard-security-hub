"""Portable HTTP transport tests; Linux namespace tests remain separate."""
import contextlib
import http.client
import importlib.util
import io
import pathlib
import socket
import threading
import unittest
from http.server import HTTPServer

source = pathlib.Path(__file__).resolve().parents[1] / 'public/tools/isolated-decoy-service.py'
spec = importlib.util.spec_from_file_location('isolated_decoy', source)
decoy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoy)


class TransportTests(unittest.TestCase):
    """Exercise the actual response handler over real loopback TCP sockets."""

    def setUp(self):
        """Create a temporary transport server with no credentials or database."""
        self.counts = {'requests': 0, 'probes': 0, 'methodDenied': 0}
        self.server = HTTPServer(('127.0.0.1', 0), decoy.handler_class(self.counts))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        """Stop and close the test listener after every case."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def call(self, method, route, body=None):
        """Make one real HTTP request and return bounded response fields."""
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=4)
        try:
            connection.request(method, route, body=body)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_fixed_no_echo_or_raw_logs(self):
        """Probe contents never appear in fixed responses, headers or logs."""
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            for route in ('/', '/.env?secret=do-not-echo', '/../../etc/passwd', '/%3Cscript%3E'):
                status, body, headers = self.call('GET', route)
                self.assertEqual(status, 404)
                self.assertEqual(body, b'Not found\n')
                self.assertEqual(headers['Connection'], 'close')
                self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(headers['Content-Security-Policy'], "default-src 'none'; frame-ancestors 'none'")
                self.assertNotIn('Server', headers)
        self.assertEqual(captured.getvalue(), '')
        self.assertEqual(self.counts, {'requests': 4, 'probes': 3, 'methodDenied': 0})

    def test_write_methods_are_not_processed(self):
        """Bodies and submitted method targets are neither executed nor echoed."""
        for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT', 'TRACE'):
            status, body, _ = self.call(method, '/admin', 'do-not-process')
            self.assertEqual((status, body), (405, b'Unavailable\n'))
        self.assertEqual(self.counts, {'requests': 7, 'probes': 0, 'methodDenied': 7})
        self.assertEqual(self.call('HEAD', '/')[0:2], (404, b''))

    def test_invalid_method_is_fixed(self):
        """Unknown method errors do not use default reflecting HTML pages."""
        status, body, headers = self.call('SECRET_METHOD', '/private-value')
        self.assertEqual((status, body), (503, b'Unavailable\n'))
        self.assertEqual(headers['Content-Type'], 'text/plain; charset=utf-8')

    def test_idle_connection_expires_and_service_recovers(self):
        """An incomplete request expires so a following request can be served."""
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as client:
            client.settimeout(4)
            client.sendall(b'GET / HTTP/1.1\r\nHost:')
            self.assertEqual(client.recv(1), b'')
        self.assertEqual(self.call('GET', '/')[0], 404)

    def test_incomplete_body_expires(self):
        """A partial small body cannot occupy the service indefinitely."""
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as client:
            client.settimeout(4)
            client.sendall(b'POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 10\r\n\r\na')
            self.assertEqual(client.recv(1), b'')
        self.assertEqual(self.call('GET', '/')[0], 404)

    def test_ambiguous_body_length_is_rejected(self):
        """Conflicting body framing is rejected rather than passed through."""
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as client:
            client.settimeout(4)
            client.sendall(b'POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nContent-Length: 9\r\n\r\n')
            response = http.client.HTTPResponse(client)
            response.begin()
            self.assertEqual(response.status, 400)
            self.assertEqual(response.read(), b'Unavailable\n')


if __name__ == '__main__':
    unittest.main()
