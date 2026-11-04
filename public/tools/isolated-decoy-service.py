#!/usr/bin/env python3
"""Owned Linux VM decoy: inherited loopback listener, isolated worker, no secrets.

--check exercises a real host-namespace listener for one minute and cleans up.
--serve runs until Ctrl+C or a bounded --seconds limit. No public binding,
firewall edits, package installation, database access or traffic forwarding.
"""
import argparse
import ctypes
import errno
import http.client
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def emit(value):
    """Emit fixed operational counters/codes, never raw requests or credentials."""
    print(json.dumps(value), flush=True)


def handler_class(counts):
    """Build the shared fixed-response handler for service and transport tests."""
    class Handler(BaseHTTPRequestHandler):
        """Return fixed dummy data with short connections and no body execution."""
        server_version = 'Decoy'
        sys_version = ''

        def setup(self):
            """Bound idle clients before any request line or headers are read."""
            self.request.settimeout(2)
            super().setup()

        def log_message(self, *args):
            """Do not collect raw paths, addresses, headers or user content."""
            pass

        def send_error(self, code, message=None, explain=None):
            """Replace standard error pages that could echo submitted content."""
            self.fixed(400 if code < 500 else 503)

        def fixed(self, status):
            """Send constant output and close rather than enabling keep-alive."""
            self.close_connection = True
            payload = b'Not found\n' if status == 404 else b'Unavailable\n'
            self.send_response_only(status)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Connection', 'close')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(payload)

        def do_GET(self):
            """Count observations without persisting or forwarding their contents."""
            counts['requests'] += 1
            if self.path != '/':
                counts['probes'] += 1
            self.fixed(404)

        def do_HEAD(self):
            """Support headers-only observation without a response body."""
            self.do_GET()

        def do_POST(self):
            """Discard at most 4 KiB within two seconds, then reject without processing."""
            counts['requests'] += 1
            counts['methodDenied'] += 1
            lengths = self.headers.get_all('Content-Length', [])
            raw = lengths[0] if lengths else '0'
            if self.headers.get('Transfer-Encoding') or len(lengths) > 1 or not raw or len(raw) > 10 or any(c not in '0123456789' for c in raw):
                self.fixed(400)
                return
            remaining = int(raw)
            if remaining > 4096:
                self.fixed(413)
                return
            deadline = time.monotonic() + 2
            while remaining:
                self.connection.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = self.rfile.read1(remaining)
                if not chunk or time.monotonic() > deadline:
                    self.fixed(400)
                    return
                remaining -= len(chunk)
            self.fixed(405)

        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST
        do_OPTIONS = do_POST
        do_CONNECT = do_POST
        do_TRACE = do_POST

    return Handler


def worker(listener_fd, root, original_namespace, seconds):
    """Use an inherited listener while denying new outbound network connections."""
    import resource
    assert os.readlink('/proc/self/ns/net') != original_namespace
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
    assert len(links) == 1 and links[0]['ifname'] == 'lo'
    for address in ('198.51.100.1', '10.0.0.1'):
        with socket.socket() as candidate:
            candidate.settimeout(1)
            try:
                candidate.connect((address, 9))
            except OSError as error:
                assert error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                       errno.EADDRNOTAVAIL)
            else:
                raise RuntimeError('NETWORK_ISOLATION_FAILED')
    counts = {'requests': 0, 'probes': 0, 'methodDenied': 0}

    Handler = handler_class(counts)

    class Server(HTTPServer):
        """Use only the prebound listener, avoiding DNS and post-isolation bind."""
        def server_bind(self):
            """Never replace the inherited host-loopback listener."""
            raise RuntimeError('UNEXPECTED_BIND')

        def handle_error(self, request, address):
            """Discard client failures without tracebacks or raw request metadata."""
            pass

    inherited = socket.socket(fileno=listener_fd)
    assert inherited.getsockname()[0] == '127.0.0.1'
    server = Server(('127.0.0.1', inherited.getsockname()[1]), Handler, bind_and_activate=False)
    server.socket.close()
    server.socket = inherited
    server.server_name = 'decoy'
    server.server_port = inherited.getsockname()[1]
    server.timeout = 1
    os.chroot(root)
    os.chdir('/')
    os.setgroups([])
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
    assert ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) == 0
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024,) * 2)
    assert os.getuid() == 65534 and os.listdir('/') == []
    emit({'event': 'ready', 'networkNamespace': True, 'loopbackOnly': True,
          'sampleEgressDenied': True, 'emptyRoot': True, 'unprivileged': True,
          'noNewPrivileges': True, 'noRawRequestLogs': True})
    end = time.monotonic() + seconds if seconds else None
    last_summary = time.monotonic()
    stopped = False

    def stop(signum, frame):
        """Stop between bounded requests, without calling shutdown on this thread."""
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopped and (end is None or time.monotonic() < end):
            server.handle_request()
            if time.monotonic() - last_summary >= 60:
                emit({'event': 'counts', **counts})
                last_summary = time.monotonic()
    finally:
        server.server_close()
    emit({'event': 'stopped', **counts})


def request(port, method, route, expected):
    """Check the actual inherited listener from the VM's original namespace."""
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request(method, route)
        response = connection.getresponse()
        payload = response.read()
        assert response.status == expected
        assert response.getheader('X-Content-Type-Options') == 'nosniff'
        assert payload == (b'' if method == 'HEAD' else b'Not found\n' if expected == 404 else b'Unavailable\n')
    finally:
        connection.close()


def supervise(check, port, seconds):
    """Own the temporary root and worker lifecycle; never pass app environment."""
    namespace = os.readlink('/proc/self/ns/net')
    with tempfile.TemporaryDirectory(prefix='velthara-service-') as root:
        os.chmod(root, 0o555)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))
            listener.listen(8)
            actual_port = listener.getsockname()[1]
            child = subprocess.Popen(
                ['unshare', '--net', sys.executable, '-I', '-S', os.path.abspath(__file__),
                 '--worker', str(listener.fileno()), root, namespace, str(70 if check else seconds)],
                pass_fds=(listener.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, start_new_session=True)
            listener.close()
            captured = []
            checks = 0
            try:
                assert select.select([child.stdout], [], [], 15)[0]
                ready = json.loads(child.stdout.readline())
                assert ready['event'] == 'ready'
                assert all(ready.get(key) is True for key in (
                    'networkNamespace', 'loopbackOnly', 'sampleEgressDenied',
                    'emptyRoot', 'unprivileged', 'noNewPrivileges', 'noRawRequestLogs'))
                captured.append(ready)
                if check:
                    for method, route, expected in [('GET', '/', 404), ('GET', '/.env', 404),
                                                   ('GET', '/../../etc/passwd', 404),
                                                   ('POST', '/admin', 405), ('HEAD', '/', 404)]:
                        request(actual_port, method, route, expected)
                        checks += 1
                    for _ in range(12):
                        time.sleep(5)
                        request(actual_port, 'GET', '/', 404)
                        checks += 1
                    child.send_signal(signal.SIGTERM)
                    output, _ = child.communicate(timeout=10)
                    captured.extend(json.loads(row) for row in output.splitlines())
                    assert child.returncode == 0
                    final = captured[-1]
                    assert final == {'event': 'stopped', 'requests': 17, 'probes': 2, 'methodDenied': 1}
                else:
                    emit({'event': 'service_ready', 'scope': 'VM loopback only', 'port': actual_port,
                          'isolatedWorker': True, 'productionTrafficForwarded': False})
                    for row in child.stdout:
                        value = json.loads(row)
                        assert value.get('event') in ('counts', 'stopped')
                        emit(value)
                    assert child.wait() == 0
            finally:
                if child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                    try:
                        child.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.communicate()
                os.chmod(root, 0o700)
            with socket.socket() as probe:
                probe.settimeout(1)
                assert probe.connect_ex(('127.0.0.1', actual_port)) != 0
    return {'schemaVersion': 1, 'scope': 'owned Linux VM loopback service only',
            'mode': 'check' if check else 'serve', 'hostNamespaceIngress': True,
            'isolatedWorker': True, 'emptyRoot': True, 'unprivileged': True,
            'sampleEgressDenied': True, 'fixedResponses': True, 'noRawRequestLogs': True,
            'checks': checks, 'listenerClosed': True, 'cleanup': 'complete',
            'hostConfigurationChanged': False, 'productionTrafficForwarded': False}


def main():
    """Require explicit check/serve and enforce loopback-only, bounded arguments."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        emit({'ok': False, 'code': 'OWNED_LINUX_VM_ROOT_REQUIRED'})
        return 2
    # The internal worker receives exactly five arguments after the script name.
    if len(sys.argv) == 6 and sys.argv[1] == '--worker':
        worker(int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--serve', action='store_true')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--seconds', type=int, default=0)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 0 <= args.seconds <= 86400:
        emit({'ok': False, 'code': 'INVALID_SERVICE_LIMIT'})
        return 2
    if not shutil.which('ip') or not shutil.which('unshare'):
        emit({'ok': False, 'code': 'IP_AND_UNSHARE_REQUIRED'})
        return 2
    def stop_supervisor(signum, frame):
        """Run worker cleanup when the operator or service manager stops us."""
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop_supervisor)
    try:
        emit(supervise(args.check, 0 if args.check else args.port, args.seconds))
        return 0
    except KeyboardInterrupt:
        emit({'ok': False, 'code': 'SUPERVISOR_INTERRUPTED_WORKER_STOPPED'})
        return 130
    except BaseException:
        emit({'ok': False, 'code': 'SERVICE_CHECK_INCOMPLETE'})
        return 1


if __name__ == '__main__':
    sys.exit(main())
