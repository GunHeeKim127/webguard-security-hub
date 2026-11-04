#!/usr/bin/env python3
"""Verify a disposable Linux decoy in an empty network namespace and filesystem.

No package installation, host firewall edit, production connection or traffic
forwarding. Run only in an owned Linux lab VM. Requires root, unshare and ip.
"""
import errno
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile


def emit(value):
    """Print bounded status data; never print target paths, IPs or request data."""
    print(json.dumps(value), flush=True)


def inside(expected_namespace):
    """Create a nonprivileged, chrooted decoy inside a fresh network namespace."""
    import ctypes
    import resource
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import TCPServer

    assert os.readlink('/proc/self/ns/net') != expected_namespace
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
    assert len(links) == 1 and links[0]['ifname'] == 'lo'
    for family in ('-4', '-6'):
        routes = subprocess.check_output(['ip', family, 'route', 'show'], text=True)
        assert all(' dev lo ' in ' ' + row + ' ' for row in routes.splitlines())
    for address, port in [('198.51.100.1', 9), ('10.0.0.1', 5432)]:
        with socket.socket() as candidate:
            candidate.settimeout(1)
            try:
                candidate.connect((address, port))
            except OSError as error:
                assert error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                       errno.EADDRNOTAVAIL)
            else:
                raise AssertionError('egress not isolated')

    with tempfile.TemporaryDirectory(prefix='velthara-decoy-') as root:
        os.chmod(root, 0o555)
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                counts = {'normal': 0, 'probe': 0, 'method_denied': 0}

                class Handler(BaseHTTPRequestHandler):
                    """Serve fixed dummy responses; no files, commands or database."""

                    server_version = 'Lab'
                    sys_version = ''

                    def log_message(self, *args):
                        """Discard raw HTTP metadata rather than persisting it."""
                        pass

                    def do_GET(self):
                        """Classify five lab requests without evaluating their content."""
                        normal = self.path == '/'
                        counts['normal' if normal else 'probe'] += 1
                        response = b'Lab decoy' if normal else b'Not found'
                        self.send_response(200 if normal else 404)
                        self.send_header('Content-Type', 'text/plain; charset=utf-8')
                        self.send_header('Content-Length', str(len(response)))
                        self.send_header('X-Content-Type-Options', 'nosniff')
                        self.end_headers()
                        self.wfile.write(response)

                    def do_POST(self):
                        """Reject writes and never read or execute a submitted body."""
                        counts['method_denied'] += 1
                        self.send_response(405)
                        self.send_header('Content-Length', '0')
                        self.end_headers()

                class Server(HTTPServer):
                    """Avoid reverse DNS and bind only namespace loopback."""

                    def server_bind(self):
                        """Bind without consulting host DNS or naming services."""
                        TCPServer.server_bind(self)
                        self.server_name = 'lab'
                        self.server_port = self.server_address[1]

                server = Server(('127.0.0.1', 0), Handler)
                port = server.server_port
                os.chroot(root)
                os.chdir('/')
                os.setgroups([])
                os.setresgid(65534, 65534, 65534)
                os.setresuid(65534, 65534, 65534)
                assert ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) == 0
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
                resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
                resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
                resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
                assert os.getuid() == 65534 and os.listdir('/') == []
                with os.fdopen(write_fd, 'w') as pipe:
                    pipe.write(json.dumps({'port': port, 'unprivileged': True,
                                           'empty_root': True}) + '\n')
                    pipe.flush()
                    server.timeout = 5
                    for _ in range(5):
                        server.handle_request()
                    server.server_close()
                    pipe.write(json.dumps(counts) + '\n')
                    pipe.flush()
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write_fd)
        try:
            with os.fdopen(read_fd) as pipe:
                ready = json.loads(pipe.readline())
                assert ready['unprivileged'] and ready['empty_root']
                for method, route, expected in [('GET', '/', 200),
                                                ('GET', '/.env', 404),
                                                ('GET', '/admin', 404),
                                                ('GET', '/../../etc/passwd', 404),
                                                ('POST', '/admin', 405)]:
                    connection = http.client.HTTPConnection('127.0.0.1', ready['port'], timeout=5)
                    connection.request(method, route)
                    response = connection.getresponse()
                    assert response.status == expected
                    assert len(response.read()) < 100
                    connection.close()
                assert json.loads(pipe.readline()) == {'normal': 1, 'probe': 3, 'method_denied': 1}
            _, status = os.waitpid(child, 0)
            child = None
            assert os.waitstatus_to_exitcode(status) == 0
        finally:
            if child is not None:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)
            os.chmod(root, 0o700)
    return {'schemaVersion': 1, 'scope': 'disposable Linux lab only',
            'networkNamespace': True, 'loopbackOnly': True,
            'samplePublicEgressDenied': True, 'samplePrivateEgressDenied': True,
            'unprivilegedChroot': True, 'fixedResponses': True,
            'noRawRequestLogs': True, 'productionTrafficForwarded': False,
            'hostConfigurationChanged': False, 'cleanup': 'complete'}


def main():
    """Check prerequisites and enforce a bounded, environment-clean lab lifetime."""
    if sys.platform != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        emit({'ok': False, 'code': 'OWNED_LINUX_LAB_ROOT_REQUIRED'})
        return 2
    if len(sys.argv) == 3 and sys.argv[1] == '--inside':
        try:
            emit(inside(sys.argv[2]))
            return 0
        except BaseException:
            emit({'ok': False, 'code': 'ISOLATION_OR_LAB_CHECK_FAILED'})
            return 1
    if len(sys.argv) != 1 or not shutil.which('unshare') or not shutil.which('ip'):
        emit({'ok': False, 'code': 'UNSHARE_AND_IP_REQUIRED'})
        return 2
    namespace = os.readlink('/proc/self/ns/net')
    try:
        child = subprocess.Popen(['unshare', '--net', sys.executable, '-I', '-S',
                                  os.path.abspath(__file__), '--inside', namespace],
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        try:
            output, _ = child.communicate(timeout=40)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        if child.returncode != 0:
            emit({'ok': False, 'code': 'NAMESPACE_UNAVAILABLE_OR_CHECK_FAILED'})
            return 1
        value = json.loads(output)
        assert value.get('cleanup') == 'complete'
        emit(value)
        return 0
    except BaseException:
        emit({'ok': False, 'code': 'LAB_INCOMPLETE'})
        return 1


if __name__ == '__main__':
    sys.exit(main())
