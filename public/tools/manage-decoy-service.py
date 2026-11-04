#!/usr/bin/env python3
"""Install/verify only the named, loopback-only VELTHARA service in an owned VM.

--install refuses existing files/services, checks pinned downloads, verifies unit,
start/stop/restart and worker isolation. --enable additionally enables boot start.
--verify checks an existing service without changing service state.
"""
import argparse
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

NAME = 'velthara-decoy.service'
TOOL = pathlib.Path('/opt/velthara-decoy/isolated-decoy-service.py')
UNIT = pathlib.Path('/etc/systemd/system') / NAME
ARTIFACTS = {
    'isolated-decoy-service.py': '6f51e8a264ec5f438ddea42a2db8e1ca02a388c003c933b47ef9a32b53196beb',
    'velthara-decoy.service': 'db46e6685a0f9cb58d985398373aa1fb873d62f941f2dda81564a3286f1a3f6c',
}


def command(*args):
    """Run fixed local service operations; never expose raw system output."""
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=25, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}).stdout


def fetch(name):
    """Fetch one pinned public artifact over verified TLS, without proxy settings."""
    url = 'https://securitywebguard.vercel.app/tools/' + name
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context))
    with opener.open(url, timeout=20) as response:
        assert response.geturl() == url and response.status == 200
        data = response.read(1024 * 1024 + 1)
    assert len(data) <= 1024 * 1024 and hashlib.sha256(data).hexdigest() == ARTIFACTS[name]
    return data


def safe_parent(path):
    """Reject symlink, non-root-owned or writable installation ancestors."""
    for candidate in (path, *path.parents):
        assert not candidate.is_symlink()
        if candidate.exists():
            status = candidate.stat()
            if not (candidate.is_dir() and status.st_uid == 0 and not status.st_mode & 0o022):
                raise RuntimeError('UNSAFE_INSTALL_PARENT')


def state():
    """Read this specific service's state and main process identifier."""
    lines = command('systemctl', 'show', NAME, '-p', 'ActiveState', '-p', 'MainPID').splitlines()
    values = dict(row.split('=', 1) for row in lines if '=' in row)
    assert values.get('ActiveState') == 'active'
    pid = int(values.get('MainPID', '0'))
    assert pid > 1
    return pid


def response_check():
    """Verify fixed content over the actual VM loopback listener."""
    connection = http.client.HTTPConnection('127.0.0.1', 8765, timeout=3)
    try:
        connection.request('GET', '/.env?decoy-self-check')
        response = connection.getresponse()
        assert response.status == 404 and response.read() == b'Not found\n'
        assert response.getheader('X-Content-Type-Options') == 'nosniff'
        assert response.getheader('Connection') == 'close'
    finally:
        connection.close()


def verify_worker():
    """Check real process namespace/UID/root/capabilities/environment, not claims alone."""
    deadline = time.monotonic() + 15
    while True:
        try:
            parent = state()
            children = pathlib.Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
            assert len(children) == 1 and children[0].isdigit()
            child = int(children[0])
            proc = pathlib.Path(f'/proc/{child}')
            status = dict(row.split(':', 1) for row in (proc / 'status').read_text().splitlines() if ':' in row)
            assert status['Uid'].split() == ['65534'] * 4
            assert status['Gid'].split() == ['65534'] * 4
            assert int(status['CapEff'].strip(), 16) == 0
            assert int(status['NoNewPrivs'].strip()) == 1
            assert os.readlink(proc / 'ns/net') != os.readlink(f'/proc/{parent}/ns/net')
            assert list((proc / 'root').iterdir()) == []
            environment = (proc / 'environ').read_bytes().split(b'\0')
            assert all(item.split(b'=', 1)[0] in (b'PATH', b'LC_CTYPE') for item in environment if item)
            assert hashlib.sha256(TOOL.read_bytes()).hexdigest() == ARTIFACTS[TOOL.name]
            assert hashlib.sha256(UNIT.read_bytes()).hexdigest() == ARTIFACTS[NAME]
            response_check()
            return parent, {'workerUnprivileged': True, 'workerCapabilitiesEmpty': True,
                            'workerNoNewPrivileges': True, 'workerNamespaceSeparated': True,
                            'workerRootEmpty': True, 'noAppSecretsInjected': True,
                            'pinnedArtifacts': True, 'fixedResponse': True}
        except (AssertionError, OSError, ValueError, subprocess.SubprocessError):
            if time.monotonic() >= deadline:
                raise RuntimeError('WORKER_VERIFICATION_FAILED') from None
            time.sleep(0.5)


def install(enable):
    """Create only a new named service, roll back own files if verification fails."""
    safe_parent(TOOL.parent)
    safe_parent(UNIT.parent)
    if TOOL.exists() or TOOL.is_symlink() or UNIT.exists() or UNIT.is_symlink():
        raise RuntimeError('EXISTING_SERVICE_NOT_OVERWRITTEN')
    load = command('systemctl', 'show', NAME, '-p', 'LoadState', '--value').strip()
    assert load == 'not-found'
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 8765))
    artifacts = {name: fetch(name) for name in ARTIFACTS}
    with tempfile.TemporaryDirectory(prefix='velthara-unit-') as temp:
        candidate = pathlib.Path(temp) / NAME
        candidate.write_bytes(artifacts[NAME])
        command('systemd-analyze', 'verify', str(candidate))
    created = []
    new_directory = not TOOL.parent.exists()
    touched_service = False
    try:
        TOOL.parent.mkdir(mode=0o755, exist_ok=True)
        for destination in (TOOL, UNIT):
            with destination.open('xb') as output:
                created.append(destination)
                output.write(artifacts[destination.name])
            destination.chmod(0o644)
        command('systemctl', 'daemon-reload')
        touched_service = True
        command('systemctl', 'start', NAME)
        first_pid, checks = verify_worker()
        command('systemctl', 'stop', NAME)
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(('127.0.0.1', 8765)) != 0
        assert not pathlib.Path(f'/proc/{first_pid}').exists()
        command('systemctl', 'start', NAME)
        second_pid, _ = verify_worker()
        assert first_pid != second_pid
        if enable:
            command('systemctl', 'enable', NAME)
            assert command('systemctl', 'is-enabled', NAME).strip() == 'enabled'
        return {'ok': True, 'scope': 'owned Linux VM loopback service only', 'installed': True,
                'startStopRestartVerified': True, 'enabledAtBoot': enable,
                'actualRebootTested': False, 'serviceLeftRunning': True,
                'publicExposure': False, 'productionTrafficForwarded': False, **checks}
    except BaseException:
        if touched_service:
            command('systemctl', 'disable', '--now', NAME)
        for destination in reversed(created):
            destination.unlink()
        if new_directory:
            TOOL.parent.rmdir()
        if touched_service:
            command('systemctl', 'daemon-reload')
        raise


def boot_evidence():
    """Compare installation time and systemd activation against the current boot."""
    boot = next(int(row.split()[1]) for row in pathlib.Path('/proc/stat').read_text().splitlines() if row.startswith('btime '))
    activated = int(command('systemctl', 'show', NAME, '-p', 'ActiveEnterTimestampMonotonic', '--value').strip())
    before_boot = UNIT.stat().st_mtime < boot and TOOL.stat().st_mtime < boot
    near_boot = 0 < activated <= 120 * 1000000
    try:
        enabled = command('systemctl', 'is-enabled', NAME).strip() == 'enabled'
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        enabled = False
    return {'installedBeforeCurrentBoot': before_boot, 'serviceStartedNearBoot': near_boot,
            'enabledAtBoot': enabled, 'actualRebootTested': before_boot and near_boot and enabled}


def main():
    """Require explicit local installation or verification; never alter other services."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        print(json.dumps({'ok': False, 'code': 'OWNED_LINUX_VM_ROOT_REQUIRED'}))
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--install', action='store_true')
    modes.add_argument('--verify', action='store_true')
    parser.add_argument('--enable', action='store_true')
    args = parser.parse_args()
    if args.enable and not args.install:
        parser.error('--enable requires --install')
    try:
        assert pathlib.Path('/proc/1/comm').read_text().strip() == 'systemd'
        assert pathlib.Path('/usr/bin/python3').is_file()
        for tool in ('systemctl', 'systemd-analyze', 'ip', 'unshare'):
            assert shutil.which(tool)
        if args.install:
            result = install(args.enable)
        else:
            _, checks = verify_worker()
            result = {'ok': True, 'scope': 'owned Linux VM loopback service only', **checks,
                      'changed': False, **boot_evidence()}
        print(json.dumps(result))
        return 0
    except BaseException as error:
        code = str(error) if isinstance(error, RuntimeError) and str(error) in (
            'WORKER_VERIFICATION_FAILED', 'UNSAFE_INSTALL_PARENT', 'EXISTING_SERVICE_NOT_OVERWRITTEN') else 'SERVICE_MANAGEMENT_INCOMPLETE'
        print(json.dumps({'ok': False, 'code': code,
                          'hint': 'Check existing service, prerequisites, pinned downloads and VM security policy; protections were not disabled.'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
