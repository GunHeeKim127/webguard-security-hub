"""Disposable loopback-only SSH authentication checks. Run as root on Linux.

Does not modify accounts, /etc/ssh, ~/.ssh, systemd, firewall or port 22.
Uses fresh host/client keys and a forced /usr/bin/true command on its own server.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import stat
import tempfile
import time


def run(args, timeout=15):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=False)


def checked(args):
    result = run(args)
    if result.returncode:
        raise RuntimeError("PREPARATION_FAILED: " + Path(args[0]).name)
    return result.stdout


CASES = ("allowed_key", "custom_key_location", "safe_symlink", "unregistered_key",
         "missing_key_file", "writable_key_file", "writable_parent", "unsafe_symlink",
         "denied_user", "root_login_disabled", "password_method_disabled")


def private_workspace():
    """Choose by observed properties, never by a presumed-safe directory name."""
    observations = []
    for candidate in ("/run", "/var/lib", "/root"):
        try:
            base = Path(candidate).resolve(strict=True)
            if not base.is_dir():
                raise ValueError("not-directory")
            for parent in (base, *base.parents):
                metadata = parent.stat()
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError("unsafe-owner-or-write-permission")
            if os.statvfs(base).f_flag & os.ST_RDONLY:
                raise ValueError("read-only-filesystem")
            workspace = tempfile.TemporaryDirectory(prefix="webguard-ssh-auth-", dir=str(base))
            observations.append({"candidate": candidate, "selected": True,
                                 "symlinkResolved": str(base) != candidate})
            return workspace, observations
        except (OSError, ValueError) as error:
            observations.append({"candidate": candidate, "selected": False,
                                 "reason": str(error) if isinstance(error, ValueError) else type(error).__name__})
    raise RuntimeError("NO_SAFE_WRITABLE_WORKSPACE")


def inspect_key_path(path):
    """Fixed metadata only. Do not emit private paths, key contents or log lines."""
    observed = {"symlink": path.is_symlink(), "exists": path.exists(), "issues": []}
    try:
        target = path.resolve(strict=True)
        metadata = target.stat()
        observed.update({"ownerUid": metadata.st_uid, "mode": oct(stat.S_IMODE(metadata.st_mode))})
        if not stat.S_ISREG(metadata.st_mode):
            observed["issues"].append("not-regular-file")
        if metadata.st_uid != 0:
            observed["issues"].append("unexpected-owner")
        if metadata.st_mode & 0o022:
            observed["issues"].append("writable-key-file")
        for parent in target.parents:
            parent_metadata = parent.stat()
            if parent_metadata.st_uid != 0 or parent_metadata.st_mode & 0o022:
                observed["issues"].append("unsafe-parent")
                break
    except FileNotFoundError:
        observed["issues"].append("missing-key-file-or-target")
    except OSError:
        observed["issues"].append("path-inspection-failed")
    return observed


def reason_guidance(codes):
    messages = {
        "unsafe-key-directory": "Check the configured key path and its resolved parent directories: owner and group/other write permissions. A directory name alone does not determine safety.",
        "unsafe-key-file": "Check the key file owner and group/other write permissions; moving the file alone may not resolve the issue.",
        "key-file-unreadable": "Check the configured key path, file existence, symlink target and access permissions.",
        "missing-file-paired-control": "Confirm that this is the intended key-file path. In this isolated test, authentication was denied with the file absent and succeeded after the same public key was placed at the same path; the temporary file was then removed.",
        "locked-account": "Check account policy. A key-path change does not resolve a locked account.",
        "user-denied": "Check the account allow/deny rule; a key-path change does not resolve this policy rejection.",
        "unregistered-key": "Check that the offered public key matches an approved key. Do not infer a path failure from authentication denial alone.",
        "root-policy-denied": "Root login is disabled in this isolated test configuration.",
        "password-method-disabled": "Password authentication is not offered; no password was submitted.",
    }
    return [messages[code] for code in codes if code in messages]


def path_notice():
    return {"severity": "info", "messageKo": "설정된 키 파일 경로가 사용자가 의도한 경로인지 확인해 주세요. 경로 지정 자체는 오류나 취약점 판정이 아닙니다.",
            "message": "Confirm that the configured key-file path is intentional. A configured path alone is not an error or vulnerability finding."}


def result_status(case, observed_expected, positive_control):
    if case != "allowed_key" and not positive_control:
        return "INCONCLUSIVE"
    return "PASS" if observed_expected else "FAIL"


def missing_file_confirmed(path_missing, denied, restored_exit, restored_key_accepted, isolated_key_source):
    # A paired intervention is stronger than depending on a version-specific
    # missing-file log phrase: same key/server/path fails absent and works present.
    return (path_missing and denied and restored_exit == 0
            and restored_key_accepted and isolated_key_source)


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run in the existing Linux root session")
    for tool in ("/usr/sbin/sshd", "/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/bin/true"):
        if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
            raise RuntimeError("MISSING_TOOL: " + tool)
    os.umask(0o077)
    results = []
    positive_control = False
    workspace, workspace_checks = private_workspace()
    with workspace as folder:
        root = Path(folder)
        for key in ("host", "allowed", "unregistered"):
            checked(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / key)])
        shutil.copyfile(root / "allowed.pub", root / "authorized_keys")
        os.chmod(root / "authorized_keys", 0o600)
        alternate = root / "custom-key-location"
        alternate.mkdir(mode=0o700)
        shutil.copyfile(root / "allowed.pub", alternate / "approved_keys")
        (root / "safe-link").symlink_to(alternate / "approved_keys")
        unsafe_parent = root / "writable-key-parent"
        unsafe_parent.mkdir(mode=0o700)
        shutil.copyfile(root / "allowed.pub", unsafe_parent / "approved_keys")
        unsafe_parent.chmod(0o777)
        (root / "unsafe-link").symlink_to(unsafe_parent / "approved_keys")
        shutil.copyfile(root / "allowed.pub", root / "writable_keys")
        (root / "writable_keys").chmod(0o666)
        paths = {"custom_key_location": alternate / "approved_keys", "safe_symlink": root / "safe-link",
                 "missing_key_file": root / "missing_keys", "writable_key_file": root / "writable_keys",
                 "writable_parent": unsafe_parent / "approved_keys", "unsafe_symlink": root / "unsafe-link"}
        for case in CASES:
            authorized_path = paths.get(case, root / "authorized_keys")
            path_inspection = inspect_key_path(authorized_path)
            restored_result = None
            initial_logs = None
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            if port == 22:
                raise RuntimeError("REFUSING_PORT_22")
            config = root / "sshd_config"
            config.write_text(
                f"Port {port}\nListenAddress 127.0.0.1\nAddressFamily inet\n"
                f"HostKey {root / 'host'}\nPidFile {root / 'server.pid'}\n"
                f"AuthorizedKeysFile {authorized_path}\n"
                "AuthorizedKeysCommand none\nStrictModes yes\nUsePAM no\n"
                "PubkeyAuthentication yes\nPasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\nPermitEmptyPasswords no\n"
                "AuthenticationMethods publickey\nAllowUsers root\n"
                f"PermitRootLogin {'no' if case == 'root_login_disabled' else 'prohibit-password'}\n"
                + ("DenyUsers root\n" if case == "denied_user" else "")
                + "DisableForwarding yes\nPermitTTY no\nPermitUserRC no\n"
                "ForceCommand /usr/bin/true\nMaxAuthTries 4\nLoginGraceTime 5\nLogLevel DEBUG1\n",
                encoding="utf-8")
            checked(["/usr/sbin/sshd", "-t", "-f", str(config)])
            effective_text = checked(["/usr/sbin/sshd", "-T", "-f", str(config)])
            effective = dict(line.split(None, 1) for line in effective_text.splitlines() if " " in line)
            if (effective.get("listenaddress") != f"127.0.0.1:{port}"
                    or effective.get("passwordauthentication") != "no"
                    or effective.get("forcecommand") != "/usr/bin/true"
                    or effective.get("authorizedkeysfile") != str(authorized_path)
                    or effective.get("authorizedkeyscommand") != "none"):
                raise RuntimeError("ISOLATION_CHECK_FAILED")
            known = root / "known_hosts"
            known.write_text(f"[127.0.0.1]:{port} " + (root / "host.pub").read_text(), encoding="utf-8")
            log_path = root / (case + ".log")
            with log_path.open("w", encoding="utf-8") as log:
                server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
                try:
                    for _ in range(60):
                        if server.poll() is not None:
                            raise RuntimeError("ISOLATED_SERVER_START_FAILED")
                        if f"Server listening on 127.0.0.1 port {port}" in log_path.read_text():
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("ISOLATED_SERVER_START_TIMEOUT")
                    key = root / ("unregistered" if case == "unregistered_key" else "allowed")
                    args = ["/usr/bin/ssh", "-F", "/dev/null", "-v", "-p", str(port), "-i", str(key)]
                    options = {"BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none",
                               "StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(known),
                               "GlobalKnownHostsFile": "/dev/null", "ConnectTimeout": "5",
                               "ConnectionAttempts": "1", "ControlMaster": "no", "ControlPath": "none",
                               "PreferredAuthentications": "password" if case == "password_method_disabled" else "publickey"}
                    if case == "password_method_disabled":
                        options["PubkeyAuthentication"] = "no"
                    for name, value in options.items():
                        args += ["-o", name + "=" + value]
                    result = run(args + ["root@127.0.0.1", "/usr/bin/true"])
                    if case == "missing_key_file":
                        initial_logs = log_path.read_text()
                        try:
                            shutil.copyfile(root / "allowed.pub", authorized_path)
                            os.chmod(authorized_path, 0o600)
                            restored_result = run(args + ["root@127.0.0.1", "/usr/bin/true"])
                        finally:
                            authorized_path.unlink(missing_ok=True)
                finally:
                    if server.poll() is None:
                        server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
            all_logs = log_path.read_text()
            logs = initial_logs if initial_logs is not None else all_logs
            denied = result.returncode == 255 and "Permission denied" in result.stderr
            if case in ("allowed_key", "custom_key_location", "safe_symlink"):
                passed = result.returncode == 0 and "Accepted publickey for root" in logs
            elif case == "unregistered_key":
                passed = denied and "Failed publickey for root" in logs
            elif case == "missing_key_file":
                passed = missing_file_confirmed(
                    "missing-key-file-or-target" in path_inspection["issues"], denied,
                    restored_result.returncode if restored_result else None,
                    "Accepted publickey for root" in all_logs, True)
            elif case == "writable_key_file":
                passed = denied and "writable-key-file" in path_inspection["issues"] and "bad ownership or modes for file" in logs
            elif case in ("writable_parent", "unsafe_symlink"):
                passed = denied and "unsafe-parent" in path_inspection["issues"] and "bad ownership or modes for directory" in logs
            elif case == "denied_user":
                passed = denied and "listed in DenyUsers" in logs
            elif case == "root_login_disabled":
                passed = denied and effective.get("permitrootlogin") == "no" and (
                    "Failed publickey for root" in logs or "ROOT LOGIN REFUSED" in logs)
            else:
                passed = denied and "Authentications that can continue: publickey" in result.stderr
            reasons = []
            markers = {
                "unsafe-key-directory": "bad ownership or modes for directory",
                "unsafe-key-file": "bad ownership or modes for file",
                "locked-account": "account is locked",
                "key-file-unreadable": "Could not open user",
                "user-denied": "listed in DenyUsers",
                "key-accepted": "Accepted publickey for root",
            }
            for code, marker in markers.items():
                if marker in logs:
                    reasons.append(code)
            if passed and case in ("unregistered_key", "root_login_disabled", "password_method_disabled"):
                reasons.append({"unregistered_key": "unregistered-key", "root_login_disabled": "root-policy-denied",
                                "password_method_disabled": "password-method-disabled"}[case])
            if passed and case == "missing_key_file":
                reasons.append("missing-file-paired-control")
            if case == "allowed_key":
                positive_control = bool(passed)
            status = result_status(case, passed, positive_control)
            results.append({"case": case, "pass": status == "PASS", "observedExpectedOutcome": bool(passed),
                            "status": status, "clientExit": result.returncode, "reasonCodes": reasons,
                            "guidance": reason_guidance(reasons), "pathNotice": path_notice(),
                            "keyPathInspection": path_inspection,
                            "authenticationDenied": denied,
                            "pairedRestoration": {"clientExit": restored_result.returncode,
                                                  "acceptedKeyObserved": "Accepted publickey for root" in all_logs,
                                                  "basis": "same server, client key and path; only temporary public-key file presence changed"}
                            if restored_result else None})
            print(status + " " + case, flush=True)
    print("CLEANUP_OK: isolated servers and temporary keys removed", flush=True)
    print(json.dumps({"schemaVersion": 4, "positiveControlPassed": positive_control, "workspaceChecks": workspace_checks,
                      "unassessed": ["extended ACL", "SELinux/AppArmor policy", "production SSH and external key lookup"],
                      "scope": "isolated loopback test configuration, not production SSH policy",
                      "passwordCase": "method disabled; no password submitted", "results": results}))
    return 0 if all(item["pass"] for item in results) else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--plan"]:
        print(json.dumps({"scope": "planned, not executed", "cases": CASES}))
        sys.exit(0)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        sys.exit(main())
    except Exception as error:
        print("CHECK_ABORTED: " + str(error), file=sys.stderr)
        sys.exit(1)
