"""Run bounded BIND tests in private loopback instances; never change host DNS.

Uses installed official tools only. Creates no accounts, modifies no system
configuration and stops only its own processes. Prints fixed observations,
never keys, configuration, paths or daemon logs. Test inputs are not for upload.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

CASES = ("recursive_allowed", "recursive_denied", "transfer_allowed", "transfer_denied",
         "dnssec_valid", "dnssec_bogus")


def run(args, cwd=None, timeout=20):
    """run: Capture a bounded installed-tool invocation without interactive input."""
    return subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=False)


def tool(name):
    """tool: Locate an installed utility without downloading or installing software."""
    value = shutil.which(name)
    if not value:
        for folder in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
            candidate = Path(folder) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                value = str(candidate)
                break
    return value


def free_port():
    """free_port: Choose a high loopback port available to both TCP and UDP DNS."""
    for _ in range(20):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("NO_FREE_LOOPBACK_PORT")


def quote(value):
    """quote: Escape a generated private workspace path for a BIND string value."""
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def options(folder, port, recursive, validation):
    """options: Build private-instance paths and explicit loopback/access settings."""
    return ("options { directory " + quote(folder) + "; "
            "listen-on port " + str(port) + " { 127.0.0.1; }; listen-on-v6 { none; }; "
            "pid-file " + quote(folder / "named.pid") + "; "
            "session-keyfile " + quote(folder / "session.key") + "; "
            "managed-keys-directory " + quote(folder) + "; "
            "recursion " + ("yes" if recursive else "no") + "; "
            "allow-recursion { 127.0.0.1; }; allow-query-cache { 127.0.0.1; }; "
            "allow-query { any; }; allow-transfer { 127.0.0.1; }; "
            "dnssec-validation " + validation + "; empty-zones-enable no; notify no; }; "
            "controls {}; ")


def stop(state):
    """stop: Terminate only the child daemon and close its private log handle."""
    if not state:
        return
    process, log = state
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    log.close()


def start(named, checkconf, config, folder):
    """start: Validate the private configuration and launch one bounded BIND process."""
    if run([checkconf, str(config)]).returncode:
        raise RuntimeError("PRIVATE_CONFIG_REJECTED")
    log = open(folder / "daemon.log", "w", encoding="utf-8")
    args = [named, "-g", "-c", str(config), "-n", "1", "-U", "1"]
    if os.geteuid() == 0:
        import pwd
        args += ["-u", pwd.getpwuid(os.geteuid()).pw_name]
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    return process, log


def query(dig, port, source="127.0.0.1", transfer=False):
    """query: Send one bounded query to the private server using an explicit source."""
    name = "wg.test" if transfer else "www.wg.test"
    return run([dig, "-b", source, "@127.0.0.1", "-p", str(port), name,
                "AXFR" if transfer else "A", "+dnssec", "+time=2", "+tries=1"], timeout=6).stdout


def ready(dig, port, state):
    """ready: Require a successful local query before interpreting any denial result."""
    for _ in range(25):
        if state[0].poll() is not None:
            raise RuntimeError("PRIVATE_DAEMON_STOPPED")
        answer = query(dig, port)
        if "status: NOERROR" in answer and "192.0.2.10" in answer:
            return answer
        time.sleep(0.2)
    raise RuntimeError("POSITIVE_CONTROL_FAILED")


def trusted_key(folder, basename):
    """trusted_key: Read only the generated KSK public key as a local static anchor."""
    if not re.fullmatch(r"K[A-Za-z0-9_.+-]+", basename):
        raise RuntimeError("TEST_KEY_OUTPUT_INVALID")
    text = (folder / (basename + ".key")).read_text(encoding="utf-8")
    text = " ".join(line.split(";", 1)[0] for line in text.splitlines())
    match = re.search(r"\bDNSKEY\s+257\s+3\s+13\s+([A-Za-z0-9+/=\s]+)", text)
    if not match:
        raise RuntimeError("TEST_KEY_OUTPUT_INVALID")
    return "".join(match[1].split())


def main():
    """main: Run positive/negative DNS controls, optionally DNSSEC, and clean up."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--prepare-tools", action="store_true", help="Download official APT tools into a private temporary folder; do not install packages or services.")
    args = parser.parse_args()
    if args.plan:
        print(json.dumps({"cases": CASES, "scope": "private loopback instances only",
                          "systemConfigurationChanged": False}))
        return
    if sys.platform != "linux":
        raise RuntimeError("LINUX_REQUIRED")
    names = {name: tool(name) for name in ("named", "named-checkconf", "dig",
                                          "dnssec-keygen", "dnssec-signzone")}
    missing = [name for name in ("named", "named-checkconf", "dig") if not names[name]]
    if missing and args.prepare_tools:
        with tempfile.TemporaryDirectory(prefix="webguard-bind-tools-") as directory:
            prepared = prepare_tools(Path(directory))
            run_checks(prepared)
        return
    if missing:
        print(json.dumps({"notAssessed": True, "missingTools": missing,
                          "systemConfigurationChanged": False}))
        return
    run_checks(names)



def prepare_tools(folder):
    """prepare_tools: Extract official APT packages privately without package/service installation."""
    apt, apt_get, extract = tool("apt"), tool("apt-get"), tool("dpkg-deb")
    if not apt or not apt_get or not extract:
        raise RuntimeError("APT_EXTRACTION_TOOLS_REQUIRED")
    lists, cache = folder / "lists", folder / "cache"
    (lists / "partial").mkdir(parents=True, mode=0o700)
    (cache / "archives/partial").mkdir(parents=True, mode=0o700)
    apt_config = folder / "apt-private.conf"
    apt_config.write_text('Dir::State::lists ' + quote(lists) + ';\nDir::Cache ' + quote(cache) +
                          ';\n#clear APT::Update::Pre-Invoke;\n#clear APT::Update::Post-Invoke;\n'
                          '#clear APT::Update::Post-Invoke-Success;\n', encoding="utf-8")
    updated = run([apt_get, "-c", str(apt_config), "-o", "APT::Update::Error-Mode=any", "update"], folder, timeout=180)
    if updated.returncode:
        raise RuntimeError("PRIVATE_APT_INDEX_UPDATE_FAILED")
    downloaded = run([apt, "-c", str(apt_config), "download", "bind9", "bind9-utils", "bind9-libs"], folder, timeout=180)
    if downloaded.returncode:
        raise RuntimeError("OFFICIAL_TOOL_DOWNLOAD_FAILED")
    packages = list(folder.glob("*.deb"))
    if len(packages) != 3:
        raise RuntimeError("OFFICIAL_TOOL_SET_INCOMPLETE")
    destination = folder / "tools"
    destination.mkdir(mode=0o700)
    for package in packages:
        if run([extract, "--extract", str(package), str(destination)], timeout=60).returncode:
            raise RuntimeError("OFFICIAL_TOOL_EXTRACTION_FAILED")
    os.environ["PATH"] = str(destination / "usr/sbin") + os.pathsep + str(destination / "usr/bin") + os.pathsep + os.environ.get("PATH", "")
    library_dirs = sorted({str(p.parent) for p in destination.rglob("*.so*") if p.is_file()})
    previous_libraries = os.environ.get("LD_LIBRARY_PATH", "")
    os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(library_dirs + ([previous_libraries] if previous_libraries else []))
    names = {name: tool(name) for name in ("named", "named-checkconf", "dig", "dnssec-keygen", "dnssec-signzone")}
    if any(not names[name] for name in ("named", "named-checkconf", "dig")):
        raise RuntimeError("PREPARED_TOOLS_MISSING")
    if run([names["named"], "-v"]).returncode:
        raise RuntimeError("PREPARED_TOOLS_UNUSABLE")
    return names


def run_checks(names):
    """run_checks: Execute DNS controls with prepared tools and clean private instances."""
    results = []
    authority = resolver = None
    with tempfile.TemporaryDirectory(prefix="webguard-dns-") as directory:
        root = Path(directory)
        auth, res = root / "authority", root / "resolver"
        auth.mkdir(mode=0o700)
        res.mkdir(mode=0o700)
        a_port, r_port = free_port(), free_port()
        while a_port == r_port:
            r_port = free_port()
        zone = auth / "zone"
        zone.write_text("$TTL 60\n@ IN SOA ns.wg.test. hostmaster.wg.test. "
                        "(1 60 60 60 60)\n@ IN NS ns.wg.test.\n"
                        "ns IN A 127.0.0.1\nwww IN A 192.0.2.10\n", encoding="utf-8")
        a_config, r_config = auth / "named.conf", res / "named.conf"
        forward = ('zone "wg.test" { type forward; forward only; forwarders { '
                   '127.0.0.1 port ' + str(a_port) + '; }; };')
        try:
            a_config.write_text(options(auth, a_port, False, "no") +
                                'zone "wg.test" { type primary; file "zone"; };', encoding="utf-8")
            r_config.write_text(options(res, r_port, True, "no") + forward, encoding="utf-8")
            authority = start(names["named"], names["named-checkconf"], a_config, auth)
            ready(names["dig"], a_port, authority)
            resolver = start(names["named"], names["named-checkconf"], r_config, res)
            ready(names["dig"], r_port, resolver)
            results.append({"case": "recursive_allowed", "pass": True})
            denied = query(names["dig"], r_port, "127.0.0.2")
            results.append({"case": "recursive_denied", "pass": "status: REFUSED" in denied})
            transferred = query(names["dig"], a_port, transfer=True)
            allowed = "192.0.2.10" in transferred and transferred.count("SOA") >= 2
            results.append({"case": "transfer_allowed", "pass": allowed})
            refused = query(names["dig"], a_port, "127.0.0.2", True)
            results.append({"case": "transfer_denied", "pass": allowed and
                            ("Transfer failed" in refused or "status: REFUSED" in refused) and
                            "192.0.2.10" not in refused})
            if not names["dnssec-keygen"] or not names["dnssec-signzone"]:
                results.extend({"case": case, "notAssessed": True} for case in CASES[-2:])
            else:
                stop(resolver)
                resolver = None
                stop(authority)
                authority = None
                keygen = names["dnssec-keygen"]
                key = run([keygen, "-q", "-a", "ECDSAP256SHA256", "-f", "KSK", "wg.test"], auth)
                zsk = run([keygen, "-q", "-a", "ECDSAP256SHA256", "wg.test"], auth)
                if key.returncode or zsk.returncode:
                    raise RuntimeError("TEST_KEY_GENERATION_FAILED")
                signed = run([names["dnssec-signzone"], "-S", "-o", "wg.test", "-f",
                              "zone.signed", "-n", "1", "zone"], auth)
                if signed.returncode:
                    raise RuntimeError("TEST_ZONE_SIGNING_FAILED")
                anchor = trusted_key(auth, key.stdout.strip())
                a_config.write_text(options(auth, a_port, False, "no") +
                                    'zone "wg.test" { type primary; file "zone.signed"; };', encoding="utf-8")
                r_config.write_text(options(res, r_port, True, "yes") + forward +
                                    'trust-anchors { "wg.test." static-key 257 3 13 "' + anchor + '"; };',
                                    encoding="utf-8")
                authority = start(names["named"], names["named-checkconf"], a_config, auth)
                ready(names["dig"], a_port, authority)
                resolver = start(names["named"], names["named-checkconf"], r_config, res)
                answer = ready(names["dig"], r_port, resolver)
                validated = bool(re.search(r"flags:[^;]*\bad\b", answer))
                results.append({"case": "dnssec_valid", "pass": validated})
                stop(resolver)
                resolver = None
                stop(authority)
                authority = None
                signed_zone = auth / "zone.signed"
                before = signed_zone.read_text(encoding="utf-8")
                if "192.0.2.10" not in before:
                    raise RuntimeError("TEST_RECORD_NOT_FOUND")
                signed_zone.write_text(before.replace("192.0.2.10", "192.0.2.11"), encoding="utf-8")
                authority = start(names["named"], names["named-checkconf"], a_config, auth)
                for _ in range(10):
                    if "192.0.2.11" in query(names["dig"], a_port):
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError("BOGUS_ZONE_CONTROL_FAILED")
                resolver = start(names["named"], names["named-checkconf"], r_config, res)
                time.sleep(1)
                bogus = query(names["dig"], r_port)
                results.append({"case": "dnssec_bogus", "pass": validated and
                                "status: SERVFAIL" in bogus})
        finally:
            stop(resolver)
            stop(authority)
    print(json.dumps({"schemaVersion": 1, "scope": "isolated loopback DNS controls",
                      "systemConfigurationChanged": False, "results": results,
                      "cleanup": "own daemons stopped and private files removed"}))
    if any(item.get("pass") is False for item in results):
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, RuntimeError) and re.fullmatch(r"[A-Z_]{3,64}", str(error)) else "DNS_TEST_TOOL_FAILURE"
        print(json.dumps({"error": code, "scope": "isolated loopback test only"}))
        sys.exit(1)
