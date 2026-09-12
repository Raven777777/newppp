#!/usr/bin/env python3
"""Local end-to-end test for newppp (Windows/Linux, no external deps).

Spins up a target HTTP server, one or more `newppp -s` servers and `newppp -c`
clients on loopback, then drives the local SOCKS5 / HTTP proxy inbounds with a
plain Python socket client. Covers:

  * SOCKS5 CONNECT and HTTP-proxy absolute-GET through the WT path
  * the HTTPS POST and WebSocket fallback paths (--url only clients)
  * P0-2 error classification: private-target-denied (SOCKS 0x02, HTTP
    `X-Newppp-Error`) and dial-failed (SOCKS 0x05)
  * P0-1 startup warnings: `--listen` IP ignored, wildcard `--bind` without
    `--inbound-auth`

Run with:  py -3 tests/e2e_local.py
Options:   --binary target/debug/newppp[.exe]   --no-build
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_BODY = b"hello-e2e\n"
API_PATH = "/api/ppp"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def log(msg):
    print(msg, flush=True)


def free_port(kind="tcp"):
    if kind == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(host, port, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"want {n} bytes, got {len(buf)}")
        buf += chunk
    return buf


class Proc:
    """A managed subprocess with its combined output captured to a file."""

    def __init__(self, name, cmd, env=None, log_path=None):
        self.name = name
        self.log_path = Path(log_path)
        self._log = open(self.log_path, "wb")
        self.p = subprocess.Popen(
            cmd,
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(ROOT),
        )
        self._closed = False

    def text(self):
        try:
            self._log.flush()
        except ValueError:
            pass
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def wait_log(self, needle, timeout=30.0):
        end = time.time() + timeout
        while time.time() < end:
            if needle in self.text():
                return True
            if self.p.poll() is not None:
                return False
            time.sleep(0.2)
        return False

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        if not self._closed:
            self._log.close()
            self._closed = True


# ---------------------------------------------------------------------------
# target HTTP server
# ---------------------------------------------------------------------------
class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(TARGET_BODY)))
        self.end_headers()
        self.wfile.write(TARGET_BODY)

    def log_message(self, *_args):
        pass


def start_target():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv


class UdpEcho(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            try:
                self.sock.sendto(b"echo:" + data, addr)
            except OSError:
                return


def start_udp_echo():
    t = UdpEcho()
    t.start()
    return t


# ---------------------------------------------------------------------------
# protocol clients
# ---------------------------------------------------------------------------
def socks5_connect(proxy_host, proxy_port, dst_host, dst_port, timeout=30.0):
    """Return (socket, reply_code). socket is connected to dst on success."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s, 2) != b"\x05\x00":
        s.close()
        raise AssertionError("SOCKS5 method negotiation failed")
    host_b = dst_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", dst_port)
    s.sendall(req)
    head = recv_exact(s, 4)
    ver, rep, _rsv, atyp = head
    assert ver == 5
    if atyp == 1:
        recv_exact(s, 4)
    elif atyp == 4:
        recv_exact(s, 16)
    elif atyp == 3:
        ln = recv_exact(s, 1)[0]
        recv_exact(s, ln)
    recv_exact(s, 2)  # bound port
    if rep != 0:
        s.close()
        return None, rep
    return s, rep


def http_get_via_socks(proxy_host, proxy_port, dst_host, dst_port):
    s, rep = socks5_connect(proxy_host, proxy_port, dst_host, dst_port)
    assert rep == 0, f"SOCKS5 CONNECT rejected with code {rep}"
    try:
        s.sendall(
            f"GET / HTTP/1.1\r\nHost: {dst_host}:{dst_port}\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def http_request(host, port, raw, timeout=30.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def proxy_absolute_get(host, port, dst_host, dst_port):
    raw = (
        f"GET http://{dst_host}:{dst_port}/ HTTP/1.1\r\n"
        f"Host: {dst_host}:{dst_port}\r\nConnection: close\r\n\r\n"
    ).encode()
    return http_request(host, port, raw)


def socks5_udp_associate(proxy_host, proxy_port, timeout=15.0):
    """Open a SOCKS5 UDP ASSOCIATE control connection; return (ctrl, relay)."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    assert recv_exact(s, 2) == b"\x05\x00", "UDP method negotiation failed"
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    _ver, rep, _rsv, atyp = recv_exact(s, 4)
    assert rep == 0, f"UDP ASSOCIATE rejected code={rep}"
    if atyp == 1:
        bnd_ip = socket.inet_ntoa(recv_exact(s, 4))
    elif atyp == 4:
        bnd_ip = socket.inet_ntop(socket.AF_INET6, recv_exact(s, 16))
    else:
        ln = recv_exact(s, 1)[0]
        bnd_ip = recv_exact(s, ln).decode()
    bnd_port = struct.unpack("!H", recv_exact(s, 2))[0]
    if bnd_ip in ("0.0.0.0", "::"):
        bnd_ip = "127.0.0.1"
    return s, (bnd_ip, bnd_port)


def socks5_udp_roundtrip(proxy_host, proxy_port, dst_host, dst_port, payload=b"ping"):
    ctrl, relay = socks5_udp_associate(proxy_host, proxy_port)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(15.0)
    try:
        pkt = (
            b"\x00\x00\x00\x01"
            + socket.inet_aton(dst_host)
            + struct.pack("!H", dst_port)
            + payload
        )
        u.sendto(pkt, relay)
        reply, _ = u.recvfrom(65535)
        assert reply[:3] == b"\x00\x00\x00", "bad SOCKS5 UDP reply header"
        atyp = reply[3]
        idx = 4
        if atyp == 1:
            idx += 4
        elif atyp == 4:
            idx += 16
        elif atyp == 3:
            idx += 1 + reply[4]
        idx += 2
        return reply[idx:]
    finally:
        u.close()
        ctrl.close()


def status_line(resp):
    return resp.split(b"\r\n", 1)[0]


# ---------------------------------------------------------------------------
# test driver
# ---------------------------------------------------------------------------
class Harness:
    def __init__(self, binary):
        self.binary = binary
        self.procs = []
        self.results = []

    def spawn(self, name, args, extra_env=None):
        tmp = tempfile.mkdtemp(prefix=f"newppp-{name}-")
        env = os.environ.copy()
        # give each server its own temp dir: --self-signed writes cert.pem there
        env["TMP"] = tmp
        env["TEMP"] = tmp
        if extra_env:
            env.update(extra_env)
        log_path = Path(tempfile.gettempdir()) / f"newppp-{name}.log"
        proc = Proc(name, [self.binary, *args], env=env, log_path=log_path)
        self.procs.append(proc)
        return proc

    def check(self, name, fn):
        try:
            detail = fn()
            self.results.append((name, True, detail or "ok"))
            log(f"  [PASS] {name}  {detail or ''}")
        except Exception as e:  # noqa: BLE001 - report everything
            import traceback

            self.results.append((name, False, repr(e)))
            log(f"  [FAIL] {name}: {e!r}")
            log("    " + traceback.format_exc().replace("\n", "\n    "))

    def cleanup(self):
        for p in reversed(self.procs):
            p.stop()


def build_binary(binary, no_build):
    if not no_build:
        log("building (cargo build) ...")
        subprocess.run(["cargo", "build"], cwd=str(ROOT), check=True)
    if not os.path.isfile(binary):
        raise SystemExit(f"binary not found: {binary} (pass --binary or drop --no-build)")


def run(args):
    binary = args.binary
    if binary is None:
        suffix = ".exe" if os.name == "nt" else ""
        binary = str(ROOT / "target" / "debug" / f"newppp{suffix}")
    build_binary(binary, args.no_build)

    target = start_target()
    target_port = target.server_address[1]
    udp_echo = start_udp_echo()
    log(f"target HTTP server on 127.0.0.1:{target_port}")
    log(f"target UDP echo on 127.0.0.1:{udp_echo.port}")

    h = Harness(binary)
    try:
        # ---- allow-private server + WT/fallback client ----
        s_wt = free_port("udp")
        s_fb = free_port()
        s_http = free_port()
        socks_a = free_port()
        hp_a = free_port()

        srv = h.spawn(
            "server-allow",
            [
                "-s", "--auth", "e2e:secret",
                "--listen", f"127.0.0.1:{s_wt}",
                "--fallback-listen", f"127.0.0.1:{s_fb}",
                "--http-listen", f"127.0.0.1:{s_http}",
                "--self-signed", "--allow-private-targets", "--log", "debug",
            ],
        )
        if not wait_port("127.0.0.1", s_fb, 30):
            raise SystemExit(f"server-allow did not open fallback port\n{srv.text()}")
        if not wait_port("127.0.0.1", s_http, 30):
            raise SystemExit("server-allow did not open http port")

        cli_a = h.spawn(
            "client-wt",
            [
                "-c", "--auth", "e2e:secret",
                "--server", f"https://127.0.0.1:{s_wt}",
                "--url", f"https://127.0.0.1:{s_fb}{API_PATH}",
                "--bind", f"127.0.0.1:{socks_a}",
                "--http-bind", f"127.0.0.1:{hp_a}",
                "--skip-verify", "--log", "debug",
            ],
        )
        if not wait_port("127.0.0.1", socks_a, 30):
            raise SystemExit(f"client-wt did not open socks port\n{cli_a.text()}")

        # T1: SOCKS5 CONNECT via client (WT primary, fallback if needed)
        h.check(
            "T1 socks5 GET through client",
            lambda: _assert_body(
                http_get_via_socks("127.0.0.1", socks_a, "127.0.0.1", target_port)
            ),
        )
        # T2: HTTP proxy absolute-URI GET
        h.check(
            "T2 http-proxy absolute GET",
            lambda: _assert_body(
                proxy_absolute_get("127.0.0.1", hp_a, "127.0.0.1", target_port)
            ),
        )
        # T2b: SOCKS5 UDP ASSOCIATE round-trip through the WT datagram path
        def t2b():
            got = socks5_udp_roundtrip(
                "127.0.0.1", socks_a, "127.0.0.1", udp_echo.port
            )
            assert got == b"echo:ping", f"unexpected UDP reply {got!r}"
            return got.decode()

        h.check("T2b socks5 UDP ASSOCIATE echo", t2b)

        # T3: dial failure -> SOCKS 0x05
        dead_port = free_port()

        def t3():
            _s, rep = socks5_connect("127.0.0.1", socks_a, "127.0.0.1", dead_port)
            assert rep == 0x05, f"expected 0x05 (connection refused), got {rep}"
            return f"reply=0x{rep:02x}"

        h.check("T3 dial-failed classified (SOCKS 0x05)", t3)

        # T4: WT path actually established (not just silently on fallback)
        h.check(
            "T4 WT connection established",
            lambda: _require(cli_a, "wt connection established"),
        )

        # ---- deny-private server + client ----
        d_wt = free_port("udp")
        d_fb = free_port()
        socks_d = free_port()
        hp_d = free_port()
        srv_d = h.spawn(
            "server-deny",
            [
                "-s", "--auth", "e2e:secret",
                "--listen", f"127.0.0.1:{d_wt}",
                "--fallback-listen", f"127.0.0.1:{d_fb}",
                "--self-signed", "--log", "debug",  # no --allow-private-targets
            ],
        )
        if not wait_port("127.0.0.1", d_fb, 30):
            raise SystemExit(f"server-deny did not open fallback port\n{srv_d.text()}")
        cli_d = h.spawn(
            "client-deny",
            [
                "-c", "--auth", "e2e:secret",
                "--server", f"https://127.0.0.1:{d_wt}",
                "--url", f"https://127.0.0.1:{d_fb}{API_PATH}",
                "--bind", f"127.0.0.1:{socks_d}",
                "--http-bind", f"127.0.0.1:{hp_d}",
                "--skip-verify", "--log", "debug",
            ],
        )
        if not wait_port("127.0.0.1", socks_d, 30):
            raise SystemExit("client-deny did not open socks port")

        def t5():
            _s, rep = socks5_connect("127.0.0.1", socks_d, "127.0.0.1", target_port)
            assert rep == 0x02, f"expected 0x02 (not allowed), got {rep}"
            return f"reply=0x{rep:02x}"

        h.check("T5 private-target denied (SOCKS 0x02)", t5)

        def t6():
            resp = proxy_absolute_get("127.0.0.1", hp_d, "127.0.0.1", target_port)
            assert b"X-Newppp-Error: private-target-denied" in resp, (
                f"missing classification header in {status_line(resp)!r}"
            )
            assert b"private-target-denied" in resp
            return "X-Newppp-Error: private-target-denied"

        h.check("T6 HTTP proxy error text classified", t6)

        # ---- fallback-only clients (POST and WS) ----
        socks_p = free_port()
        cli_p = h.spawn(
            "client-post",
            [
                "-c", "--auth", "e2e:secret",
                "--url", f"https://127.0.0.1:{s_fb}{API_PATH}",
                "--bind", f"127.0.0.1:{socks_p}",
                "--skip-verify", "--log", "debug",
            ],
        )
        if not wait_port("127.0.0.1", socks_p, 30):
            raise SystemExit("client-post did not open socks port")
        h.check(
            "T7 HTTPS POST fallback path",
            lambda: _assert_body(
                http_get_via_socks("127.0.0.1", socks_p, "127.0.0.1", target_port)
            ),
        )

        socks_ws = free_port()
        cli_ws = h.spawn(
            "client-ws",
            [
                "-c", "--auth", "e2e:secret",
                "--url", f"wss://127.0.0.1:{s_fb}{API_PATH}",
                "--bind", f"127.0.0.1:{socks_ws}",
                "--skip-verify", "--log", "debug",
            ],
        )
        if not wait_port("127.0.0.1", socks_ws, 30):
            raise SystemExit("client-ws did not open socks port")
        h.check(
            "T8 WebSocket fallback path",
            lambda: _assert_body(
                http_get_via_socks("127.0.0.1", socks_ws, "127.0.0.1", target_port)
            ),
        )

        # ---- P0-1 startup warnings ----
        h.check(
            "T9 --listen IP-ignored warning",
            lambda: _require(srv, "IP part is ignored"),
        )

        warn_port = free_port()
        cli_warn = h.spawn(
            "client-warn",
            [
                "-c", "--auth", "e2e:secret",
                "--server", f"https://127.0.0.1:{s_wt}",
                "--bind", f"0.0.0.0:{warn_port}",
                "--skip-verify", "--log", "debug",
            ],
        )
        if not wait_port("127.0.0.1", warn_port, 30):
            raise SystemExit("client-warn did not open socks port")

        def t10():
            assert cli_warn.wait_log("without --inbound-auth", 10), (
                "wildcard bind without auth did not warn"
            )
            return "wildcard bind warning present"

        h.check("T10 wildcard bind without auth warning", t10)
    finally:
        h.cleanup()
        target.shutdown()

    # ---- summary ----
    failed = [r for r in h.results if not r[1]]
    log("")
    log(f"{len(h.results) - len(failed)}/{len(h.results)} checks passed")
    for name, ok, detail in h.results:
        log(f"  {'PASS' if ok else 'FAIL'}  {name}")
    return 1 if failed else 0


def _assert_body(resp):
    assert b"200" in status_line(resp), f"bad status: {status_line(resp)!r}"
    assert TARGET_BODY.strip() in resp, "target body missing"
    return status_line(resp).decode(errors="replace")


def _require(proc, needle):
    assert proc.wait_log(needle, 15), f"log missing {needle!r}"
    return f"found {needle!r}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=None, help="path to the newppp binary")
    parser.add_argument(
        "--no-build", action="store_true", help="do not run cargo build first"
    )
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
