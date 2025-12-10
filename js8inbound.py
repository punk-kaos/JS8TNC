#!/usr/bin/env python3
import argparse
import json
import logging
import socket
import threading
import time
from collections import deque
from hashlib import sha1
from typing import Dict, Optional, Tuple

DEFAULT_JS8_HOST = "127.0.0.1"
DEFAULT_JS8_PORT = 2442
DEFAULT_VISIBLE_TIMEOUT = 900  # seconds
DEFAULT_MIN_SNR = -30.0
DEFAULT_APRS_SERVER = "rotate.aprs2.net:14580"
DEDUP_EXPIRY = 3600  # seconds
MAX_JS8_VALUE_LEN = 200


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")


def parse_host_port(value: str) -> Tuple[str, int]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("server must be host:port")
    host, port_str = value.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not host:
        raise argparse.ArgumentTypeError("host is required")
    return host, port


def sanitize_text(text: str) -> str:
    ascii_only = "".join(ch for ch in text if ord(ch) < 128)
    collapsed = " ".join(ascii_only.split())
    return collapsed.strip()


def _is_valid_callsign(value: str) -> bool:
    if not value or len(value) < 3 or len(value) > 10:
        return False
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    return all(ch in allowed for ch in value)


def compute_aprs_pass(callsign: str) -> int:
    basecall = callsign.upper().split("-")[0] + "\0"
    result = 0x73E2
    idx = 0
    while (idx + 1) < len(basecall):
        result ^= ord(basecall[idx]) << 8
        result ^= ord(basecall[idx + 1])
        idx += 2
    return result & 0x7FFF


class Deduplicator:
    def __init__(self, expiry: float = DEDUP_EXPIRY, max_items: int = 2048) -> None:
        self.expiry = expiry
        self.max_items = max_items
        self._items = deque()
        self._seen = set()
        self._lock = threading.Lock()

    def check(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            while self._items and now - self._items[0][1] > self.expiry:
                old_key, _ = self._items.popleft()
                self._seen.discard(old_key)
            if key in self._seen:
                return True
            self._seen.add(key)
            self._items.append((key, now))
            if len(self._items) > self.max_items:
                old_key, _ = self._items.popleft()
                self._seen.discard(old_key)
        return False


class JS8VisibilityTracker:
    def __init__(
        self,
        host: str,
        port: int,
        min_snr: float,
        visible_timeout: float,
        stop_event: threading.Event,
        on_message=None,
    ) -> None:
        self.host = host
        self.port = port
        self.min_snr = min_snr
        self.visible_timeout = visible_timeout
        self.stop_event = stop_event
        self._on_message = on_message
        self._heard: Dict[str, Dict[str, float]] = {}
        self._lock = threading.Lock()
        self._sock_lock = threading.Lock()
        self._thread = threading.Thread(target=self._listen_loop, name="js8-tcp-listen", daemon=True)
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self._safe_close_socket()
        self._thread.join(timeout=2)

    def _listen_loop(self) -> None:
        backoff = 1
        while not self.stop_event.is_set():
            sock = None
            try:
                sock = socket.create_connection((self.host, self.port), timeout=10)
                sock.settimeout(30)
                with self._sock_lock:
                    self._sock = sock
                logging.info(f"Connected to JS8Call TCP {self.host}:{self.port} for visibility tracking")
                backoff = 1
                self._seed_call_activity(sock)
                sock_file = sock.makefile("r", encoding="utf-8", errors="ignore", newline="\n")
                while not self.stop_event.is_set():
                    try:
                        line = sock_file.readline()
                    except socket.timeout:
                        continue
                    if not line:
                        raise ConnectionError("JS8 TCP socket closed")
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        logging.debug("Ignoring non-JSON payload from JS8")
                        continue
                    self._record_visibility(msg)
            except Exception as exc:
                if self.stop_event.is_set():
                    break
                logging.warning(f"JS8 visibility error: {exc}; reconnecting in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
            finally:
                if sock:
                    self._safe_close_socket()
                    sock_file = None

    def _seed_call_activity(self, sock: socket.socket) -> None:
        try:
            seed_req = {
                "params": {"_ID": int(time.time() * 1000)},
                "type": "RX.GET_CALL_ACTIVITY",
                "value": "",
            }
            line = json.dumps(seed_req) + "\n"
            sock.sendall(line.encode("utf-8"))
            logging.debug("Requested initial JS8 call activity")
        except Exception as exc:
            logging.debug(f"Failed to request initial call activity: {exc}")

    def _record_visibility(self, msg: dict) -> None:
        msg_type = msg.get("type", "") or ""
        params = msg.get("params", {}) or {}
        value = msg.get("value", {}) or {}

        if msg_type == "RX.CALL_ACTIVITY":
            payload = params if isinstance(params, dict) and params else value if isinstance(value, dict) else {}
            for call, info in payload.items():
                call_str = str(call).strip().upper()
                if not _is_valid_callsign(call_str):
                    continue
                snr_val = self._as_float(info.get("snr") if isinstance(info, dict) else None)
                freq_val = self._as_float(info.get("freq") if isinstance(info, dict) else None)
                self._store_visibility(call_str, snr_val, freq_val)
            return

        callsign = params.get("FROM") or params.get("from") or (value.get("FROM") if isinstance(value, dict) else None) or (
            value.get("from") if isinstance(value, dict) else None
        )
        text = (
            params.get("TEXT")
            or params.get("text")
            or (value.get("TEXT") if isinstance(value, dict) else None)
            or (value.get("text") if isinstance(value, dict) else None)
            or (value if isinstance(value, str) else "")
        )
        if not callsign:
            return
        snr_val = self._as_float(params.get("SNR") or params.get("snr"))
        freq_val = self._as_float(params.get("FREQ") or params.get("freq"))
        self._store_visibility(str(callsign), snr_val, freq_val)
        if self._on_message and text:
            try:
                self._on_message(str(callsign).strip().upper(), str(text))
            except Exception as exc:
                logging.debug(f"on_message handler error: {exc}")

    def _store_visibility(self, callsign: str, snr_val: Optional[float], freq_val: Optional[float]) -> None:
        callsign = str(callsign).strip().upper()
        if not callsign or not _is_valid_callsign(callsign):
            return
        now = time.time()
        with self._lock:
            entry = self._heard.get(callsign, {}) or {}
            entry["last_heard"] = now
            if snr_val is not None:
                entry["snr"] = snr_val
            if freq_val is not None:
                entry["freq"] = freq_val
            self._heard[callsign] = entry
        logging.debug(f"JS8 visible: {callsign} snr={snr_val} freq={freq_val}")

    def _safe_close_socket(self) -> None:
        with self._sock_lock:
            sock = self._sock
            self._sock = None
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    def refresh_call_activity(self) -> None:
        with self._sock_lock:
            sock = self._sock
        if not sock:
            return
        try:
            req = {
                "params": {"_ID": int(time.time() * 1000)},
                "type": "RX.GET_CALL_ACTIVITY",
                "value": "",
            }
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            logging.debug("Requested JS8 call activity refresh")
        except Exception as exc:
            logging.debug(f"Failed to refresh call activity: {exc}")

    def last_heard_at(self, callsign: str) -> Optional[float]:
        with self._lock:
            entry = self._heard.get(callsign)
        if not entry:
            return None
        return entry.get("last_heard")

    def pending_send_ready(self) -> bool:
        return self.is_connected()

    @staticmethod
    def _as_float(value: object) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def is_visible(self, callsign: str) -> Optional[Dict[str, float]]:
        now = time.time()
        with self._lock:
            entry = self._heard.get(callsign)
        if not entry:
            return None
        last_heard = entry.get("last_heard", 0)
        if now - last_heard > self.visible_timeout:
            return None
        snr = entry.get("snr")
        if snr is not None:
            if snr < self.min_snr:
                return None
        else:
            # If no SNR was reported, accept visibility on recency alone
            pass
        return entry.copy()

    def is_connected(self) -> bool:
        with self._sock_lock:
            return self._sock is not None

    def send_message(self, target: str, from_call: str, text: str) -> None:
        payload = sanitize_text(text)
        message_text = f"{target} msg {from_call}/APRS: {payload}".strip()
        if len(message_text) > MAX_JS8_VALUE_LEN:
            message_text = message_text[: MAX_JS8_VALUE_LEN - 3] + "..."
        js8_line = json.dumps(
            {
                "params": {"_ID": int(time.time() * 1000)},
                "type": "TX.SEND_MESSAGE",
                "value": message_text,
            }
        )
        data = (js8_line + "\n").encode("utf-8")
        with self._sock_lock:
            sock = self._sock
        if not sock:
            logging.warning("JS8 not connected; dropping TX")
            return
        try:
            sock.sendall(data)
        except OSError as exc:
            logging.warning(f"JS8 send failed ({exc}); reconnecting")
            self._safe_close_socket()
            return
        logging.info(f"Gated to JS8: {message_text}")


def parse_aprs_message(line: str) -> Optional[Tuple[str, str, str, Optional[str]]]:
    # Expected: SRC>DEST,PATH:':ADDRESSEE:message{msgid'
    if not line or line.startswith("#"):
        return None
    if ">" not in line or ":" not in line:
        return None
    try:
        header, payload = line.split(":", 1)
    except ValueError:
        return None
    if not payload.startswith(":"):
        return None
    body = payload[1:]
    if len(body) < 9:
        return None
    addressee = body[:9].strip().upper()
    text_part = body[9:]
    if text_part.startswith(":"):
        text_part = text_part[1:]
    msg_id = None
    if "{" in text_part:
        text_part, msg_id = text_part.rsplit("{", 1)
        msg_id = msg_id.strip()
    text_part = sanitize_text(text_part)
    if not addressee or not text_part:
        return None
    if text_part.lower().startswith(("ack", "rej")):
        return None
    from_call = header.split(">", 1)[0].strip().upper()
    return from_call, addressee, text_part, msg_id


class AprsClient:
    def __init__(
        self,
        server: Tuple[str, int],
        login_call: str,
        passcode: str,
        calls_to_watch: Optional[set],
        on_message,
        stop_event: threading.Event,
    ) -> None:
        self.server = server
        self.login_call = login_call
        self.passcode = passcode
        self.calls_to_watch = calls_to_watch
        self.on_message = on_message
        self.stop_event = stop_event
        self._thread = threading.Thread(target=self._run, name="aprs-loop", daemon=True)
        self._sock: Optional[socket.socket] = None
        self._write_lock = threading.Lock()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self._thread.join(timeout=2)
        with self._write_lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def _run(self) -> None:
        backoff = 3
        while not self.stop_event.is_set():
            try:
                self._connect_and_consume()
                backoff = 3
            except Exception as exc:
                logging.warning(f"APRS-IS connection error: {exc}; retrying in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)

    def _connect_and_consume(self) -> None:
        host, port = self.server
        logging.info(f"Connecting to APRS-IS {host}:{port} as {self.login_call}")
        with socket.create_connection((host, port), timeout=15) as sock:
            with self._write_lock:
                self._sock = sock
            sock_file = sock.makefile("r", encoding="utf-8", errors="ignore", newline="\n")
            filter_calls = {self.login_call}
            if self.calls_to_watch:
                filter_calls.update(self.calls_to_watch)
            filter_clause = " ".join(
                ["b/" + "/".join(sorted(filter_calls)), "t/m"]
            ).strip()
            login_line = f"user {self.login_call} pass {self.passcode} vers js8inbound 1.0"
            if filter_clause:
                login_line += f" filter {filter_clause}"
            sock.sendall((login_line + "\r\n").encode("ascii", errors="ignore"))
            logging.debug(f"Sent APRS-IS login: {login_line}")

            while not self.stop_event.is_set():
                line = sock_file.readline()
                if not line:
                    raise ConnectionError("APRS-IS socket closed")
                line = line.strip()
                msg = parse_aprs_message(line)
                if not msg:
                    continue
                self.on_message(msg[0], msg[1], msg[2], msg[3], line)
        with self._write_lock:
            self._sock = None

    def send_ack(self, to_call: str, msg_id: str) -> None:
        if not msg_id:
            return
        frame = f"{self.login_call}>APRS::{to_call.ljust(9)}:ack{msg_id}"
        data = (frame + "\r\n").encode("ascii", errors="ignore")
        with self._write_lock:
            sock = self._sock
            if not sock:
                logging.warning("APRS socket not connected; cannot send ack")
                return
            try:
                sock.sendall(data)
                logging.info(f"Sent APRS ack to {to_call} for msg {msg_id}")
            except OSError as exc:
                logging.warning(f"Failed to send APRS ack: {exc}")


class AprsJs8Gateway:
    def __init__(
        self,
        aprs_server: Tuple[str, int],
        aprs_call: str,
        aprs_pass: str,
        js8_host: str,
        js8_port: int,
        visible_timeout: float,
        min_snr: float,
        calls_filter: Optional[set],
    ) -> None:
        self.stop_event = threading.Event()
        self.calls_filter = calls_filter
        self.dedupe = Deduplicator()
        self.pending_acks: Dict[str, Tuple[str, str, float]] = {}
        self.pending_lock = threading.Lock()
        self.visibility = JS8VisibilityTracker(
            js8_host, js8_port, min_snr, visible_timeout, self.stop_event, on_message=self._handle_js8_message
        )
        self.aprs = AprsClient(
            aprs_server,
            aprs_call,
            aprs_pass,
            calls_filter,
            self._handle_aprs_message,
            self.stop_event,
        )

    def start(self) -> None:
        self.visibility.start()
        self.aprs.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.aprs.stop()
        self.visibility.stop()

    def _handle_aprs_message(
        self, from_call: str, target_call: str, text: str, msg_id: Optional[str], raw_line: str
    ) -> None:
        key = sha1(f"{from_call}|{target_call}|{text}|{msg_id}".encode("utf-8", errors="ignore")).hexdigest()
        if self.dedupe.check(key):
            logging.debug("Dropping duplicate APRS message")
            return

        if self.calls_filter and target_call not in self.calls_filter:
            logging.debug(f"Ignoring APRS message to {target_call}; not in allowed list")
            return

        visible = self.visibility.is_visible(target_call)
        if not visible:
            self.visibility.refresh_call_activity()
            time.sleep(0.2)
            visible = self.visibility.is_visible(target_call)
        if not visible:
            last_seen = self.visibility.last_heard_at(target_call)
            if last_seen:
                age = time.time() - last_seen
                logging.info(
                    f"Target {target_call} not recently visible on JS8; last seen {age:.1f}s ago"
                )
            else:
                logging.info(f"Target {target_call} not recently visible on JS8; dropping message")
            return

        if msg_id:
            with self.pending_lock:
                self.pending_acks[msg_id] = (from_call, target_call, time.time())
                logging.debug(f"Tracking pending APRS ack id={msg_id} from={from_call} to={target_call}")

        self.visibility.send_message(target_call, from_call, text)

    def _handle_js8_message(self, from_call: str, text: str) -> None:
        msg = (text or "").strip()
        if not msg:
            return
        logging.debug(f"JS8 RX from {from_call}: {msg}")
        cleaned = msg[1:].strip() if msg.startswith(":") else msg
        tokens = cleaned.split()
        ack_id = None
        ack_found = False
        for idx, tok in enumerate(tokens):
            token_upper = tok.upper().strip(":")
            if "ACK" == token_upper or "RR" == token_upper or token_upper.startswith("ACK") or token_upper.startswith("RR"):
                ack_found = True
                # If token includes the id glued, peel it
                tail = token_upper[3:] if token_upper.startswith("ACK") else token_upper[2:]
                if tail:
                    ack_id = "".join(ch for ch in tail if ch.isalnum())
                elif idx + 1 < len(tokens):
                    ack_id = "".join(ch for ch in tokens[idx + 1] if ch.isalnum())
                break
        if not ack_found:
            return

        to_ack: Optional[Tuple[str, str]] = None
        with self.pending_lock:
            self._expire_pending_locked()
            if ack_id and ack_id in self.pending_acks:
                aprs_from, target_call, _ = self.pending_acks.pop(ack_id)
                to_ack = (aprs_from, ack_id)
            else:
                # Fallback: match any pending for this JS8 sender
                for mid, (aprs_from, target_call, ts) in list(self.pending_acks.items()):
                    if self._calls_match(target_call, from_call):
                        to_ack = (aprs_from, mid)
                        self.pending_acks.pop(mid, None)
                        break
        if to_ack:
            aprs_from, mid = to_ack
            logging.info(f"JS8 ACK from {from_call} matched pending id {mid}; sending APRS ack to {aprs_from}")
            self.aprs.send_ack(aprs_from, mid)
        else:
            logging.info(f"JS8 ACK from {from_call} did not match pending ids (ack_id={ack_id})")

    def _expire_pending_locked(self) -> None:
        now = time.time()
        expired = [mid for mid, (_, _, ts) in self.pending_acks.items() if now - ts > 3600]
        for mid in expired:
            self.pending_acks.pop(mid, None)

    @staticmethod
    def _calls_match(target: str, incoming: str) -> bool:
        t = (target or "").upper()
        i = (incoming or "").upper()
        if t == i:
            return True
        t_base = t.split("-", 1)[0]
        i_base = i.split("-", 1)[0]
        return t_base == i_base


def main() -> None:
    parser = argparse.ArgumentParser(description="One-way APRS -> JS8 inbound gateway")
    parser.add_argument(
        "--aprs-server",
        type=parse_host_port,
        default=parse_host_port(DEFAULT_APRS_SERVER),
        help=f"APRS-IS server host:port (default: {DEFAULT_APRS_SERVER})",
    )
    parser.add_argument("--aprs-call", required=True, help="APRS-IS login callsign-SSID")
    parser.add_argument(
        "--aprs-pass",
        help="APRS-IS passcode (default: auto-derived from callsign)",
    )
    parser.add_argument("--js8-host", default=DEFAULT_JS8_HOST, help="JS8Call host (default: 127.0.0.1)")
    parser.add_argument("--js8-port", type=int, default=DEFAULT_JS8_PORT, help="JS8Call TCP port (default: 2442)")
    parser.add_argument(
        "--visible-timeout",
        type=float,
        default=DEFAULT_VISIBLE_TIMEOUT,
        help="Seconds to consider a JS8 station visible (default: 900)",
    )
    parser.add_argument(
        "--min-snr",
        type=float,
        default=DEFAULT_MIN_SNR,
        help="Minimum SNR to treat JS8 station as visible (default: -30 dB)",
    )
    parser.add_argument(
        "--calls",
        help="Comma-separated callsigns to gate; if omitted, gate any JS8-visible call",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--test", action="store_true", help="Send a JS8 test message to the APRS callsign and exit")
    args = parser.parse_args()

    configure_logging(args.debug)

    calls_filter = None
    if args.calls:
        calls_filter = {c.strip().upper() for c in args.calls.split(",") if c.strip()}

    aprs_call = args.aprs_call.upper()
    aprs_pass = args.aprs_pass
    if aprs_pass is None:
        aprs_pass = str(compute_aprs_pass(aprs_call))
        logging.info("Computed APRS passcode from callsign")

    logging.info(
        "Config: aprs_server=%s:%s aprs_call=%s js8=%s:%s visible_timeout=%ss min_snr=%sdB calls=%s",
        args.aprs_server[0],
        args.aprs_server[1],
        aprs_call,
        args.js8_host,
        args.js8_port,
        args.visible_timeout,
        args.min_snr,
        ",".join(sorted(calls_filter)) if calls_filter else "any visible",
    )

    gateway = AprsJs8Gateway(
        aprs_server=args.aprs_server,
        aprs_call=aprs_call,
        aprs_pass=str(aprs_pass),
        js8_host=args.js8_host,
        js8_port=args.js8_port,
        visible_timeout=args.visible_timeout,
        min_snr=args.min_snr,
        calls_filter=calls_filter,
    )

    gateway.start()

    if args.test:
        for _ in range(20):
            if gateway.visibility.is_connected():
                break
            time.sleep(0.1)
        logging.info("Sending JS8 test message to %s (--test)", aprs_call)
        gateway.visibility.send_message(aprs_call, aprs_call, "js8inbound test")
        gateway.stop()
        return

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        gateway.stop()


if __name__ == "__main__":
    main()
