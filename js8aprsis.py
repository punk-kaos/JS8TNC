#!/usr/bin/env python3
import argparse
import json
import logging
import socket
import time
import traceback
from typing import Optional, Tuple

import aprslib


def getPass(callsign: str) -> int:
    basecall = callsign.upper().split('-')[0] + '\0'
    result = 0x73e2
    c = 0
    while (c + 1) < len(basecall):
        result ^= ord(basecall[c]) << 8
        result ^= ord(basecall[c + 1])
        c += 2
    result &= 0x7fff
    return result


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s: %(message)s')


class JS8Client:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.rfile = None

    def _connect(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((self.host, self.port))
        s.settimeout(None)
        self.sock = s
        self.rfile = s.makefile('r', encoding='utf-8', newline='\n')
        logging.info(f"Connected to JS8Call at {self.host}:{self.port}")

    def ensure_connected(self) -> None:
        if self.sock is not None:
            return
        backoff = 1
        while self.sock is None:
            try:
                logging.info("Connecting to JS8Call...")
                self._connect()
            except Exception as e:
                logging.warning(f"JS8 connect failed: {e}; retrying in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)

    def _send_line(self, line: str) -> None:
        self.ensure_connected()
        data = line if line.endswith("\n") else (line + "\n")
        try:
            assert self.sock is not None
            self.sock.sendall(data.encode('utf-8'))
            logging.info(f"SEND_JS8: {line}")
        except Exception as e:
            logging.warning(f"JS8 send failed: {e}; resetting connection")
            try:
                if self.sock:
                    self.sock.close()
            finally:
                self.sock = None
                self.rfile = None
            # retry once
            self.ensure_connected()
            assert self.sock is not None
            self.sock.sendall(data.encode('utf-8'))
            logging.info(f"SEND_JS8(retry): {line}")

    def send_text(self, text: str) -> None:
        js = {
            "params": {"_ID": int(time.time() * 1000)},
            "type": "TX.SEND_MESSAGE",
            "value": text,
        }
        self._send_line(json.dumps(js))

    def _read_json_until(self, match_type: str, timeout: float = 5.0) -> Optional[dict]:
        self.ensure_connected()
        start = time.time()
        while time.time() - start < timeout:
            line = self.rfile.readline() if self.rfile else ''
            if not line:
                # connection broken
                logging.warning("JS8 socket EOF; reconnecting")
                try:
                    if self.sock:
                        self.sock.close()
                finally:
                    self.sock = None
                    self.rfile = None
                self.ensure_connected()
                continue
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                logging.debug("Ignoring non-JSON line from JS8")
                continue
            if msg.get('type', '') == match_type:
                return msg
        return None

    def get_callsign(self, timeout: float = 5.0) -> Optional[str]:
        req = {"params": {}, "type": "STATION.GET_CALLSIGN", "value": ""}
        self._send_line(json.dumps(req))
        # Try to read a station response line with a 'value'
        start = time.time()
        while time.time() - start < timeout:
            line = self.rfile.readline() if self.rfile else ''
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = msg.get('type', '')
            if t.startswith('STATION') and isinstance(msg.get('value', None), str):
                callsign = msg.get('value', '').strip()
                if callsign:
                    return callsign
        return None

    def get_heard_calls(self, timeout: float = 5.0) -> Optional[set]:
        req = {"params": {"_ID": int(time.time() * 1000)}, "type": "RX.GET_CALL_ACTIVITY", "value": ""}
        self._send_line(json.dumps(req))
        msg = self._read_json_until("RX.CALL_ACTIVITY", timeout=timeout)
        if not msg:
            return None
        params = msg.get('params', {}) or {}
        # Params keys are callsigns according to prior usage
        heard = set()
        try:
            for k in params.keys():
                if isinstance(k, str) and k:
                    heard.add(k.upper())
        except Exception:
            pass
        return heard


def _sanitize_text(text: str, max_len: int = 240) -> str:
    ascii_text = ''.join(ch for ch in text if ord(ch) < 128)
    collapsed = ' '.join(ascii_text.split())
    if len(collapsed) > max_len:
        return collapsed[: max_len - 3] + '...'
    return collapsed


def parse_target_and_body(msg: str) -> Tuple[Optional[str], Optional[str], str]:
    s = (msg or '').strip()
    if not s:
        return None, None, 'empty'
    if s in ('?', '??'):
        return None, None, 'query'
    if ':' in s:
        target, body = s.split(':', 1)
        return target.strip().upper(), body.strip(), 'message'
    parts = s.split(None, 1)
    if len(parts) == 1:
        return parts[0].strip().upper(), '', 'message'
    return parts[0].strip().upper(), parts[1].strip(), 'message'


def send_aprs_message(aprs_conn: aprslib.IS, from_call: str, to_call: str, text: str) -> None:
    # Construct a simple APRS message frame and try sending via aprslib
    frame = f"{from_call}>APRS::{to_call.ljust(9)}:{text}"
    try:
        if hasattr(aprs_conn, 'sendall'):
            aprs_conn.sendall(frame)
        else:
            # Fallback: older versions may expose .sock
            sock = getattr(aprs_conn, 'sock', None) or getattr(aprs_conn, '_sock', None)
            if sock:
                sock.sendall((frame + "\r\n").encode('ascii', errors='ignore'))
            else:
                logging.warning("APRS send not supported by aprslib.IS instance")
    except Exception as e:
        logging.warning(f"Failed to send APRS-IS message: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="APRS-IS -> JS8Call message bridge (APRS dest to JS8)")
    parser.add_argument('--js8-host', default='127.0.0.1', help='JS8Call host (default: 127.0.0.1)')
    parser.add_argument('--js8-port', type=int, default=2442, help='JS8Call TCP port (default: 2442)')
    parser.add_argument('--aprs-server', default='rotate.aprs2.net', help='APRS-IS server (default: rotate.aprs2.net)')
    parser.add_argument('--aprs-port', type=int, default=14580, help='APRS-IS port (default: 14580 for filters)')
    parser.add_argument('--aprs-user', help='APRS-IS login callsign (default: query from JS8Call)')
    parser.add_argument('--aprs-passcode', type=int, help='APRS-IS passcode (if omitted, computed from user)')
    parser.add_argument('--aprs-dest', default='JS8USER', help='Only forward APRS messages addressed to this destination (default: JS8USER)')
    parser.add_argument('--min-interval', type=float, default=0.0, help='Minimum seconds between JS8 sends (rate limit)')
    parser.add_argument('--require-heard', action='store_true', default=True, help='Only send to JS8 if target was recently heard (default: true)')
    parser.add_argument('--no-require-heard', dest='require_heard', action='store_false', help='Disable heard requirement')
    parser.add_argument('--reply-not-heard', action='store_true', default=True, help='Reply on APRS when target not heard (default: true)')
    parser.add_argument('--no-reply-not-heard', dest='reply_not_heard', action='store_false', help='Disable APRS reply when not heard')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (-v, -vv)')
    args = parser.parse_args()

    configure_logging(args.verbose)

    js8 = JS8Client(args.js8_host, args.js8_port)

    # Determine APRS-IS login user if not provided
    aprs_user = args.aprs_user
    if not aprs_user:
        logging.info("Fetching station callsign from JS8Call for APRS-IS login")
        aprs_user = js8.get_callsign() or ''
    if not aprs_user:
        logging.error("Could not determine APRS-IS user (provide --aprs-user or ensure JS8Call answers STATION.GET_CALLSIGN)")
        return
    passcode = args.aprs_passcode if args.aprs_passcode is not None else getPass(aprs_user)

    # Build APRS-IS server-side filter: messages + optional destination prefix
    filter_parts = ["t/m"]
    if args.aprs_dest:
        # Many igates set TOCALL in 'to' field; no direct server filter for destination prefix, but some servers support p/ for prefixes. Keep client-side.
        pass
    server_filter = ' '.join(filter_parts)

    backoff = 1
    last_sent = 0.0

    while True:
        try:
            aprs = aprslib.IS(aprs_user, str(passcode))
            if server_filter:
                logging.info(f"Applying APRS-IS filter: {server_filter}")
                aprs.set_filter(server_filter)
            logging.info(f"Connecting to APRS-IS {args.aprs_server}:{args.aprs_port} as {aprs_user}")
            aprs.connect(args.aprs_server, args.aprs_port)
            logging.info("Connected to APRS-IS")
            backoff = 1

            def packet_handler(packet):
                nonlocal last_sent
                try:
                    if 'message_text' not in packet:
                        return
                    tocall = (packet.get('to', '') or '').upper()
                    if args.aprs_dest and tocall != args.aprs_dest.upper():
                        return
                    fromcall = (packet.get('from', '') or '').upper()
                    msg_text = packet.get('message_text', '') or ''

                    target, body, kind = parse_target_and_body(msg_text)
                    if kind == 'empty':
                        return
                    if kind == 'query':
                        heard = js8.get_heard_calls(timeout=4.0) or set()
                        if args.reply_not_heard:
                            txt = 'heard: ' + ' '.join(sorted(heard))
                            send_aprs_message(aprs, aprs_user, fromcall, txt)
                        return

                    # Rate limit
                    now = time.time()
                    if args.min_interval > 0 and (now - last_sent) < args.min_interval:
                        logging.debug("Dropping due to rate limit")
                        return

                    if not target:
                        return

                    ok_to_send = True
                    if args.require_heard:
                        heard = js8.get_heard_calls(timeout=4.0) or set()
                        ok_to_send = (target in heard)
                        if not ok_to_send and args.reply_not_heard:
                            send_aprs_message(aprs, aprs_user, fromcall, f"JS8 Callsign {target} not heard.")
                    if not ok_to_send:
                        return

                    out_text = f"{target} MSG FROM {fromcall} via APRS: {_sanitize_text(body)}"
                    js8.send_text(out_text)
                    last_sent = now
                except Exception as e:
                    logging.error(f"Packet handling error: {e}")
                    logging.debug(traceback.format_exc())

            aprs.consumer(packet_handler)

        except KeyboardInterrupt:
            logging.info("Interrupted; shutting down")
            try:
                aprs.close()
            except Exception:
                pass
            break
        except Exception as e:
            logging.warning(f"APRS-IS connection error: {e}; reconnecting in {backoff}s")
            try:
                aprs.close()
            except Exception:
                pass
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


if __name__ == '__main__':
    main()

