import argparse
import aprslib
import json
import logging
import socket
import time
import traceback
from collections import deque
from hashlib import sha1
from typing import Optional


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


class JS8Client:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def _connect(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((self.host, self.port))
        s.settimeout(None)
        self.sock = s
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

    def send_line(self, line: str) -> None:
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
            # retry once
            self.ensure_connected()
            assert self.sock is not None
            self.sock.sendall(data.encode('utf-8'))
            logging.info(f"SEND_JS8(retry): {line}")


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s: %(message)s')


MAX_VALUE_LEN = 240  # cap JS8 value length for reliability


def _sanitize_value(text: str) -> str:
    # Remove non-ASCII, collapse whitespace
    ascii_text = ''.join(ch for ch in text if ord(ch) < 128)
    collapsed = ' '.join(ascii_text.split())
    return collapsed


def handle_aprs_message(js8: JS8Client, callsign: str, message_text: str, destination: str) -> None:
    try:
        payload = _sanitize_value(message_text)
        value = f"@APRSGATE {payload}"
        if len(value) > MAX_VALUE_LEN:
            value = value[: MAX_VALUE_LEN - 3] + "..."
        js = {
            "params": {"_ID": int(time.time() * 1000)},
            "type": "TX.SEND_MESSAGE",
            "value": value,
        }
        js8.send_line(json.dumps(js))
    except Exception as e:
        logging.error(f"Error handling APRS message: {e}")
        logging.debug(traceback.format_exc())


def main() -> None:
    parser = argparse.ArgumentParser(description="APRS-IS -> JS8Call gateway")
    parser.add_argument('--aprs-server', default='rotate.aprs2.net', help='APRS-IS server (default: rotate.aprs2.net)')
    parser.add_argument('--aprs-port', type=int, default=10152, help='APRS-IS port (default: 10152)')
    parser.add_argument('--aprs-user', required=True, help='APRS-IS login callsign (e.g., N0CALL)')
    parser.add_argument('--aprs-passcode', type=int, help='APRS-IS passcode (if omitted, computed from user)')
    parser.add_argument('--js8-host', default='127.0.0.1', help='JS8Call host (default: 127.0.0.1)')
    parser.add_argument('--js8-port', type=int, default=2442, help='JS8Call TCP port (default: 2442)')
    parser.add_argument('--filter-dest-prefix', help='Only forward if packet "to" startswith this prefix (case-insensitive)')
    parser.add_argument('--filter-path', help='Only forward if any path hop startswith this value (case-insensitive)')
    parser.add_argument('--filter-trigger', help='Only forward if this substring appears in raw packet')
    parser.add_argument('--min-interval', type=float, default=0.0, help='Minimum seconds between forwards (rate limit)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (-v, -vv)')
    args = parser.parse_args()

    configure_logging(args.verbose)

    passcode = args.aprs_passcode if args.aprs_passcode is not None else getPass(args.aprs_user)
    logging.info(
        f"Connecting to APRS-IS {args.aprs_server}:{args.aprs_port} as {args.aprs_user}"
    )

    js8 = JS8Client(args.js8_host, args.js8_port)

    # Build APRS-IS server-side filter if possible
    filter_parts = []
    if args.filter_path:
        # Digipeater path alias filter
        alias = str(args.filter_path).strip().upper()
        if alias:
            filter_parts.append(f"d/{alias}")
    # Destination prefix filter does not have a direct APRS-IS filter; keep client-side.
    server_filter = ' '.join(filter_parts)

    # If we have a server-side filter and user left aprs-port at default, use 14580
    aprs_port = args.aprs_port
    if server_filter and args.aprs_port == 10152:
        aprs_port = 14580
        logging.info("Using APRS-IS user-defined filter port 14580 for server-side filtering")

    try:
        backoff = 1
        last_sent = 0.0
        seen_hashes = deque(maxlen=512)
        seen_set = set()

        while True:
            try:
                aprs = aprslib.IS(args.aprs_user, str(passcode))
                if server_filter:
                    logging.info(f"Applying server filter: {server_filter}")
                    aprs.set_filter(server_filter)
                logging.info(f"Connecting to APRS-IS {args.aprs_server}:{aprs_port}")
                aprs.connect(args.aprs_server, aprs_port)
                logging.info("Connected to APRS-IS")
                backoff = 1

                def _norm_hop(h) -> str:
                    try:
                        # aprslib may emit dict hops; prefer 'call' field if present
                        if isinstance(h, dict):
                            h = h.get('call', '')
                        s = str(h)
                        return s.strip().rstrip('*').upper()
                    except Exception:
                        return ''

                def packet_handler(packet):
                    nonlocal last_sent
                    try:
                        raw = packet.get('raw', '') or ''
                        to = packet.get('to', '') or ''
                        path = packet.get('path', []) or []

                        # Apply filters only if provided
                        if args.filter_dest_prefix:
                            if not str(to).upper().startswith(str(args.filter_dest_prefix).upper()):
                                return
                        if args.filter_path:
                            want = str(args.filter_path).strip().upper()
                            hops = path if isinstance(path, list) else [path]
                            if not any(_norm_hop(h).startswith(want) for h in hops):
                                return
                        if args.filter_trigger and args.filter_trigger not in raw:
                            return

                        # Rate limit
                        now = time.time()
                        if args.min_interval > 0 and (now - last_sent) < args.min_interval:
                            logging.debug("Dropping due to rate limit")
                            return

                        # Deduplicate
                        h = sha1(raw.encode('utf-8', errors='ignore')).hexdigest()
                        if h in seen_set:
                            logging.debug("Dropping duplicate APRS packet")
                            return
                        seen_hashes.append(h)
                        seen_set.add(h)
                        if len(seen_hashes) == seen_hashes.maxlen:
                            # shrink set when deque rolls
                            while len(seen_set) > len(seen_hashes):
                                # not perfect, but maintain size balance
                                break

                        callsign = packet.get('from', '') or ''
                        logging.info(f"Forwarding APRS from {callsign}")
                        logging.debug(f"Raw: {raw}")
                        handle_aprs_message(js8, callsign, raw, packet.get('destination', ''))
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

    except Exception as e:
        logging.error(f"Error: {e}")
        logging.debug(traceback.format_exc())


if __name__ == "__main__":
    main()
