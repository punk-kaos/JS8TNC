#!/usr/bin/env python3
import argparse
import json
import logging
import re
import socket
import threading
import time
from typing import Optional

# KISS special characters
FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD

# Defaults
DEFAULT_BIND = "127.0.0.1"
DEFAULT_KISS_PORT = 8001
DEFAULT_JS8_HOST = "127.0.0.1"
DEFAULT_JS8_PORT = 2442

GATE_RAW = "raw"  # Send full APRS via @APRSGATE
GATE_CMD = "cmd"  # Send only message via @APRSIS CMD


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(threadName)s: %(message)s",
    )


def remove_non_ascii(text: str) -> str:
    return re.sub(r"[^\x00-\x7F]+", "", text)


def kiss_escape(payload: bytes) -> bytes:
    escaped = bytearray()
    for byte in payload:
        if byte == FEND:
            escaped.extend([FESC, TFEND])
        elif byte == FESC:
            escaped.extend([FESC, TFESC])
        else:
            escaped.append(byte)
    return bytes(escaped)


def kiss_unescape(payload: bytes) -> bytes:
    unescaped = bytearray()
    i = 0
    while i < len(payload):
        byte = payload[i]
        if byte == FESC and i + 1 < len(payload):
            next_byte = payload[i + 1]
            if next_byte == TFEND:
                unescaped.append(FEND)
                i += 2
                continue
            if next_byte == TFESC:
                unescaped.append(FESC)
                i += 2
                continue
        unescaped.append(byte)
        i += 1
    return bytes(unescaped)


def build_kiss_frame(payload: bytes) -> bytes:
    frame = bytearray([FEND, 0x00])
    frame.extend(kiss_escape(payload))
    frame.append(FEND)
    return bytes(frame)


def parse_kiss_frames(buffer: bytearray):
    frames = []
    while True:
        if FEND not in buffer:
            break
        start = buffer.find(FEND)
        if start != 0:
            del buffer[:start]
        if len(buffer) < 2:
            break
        buffer.pop(0)  # remove opening FEND
        if FEND not in buffer:
            buffer.insert(0, FEND)
            break
        end = buffer.find(FEND)
        frame = buffer[:end]
        del buffer[:end + 1]
        if not frame:
            continue
        command = frame[0]
        payload = kiss_unescape(frame[1:])
        frames.append((command, payload))
    return frames


def format_call(callsign: str, ssid: int) -> str:
    callsign = callsign.strip().upper()
    if ssid:
        return f"{callsign}-{ssid}"
    return callsign


def decode_ax25_address(raw: bytes):
    callsign = "".join(chr(b >> 1) for b in raw[:6]).strip()
    ssid = (raw[6] >> 1) & 0x0F
    repeated = bool(raw[6] & 0x80)
    return {
        "callsign": callsign,
        "ssid": ssid,
        "repeated": repeated,
        "last": bool(raw[6] & 0x01),
    }


def ax25_frame_to_text(frame: bytes) -> str:
    if len(frame) < 16:
        raise ValueError("Frame too short to be AX.25")
    addresses = []
    idx = 0
    last = False
    while not last:
        if idx + 7 > len(frame):
            raise ValueError("Incomplete address field")
        addr = decode_ax25_address(frame[idx : idx + 7])
        addresses.append(addr)
        last = addr["last"]
        idx += 7
        if len(addresses) > 10:
            raise ValueError("Too many address fields")
    if len(addresses) < 2:
        raise ValueError("AX.25 frame missing source/destination")
    if idx + 2 > len(frame):
        raise ValueError("Missing control/PID bytes")
    control = frame[idx]
    pid = frame[idx + 1]
    info = frame[idx + 2 :]
    if control != 0x03 or pid != 0xF0:
        raise ValueError("Unsupported AX.25 control/PID")
    dest = addresses[0]
    source = addresses[1]
    digis = addresses[2:]
    header = f"{format_call(source['callsign'], source['ssid'])}>{format_call(dest['callsign'], dest['ssid'])}"
    if digis:
        digi_text = []
        for digi in digis:
            call = format_call(digi["callsign"], digi["ssid"])
            if digi["repeated"]:
                call += "*"
            digi_text.append(call)
        header += "," + ",".join(digi_text)
    try:
        info_text = info.decode("ascii", errors="ignore")
    except Exception as exc:
        raise ValueError("Unable to decode info field") from exc
    return f"{header}:{info_text}"


def parse_callsign(value: str):
    value = value.strip().upper()
    repeated = value.endswith("*")
    if repeated:
        value = value.rstrip("*")
    if "-" in value:
        call, ssid_part = value.split("-", 1)
        ssid = int(ssid_part or 0)
    else:
        call = value
        ssid = 0
    return call, ssid, repeated


def encode_address_bytes(call: str, ssid: int, last: bool, repeated: bool = False) -> bytes:
    call = call.ljust(6)[:6]
    address = [(ord(char) << 1) for char in call]
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)
    if repeated:
        ssid_byte |= 0x80
    if last:
        ssid_byte |= 0x01
    else:
        ssid_byte &= 0xFE
    address.append(ssid_byte)
    return bytes(address)


def text_to_ax25_frame(aprs_text: str) -> bytes:
    if ":" not in aprs_text or ">" not in aprs_text:
        raise ValueError("APRS text missing header/payload delimiters")
    header, info = aprs_text.split(":", 1)
    source, remainder = header.split(">", 1)
    path_parts = [part for part in remainder.split(",") if part]
    if not path_parts:
        raise ValueError("APRS header missing destination")
    destination = path_parts[0]
    digis = path_parts[1:]
    addresses = []
    dest_call, dest_ssid, dest_repeated = parse_callsign(destination)
    addresses.append((dest_call, dest_ssid, dest_repeated))
    src_call, src_ssid, src_repeated = parse_callsign(source)
    addresses.append((src_call, src_ssid, src_repeated))
    for digi in digis:
        digi_call, digi_ssid, digi_repeated = parse_callsign(digi)
        addresses.append((digi_call, digi_ssid, digi_repeated))
    if len(addresses) < 2:
        raise ValueError("Need at least source and destination")
    frame = bytearray()
    for idx, (call, ssid, repeated) in enumerate(addresses):
        last = idx == len(addresses) - 1
        frame.extend(encode_address_bytes(call, ssid, last, repeated=repeated))
    frame.append(0x03)  # UI frame
    frame.append(0xF0)  # No layer 3
    frame.extend(info.encode("ascii", errors="replace"))
    return bytes(frame)


class JS8TNCBridge:
    def __init__(self, bind_host: str, kiss_port: int, js8_host: str, js8_port: int, gate_mode: str) -> None:
        self.bind_host = bind_host
        self.kiss_port = kiss_port
        self.js8_host = js8_host
        self.js8_port = js8_port
        self.gate_mode = gate_mode

        self.kiss_socket: Optional[socket.socket] = None
        self.kiss_connection: Optional[socket.socket] = None
        self.kiss_lock = threading.Lock()

        self.js8_socket: Optional[socket.socket] = None
        self.js8_lock = threading.Lock()

        self._stop = threading.Event()

    # ---- socket utils ----
    def _set_tcp_keepalive(self, sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

    # ---- KISS side ----
    def start_kiss_listener(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._set_tcp_keepalive(sock)
        sock.bind((self.bind_host, self.kiss_port))
        sock.listen(1)
        self.kiss_socket = sock
        logging.info(f"KISS TNC listening on {self.bind_host}:{self.kiss_port}")

    def accept_kiss_loop(self) -> None:
        assert self.kiss_socket is not None
        while not self._stop.is_set():
            try:
                logging.info("Waiting for KISS client to connect...")
                conn, addr = self.kiss_socket.accept()
                self._set_tcp_keepalive(conn)
                logging.info(f"KISS client connected from {addr}")
                with self.kiss_lock:
                    if self.kiss_connection:
                        try:
                            self.kiss_connection.close()
                        except OSError:
                            pass
                    self.kiss_connection = conn
                self.handle_kiss_client(conn)
            except OSError as e:
                if self._stop.is_set():
                    break
                logging.warning(f"KISS accept error: {e}")
                time.sleep(1)

    def handle_kiss_client(self, conn: socket.socket) -> None:
        buffer = bytearray()
        try:
            while not self._stop.is_set():
                data = conn.recv(4096)
                if not data:
                    logging.info("KISS client disconnected")
                    break
                buffer.extend(data)
                frames = parse_kiss_frames(buffer)
                for command, payload in frames:
                    if command != 0x00:
                        logging.info(f"Ignoring unsupported KISS command {command}")
                        continue
                    try:
                        aprs_text = ax25_frame_to_text(payload)
                        logging.info(f"Decoded APRS: {aprs_text}")
                        if self.gate_mode == GATE_CMD:
                            message = aprs_text.split(":", 1)[1]
                            json_message = {
                                "params": {"_ID": int(time.time() * 1000)},
                                "type": "TX.SEND_MESSAGE",
                                "value": "@APRSIS CMD " + message,
                            }
                        else:
                            json_message = {
                                "params": {"_ID": int(time.time() * 1000)},
                                "type": "TX.SEND_MESSAGE",
                                "value": "@APRSGATE " + aprs_text,
                            }
                        json_string = json.dumps(json_message)
                        self.send_js8_line(json_string)
                    except Exception as e:
                        logging.exception(f"Error processing KISS frame: {e}")
        finally:
            with self.kiss_lock:
                if self.kiss_connection is conn:
                    self.kiss_connection = None
            try:
                conn.close()
            except OSError:
                pass

    def send_kiss_frame(self, aprs_text: str) -> None:
        with self.kiss_lock:
            conn = self.kiss_connection
        if conn is None:
            logging.warning("No KISS client connected; dropping APRS frame")
            return
        try:
            ax25_payload = text_to_ax25_frame(aprs_text)
            kiss_payload = build_kiss_frame(ax25_payload)
            conn.sendall(kiss_payload)
            logging.info(f"SEND_KISS: {aprs_text}")
        except Exception as exc:
            logging.exception(f"Error sending KISS frame: {exc}")

    # ---- JS8 side ----
    def _connect_js8(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        self._set_tcp_keepalive(sock)
        logging.info(f"Connecting to JS8Call at {self.js8_host}:{self.js8_port}...")
        sock.connect((self.js8_host, self.js8_port))
        sock.settimeout(None)
        logging.info("Connected to JS8Call")
        return sock

    def js8_connect_loop(self) -> None:
        backoff = 1
        while not self._stop.is_set():
            try:
                sock = self._connect_js8()
                with self.js8_lock:
                    if self.js8_socket:
                        try:
                            self.js8_socket.close()
                        except OSError:
                            pass
                    self.js8_socket = sock
                backoff = 1
                self.read_js8_lines(sock)
            except Exception as e:
                if self._stop.is_set():
                    break
                logging.warning(f"JS8 connect/read error: {e}")
            with self.js8_lock:
                if self.js8_socket:
                    try:
                        self.js8_socket.close()
                    except OSError:
                        pass
                    self.js8_socket = None
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

    def read_js8_lines(self, sock: socket.socket) -> None:
        sock_file = sock.makefile("r", encoding="utf-8", newline="\n")
        while not self._stop.is_set():
            line = sock_file.readline()
            if not line:
                raise ConnectionError("JS8 socket EOF")
            js8_line = line.strip()
            if not js8_line:
                continue
            logging.debug(f"JS8 RX: {js8_line}")
            # Expect JSON per line
            try:
                message = json.loads(js8_line)
            except json.JSONDecodeError:
                logging.debug("Non-JSON line from JS8; ignoring")
                continue
            mtype = message.get("type", "")
            params = message.get("params", {}) or {}
            if not isinstance(params, dict):
                continue
            text = params.get("TEXT", "")
            if not isinstance(text, str):
                continue
            if "@APRSIS" in text:
                try:
                    body = remove_non_ascii(text.split("CMD", 1)[1].strip())
                except Exception:
                    continue
                from_call = params.get("FROM", "JS8CALL")
                aprs_text = f"{from_call}>APJ8CL:{body}"
                logging.info(f"Forwarding JS8 @APRSIS to KISS: {aprs_text}")
                self.send_kiss_frame(aprs_text)
            elif "@APRSGATE" in text:
                try:
                    body = remove_non_ascii(text.split("@APRSGATE", 1)[1].strip())
                except Exception:
                    continue
                aprs_text = body
                logging.info(f"Forwarding JS8 @APRSGATE to KISS: {aprs_text}")
                self.send_kiss_frame(aprs_text)

    def send_js8_line(self, msg: str) -> None:
        line = msg if msg.endswith("\n") else msg + "\n"
        with self.js8_lock:
            sock = self.js8_socket
        if not sock:
            logging.warning("JS8 not connected; dropping TX")
            return
        try:
            sock.sendall(line.encode("utf-8"))
            logging.info(f"SEND_JS8: {msg}")
        except OSError as e:
            logging.warning(f"JS8 send error: {e}")
            try:
                sock.close()
            except OSError:
                pass
            with self.js8_lock:
                if self.js8_socket is sock:
                    self.js8_socket = None

    # ---- lifecycle ----
    def stop(self) -> None:
        self._stop.set()
        with self.kiss_lock:
            if self.kiss_connection:
                try:
                    self.kiss_connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.kiss_connection.close()
                except OSError:
                    pass
                self.kiss_connection = None
            if self.kiss_socket:
                try:
                    self.kiss_socket.close()
                except OSError:
                    pass
                self.kiss_socket = None
        with self.js8_lock:
            if self.js8_socket:
                try:
                    self.js8_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.js8_socket.close()
                except OSError:
                    pass
                self.js8_socket = None


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP KISS <-> JS8Call bridge")
    parser.add_argument("--bind", default=DEFAULT_BIND, help="Bind host for KISS (default: 127.0.0.1)")
    parser.add_argument("--kiss-port", type=int, default=DEFAULT_KISS_PORT, help="KISS TCP port (default: 8001)")
    parser.add_argument("--js8-host", default=DEFAULT_JS8_HOST, help="JS8Call host (default: 127.0.0.1)")
    parser.add_argument("--js8-port", type=int, default=DEFAULT_JS8_PORT, help="JS8Call TCP port (default: 2442)")
    parser.add_argument("--gate-mode", choices=[GATE_RAW, GATE_CMD], default=GATE_CMD, help="APRS gate mode: raw or cmd (default: cmd)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    args = parser.parse_args()

    configure_logging(args.verbose)

    logging.info(
        f"Starting js8tnc: bind={args.bind}:{args.kiss_port} js8={args.js8_host}:{args.js8_port} mode={args.gate_mode}"
    )

    bridge = JS8TNCBridge(
        bind_host=args.bind,
        kiss_port=args.kiss_port,
        js8_host=args.js8_host,
        js8_port=args.js8_port,
        gate_mode=args.gate_mode,
    )

    bridge.start_kiss_listener()

    kiss_thread_t = threading.Thread(target=bridge.accept_kiss_loop, name="kiss-accept", daemon=True)
    js8_thread_t = threading.Thread(target=bridge.js8_connect_loop, name="js8-loop", daemon=True)
    kiss_thread_t.start()
    js8_thread_t.start()

    try:
        while kiss_thread_t.is_alive() and js8_thread_t.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        bridge.stop()


if __name__ == "__main__":
    main()
