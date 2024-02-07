import aprslib
import socket
import json
import traceback

def getPass(callsign):
    basecall = callsign.upper().split('-')[0] + '\0'
    result = 0x73e2

    c = 0
    while (c+1 < len(basecall)):
        result ^= ord(basecall[c]) << 8
        result ^= ord(basecall[c+1])
        c += 2

    result &= 0x7fff
    return result

# Configure APRS server details
APRS_SERVER = 'rotate.aprs2.net'
APRS_PORT = 10152
APRS_USER = 'KI7WKZ'
APRS_PASSCODE = getPass(APRS_USER)  # Generate your passcode using getPass function

# Configure JS8Call TCP server details
JS8CALL_HOST = '127.0.0.1'  # Host running JS8Call
JS8CALL_PORT = 2442

# Configure APRS destination prefix to filter
APRS_FILTER_DESTINATION_PREFIX = 'JS8GATE'

# Configure APRS path to filter
APRS_FILTER_PATH = 'WIDE1-1'

# Flags to enable/disable filtering for destination and path
ENABLE_FILTERING_DESTINATION = False
ENABLE_FILTERING_PATH = True

def send_to_js8call(payload):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((JS8CALL_HOST, JS8CALL_PORT))
            print(f"Payload: {payload}")
            payload = payload + "\n"
            sock.sendall(payload.encode())
    except Exception as e:
        print("Error sending message to JS8Call:", e)

def handle_aprs_message(callsign, message_text, destination):
    try:
        son_message = {
            "params": {},
            "type": "TX.SEND_MESSAGE",
            "value": f"@APRSGATE {message_text}"
        }
        js8call_message = json.dumps(son_message)
        send_to_js8call(js8call_message)
    except Exception as e:
        print("Error handling APRS message:", e)
        traceback.print_exc()

def main():
    try:
        aprs = aprslib.IS(APRS_USER, APRS_PASSCODE)
        aprs.connect(APRS_SERVER, APRS_PORT)

        print(f"Connected to APRS-IS server {APRS_SERVER}")

        def packet_handler(packet):
            if (not ENABLE_FILTERING_DESTINATION or (packet['to'].startswith(APRS_FILTER_DESTINATION_PREFIX))) \
                    and (not ENABLE_FILTERING_PATH or packet['path'][0].startswith(APRS_FILTER_PATH)):
                callsign = packet['from']
                message_text = packet['raw']
                print(f"Packet: {packet['raw']}")
                handle_aprs_message(callsign, message_text, packet.get('destination', ''))

        aprs.consumer(packet_handler)

    except Exception as e:
        print("Error:", e)
        traceback.print_exc()

if __name__ == "__main__":
    main()
