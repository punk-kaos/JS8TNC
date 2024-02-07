#!/usr/bin/env python3
import socket
import time
import json
import threading
import re

# Define ports
kiss_port = 8001
js8_port = 2442

# Create TCP socket for KISS TNC
kiss_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
kiss_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
kiss_socket.bind(("0.0.0.0", kiss_port))
kiss_socket.listen(1)
print("TNC started on port", kiss_port)
print("Waiting for TNC client to connect...")

# Create TCP socket for JS8Call
js8_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    js8_socket.connect(("127.0.0.1", js8_port))
    print("Connected to JS8...")
except Exception as e:
    print("ERROR CONNECTING TO JS8:", e)
    exit()

print("Connected to JS8 on port", js8_port)

kiss_connection = None  # Global variable to store the KISS connection

def remove_non_ascii(text):
    return re.sub(r'[^\x00-\x7F]+', '', text)

def send_tcp(socket, msg):
    msg = msg + "\n"
    socket.sendall(msg.encode())
    print(f"SEND_TCP: {msg}")

def kiss_thread():
    global kiss_connection  # Use the global variable

    # Accept KISS connection
    print("Waiting for data from KISS...")
    kiss_connection, kiss_address = kiss_socket.accept()
    print('TNC Client connected from:', kiss_address)

    while True:
        kiss_data = kiss_connection.recv(1024)
        if not kiss_data:
            print("Disconnected from KISS.")
            kiss_connection.close()
            break

        # Process KISS frame
        try:
            # Extract message
            message = kiss_data.decode('utf-8', errors='ignore').split(":", 1)[1]
            print("Extracted message:", message)

            # Construct JSON message for JS8Call
            json_message = {
                "params": {},
                "type": "TX.SEND_MESSAGE",
                "value": "@APRSIS CMD " + message
            }
            json_string = json.dumps(json_message)
            print("JSON message:", json_string)
            send_tcp(js8_socket, json_string)

        except Exception as e:
            print("Error processing KISS frame:", e)
            continue

def js8_thread():
    while True:
        global kiss_connection  # Use the global variable
        if kiss_connection is None:
            time.sleep(1)  # Wait for the KISS connection to be established
            continue

        print("Waiting for data from JS8...")
        js8_data = js8_socket.recv(1024)
        if not js8_data:
            print("Disconnected from JS8.")
            js8_socket.close()
            exit()

        # Process JS8Call message
        try:
            js8_message = js8_data.decode("utf-8").strip()
            print("JS8Call message:", js8_message)

            # Check if message is directed to @APRSIS group
            if "@APRSIS" in js8_message:
                # Extract message content and send to KISS TNC
                message=json.loads(js8_message)
                message_body=remove_non_ascii(message['params']['TEXT'].split("CMD")[1].strip())
                message_from=message['params']['FROM']
                data=f"{message_from}>APJ8CL:{message_body}"
                kiss_message = data
                print("KISS message:", kiss_message)
                send_tcp(kiss_connection, kiss_message)
            if "@APRSGATE" in js8_message:
                # Extract message content and send to KISS TNC
                message=json.loads(js8_message)
                message_body=remove_non_ascii(message['params']['TEXT'].split("@APRSGATE")[1].strip())
                message_from=message['params']['FROM']
                data=f"{message_body}"
                kiss_message = data
                print("KISS message:", kiss_message)
                send_tcp(kiss_connection, kiss_message)

        except Exception as e:
            print("Error processing JS8Call message:", e)
            continue

# Start KISS TNC thread
kiss_thread = threading.Thread(target=kiss_thread)
kiss_thread.start()

# Start JS8Call thread
js8_thread = threading.Thread(target=js8_thread)
js8_thread.start()

# Join threads to keep the main thread running
kiss_thread.join()
js8_thread.join()

# Close sockets (this won't be reached as threads are infinite loops)
kiss_socket.close()
js8_socket.close()
