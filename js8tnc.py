#!/usr/bin/env python3
import socket
import time
import json
import threading

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

def send_tcp(socket, msg):
    msg = msg + "\n"
    socket.sendall(msg.encode())
    print(f"Sent to JS8: {msg}")

def kiss_thread():
    while True:
        print("Waiting for data from KISS...")
        kiss_connection, kiss_address = kiss_socket.accept()
        print('TNC Client connected from:', kiss_address)
        kiss_data = kiss_connection.recv(1024)
        if not kiss_data:
            kiss_connection.close()
            continue

        # Process KISS frame
        try:
            # Extract message
            message = kiss_data.decode('utf-8', errors='ignore').split("\u0003")[1]
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
        finally:
            kiss_connection.close()

def js8_thread():
    while True:
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
                message_body=message['params']['TEXT'].split("CMD")[1].strip()
                message_from=message['params']['FROM']
                kiss_message=f"{message_from}:{message_body}"
                #print(f"KISS MESSAGE: {message_from} {message_body}")

                #kiss_message = message_parts #f"\x1b\x03{message_content}\x0f"
                print("KISS message:", kiss_message)
                send_tcp(kiss_socket, kiss_message)

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
