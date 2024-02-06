#!/usr/bin/env python3
import socket
import time
import json

# Define ports
kiss_port = 8001
print("JS8 KISS TNC V2BETA")
# Create TCP socket for KISS TNC
kiss_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
kiss_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
kiss_socket.bind(("0.0.0.0", kiss_port))
kiss_socket.listen(1)
print("TNC started on port", kiss_port)
print("Waiting for TNC client to connect...")

# Wait for KISS TNC client connection
kiss_connection, kiss_address = kiss_socket.accept()
print('TNC Client connected from:', kiss_address)

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect(("127.0.0.1", 2442))
    print("Connected to JS8...")
except:
    print("ERROR CONNECTING TO JS8!")
    exit()

def send_tcp(msg):

    msg = msg + "\n"
    s.sendall(msg.encode())
    print(f"Sent to JS8: {msg}")

# Main loop
while True:
    print("KISS loop")
    kiss_data = kiss_connection.recv(1024)
    if not kiss_data:
        break

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
        send_tcp(json_string)


    except Exception as e:
        print("Error processing KISS frame:", e)
        continue

# Close sockets
kiss_connection.close()
kiss_socket.close()
s.close()
