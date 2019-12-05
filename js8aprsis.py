#!/usr/local/bin/python3

import socket
import aprs
import time
import json 

#config goes here
aprs_pass = "17574"
js8port = 2242


sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind(("",js8port))

def callback(x):
  print(x)
  

print("APRS-IS to JS8 Gateway. V0.1")
print("Waiting for JS8 to connect...")
rec, js8sock = sock.recvfrom(1024)
print ("JS8 Connected " + str(js8sock))
jsonout= "{\"params\": {\"_ID\": "+str(int(time.time()*1000))+"}, \"type\": \"STATION.GET_CALLSIGN\", \"value\": \"\"}"
sock.sendto(bytes(jsonout,"utf8"), js8sock)
rec = sock.recv(1024)
json_object = json.loads(rec)
print ("foo:"+ json_object['value'])

print("Connecting to APRS-IS...")
aprs = aprs.TCP(bytes(json_object['value'], 'utf8'),aprs_pass,False,"t/m")
aprs.start()
aprs.receive(callback=callback)

