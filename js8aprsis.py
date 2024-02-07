#!/usr/local/bin/python3

import socket
import aprs
import time
import json 
import sys

# Configurations
js8_host = "localhost"  # Change this to the actual host where JS8Call is running
js8_port = 2442

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

def eatping(x):
    pingtest = str(x)
    while (pingtest.find("PING") != -1):
        print("eating ping: PING!!")
        x = sock.recv(1024)
        pingtest = str(x)
    return x

def getmessageoftype(x, rec):
    print("In getmessageoftype(x,rec)")
    msgtype = str(x)
    print("Message type:" + msgtype)
    packet = str(rec)
    print(packet)
    while (packet.find(msgtype) == -1):
        print ("Looking for type:" + msgtype)
        print(packet)
        rec = js8sock.recv(2048)
        packet = str(rec)
    return rec

def callback(x):
    print(x)

    if (str(x).split(":")[3] == "??"):
        print("Return list:")
        jsonout = "{\"params\": {\"_ID\": " + str(int(time.time()*1000)) + "}, \"type\": \"RX.GET_CALL_ACTIVITY\", \"value\": \"\"}"
        jsn=jsonout+"\n"
        js8sock.sendall(jsn.encode())
        print("1")
        rec = js8sock.recv(2048)
        print("2")
        print("Call getmessageoftype(x,rec)")
        rec = getmessageoftype("RX.CALL_ACTIVITY", rec)
        print(f"TEH REK! {rec}")
        json_object = json.loads(rec)
        print("Out of getmessageoftype")
        print(rec)
        calllist = ""
        for params in json_object['params']:
            calllist += params + " "
            print(params)
        print("after call list build")
        calllist = calllist.replace("_ID", "")
        print(calllist)
        fromcall = str(x).split(">")[0]
        frame = callsign +'>APRS::'+fromcall.ljust(9, ' ')+':heard:' + calllist
        aprs.send(bytes(frame, "utf8"))
        return

    try:
        fromcall = str(x).split(">")[0]
    except:
        return
    try:
        targetcall = str(x).split(":")[3]
    except:
        return
    try:
        sendmsg = str(x).split(":")[4]
    except:
        return
    print("From Call:" + fromcall)
    print("Target callsign:" + targetcall)
    print("Outgoing message:" + sendmsg)

    jsonout = "{\"params\": {\"_ID\": " + str(int(time.time()*1000)) + "}, \"type\": \"RX.GET_CALL_ACTIVITY\", \"value\": \"\"}"
    jsn=jsonout+"\n"
    js8sock.sendall(jsn.encode())
    rec = js8sock.recv(2048)
    rec = getmessageoftype("RX.CALL_ACTIVITY", rec)
    json_object = json.loads(rec)
    if (str(json_object).find(targetcall) != -1): 
        print("FOUND CALL! WOO!")
        js8string = targetcall + " MSG FROM " + fromcall + " via APRS:" + sendmsg
        print("Final out:" + js8string.rstrip())
        jsonout = "{\"params\": {\"_ID\": " + str(int(time.time()*1000)) + "}, \"type\": \"TX.SEND_MESSAGE\", \"value\": \"" + js8string.rstrip() + "\"}"
        print("Jsonout:" + jsonout)
        print("Sending to JS8!")
        jsn=jsonout+"\n"
        js8sock.sendall(jsn.encode())
    else:
        frame = callsign +'>APRS::'+fromcall.ljust(9, ' ')+':JS8 Callsign '+targetcall+' not heard.'
        aprs.send(bytes(frame, "utf8"))

print("APRS-IS to JS8 Gateway. V0.1")
print("Initiating connection to JS8Call...")
try:
    js8sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    js8sock.connect((js8_host, js8_port))
    print("Connected to JS8Call.")
except Exception as e:
    print("Failed to connect to JS8Call:", e)
    sys.exit(1)

# Get Callsign from JS8
jsonout = '{"params": {}, "type": "STATION.GET_CALLSIGN", "value": ""}'
jsn=jsonout+"\n"
js8sock.sendall(jsn.encode())
rec = js8sock.recv(1024)
print(rec)
json_object = json.loads(rec)
print("Callsign:" + json_object['value'])
callsign = json_object['value']

print("Connecting to APRS-IS...")
aprs_prepass = getPass(callsign)
aprs_pass = str(aprs_prepass)
aprs = aprs.TCP(bytes(callsign, 'utf8'), aprs_pass, False, "d/JS8*")
aprs.start()
aprs.receive(callback=callback)

