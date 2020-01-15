#!/usr/local/bin/python3

import socket
import aprs
import time
import json 
import sys

#config goes here
js8port = 2242

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

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind(("",js8port))

def eatping(x):
  pingtest=str(x)
  while (pingtest.find("PING") != -1):
   print("eating ping: PING!!")
   x = sock.recv(1024)
   pingtest = str(x)
  return x

def getmessageoftype(x,rec):
  print("In getmessageoftype(x,rec)")
  msgtype=str(x)
  print("Message type:"+msgtype)
  packet=str(rec)
  print(packet)
  while (packet.find(msgtype) == -1):
    print ("Looking for type:" + msgtype)
    print(packet)
    rec = sock.recv(1024)
    packet=str(rec)
  return rec

def callback(x):
  print(x)

  if (str(x).split(":")[3] == "??"):
    print("Return list:")
    jsonout= "{\"params\": {\"_ID\": "+str(int(time.time()*1000))+"}, \"type\": \"RX.GET_CALL_ACTIVITY\", \"value\": \"\"}"
    sock.sendto(bytes(jsonout,"utf8"), js8sock)
    rec = sock.recv(1024)
    print("Call getmessageoftype(x,rec)")
    rec=getmessageoftype("RX.CALL_ACTIVITY",rec)
    json_object = json.loads(rec)
    print("Out of getmessageoftype")
    print(rec)
    calllist=""
    for params in json_object['params']:
      calllist+=params + " "
      print (params)
    print("after call list build")
    print (calllist)
    fromcall = str(x).split(">")[0]
    frame = callsign +'>APRS::'+fromcall.ljust(9, ' ')+':heard:' + calllist
    aprs.send(bytes(frame,"utf8"))
    return

  try:
   fromcall = str(x).split(">")[0]
  except: return
  try:
   targetcall = str(x).split(":")[3]
  except: return
  try:
   sendmsg = str(x).split(":")[4]
  except: return
  print("From Call:" + fromcall)
  print("Target callsign:" + targetcall)
  print("Outgoing message:" + sendmsg)

  jsonout= "{\"params\": {\"_ID\": "+str(int(time.time()*1000))+"}, \"type\": \"RX.GET_CALL_ACTIVITY\", \"value\": \"\"}"
  sock.sendto(bytes(jsonout,"utf8"), js8sock)
  rec = sock.recv(1024)
  rec=getmessageoftype("RX.CALL_ACTIVITY",rec)
  json_object = json.loads(rec)
  if (str(json_object).find(targetcall) !=-1): 
      print("FOUND CALL! WOO!")
      js8string = targetcall + " MSG FROM " + fromcall +"via APRS:" + sendmsg
      print("Final out:" + js8string.rstrip())
      jsonout= "{\"params\": {\"_ID\": "+str(int(time.time()*1000))+"}, \"type\": \"TX.SEND_MESSAGE\", \"value\": \"" + js8string.rstrip() + "\"}"
      print("Jsonout:" + jsonout)
      print("Sending to JS8!")
      sock.sendto(bytes(jsonout,"utf8"), js8sock)
  else:
     frame = callsign +'>APRS::'+fromcall.ljust(9, ' ')+':JS8 Callsign '+targetcall+' not heard.'
     #frame = "KI7WKZ>APRS:>Hello World!"
     aprs.send(bytes(frame,"utf8"))

print("APRS-IS to JS8 Gateway. V0.1")
print("Waiting for JS8 to connect...")
rec, js8sock = sock.recvfrom(1024)
print ("JS8 Connected " + str(js8sock))
#Get Callsign from JS8
jsonout= "{\"params\": {\"_ID\": "+str(int(time.time()*1000))+"}, \"type\": \"STATION.GET_CALLSIGN\", \"value\": \"\"}"
sock.sendto(bytes(jsonout,"utf8"), js8sock)
rec = sock.recv(1024)
json_object = json.loads(rec)
print ("Callsign:"+ json_object['value'])
callsign=json_object['value']

print("Connecting to APRS-IS...")
aprs_prepass = getPass(callsign)
aprs_pass = str(aprs_prepass)
aprs = aprs.TCP(bytes(callsign, 'utf8'),aprs_pass,False,"d/JS8*")
aprs.start()
aprs.receive(callback=callback)

