#!/usr/local/bin/python3
import socket
import time
import json

port = 2242
kiss_port = 8001

kiss = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0",port))
print ("JS8Call TNC V0.2")
print ("Waiting for JS8 to connect...")
rec, js8sock = sock.recvfrom(1024)
print ("JS8 Connected " + str(js8sock))
kiss.bind(("", kiss_port))
#kiss.setblocking(False)
kiss.listen(1)
print ("TNC started on port " + str(kiss_port))
print ("Waiting for TNC client to connect...")
conn, addr = kiss.accept()
print ('TNC Client connected from: ', addr)


while True:

   print ("KISS loop")
   kiss_in = conn.recv(1024)
   if not len(kiss_in) >0: break
   print (kiss_in.decode("utf8","ignore"))

   try:
     print (kiss_in.decode("utf8","ignore").split('bbnc')[1])
   except:
     print ("Error decoding frame.")
     continue  
   
   js8string = "@APRSIS CMD " + kiss_in.decode("utf8","ignore").split('bbnc')[1]
   jsonout= "{\"params\": {\"_ID\": "+str(int(time.time()*1000))+"}, \"type\": \"TX.SEND_MESSAGE\", \"value\": \"" + js8string.rstrip() + "\"}"
   print (jsonout)
   sock.sendto(bytes(jsonout,"utf8"), js8sock)
