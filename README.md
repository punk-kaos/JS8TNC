# JS8TNC
A quick and dirty Packet TNC for JS8Call


js8tnc.py will listen for a TEXT TNC client to connect to it, then act as an interface to JS8 so you can transmit APRS messages via JS8 using JS8's built in @APRSIS target.
Packets received to the @APRSIS call will be echoed back to the TNC client allowing for two way APRS support over JS8.

js8aprsis.py will connect to APRS-IS and listen for messages to your callsign in the following format "JS8USER: message", it will then query JS8 to see if it hears the requested
             user and if so transmit the message to the user via JS8. 
You can also send your station "??" and it will return the stations it hears on JS8 to you via APRS. 

