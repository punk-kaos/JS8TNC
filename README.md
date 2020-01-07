# JS8TNC
A quick and dirty Packet TNC for JS8Call


js8tnc.py will listen for a KISS client to connect to it, then act as an interface to JS8 so you can transmit APRS messages via JS8 using JS8's built in @APRSIS target. 

js8aprsis.py will connect to APRS-IS and listen for messages to your callsign in the following format "JS8USER: message", it will then query JS8 to see if it hears the requested
             user and if so transmit the message to the user via JS8. 
