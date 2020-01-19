#!/bin/bash
echo "Installing Files"
sudo apt-get install python3-pip
pip3 install --upgrade pyserial 
pip3 install aprs -v
pip3 install aprs --upgrade -v
echo "Complete please enter your CALLSIGN into JS8CALL before running program"
