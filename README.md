# ProbesFinder
This is a simple python tool to find all wireless clients probes and categorize it by ESSID, and it's relevant client probes associated with the MAC addresses of the clients and its vendors.

Supported Python:
    only supports Python 3.

Supported OS:
    It can work on any linux enviroment, but i do prefer Kali Linux, also it is tested on kali and works with no issue.

Required Hardware:
    Any wireless card can support monitor mode, like below:
        - Alfa Cards.
        - TP-Link 722n V1, V1.1, V2.
        - LB-Link Cards
        any other vendor can support monitor mode, is most welcome :)
        this tool is tested on the mentioned vendors.

Installation:
    Just install the required packages by the below command:
            pip install -r requirements

Usage:
it is simple, just use -h option to see help!

Usage: probesFinder.py [options]

Options:
  -h, --help            show this help message and exit
  
  -i INTERFACE, --interface=INTERFACE
                        Wireless interface to be used, Must Support Packet
                        Monitoring. Default vlaue: wlan0
                        
  -q, --quiet           don't print status messages to stdout.
  
  -c COUNTER, --counter=COUNTER
                        Number of sniffed packets. Default value: 50K packets.
                        
  -t TIMEOUT, --timeout=TIMEOUT
                        Time to sniff packets (in seconds). Default value: 30
                        seconds



