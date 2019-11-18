#!/bin/python

import codecs
import json
import urllib.request as urllib2
from optparse import OptionParser

from prettytable import PrettyTable
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


debug = 0
essidProbes = {}

def findVendor(mac):
    # API base url,you can also use https if you need
    url = "http://macvendors.co/api/"
    # Mac address to lookup vendor from
    mac_address = mac
    request = urllib2.Request(url + mac_address, headers={'User-Agent': "API Browser"})
    response = urllib2.urlopen(request)

    # Fix: json object must be str, not 'bytes'
    reader = codecs.getreader("utf-8")

    obj = json.load(reader(response))
    # Print company name
    vendor = obj['result']['company']
    return vendor


def essidTableBuild(Dictionary, tableHeader):
    table = PrettyTable(tableHeader)
    for essid in Dictionary.keys():
        try:
            vendor = findVendor(str(Dictionary[essid][0]))
        except Exception as e:
            vendor = "**Unkown**"
        table.add_row([essid.decode('utf-8'), str(Dictionary[essid][0]), vendor, str(len(Dictionary[essid]))])
        # print (Dictionary[essid])
        for mac in Dictionary[essid][1:]:
            # print ("Vendor for  Mac : {}".format(str(mac)))
            try:
                vendor = findVendor(str(mac))
            except Exception as e:
                vendor = "**Unkown**"
            table.add_row(["", mac, vendor, ""])
    return table


def PacketHandler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) > 0:
            clientMAC = pkt.addr2
            essid = pkt.info
            iterator = 0
            # Dictionary for ESSIDs and its corresponding client probes
            if essid in essidProbes.keys():
                if clientMAC not in essidProbes[essid]:
                    essidProbes[essid].append(clientMAC)
                    if debug >= 1:
                        print(bcolors.OKBLUE + "New Client, Known ESSID Found: from {} for {}".format(pkt.addr2,
                                                                                                      (pkt.info).decode(
                                                                                                          'utf-8')) + bcolors.ENDC)
            else:
                essidProbes[essid] = [clientMAC]
                if debug >= 1:
                    print(bcolors.WARNING + "New Client, New ESSID Found: from {} for {}".format(pkt.addr2,
                                                                                                 (pkt.info).decode(
                                                                                                     'utf-8')) + bcolors.ENDC)


def hopperRange(iface, rangeStart, rangeEnd):
    n = rangeStart
    stop_hopper = False
    while not stop_hopper:
        for x in range(rangeStart, rangeEnd):
            time.sleep(1)
            os.system('iwconfig %s channel %d' % (iface, x))
            if debug >= 2:
                print ("Wireless Interface: {} Current Channel: {}".format(iface, n))
            dig = int(random.randint(rangeStart, rangeEnd))
            if dig != 0 and dig != n:
                n = dig


def sniffer(iface, count, timeout, prn, rangeStart=1, rangeEnd=14):
    print ("Trying to set monitor mode for device " + iface + "...")
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode monitor")
    os.system("ifconfig " + iface + " up")
    # print "Done. If you don't see any data, the monitor mode setup may have failed.\n\n"
    print ("Wireless Interface : {} Start Sniffing .....".format(iface))

    threadHopper = threading.Thread(target=hopperRange, args=(iface, rangeStart, rangeEnd), name="hopperRange")
    threadHopper.daemon = True
    threadHopper.start()

    sniff(iface=iface, count=count, timeout=timeout, prn=prn)


def main():
    global debug

    parser = OptionParser()
    parser.add_option("-i", "--interface",
                      help="Wireless interface to be used, Must Support Packet Monitoring. Default vlaue: wlan0",
                      action="store", dest="interface", default="wlan0", type="string")

    parser.add_option("-q", "--quiet", help="don't print status messages to stdout",
                      action="store_false", dest="verbose", default=True)

    parser.add_option("-c", "--counter", help="Number of sniffed packets. Default value: 50K packets",
                      action="store", dest="counter", default=50000, type="int")

    parser.add_option("-t", "--timeout", help="Time to sniff packets (in seconds). Default value: 30 seconds",
                      action="store", dest="timeout", default=30, type="int")

    (options, args) = parser.parse_args()
    if options.debug:
        debug = 2

    try:
        sniffer(iface=options.interface, count=options.counter, timeout=options.timeout, prn=PacketHandler,
                rangeStart=1,
                rangeEnd=14)
        essidsTable = essidTableBuild(essidProbes, ['ESSID', 'client MAC', 'Vendor', 'Count'])
        print(essidsTable)
    except KeyboardInterrupt:
        essidsTable = essidTableBuild(essidProbes, ['ESSID', 'client MAC', 'Vendor', 'Count'])
        print(essidsTable.get_string(title="Found Probes!"))
    except Exception as e:
        raise e


if __name__ == '__main__':
    main()
