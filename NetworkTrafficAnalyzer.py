# Import all the required library
import pygeoip # used for tracking the ip after we idetify the DDoS attacker
import socket
import dpkt # used for parsing the each individual packet for extract each header
import operator
from urllib.parse import unquote

# here you can either create the individual function then run the for loop.
# because of limited test cases , i directly run the for loop for execution

for i in range(1,11): # you can put the range accoding to the test case availability
    a = "/Users/shaileshchauhan/Desktop/EE209project/" + 'Test' + str(i) + 'Loic' + ".pcap"
    b = "/Users/shaileshchauhan/Desktop/EE209project/" + 'Test' + str(i) + 'DDOS' + ".pcap"

    def printPcap1(pcap):

        for timestamp, buf in pcap:

            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)

            # Now grab the data within the Ethernet frame (the IP packet)
            ip = eth.data

            # Set the TCP data
            tcp = ip.data

            # Now see if we can parse the contents as a HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
                print(request.uri)

                if request.method == 'GET':

                    uri1 = request.uri.lower()
                    uri = unquote(uri1)
                    print(uri)

                    if '.pdf' in uri and 'loic' in uri:
                        print('[!] ' + 'this host '+ ' Downloadped LOIC.')
                        print('HTTP request: %s\n' % repr(request))
                        break
            except:
                pass

    f = open(a, 'rb')
    pcap = dpkt.pcap.Reader(f) # read and then parse the Loic test case
    printPcap1(pcap)
