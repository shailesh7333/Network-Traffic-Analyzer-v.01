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

    # now DDOS test case
        def findAttack(pcap):
        THRESH = 1000 # threshold of DDoS
        b = 0
        count = {}
        count1 = {}
        for (ts, buf) in pcap:
            try:

                eth = dpkt.ethernet.Ethernet(buf)

                ip = eth.data

                src = socket.inet_ntoa(ip.src)

                dst = socket.inet_ntoa(ip.dst)

                if src in count:  # add the ip as key and value as number of packet sent from this source
                    count[src] += 1
                else:
                    count[src] = 1

                if dst in count1: # add the ip as a key and value as number of packet destinated for this ip.
                    count1[dst] += 1
                else:
                    count1[dst] = 1


            except:

                pass

        print(count)
        b = str(count[src])
        print(count1)
        Attacker = str(max(count, key=count.get))

        if count[src] > THRESH: # if the packet is above threshold value just print the msg with the attacker ip and number of packet
            print('[+] ' + Attacker + ' initiate the attacke with ' + b + ' packets ')
        else: # otherwise says it's safe
            print('Host is Safe!!')

        print(" ")

    #if this pcap file contains the LOIC download then find out either this host part of any DDos or initiate any DDos.

    f = open(b,'rb')

    pcap = dpkt.pcap.Reader(f)

    findAttack(pcap)
