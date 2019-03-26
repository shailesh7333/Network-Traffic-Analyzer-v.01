import pygeoip
import socket
import dpkt
import operator
from urllib.parse import unquote

gi = pygeoip.GeoIP("/opt/GeoIP/Geo.dat")

# finding out the city name and geo-location of IP


def ip_info(ip):

    rec = gi.record_by_name(ip)

    print(rec)

    city = rec["city"]

    country = rec["country_name"]

    long = rec["longitude"]

    lat = rec["latitude"]

    print("[∗] IP: " + ip + " Geo - located. ")

    print("[+]" + str(city) + "," + str(country))

    print("[+]Latitude:"+str(lat) + ", Longitude: " + str(long))

ip = "172.123.34.25"

ip_info(ip)

#finding out the blacklisted site downloader or anything content related LOIC in any format

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




f = open("/Users/shaileshchauhan/Desktop/Test1Loic.pcap", 'rb')

pcap = dpkt.pcap.Reader(f)

printPcap1(pcap)

def findAttack(pcap):
    THRESH = 1000
    b = 0
    count = {}
    count1 = {}
    for (ts, buf) in pcap:
        try:

            eth = dpkt.ethernet.Ethernet(buf)

            ip = eth.data

            src = socket.inet_ntoa(ip.src)

            dst = socket.inet_ntoa(ip.dst)

            if src in count:
                count[src] += 1
            else:
                count[src] = 1

            if dst in count1:
                count1[dst] += 1
            else:
                count1[dst] = 1


        except:

            pass

    print(count)
    b = str(count[src])
    Attacker = str(max(count, key=count.get))

    if count[src] > THRESH:
        print('[+] ' + Attacker + ' initiate the attacke with ' + b + ' packets ')
    else:
        print('Host is Safe!!')

    print(" ")

#if this pcap file contains the LOIC download then find out either this host part of any DDos or initiate any DDos.

f = open("/Users/shaileshchauhan/Desktop/Test1DDOS.pcap",'rb')

pcap = dpkt.pcap.Reader(f)

findAttack(pcap)