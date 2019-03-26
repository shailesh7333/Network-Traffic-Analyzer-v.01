# then we have to run the ip_info(ip) section for the finding the detailed info of the DDoS attack ip
import pygeoip

gi = pygeoip.GeoIP("/opt/GeoIP/Geo.dat")

a = input() # after detailed analyses we have to put the ip address , ask for the use input.

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

ip_info(a)
