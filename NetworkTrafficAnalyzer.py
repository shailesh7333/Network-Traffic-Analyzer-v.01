# Import all the required library
import pygeoip # used for tracking the ip after we idetify the DDoS attacker
import socket
import dpkt # used for parsing the each individual packet for extract each header
import operator
from urllib.parse import unquote
