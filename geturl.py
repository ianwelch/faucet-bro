'''Downloads a block list from zeustracker.abuse.ch, and finds the associated ip for each url
to add that to the list as well.'''

import urllib2
import socket

ips = {}

req = urllib2.Request("https://zeustracker.abuse.ch/blocklist.php?download=baddomains")
for url in urllib2.urlopen(req).read().splitlines():
    if url and url[0] != '#':
        try:
            for info in socket.getaddrinfo(url, 80):
                ips[(info[4][0])] = url
        except socket.error as exc:
            print exc, url

with open("block_list.data", 'w') as ipblacklist:
    ipblacklist.write('#fields\tip\turl\n'+'\n'.join([ip+'\t'+ips[ip] for ip in ips]))
