import socket

ips = {}

with open("blacklist.data", 'r') as blacklist:
    for address in blacklist.read().splitlines()[1:]:
        try:
            for info in socket.getaddrinfo(address, 80):
                ips[(info[4][0])] = address
        except Exception as e:
            print e, address

with open("ipblacklist.data", 'w') as ipblacklist:
    ipblacklist.write('#fields\tip\turl\n'+'\n'.join([ip+'\t'+ips[ip] for ip in ips]))

   
