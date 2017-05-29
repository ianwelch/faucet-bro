'''Adds a port to a different vlan in dps.yaml.
'''

import os
import json
import httplib
import yaml

FILE_NAME = 'dps.yaml'

new_mac = raw_input()

conn = httplib.HTTPConnection("localhost", 5984)
conn.request("GET", "/flows_bak/_design/flows/_view/mac?key=%%22%s%%22"%new_mac)
response = json.loads(conn.getresponse().read())

if "rows" in response and response["rows"]:
    new_port = int(response["rows"][0]["value"])

    stream = file(FILE_NAME, 'r')
    dps = yaml.load(stream)
    stream.close()

    interfaces = dps["dps"]["test-switch-1"]["interfaces"]
    for port in interfaces:
        if port == new_port:
            interfaces[port]["native_vlan"] = 200
            break

    yaml.dump(dps, file(FILE_NAME, 'w'))

    os.system("pkill -SIGHUP -f \"faucet.py\"")
