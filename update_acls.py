'''This script removes ips from acls.yaml that aren't in block_list.data.
If 'clear' is passed as an argument, this clears all blocked addresses.
'''

import os
import sys
import yaml

FILE_NAME = 'acls.yaml'

blocked_set = set()

if 'clear' not in sys.argv:
    bad_set = set()
    with open("block_list.data", 'r') as blacklist:
        for address in blacklist.read().splitlines()[1:]:
            bad_set.add(address.split()[0])

    stream = file(FILE_NAME, 'r')
    acls = yaml.load(stream)
    stream.close()
    for rule in acls['acls'][1]:
        if 'nw_dst' in rule['rule'] and rule['rule']['nw_dst'] in bad_set:
            blocked_set.add(rule['rule']['nw_dst'])

rules = []

for ip in blocked_set:
    rules.append({'rule':{'dl_type':0x0800, 'nw_dst':ip, 'actions': {'allow':0}}})

rules.append({'rule':{'actions': {'allow':1, 'mirror':4}}})

yaml.dump({'version':2, 'acls':{1:rules}}, file(FILE_NAME, 'w'))

os.system("pkill -SIGHUP -f \"faucet.py\"")
