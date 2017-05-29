'''Adds a blocked ip address to acls.yaml.'''

import os
import yaml

FILE_NAME = 'acls.yaml'

new_ip = raw_input()

blocked_set = set()

stream = file(FILE_NAME, 'r')

acls = yaml.load(stream)
stream.close()
for rule in acls['acls'][1]:
    if 'nw_dst' in rule['rule']:
        blocked_set.add(rule['rule']['nw_dst'])

if new_ip not in blocked_set:
    blocked_set.add(new_ip)

    rules = []

    for ip in blocked_set:
        rules.append({'rule':{'dl_type':0x0800, 'nw_dst':ip, 'actions':{'allow':0}}})

    rules.append({'rule':{'actions':{'allow':1, 'mirror':4}}})

    yaml.dump({'version':2, 'acls':{1:rules}}, file(FILE_NAME, 'w'))

    os.system("pkill -SIGHUP -f \"faucet.py\"")
