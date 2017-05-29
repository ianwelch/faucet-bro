blacklist.bro - bro script to detect blocked addresses and block them.
block_ip.py - used by blacklist.bro
block_list.data - list of blocked urls and ips
block_port.py - used by mhr.bro
geturl.py - downloads blocklist from website
mhr.bro - bro script to check file hashes of downloads
tests.py - tests for blacklist.bro
update_acls.py - clears blocked ips that are no longer in block_list.data, or clears all if 'clear' is passed as argument.
update_blocked - runs geturl.py then update_acls.py

